use chrono::Local;
use std::{
    backtrace::Backtrace,
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    panic,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

const MAX_LOG_LINE_CHARS: usize = 4_096;
const LOG_DIRECTORY_ENV: &str = "REMOTE_OPEN_POWER_LOG_DIR";
const MAX_TERMINAL_LOGS: usize = 2_048;
static TERMINAL_ACTIVE: AtomicBool = AtomicBool::new(false);
static EMERGENCY: OnceLock<Mutex<LogQueue>> = OnceLock::new();

static STATE: OnceLock<Mutex<LoggerState>> = OnceLock::new();
static NEXT_GUARD_ID: AtomicU64 = AtomicU64::new(1);
static PANIC_HOOK_INSTALLED: OnceLock<()> = OnceLock::new();
#[cfg(test)]
pub(crate) static TEST_SERIAL: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Level {
    Info,
    Warn,
    Error,
    Fatal,
}

impl Level {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
        }
    }
}

#[derive(Default)]
struct LoggerState {
    sink: Option<(u64, Arc<Mutex<LogQueue>>)>,
    file: Option<FileTarget>,
}

struct FileTarget {
    id: u64,
    file: File,
}

pub struct SinkGuard {
    id: u64,
}

#[derive(Default)]
struct LogQueue {
    lines: VecDeque<String>,
    omitted: usize,
}

impl LogQueue {
    fn push(&mut self, line: String) {
        if self.lines.len() == MAX_TERMINAL_LOGS {
            self.lines.pop_front();
            self.omitted = self.omitted.saturating_add(1);
        }
        self.lines.push_back(line);
    }

    fn drain(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.omitted != 0 {
            lines.push(format!(
                "WARN {} terminal log lines omitted; consult the service log",
                self.omitted
            ));
            self.omitted = 0;
        }
        lines.extend(self.lines.drain(..));
        lines
    }
}

pub struct LogReceiver(Arc<Mutex<LogQueue>>);

impl LogReceiver {
    pub fn drain(&self) -> Vec<String> {
        flush_emergency();
        recover_lock(&self.0).drain()
    }
}

fn recover_lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

impl Drop for SinkGuard {
    fn drop(&mut self) {
        flush_emergency();
        let remaining = {
            let mut state = lock_state();
            if state.sink.as_ref().is_some_and(|(id, _)| *id == self.id) {
                let (_, queue) = state.sink.take().expect("matching terminal sink");
                TERMINAL_ACTIVE.store(false, Ordering::Release);
                recover_lock(&queue).drain()
            } else {
                Vec::new()
            }
        };
        for line in remaining {
            if let Err(error) = write_line(&mut io::stdout(), &line) {
                eprintln!("FATAL terminal log flush failed: {error}; original={line}");
            }
        }
    }
}

pub struct FileGuard {
    id: u64,
    path: PathBuf,
}

impl FileGuard {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FileGuard {
    fn drop(&mut self) {
        flush_emergency();
        let mut state = lock_state();
        if state
            .file
            .as_ref()
            .is_some_and(|target| target.id == self.id)
        {
            state.file = None;
        }
    }
}

pub fn install_sink() -> (SinkGuard, LogReceiver) {
    let id = next_guard_id();
    let queue = Arc::new(Mutex::new(LogQueue::default()));
    lock_state().sink = Some((id, Arc::clone(&queue)));
    TERMINAL_ACTIVE.store(true, Ordering::Release);
    (SinkGuard { id }, LogReceiver(queue))
}

pub fn install_file(directory: &Path) -> io::Result<FileGuard> {
    let mut state = lock_state();
    if state.file.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a service log is already active in this process",
        ));
    }
    fs::create_dir_all(directory)?;
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "log path must be a regular directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = unsafe { libc::geteuid() };
        if metadata.permissions().mode() & 0o022 != 0
            || (metadata.uid() != effective_uid && metadata.uid() != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "log directory must be owned by the service user or root and must not be group/world writable",
            ));
        }
    }

    let stamp = Local::now().format("%Y-%m-%d_%H%M");
    let (path, file) = (1..=9_999)
        .find_map(|sequence| {
            let path = directory.join(format!("{stamp}_{sequence:03}.log"));
            match open_new_log_file(&path) {
                Ok(file) => Some(Ok((path, file))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .transpose()?
        .ok_or_else(|| io::Error::other("log sequence exhausted for the current minute"))?;

    let id = next_guard_id();
    state.file = Some(FileTarget { id, file });
    Ok(FileGuard { id, path })
}

pub fn directory_for_config(config_path: &Path) -> PathBuf {
    std::env::var_os(LOG_DIRECTORY_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            config_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .join("logs")
        })
}

pub fn log(level: Level, message: impl AsRef<str>) {
    flush_emergency();
    for line in normalized_lines(message.as_ref()) {
        emit(level, &line);
    }
}

fn flush_emergency() {
    let lines = EMERGENCY
        .get()
        .map(|queue| recover_lock(queue).drain())
        .unwrap_or_default();
    for line in lines {
        emit(Level::Fatal, &line);
    }
}

pub fn report(level: Level, headline: &str, details: &str) {
    log(level, headline);
    for line in details.lines() {
        emit(level, &format!("report {line}"));
    }
}

pub fn install_panic_hook() {
    if PANIC_HOOK_INSTALLED.set(()).is_err() {
        return;
    }
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("unnamed");
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("non-string panic payload");
        let location = info.location().map_or_else(
            || "unknown".to_owned(),
            |location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                )
            },
        );
        let backtrace = Backtrace::force_capture();
        let details = format!(
            "thread={thread_name}\nlocation={location}\npayload={payload}\nbacktrace:\n{backtrace}"
        );
        try_report_from_panic("process panic", &details);
        if !TERMINAL_ACTIVE.load(Ordering::Acquire) {
            previous(info);
        }
    }));
}

fn emit(level: Level, message: &str) {
    let message = sanitize_line(message);
    let timestamp = display_timestamp();
    let disk_line = format!("{timestamp} {:<5} {message}", level.as_str());
    let sink_line = format!("{} {message}", level.as_str());
    let (sink, file_error) = {
        let mut state = lock_state();
        let file_error = state
            .file
            .as_mut()
            .and_then(|target| write_line(&mut target.file, &disk_line).err());
        if file_error.is_some() {
            state.file = None;
        }
        (
            state.sink.as_ref().map(|(_, queue)| Arc::clone(queue)),
            file_error,
        )
    };

    if let Some(queue) = sink {
        let mut queue = recover_lock(&queue);
        if let Some(error) = file_error {
            queue.push(format!(
                "FATAL log file disabled after write failure: {error}"
            ));
        }
        queue.push(sink_line);
        return;
    }
    if let Some(error) = file_error {
        eprintln!("FATAL log file disabled after write failure: {error}");
    }
    let mut stdout = io::stdout();
    if let Err(error) = write_line(&mut stdout, &disk_line) {
        eprintln!("FATAL stdout log write failed: {error}; original={disk_line}");
    }
}

fn try_report_from_panic(headline: &str, details: &str) {
    let timestamp = display_timestamp();
    let mut lines = Vec::with_capacity(details.lines().count() + 1);
    lines.push(sanitize_line(headline));
    lines.extend(
        details
            .lines()
            .map(|line| sanitize_line(&format!("report {line}"))),
    );

    let state = logger_state();
    let mut state = match state.try_lock() {
        Ok(state) => state,
        Err(TryLockError::Poisoned(error)) => error.into_inner(),
        Err(TryLockError::WouldBlock) => {
            for line in &lines {
                recover_lock(EMERGENCY.get_or_init(|| Mutex::new(LogQueue::default())))
                    .push(format!("panic report deferred: {line}"));
                if !TERMINAL_ACTIVE.load(Ordering::Acquire) {
                    eprintln!("{timestamp} FATAL {line}");
                }
            }
            return;
        }
    };
    for line in &lines {
        let disk_line = format!("{timestamp} FATAL {line}");
        if let Some(target) = state.file.as_mut()
            && let Err(error) = write_line(&mut target.file, &disk_line)
        {
            state.file = None;
            let failure = format!("FATAL panic report file write failed: {error}");
            if let Some((_, queue)) = &state.sink {
                recover_lock(queue).push(failure);
            } else {
                eprintln!("{failure}");
            }
        }
        if let Some((_, queue)) = &state.sink {
            recover_lock(queue).push(format!("FATAL {line}"));
        } else {
            eprintln!("{disk_line}");
        }
    }
}

fn write_line(writer: &mut impl Write, line: &str) -> io::Result<()> {
    writeln!(writer, "{line}")?;
    writer.flush()
}

fn normalized_lines(message: &str) -> Vec<String> {
    let lines = message.lines().map(sanitize_line).collect::<Vec<_>>();
    if lines.is_empty() {
        vec![String::new()]
    } else {
        lines
    }
}

fn sanitize_line(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_LOG_LINE_CHARS)
        .collect()
}

fn display_timestamp() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

fn open_new_log_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn next_guard_id() -> u64 {
    NEXT_GUARD_ID.fetch_add(1, Ordering::Relaxed)
}

fn logger_state() -> &'static Mutex<LoggerState> {
    STATE.get_or_init(|| Mutex::new(LoggerState::default()))
}

fn lock_state() -> std::sync::MutexGuard<'static, LoggerState> {
    match logger_state().lock() {
        Ok(state) => state,
        Err(error) => error.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn service_logs_use_timestamped_sequence_and_standard_levels() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "remote-open-power-log-test-{}-{nonce}",
            std::process::id()
        ));

        let first_path = {
            let guard = install_file(&directory).expect("first log");
            log(Level::Info, "started");
            log(Level::Warn, "limited");
            log(Level::Error, "recoverable");
            report(Level::Fatal, "stopped", "cause=test\ndetail=full");
            guard.path().to_path_buf()
        };
        let second_path = {
            let guard = install_file(&directory).expect("second log");
            guard.path().to_path_buf()
        };

        assert!(
            first_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with("_001.log")
        );
        assert!(
            second_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with("_002.log")
        );
        let contents = fs::read_to_string(&first_path).expect("read log");
        for level in ["INFO", "WARN", "ERROR", "FATAL"] {
            assert!(contents.contains(level), "missing level {level}");
        }
        assert!(contents.contains("report cause=test"));
        assert!(contents.contains("report detail=full"));
        fs::remove_dir_all(directory).expect("remove log test directory");
    }

    #[test]
    fn terminal_sink_retains_errors_and_deferred_panic_reports() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let directory = crate::test_support::TestDirectory::new();
        let (_sink, receiver) = install_sink();
        let file = install_file(&directory.0).unwrap();
        {
            let _locked = lock_state();
            try_report_from_panic("worker panic", "bounded test report");
        }
        assert!(
            receiver
                .drain()
                .iter()
                .any(|line| line.contains("bounded test report"))
        );
        let saved = fs::read_to_string(file.path()).unwrap();
        assert!(saved.contains("bounded test report"));
        {
            let mut state = lock_state();
            state.file.as_mut().unwrap().file = File::open(file.path()).unwrap();
        }
        log(Level::Error, "terminal error marker");
        let lines = receiver.drain();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("FATAL log file disabled"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("terminal error marker"))
        );
        assert!(lock_state().file.is_none());
        drop(receiver);
        log(Level::Warn, "receiver dropped marker");
        let queue = lock_state().sink.as_ref().unwrap().1.clone();
        assert!(
            recover_lock(&queue)
                .drain()
                .iter()
                .any(|line| line.contains("receiver dropped marker"))
        );
    }

    #[test]
    fn terminal_log_queue_is_bounded_and_reports_omissions() {
        let mut queue = LogQueue::default();
        for index in 0..MAX_TERMINAL_LOGS + 3 {
            queue.push(index.to_string());
        }
        let lines = queue.drain();
        assert_eq!(lines.len(), MAX_TERMINAL_LOGS + 1);
        assert!(lines[0].contains("3 terminal log lines omitted"));
        assert!(queue.drain().is_empty());
    }

    #[test]
    fn daemon_panic_during_logging_is_persisted_after_unlock() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let directory = crate::test_support::TestDirectory::new();
        let guard = install_file(&directory.0).unwrap();
        let path = guard.path().to_path_buf();
        {
            let _locked = lock_state();
            try_report_from_panic("daemon panic marker", "report while logger locked");
        }
        drop(guard);
        let text = fs::read_to_string(path).unwrap();
        assert!(text.contains("daemon panic marker"));
        assert!(text.contains("report while logger locked"));
    }
}
