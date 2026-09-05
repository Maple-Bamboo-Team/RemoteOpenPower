use chrono::Local;
use std::{
    backtrace::Backtrace,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    panic,
    path::{Path, PathBuf},
    sync::{
        Mutex, OnceLock, TryLockError,
        atomic::{AtomicU64, Ordering},
        mpsc::Sender,
    },
};

const MAX_LOG_LINE_CHARS: usize = 4_096;
const LOG_DIRECTORY_ENV: &str = "REMOTE_OPEN_POWER_LOG_DIR";

static STATE: OnceLock<Mutex<LoggerState>> = OnceLock::new();
static NEXT_GUARD_ID: AtomicU64 = AtomicU64::new(1);
static PANIC_HOOK_INSTALLED: OnceLock<()> = OnceLock::new();

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
    sink: Option<(u64, Sender<String>)>,
    file: Option<FileTarget>,
}

struct FileTarget {
    id: u64,
    file: File,
}

pub struct SinkGuard {
    id: u64,
}

impl Drop for SinkGuard {
    fn drop(&mut self) {
        let mut state = lock_state();
        if state.sink.as_ref().is_some_and(|(id, _)| *id == self.id) {
            state.sink = None;
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

pub fn install_sink(sender: Sender<String>) -> SinkGuard {
    let id = next_guard_id();
    lock_state().sink = Some((id, sender));
    SinkGuard { id }
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
    for line in normalized_lines(message.as_ref()) {
        emit(level, &line);
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
        previous(info);
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
            state.sink.as_ref().map(|(_, sender)| sender.clone()),
            file_error,
        )
    };

    if let Some(error) = file_error {
        eprintln!("FATAL log file disabled after write failure: {error}");
    }

    if let Some(sender) = sink
        && sender.send(sink_line).is_ok()
    {
        return;
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
    match state.try_lock() {
        Ok(mut state) => {
            for line in &lines {
                let disk_line = format!("{timestamp} {:<5} {line}", Level::Fatal.as_str());
                let file_error = state
                    .file
                    .as_mut()
                    .and_then(|target| write_line(&mut target.file, &disk_line).err());
                if let Some(error) = file_error {
                    state.file = None;
                    eprintln!("FATAL panic report file write failed: {error}");
                }
                if let Some((_, sender)) = state.sink.as_ref() {
                    if sender.send(format!("FATAL {line}")).is_err() {
                        eprintln!("{disk_line}");
                    }
                } else {
                    eprintln!("{disk_line}");
                }
            }
        }
        Err(TryLockError::Poisoned(error)) => {
            let mut state = error.into_inner();
            for line in &lines {
                let disk_line = format!("{timestamp} {:<5} {line}", Level::Fatal.as_str());
                if let Some(target) = state.file.as_mut()
                    && let Err(error) = write_line(&mut target.file, &disk_line)
                {
                    eprintln!("FATAL poisoned logger file write failed: {error}");
                }
                eprintln!("{disk_line}");
            }
        }
        Err(TryLockError::WouldBlock) => {
            for line in &lines {
                eprintln!("{timestamp} {:<5} {line}", Level::Fatal.as_str());
            }
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
}
