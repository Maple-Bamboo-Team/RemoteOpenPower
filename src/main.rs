#[cfg(test)]
mod cli_tests;
mod client;
mod config;
mod logging;
mod private_file;
mod probe;
mod protocol;
mod security;
mod server;
#[cfg(test)]
mod test_support;
mod tui;
mod wake;
mod wol;

use clap::Parser;
use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

struct AnsiStyle(&'static str);

impl std::fmt::Display for AnsiStyle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if tui::cli_color_enabled() {
            formatter.write_str(self.0)
        } else {
            Ok(())
        }
    }
}

const RESET: AnsiStyle = AnsiStyle("\x1b[0m");
const BOLD: AnsiStyle = AnsiStyle("\x1b[1m");
const CYAN: AnsiStyle = AnsiStyle("\x1b[36m");
const GREEN: AnsiStyle = AnsiStyle("\x1b[32m");
const YELLOW: AnsiStyle = AnsiStyle("\x1b[33m");
const RED: AnsiStyle = AnsiStyle("\x1b[31m");
const DIM: AnsiStyle = AnsiStyle("\x1b[2m");
const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

#[cfg(windows)]
#[link(name = "msvcrt")]
unsafe extern "C" {
    fn _getch() -> i32;
}

#[derive(Debug, Parser)]
#[command(
    name = "remote-open-power",
    version,
    about = "Secure LAN Wake-on-LAN terminal"
)]
struct Cli {
    /// Run the TCP WoL daemon.
    #[arg(long)]
    server: bool,
    /// Run the non-interactive client command.
    #[arg(long)]
    client: bool,
    /// TOML settings path. Client credentials load from an adjacent private bundle.
    #[arg(long, default_value = config::DEFAULT_CONFIG_FILE)]
    config: PathBuf,
    /// Server bind IP literal override (server mode).
    #[arg(long)]
    bind: Option<String>,
    /// TCP port override.
    #[arg(long)]
    port: Option<u16>,
    /// Server address override (client mode).
    #[arg(long)]
    address: Option<String>,
    /// Host IDs to wake, comma separated. Omit to list hosts/statuses.
    #[arg(long, value_delimiter = ',')]
    wake: Vec<String>,
}

fn main() {
    logging::install_panic_hook();
    exit_on_error(run());
}

fn exit_on_error(result: Result<(), String>) {
    if let Err(error) = result {
        eprintln!("{RED}error:{RESET} {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    if cli.server && cli.client {
        return Err("--server and --client are mutually exclusive".to_owned());
    }
    if cli.server {
        return server::run_server(&cli.config, cli.bind, cli.port).map_err(|e| e.to_string());
    }
    if cli.client {
        return run_client_cli(&cli);
    }
    tui::run(&cli.config)
}

fn receive_catalog(
    handle: &client::ClientHandle,
) -> Result<(Vec<protocol::HostSummary>, u64), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut catalog: Option<(Vec<protocol::HostSummary>, u64)> = None;
    let mut status_map: HashMap<String, protocol::HostStatus> = HashMap::new();
    let mut table = None;
    let mut pending_error = None;
    loop {
        while let Ok(event) = handle.events.try_recv() {
            match event {
                client::ClientEvent::Connecting { .. } => {}
                client::ClientEvent::ConnectionFailed { code, message, .. } => {
                    pending_error = Some(format!("[{}] {message}", code.as_str()));
                }
                client::ClientEvent::Connected {
                    peer,
                    server_fingerprint,
                } => println!("{GREEN}connected{RESET} {peer}  server={server_fingerprint}"),
                client::ClientEvent::Hosts {
                    catalog_version,
                    hosts,
                } => {
                    if table.is_none() {
                        table = Some(HostTableView::new(&hosts, &status_map));
                    }
                    catalog = Some((hosts, catalog_version));
                }
                client::ClientEvent::Statuses { statuses, .. } => {
                    for status in statuses {
                        status_map.insert(status.host_id.clone(), status.clone());
                        if let Some(view) = table.as_mut() {
                            view.update(status);
                        }
                    }
                }
                client::ClientEvent::Error(error) => pending_error = Some(error),
                client::ClientEvent::Disconnected => {
                    if let Some(view) = table.as_mut() {
                        view.finish();
                    }
                    return Err("服务端已断开".to_owned());
                }
                _ => {}
            }
        }
        if let Some((hosts, catalog_version)) = &catalog
            && (hosts.is_empty() || status_map.len() >= hosts.len())
        {
            if let Some(view) = table.as_mut() {
                view.finish();
            } else {
                print_host_table(hosts, &status_map);
            }
            if let Some(error) = pending_error.take() {
                println!("{RED}{error}{RESET}");
            }
            return Ok((hosts.clone(), *catalog_version));
        }
        if Instant::now() >= deadline {
            if let Some((hosts, catalog_version)) = catalog {
                if let Some(view) = table.as_mut() {
                    view.finish();
                } else {
                    print_host_table(&hosts, &status_map);
                }
                if let Some(error) = pending_error.take() {
                    println!("{RED}{error}{RESET}");
                }
                return Ok((hosts, catalog_version));
            }
            return Err(pending_error
                .map(|error| format!("连接失败: {error}"))
                .unwrap_or_else(|| "等待主机目录超时".to_owned()));
        }
        if let Some(view) = table.as_mut() {
            let received = status_map.len();
            let total = view.host_count();
            view.set_footer(&format!("  状态: 正在获取在线状态 {received}/{total}"));
        } else {
            spinner_line("正在获取主机目录");
        }
        thread::sleep(Duration::from_millis(80));
    }
}

const HOST_ID_COLUMN: usize = 26;

struct HostTableView {
    hosts: Vec<protocol::HostSummary>,
    statuses: HashMap<String, protocol::HostStatus>,
    interactive: bool,
    rendered: bool,
    finished: bool,
    footer: String,
}

impl HostTableView {
    fn new(
        hosts: &[protocol::HostSummary],
        statuses: &HashMap<String, protocol::HostStatus>,
    ) -> Self {
        let mut view = Self {
            hosts: hosts.to_vec(),
            statuses: statuses.clone(),
            interactive: tui::cli_cursor_enabled(),
            rendered: false,
            finished: false,
            footer: String::new(),
        };
        if view.interactive {
            view.render();
        }
        view
    }

    fn host_count(&self) -> usize {
        self.hosts.len()
    }

    fn render(&mut self) {
        println!("\n{BOLD}{CYAN}可用主机{RESET}");
        println!("  {:>3}  {:<HOST_ID_COLUMN$}  状态", "#", "HOST ID");
        for (index, host) in self.hosts.iter().enumerate() {
            println!("{}", self.row(index, host));
        }
        self.footer = "  状态: 正在获取在线状态".to_owned();
        println!("{}", self.footer);
        self.rendered = true;
    }

    fn update(&mut self, status: protocol::HostStatus) {
        let host_id = status.host_id.clone();
        self.statuses.insert(host_id.clone(), status);
        if !self.interactive || !self.rendered {
            return;
        }
        let Some(index) = self.hosts.iter().position(|host| host.host_id == host_id) else {
            return;
        };
        let host = self.hosts[index].clone();
        let row = self.row(index, &host);
        update_line_from_bottom(self.hosts.len() + 1 - index, &row);
    }

    fn set_footer(&mut self, message: &str) {
        if self.footer == message {
            return;
        }
        self.footer = message.to_owned();
        if self.interactive && self.rendered {
            update_line_from_bottom(1, message);
        }
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if self.interactive && self.rendered {
            self.set_footer("  状态: 主机目录已就绪");
            println!();
        } else {
            print_host_table(&self.hosts, &self.statuses);
        }
    }

    fn row(&self, index: usize, host: &protocol::HostSummary) -> String {
        let state = self
            .statuses
            .get(&host.host_id)
            .map(|status| format_state(&status.state))
            .unwrap_or_else(|| format!("{DIM}UNKNOWN{RESET}"));
        format!(
            "  {:>3}  {}  {}",
            index + 1,
            cell(&host.host_id, HOST_ID_COLUMN),
            state
        )
    }
}

fn print_host_table(
    hosts: &[protocol::HostSummary],
    statuses: &HashMap<String, protocol::HostStatus>,
) {
    println!("\n{BOLD}{CYAN}可用主机{RESET}");
    println!("  {:>3}  {:<HOST_ID_COLUMN$}  状态", "#", "HOST ID");
    for (index, host) in hosts.iter().enumerate() {
        let state = statuses
            .get(&host.host_id)
            .map(|status| format_state(&status.state))
            .unwrap_or_else(|| "UNKNOWN".to_owned());
        println!(
            "  {:>3}  {}  {}",
            index + 1,
            cell(&host.host_id, HOST_ID_COLUMN),
            state
        );
    }
}

const OPERATION_HOST_COLUMN: usize = 30;

struct WakePanel {
    targets: Vec<String>,
    states: HashMap<String, String>,
    interactive: bool,
    rendered: bool,
    finished: bool,
    footer: String,
}

impl WakePanel {
    fn new(targets: &HashSet<String>, attempt: u8) -> Self {
        let mut ordered_targets: Vec<String> = targets.iter().cloned().collect();
        ordered_targets.sort();
        let states = ordered_targets
            .iter()
            .map(|target| (target.clone(), "QUEUED".to_owned()))
            .collect();
        let mut panel = Self {
            targets: ordered_targets,
            states,
            interactive: tui::cli_cursor_enabled(),
            rendered: false,
            finished: false,
            footer: String::new(),
        };
        if panel.interactive {
            panel.render(attempt);
        }
        panel
    }

    fn render(&mut self, attempt: u8) {
        println!("\n{BOLD}{CYAN}唤醒操作{RESET}");
        println!("  {:<OPERATION_HOST_COLUMN$}  状态", "HOST ID");
        for (index, target) in self.targets.iter().enumerate() {
            println!("{}", self.row(index, target));
        }
        self.footer = format!("  attempt={attempt}  等待服务端执行回执");
        println!("{}", self.footer);
        self.rendered = true;
    }

    fn set_state(&mut self, target: &str, state: &str) {
        if !self.states.contains_key(target) {
            return;
        }
        self.states.insert(target.to_owned(), state.to_owned());
        if !self.interactive || !self.rendered {
            return;
        }
        let Some(index) = self.targets.iter().position(|value| value == target) else {
            return;
        };
        let row = self.row(index, target);
        update_line_from_bottom(self.targets.len() + 1 - index, &row);
    }

    fn set_states<'a, I>(&mut self, targets: I, state: &str)
    where
        I: IntoIterator<Item = &'a String>,
    {
        for target in targets {
            self.set_state(target, state);
        }
    }

    fn set_footer(&mut self, message: &str) {
        if self.footer == message {
            return;
        }
        self.footer = message.to_owned();
        if self.interactive && self.rendered {
            update_line_from_bottom(1, message);
        }
    }

    fn finish(&mut self, message: &str) {
        if self.finished {
            return;
        }
        self.finished = true;
        if self.interactive && self.rendered {
            self.set_footer(message);
            println!();
        } else {
            self.print_plain();
            println!("{message}");
        }
    }

    fn print_plain(&self) {
        println!("\n{BOLD}{CYAN}唤醒操作{RESET}");
        println!("  {:<OPERATION_HOST_COLUMN$}  状态", "HOST ID");
        for (index, target) in self.targets.iter().enumerate() {
            println!("{}", self.row(index, target));
        }
    }

    fn row(&self, index: usize, target: &str) -> String {
        let state = self
            .states
            .get(target)
            .map(|value| format_operation_state(value))
            .unwrap_or_else(|| format!("{DIM}UNKNOWN{RESET}"));
        format!(
            "  {:>3}  {}  {}",
            index + 1,
            cell(target, OPERATION_HOST_COLUMN - 5),
            state
        )
    }
}

fn format_operation_state(state: &str) -> String {
    match state {
        "ONLINE" => format!("{GREEN}{state}{RESET}"),
        "SENT" => format!("{CYAN}{state}{RESET}"),
        "RETRYING" => format!("{YELLOW}{state}{RESET}"),
        "REJECTED" | "FAILED" => format!("{RED}{state}{RESET}"),
        _ => format!("{DIM}{state}{RESET}"),
    }
}

fn run_wake_session(
    handle: &client::ClientHandle,
    targets: HashSet<String>,
    catalog_version: u64,
) -> Result<(), String> {
    let operation_id = client::random_id();
    let boot_nonce = client::random_id();
    let mut panel = WakePanel::new(&targets, 1);
    if handle
        .commands
        .send(client::ClientCommand::Wake {
            host_ids: targets.iter().cloned().collect(),
            catalog_version,
            operation_id,
            boot_nonce,
            attempt: 1,
            retry_ticket: None,
        })
        .is_err()
    {
        panel.finish("  失败: 客户端 actor 已退出");
        return Err("客户端 actor 已退出".to_owned());
    }

    let mut attempt = 1u8;
    let mut ticket = None;
    let target_ids = targets.iter().cloned().collect::<Vec<_>>();
    let mut progress = wake::Progress::new(Instant::now());
    let mut receipt = false;
    let mut receipt_deadline = Instant::now() + client::RECEIPT_TIMEOUT;
    loop {
        while let Ok(event) = handle.events.try_recv() {
            match event {
                client::ClientEvent::Connecting { .. } => {}
                client::ClientEvent::ConnectionFailed { code, message, .. } => {
                    panel.finish(&format!("  失败 [{}]: {message}", code.as_str()));
                    return Err(format!("[{}] {message}", code.as_str()));
                }
                client::ClientEvent::CommandExecuted {
                    operation_id: event_operation,
                    attempt: event_attempt,
                    retry_ticket,
                    deadline_ms: _,
                    results,
                } if event_operation == operation_id && event_attempt == attempt => {
                    ticket = Some(retry_ticket);
                    receipt = true;
                    for result in &results {
                        panel.set_state(
                            &result.host_id,
                            if result.accepted { "SENT" } else { "REJECTED" },
                        );
                    }
                    progress.receive(&results, Instant::now());
                    if progress.accepted.is_empty() {
                        panel.finish("  失败: 服务端拒绝了全部目标");
                        return Err("服务端拒绝了全部目标".into());
                    }
                    // Retry timing belongs to the client. The server deadline
                    // only bounds its online observations; it must never
                    // shorten or extend either local one-minute wait window.
                    panel.set_footer(&format!(
                        "  attempt={}  已收到执行回执 | 在线 {}/{} | 本地等待 60s",
                        attempt,
                        progress.online.len(),
                        targets.len()
                    ));
                }
                client::ClientEvent::TargetOnline {
                    operation_id: event_operation,
                    attempt: event_attempt,
                    host_id,
                    ..
                } if event_operation == operation_id
                    && event_attempt == attempt
                    && progress.accepted.contains(&host_id) =>
                {
                    progress.observe(&host_id);
                    panel.set_state(&host_id, "ONLINE");
                }
                client::ClientEvent::Error(error) => {
                    panel.set_footer(&format!("  {RED}错误: {error}{RESET}"));
                }
                client::ClientEvent::Disconnected => {
                    panel.finish("  失败: 服务端已断开");
                    return Err("服务端已断开".to_owned());
                }
                _ => {}
            }
        }
        match progress.outcome(&target_ids) {
            wake::Outcome::Complete => {
                panel.finish("  OK: 全部目标已上线");
                return Ok(());
            }
            wake::Outcome::Partial => {
                panel.finish("  失败: 部分目标被拒绝");
                return Err("部分目标被拒绝".into());
            }
            wake::Outcome::Rejected | wake::Outcome::Waiting => {}
        }
        if !receipt && Instant::now() >= receipt_deadline {
            panel.finish("  失败: 等待服务端执行回执超时");
            return Err("等待服务端执行回执超时".into());
        }
        if receipt && Instant::now() >= progress.deadline {
            if attempt == 1 {
                let Some(retry_ticket) = ticket else {
                    panel.finish("  失败: 服务端未返回 retry ticket");
                    return Err("服务端未返回 retry ticket".to_owned());
                };
                panel.set_states(targets.iter(), "RETRYING");
                if handle
                    .commands
                    .send(client::ClientCommand::Wake {
                        host_ids: targets.iter().cloned().collect(),
                        catalog_version,
                        operation_id,
                        boot_nonce,
                        attempt: 2,
                        retry_ticket: Some(retry_ticket),
                    })
                    .is_err()
                {
                    panel.finish("  失败: 客户端 actor 已退出");
                    return Err("客户端 actor 已退出".to_owned());
                }
                attempt = 2;
                receipt = false;
                progress = wake::Progress::new(Instant::now());
                receipt_deadline = Instant::now() + client::RECEIPT_TIMEOUT;
                panel.set_footer("  attempt=2  一分钟未全部上线，已按授权票据重试");
            } else {
                panel.finish("  失败: 两次等待均超时");
                return Err("两次等待均超时".into());
            }
        }
        let remaining = if receipt {
            progress
                .deadline
                .saturating_duration_since(Instant::now())
                .as_secs()
        } else {
            receipt_deadline
                .saturating_duration_since(Instant::now())
                .as_secs()
        };
        panel.set_footer(&format!(
            "  attempt={}  在线 {}/{}  剩余={}s",
            attempt,
            progress.online.len(),
            targets.len(),
            remaining
        ));
        thread::sleep(Duration::from_millis(100));
    }
}

fn run_client_cli(cli: &Cli) -> Result<(), String> {
    let runtime = client::load_runtime(&cli.config, cli.address.clone(), cli.port)
        .map_err(|e| e.to_string())?;
    if let Some(label) = runtime.device_label.as_deref() {
        println!("  credential label  {label}  {DIM}(仅供显示，不参与授权){RESET}");
    }
    let handle = client::spawn_client(runtime).map_err(|error| error.to_string())?;
    if cli.wake.is_empty() {
        let result = receive_catalog(&handle).map(|_| ());
        request_client_shutdown(&handle);
        return result;
    }
    let wanted: HashSet<String> = cli
        .wake
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .collect();
    if wanted.len() > protocol::MAX_WAKE_TARGETS {
        return Err(format!(
            "--wake 单次最多包含 {} 台主机",
            protocol::MAX_WAKE_TARGETS
        ));
    }
    let (hosts, catalog) = receive_catalog(&handle)?;
    let available: HashSet<String> = hosts.iter().map(|host| host.host_id.clone()).collect();
    if !wanted.is_subset(&available) {
        request_client_shutdown(&handle);
        return Err("--wake 包含不在服务端目录中的主机 ID".to_owned());
    }
    let result = run_wake_session(&handle, wanted, catalog);
    request_client_shutdown(&handle);
    result
}

fn request_client_shutdown(handle: &client::ClientHandle) {
    if let Err(error) = handle.commands.send(client::ClientCommand::Shutdown) {
        logging::log(
            logging::Level::Warn,
            format!("client shutdown request was not delivered: {error}"),
        );
    }
}

fn spinner_line(message: &str) {
    if !tui::cli_cursor_enabled() {
        return;
    }
    static TICK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let tick = TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    print!(
        "\r\x1b[2K{CYAN}{}{RESET} {}",
        SPINNER[tick % SPINNER.len()],
        message
    );
    if let Err(error) = io::stdout().flush() {
        logging::log(
            logging::Level::Warn,
            format!("terminal output flush failed: {error}"),
        );
    }
}

fn update_line_from_bottom(lines_up: usize, text: &str) {
    if lines_up == 0 || !tui::cli_cursor_enabled() {
        return;
    }
    print!("\x1b[s\x1b[{}A\r\x1b[2K{}\x1b[u", lines_up, text);
    if let Err(error) = io::stdout().flush() {
        logging::log(
            logging::Level::Warn,
            format!("terminal output flush failed: {error}"),
        );
    }
}

fn cell(value: &str, width: usize) -> String {
    let mut output: String = value.chars().take(width).collect();
    if value.chars().count() > width && width >= 3 {
        output = value.chars().take(width - 3).collect();
        output.push_str("...");
    }
    format!("{output:<width$}")
}

fn format_state(state: &protocol::HostState) -> String {
    match state {
        protocol::HostState::Online | protocol::HostState::Succeeded => {
            format!("{GREEN}ONLINE{RESET}")
        }
        protocol::HostState::Waking => format!("{YELLOW}WAKING{RESET}"),
        protocol::HostState::Offline => format!("{RED}OFFLINE{RESET}"),
        protocol::HostState::Failed => format!("{RED}FAILED{RESET}"),
        protocol::HostState::Unknown => format!("{DIM}UNKNOWN{RESET}"),
    }
}
