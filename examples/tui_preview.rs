use std::{
    collections::VecDeque,
    io::{self, IsTerminal, stdout},
    net::IpAddr,
    panic,
    time::{Duration, Instant},
};

use chrono::Local;
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{
        Clear as TerminalClear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
        disable_raw_mode, enable_raw_mode,
    },
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, Gauge, List, ListItem, Paragraph, Row, Table,
        TableState, Wrap,
    },
};
use tui_input::{Input, backend::crossterm::EventHandler};

const TICK_RATE: Duration = Duration::from_millis(100);
const MIN_WIDTH: u16 = 72;
const MIN_HEIGHT: u16 = 24;
const LOG_LIMIT: usize = 200;
const MAX_HOST_ID_BYTES: usize = 64;
const MAX_HOST_NAME_BYTES: usize = 128;
const MAX_MAC_BYTES: usize = 20;
const MAX_IP_BYTES: usize = 45;
const MAX_INTERFACE_INDEX_BYTES: usize = 10;
const MAX_PORT_BYTES: usize = 5;
const MAX_HEADER_NAME_BYTES: usize = 32;
const MAX_HEADER_VALUE_BYTES: usize = 256;
const MAX_CREDENTIAL_LABEL_BYTES: usize = 128;
const MAX_OUTPUT_PATH_BYTES: usize = 240;
const MAX_ENDPOINT_BYTES: usize = 253;
const MAX_HOSTS: usize = 64;
const MAX_CLIENTS: usize = 128;
const MAX_HEADERS: usize = 32;
const MAX_HEADER_BYTES: usize = 4_096;
const DEFAULT_CUSTOM_BIND: &str = "127.0.0.1";
const DEFAULT_V4_BIND: &str = "0.0.0.0";
const DEFAULT_V6_BIND: &str = "::";
const DEFAULT_SERVER_PORT: &str = "45890";
const DEFAULT_CLOCK_SKEW: &str = "30";
const DEFAULT_CLIENT_ADDRESS: &str = "";
const DEFAULT_CLIENT_PORT: &str = "45890";

const GREEN: Color = Color::Rgb(80, 200, 120);
const CYAN: Color = Color::Rgb(90, 190, 220);
const YELLOW: Color = Color::Rgb(235, 190, 80);
const MUTED: Color = Color::Rgb(135, 145, 150);
const PANEL: Color = Color::Rgb(55, 62, 66);

#[allow(dead_code)]
fn main() -> io::Result<()> {
    let capabilities = TerminalCapabilities::detect();
    if !capabilities.is_terminal {
        eprintln!("TUI 预览需要在交互式终端中运行。");
        return Ok(());
    }
    if !capabilities.ansi_supported && !cfg!(windows) {
        eprintln!("当前终端不支持 ANSI 光标控制，无法安全启动 TUI；请使用标准终端。");
        return Ok(());
    }

    install_panic_hook();
    enable_raw_mode()?;
    let _guard = TerminalGuard;

    let mut output = stdout();
    execute!(output, EnterAlternateScreen, Hide)?;
    let backend = CrosstermBackend::new(output);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::with_capabilities(capabilities);
    while !app.should_quit {
        app.tick();
        terminal.draw(|frame| render(frame, &app))?;

        if event::poll(TICK_RATE)? {
            let event = event::read()?;
            app.handle_event(event);
        }
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct TerminalCapabilities {
    is_terminal: bool,
    ansi_supported: bool,
    color_enabled: bool,
    note: String,
}

impl TerminalCapabilities {
    fn detect() -> Self {
        let is_terminal = stdout().is_terminal();
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
        let term_is_dumb = std::env::var("TERM").is_ok_and(|value| value == "dumb");

        #[cfg(windows)]
        let ansi_supported = crossterm::ansi_support::supports_ansi();
        #[cfg(not(windows))]
        let ansi_supported = !term_is_dumb;

        let native_color_fallback = cfg!(windows) && !ansi_supported;
        let color_enabled = is_terminal && !no_color && (ansi_supported || native_color_fallback);
        let note = if !is_terminal {
            "非交互式输出：TUI 已禁用".into()
        } else if no_color {
            "检测到 NO_COLOR：使用单色主题".into()
        } else if native_color_fallback {
            "ANSI 不可用：使用 Windows Console API 颜色回退".into()
        } else if term_is_dumb {
            "TERM=dumb：ANSI 控制不可用".into()
        } else {
            "ANSI 与颜色支持正常".into()
        };
        Self {
            is_terminal,
            ansi_supported,
            color_enabled,
            note,
        }
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn install_panic_hook() {
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(
        stdout(),
        Show,
        LeaveAlternateScreen,
        TerminalClear(ClearType::All),
        MoveTo(0, 0)
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Screen {
    Landing,
    ServerHome,
    HostEditor,
    ServerSettings,
    HeaderEditor,
    Credentials,
    CredentialIssue,
    ServerRunning,
    ClientConnect,
    ClientHosts,
    Wake,
    SaveExit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostState {
    Online,
    Offline,
    Unknown,
    Waking,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenMode {
    Custom,
    V6Only,
    V4Only,
    DualStack,
}

impl ListenMode {
    fn label(self) -> &'static str {
        match self {
            Self::Custom => "自定义",
            Self::V6Only => "仅v6",
            Self::V4Only => "仅v4",
            Self::DualStack => "双栈",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Custom => Self::V6Only,
            Self::V6Only => Self::V4Only,
            Self::V4Only => Self::DualStack,
            Self::DualStack => Self::Custom,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Custom => Self::DualStack,
            Self::V6Only => Self::Custom,
            Self::V4Only => Self::V6Only,
            Self::DualStack => Self::V4Only,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettingField {
    Mode,
    CustomAddress,
    V4Address,
    V6Address,
    Port,
    ClockSkew,
    Headers,
}

impl HostState {
    fn label(self) -> &'static str {
        match self {
            Self::Online => "在线",
            Self::Offline => "离线",
            Self::Unknown => "未知",
            Self::Waking => "唤醒中",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::Online => GREEN,
            Self::Offline => MUTED,
            Self::Unknown => YELLOW,
            Self::Waking => CYAN,
        }
    }
}

#[derive(Clone, Debug)]
struct PreviewHost {
    id: String,
    name: String,
    mac: String,
    ip: String,
    wol_ipv6_interface: u32,
    state: HostState,
    selected: bool,
}

#[derive(Clone, Debug)]
struct PreviewClient {
    label: String,
    access: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// ERROR/FATAL are populated by the production controller; the standalone
// preview has no real server failure source.
#[allow(dead_code)]
enum LogLevel {
    Info,
    Warn,
    Error,
    Fatal,
}

#[derive(Clone, Debug)]
struct LogEntry {
    clock: String,
    level: LogLevel,
    message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Modal {
    Help,
    DeleteHost,
    DeleteHeader,
    RevokeCredential,
    StopServer,
    ExitPreview,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WakePhase {
    Sending,
    Waiting,
    Retrying,
    Complete,
}

struct App {
    screen: Screen,
    should_quit: bool,
    production: bool,
    modal: Option<Modal>,
    color_enabled: bool,
    terminal_note: String,
    landing_index: usize,
    host_index: usize,
    client_host_index: usize,
    credential_index: usize,
    hosts: Vec<PreviewHost>,
    clients: Vec<PreviewClient>,
    logs: VecDeque<LogEntry>,
    started_at: Instant,
    last_log_at: Instant,
    next_log: usize,
    log_scroll: usize,
    toast: Option<(String, Instant)>,
    edit_index: Option<usize>,
    editor_field: usize,
    editor_inputs: Vec<Input>,
    settings_field: usize,
    settings_editing: bool,
    custom_bind_input: Input,
    bind_v4_input: Input,
    bind_v6_input: Input,
    server_port_input: Input,
    clock_skew_input: Input,
    listen_mode: ListenMode,
    headers: Vec<(String, String)>,
    header_index: usize,
    header_edit_index: Option<usize>,
    header_editor_field: usize,
    header_inputs: Vec<Input>,
    issue_edit_index: Option<usize>,
    issue_field: usize,
    issue_host_index: usize,
    issue_selected: Vec<bool>,
    issue_label_input: Input,
    issue_output_input: Input,
    issue_default_label: String,
    issue_default_output: String,
    connect_field: usize,
    address_input: Input,
    port_input: Input,
    wake_phase: WakePhase,
    wake_attempt: u8,
    wake_started_at: Instant,
    wake_receipt: bool,
    wake_online: Vec<bool>,
    credential_display: String,
    credential_status: String,
    connection_display: String,
    config_status: String,
    server_running: bool,
    server_public_key_display: String,
    deployment_summary: String,
    deployment_lines: Vec<String>,
}

impl App {
    #[cfg(test)]
    fn new() -> Self {
        Self::with_capabilities(TerminalCapabilities::detect())
    }

    fn with_capabilities(capabilities: TerminalCapabilities) -> Self {
        let now = Instant::now();
        Self {
            screen: Screen::Landing,
            should_quit: false,
            production: false,
            modal: None,
            color_enabled: capabilities.color_enabled,
            terminal_note: capabilities.note,
            landing_index: 0,
            host_index: 0,
            client_host_index: 0,
            credential_index: 0,
            hosts: vec![
                PreviewHost {
                    id: "lab-workstation".into(),
                    name: "实验室工作站".into(),
                    mac: "00-E2-69-72-84-5D".into(),
                    ip: "192.168.0.5".into(),
                    wol_ipv6_interface: 0,
                    state: HostState::Online,
                    selected: false,
                },
                PreviewHost {
                    id: "render-node-02".into(),
                    name: "渲染节点 02".into(),
                    mac: "A4-B1-C1-22-7F-09".into(),
                    ip: "192.168.0.27".into(),
                    wol_ipv6_interface: 0,
                    state: HostState::Offline,
                    selected: false,
                },
                PreviewHost {
                    id: "nas-backup".into(),
                    name: "备份存储".into(),
                    mac: "74-56-3C-91-18-2A".into(),
                    ip: "fd12:3456:789a::18".into(),
                    wol_ipv6_interface: 7,
                    state: HostState::Unknown,
                    selected: false,
                },
                PreviewHost {
                    id: "classroom-pc".into(),
                    name: "教室终端".into(),
                    mac: "1C-69-7A-33-41-B0".into(),
                    ip: "10.20.8.116".into(),
                    wol_ipv6_interface: 0,
                    state: HostState::Offline,
                    selected: false,
                },
            ],
            clients: vec![
                PreviewClient {
                    label: "portable-admin".into(),
                    access: "全部 4 台主机".into(),
                },
                PreviewClient {
                    label: "school-laptop".into(),
                    access: "2 台主机".into(),
                },
            ],
            logs: VecDeque::from([
                LogEntry {
                    clock: local_clock_hm(),
                    level: LogLevel::Info,
                    message: "starting protocol=rop/1 security=Noise_IKpsk0+psk2".into(),
                },
                LogEntry {
                    clock: local_clock_hm(),
                    level: LogLevel::Info,
                    message: "listening mode=dual v4=0.0.0.0 v6=[::] port=45890".into(),
                },
            ]),
            started_at: now,
            last_log_at: now,
            next_log: 0,
            log_scroll: 0,
            toast: Some((
                "预览模式：所有数据均为模拟数据".into(),
                now + Duration::from_secs(4),
            )),
            edit_index: None,
            editor_field: 0,
            editor_inputs: vec![
                Input::default(),
                Input::default(),
                Input::default(),
                Input::default(),
                Input::new("0".into()),
            ],
            settings_field: 0,
            settings_editing: false,
            custom_bind_input: Input::new(DEFAULT_CUSTOM_BIND.into()),
            bind_v4_input: Input::new(DEFAULT_V4_BIND.into()),
            bind_v6_input: Input::new(DEFAULT_V6_BIND.into()),
            server_port_input: Input::new(DEFAULT_SERVER_PORT.into()),
            clock_skew_input: Input::new(DEFAULT_CLOCK_SKEW.into()),
            listen_mode: ListenMode::DualStack,
            headers: vec![
                ("site-id".into(), "campus-east".into()),
                ("deployment".into(), "portable".into()),
            ],
            header_index: 0,
            header_edit_index: None,
            header_editor_field: 0,
            header_inputs: vec![Input::default(); 2],
            issue_edit_index: None,
            issue_field: 0,
            issue_host_index: 0,
            issue_selected: Vec::new(),
            issue_label_input: Input::default(),
            issue_output_input: Input::default(),
            issue_default_label: String::new(),
            issue_default_output: String::new(),
            connect_field: 0,
            address_input: Input::new(DEFAULT_CLIENT_ADDRESS.into()),
            port_input: Input::new(DEFAULT_CLIENT_PORT.into()),
            wake_phase: WakePhase::Sending,
            wake_attempt: 1,
            wake_started_at: now,
            wake_receipt: false,
            wake_online: Vec::new(),
            credential_display: "remote-open-power.credential.toml".into(),
            credential_status: "预览身份".into(),
            connection_display: "待连接".into(),
            config_status: "预览数据".into(),
            server_running: false,
            server_public_key_display: String::new(),
            deployment_summary: String::new(),
            deployment_lines: Vec::new(),
        }
    }

    fn handle_event(&mut self, event: Event) {
        let Event::Key(key) = event else {
            return;
        };
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            return;
        }

        if key.code == KeyCode::F(1) {
            if self.modal == Some(Modal::Help) {
                self.modal = None;
            } else if self.modal.is_none() {
                self.modal = Some(Modal::Help);
            }
            return;
        }

        if let Some(modal) = self.modal {
            self.handle_modal(modal, key);
            return;
        }

        if self.navigate_server_page(key) {
            return;
        }

        match self.screen {
            Screen::Landing => self.handle_landing(key),
            Screen::ServerHome => self.handle_server_home(key),
            Screen::HostEditor => self.handle_host_editor(key),
            Screen::ServerSettings => self.handle_server_settings(key),
            Screen::HeaderEditor => self.handle_header_editor(key),
            Screen::Credentials => self.handle_credentials(key),
            Screen::CredentialIssue => self.handle_credential_issue(key),
            Screen::ServerRunning => self.handle_server_running(key),
            Screen::ClientConnect => self.handle_client_connect(key),
            Screen::ClientHosts => self.handle_client_hosts(key),
            Screen::Wake => self.handle_wake(key),
            Screen::SaveExit => self.handle_save_exit(key),
        }
    }

    /// Navigate between the five server pages without requiring an Esc round
    /// trip.  Text editors keep numeric keys for their fields; page navigation
    /// is therefore active only on the top-level server pages.
    fn navigate_server_page(&mut self, key: KeyEvent) -> bool {
        if !key.modifiers.is_empty()
            || self.settings_editing
            || !matches!(
                self.screen,
                Screen::ServerSettings
                    | Screen::Credentials
                    | Screen::ServerRunning
                    | Screen::SaveExit
            )
        {
            return false;
        }
        let target = match key.code {
            KeyCode::Char('1') => Screen::ServerHome,
            KeyCode::Char('2') => Screen::ServerSettings,
            KeyCode::Char('3') => Screen::Credentials,
            KeyCode::Char('4') => Screen::ServerRunning,
            KeyCode::Char('5') => Screen::SaveExit,
            _ => return false,
        };
        self.screen = target;
        true
    }

    fn handle_modal(&mut self, modal: Modal, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') => self.modal = None,
            KeyCode::Enter | KeyCode::Char('y') => {
                self.modal = None;
                match modal {
                    Modal::Help => {}
                    Modal::DeleteHost => {
                        if !self.hosts.is_empty() {
                            let removed = self.hosts.remove(self.host_index);
                            self.host_index =
                                self.host_index.min(self.hosts.len().saturating_sub(1));
                            self.notify(format!("已删除 {}", removed.id));
                        }
                    }
                    Modal::DeleteHeader => {
                        if !self.headers.is_empty() {
                            let removed = self.headers.remove(self.header_index);
                            self.header_index =
                                self.header_index.min(self.headers.len().saturating_sub(1));
                            self.notify(format!("已删除 Header {}", removed.0));
                        }
                    }
                    Modal::RevokeCredential => {
                        if !self.clients.is_empty() {
                            let removed = self.clients.remove(self.credential_index);
                            self.credential_index = self
                                .credential_index
                                .min(self.clients.len().saturating_sub(1));
                            self.notify(format!("已撤销 {}", removed.label));
                        }
                    }
                    Modal::StopServer => {
                        self.server_running = false;
                        self.screen = Screen::ServerHome;
                        self.notify("模拟服务已停止".into());
                    }
                    Modal::ExitPreview => self.should_quit = true,
                }
            }
            _ => {}
        }
    }

    fn handle_landing(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.landing_index = self.landing_index.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.landing_index = (self.landing_index + 1).min(2)
            }
            KeyCode::Char('1') => self.screen = Screen::ServerHome,
            KeyCode::Char('2') => self.screen = Screen::ClientConnect,
            KeyCode::Enter => match self.landing_index {
                0 => self.screen = Screen::ServerHome,
                1 => self.screen = Screen::ClientConnect,
                _ => self.modal = Some(Modal::ExitPreview),
            },
            KeyCode::Esc | KeyCode::Char('q') => self.modal = Some(Modal::ExitPreview),
            _ => {}
        }
    }

    fn handle_server_home(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.notify("配置已模拟保存".into());
            return;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.host_index = self.host_index.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.host_index = (self.host_index + 1).min(self.hosts.len().saturating_sub(1))
            }
            KeyCode::Char('a') if self.hosts.len() < MAX_HOSTS => self.open_host_editor(None),
            KeyCode::Char('a') => self.notify(format!("开机项最多允许 {MAX_HOSTS} 条")),
            KeyCode::Char('e') | KeyCode::Enter if !self.hosts.is_empty() => {
                self.open_host_editor(Some(self.host_index))
            }
            KeyCode::Char('d') if !self.hosts.is_empty() => self.modal = Some(Modal::DeleteHost),
            KeyCode::Char('1') => {}
            KeyCode::Char('2') | KeyCode::Char('s') => self.screen = Screen::ServerSettings,
            KeyCode::Char('3') | KeyCode::Char('c') => self.screen = Screen::Credentials,
            KeyCode::Char('4') | KeyCode::Char('r') => {
                self.started_at = Instant::now();
                self.last_log_at = self.started_at;
                self.server_running = true;
                self.screen = Screen::ServerRunning;
            }
            KeyCode::Char('5') | KeyCode::Char('q') => self.open_deployment(),
            KeyCode::Esc => self.screen = Screen::Landing,
            _ => {}
        }
    }

    fn open_host_editor(&mut self, index: Option<usize>) {
        self.edit_index = index;
        self.editor_field = 0;
        self.editor_inputs = if let Some(host) = index.and_then(|i| self.hosts.get(i)) {
            vec![
                Input::new(host.id.clone()),
                Input::new(host.name.clone()),
                Input::new(host.mac.clone()),
                Input::new(host.ip.clone()),
                Input::new(host.wol_ipv6_interface.to_string()),
            ]
        } else {
            vec![
                Input::default(),
                Input::default(),
                Input::default(),
                Input::default(),
                Input::new("0".into()),
            ]
        };
        self.screen = Screen::HostEditor;
    }

    fn handle_host_editor(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.screen = Screen::ServerHome,
            KeyCode::Tab | KeyCode::Down => self.editor_field = (self.editor_field + 1) % 5,
            KeyCode::BackTab | KeyCode::Up => self.editor_field = (self.editor_field + 4) % 5,
            KeyCode::Enter if self.editor_field < 4 => {
                self.editor_field += 1;
            }
            KeyCode::Enter => {
                let mut values: Vec<String> = self
                    .editor_inputs
                    .iter()
                    .map(|input| input.value().trim().to_owned())
                    .collect();
                if values[4].is_empty() {
                    values[4] = "0".into();
                    self.editor_inputs[4] = Input::new("0".into());
                }
                if let Err(message) = validate_host_form(&values) {
                    self.notify(message);
                    return;
                }
                let duplicate = self.hosts.iter().enumerate().any(|(index, host)| {
                    Some(index) != self.edit_index && host.id.eq_ignore_ascii_case(&values[0])
                });
                if duplicate {
                    self.notify("Host ID 不能重复".into());
                    return;
                }
                if self.edit_index.is_none() && self.hosts.len() >= MAX_HOSTS {
                    self.notify(format!("开机项最多允许 {MAX_HOSTS} 条"));
                    return;
                }
                let host = PreviewHost {
                    id: values[0].to_ascii_lowercase(),
                    name: values[1].clone(),
                    mac: values[2].clone(),
                    ip: values[3].clone(),
                    wol_ipv6_interface: values[4].parse().expect("validated interface index"),
                    state: HostState::Unknown,
                    selected: false,
                };
                if let Some(index) = self.edit_index {
                    self.hosts[index] = host;
                    self.notify("主机修改已写入预览状态".into());
                } else {
                    self.hosts.push(host);
                    self.host_index = self.hosts.len() - 1;
                    self.notify("主机已加入预览列表".into());
                }
                self.screen = Screen::ServerHome;
            }
            _ => {
                let maximum = [
                    MAX_HOST_ID_BYTES,
                    MAX_HOST_NAME_BYTES,
                    MAX_MAC_BYTES,
                    MAX_IP_BYTES,
                    MAX_INTERFACE_INDEX_BYTES,
                ][self.editor_field];
                if !handle_bounded_input(&mut self.editor_inputs[self.editor_field], key, maximum) {
                    self.notify(format!("该字段最多允许 {maximum} 字节"));
                }
            }
        }
    }

    fn handle_server_settings(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            if self.settings_editing {
                self.notify("当前设置尚未确认，请先按 Enter 确认".into());
            } else {
                self.notify("监听与安全设置已模拟保存".into());
            }
            return;
        }

        let field = self.active_setting_field();
        match key.code {
            KeyCode::Esc => {
                if self.settings_editing {
                    self.blur_setting_field(field);
                }
                self.screen = Screen::ServerHome;
            }
            KeyCode::Tab => {
                let next = (self.settings_field + 1) % self.setting_field_count();
                self.change_settings_field(next);
            }
            KeyCode::BackTab => {
                let count = self.setting_field_count();
                let next = if self.settings_field == 0 {
                    count.saturating_sub(1)
                } else {
                    self.settings_field - 1
                };
                self.change_settings_field(next);
            }
            KeyCode::Up if field == SettingField::Headers && !self.headers.is_empty() => {
                self.header_index = self.header_index.saturating_sub(1)
            }
            KeyCode::Down if field == SettingField::Headers && !self.headers.is_empty() => {
                self.header_index =
                    (self.header_index + 1).min(self.headers.len().saturating_sub(1))
            }
            KeyCode::Up => self.change_settings_field(self.settings_field.saturating_sub(1)),
            KeyCode::Down => self.change_settings_field(self.settings_field + 1),
            KeyCode::Char(' ') | KeyCode::Right if field == SettingField::Mode => {
                self.listen_mode = self.listen_mode.next();
                self.clamp_settings_field();
            }
            KeyCode::Left if field == SettingField::Mode => {
                self.listen_mode = self.listen_mode.previous();
                self.clamp_settings_field();
            }
            KeyCode::Char('a') if field == SettingField::Headers => {
                if self.headers.len() >= MAX_HEADERS {
                    self.notify(format!("自定义 Header 最多允许 {MAX_HEADERS} 项"));
                } else {
                    self.open_header_editor(None);
                }
            }
            KeyCode::Char('e') | KeyCode::Enter
                if field == SettingField::Headers && !self.headers.is_empty() =>
            {
                self.open_header_editor(Some(self.header_index))
            }
            KeyCode::Char('d') if field == SettingField::Headers && !self.headers.is_empty() => {
                self.modal = Some(Modal::DeleteHeader)
            }
            KeyCode::Enter if field == SettingField::Headers => {}
            KeyCode::Enter if field == SettingField::Mode => {
                let next = (self.settings_field + 1) % self.setting_field_count();
                self.change_settings_field(next)
            }
            KeyCode::Enter => self.confirm_setting_input(field),
            _ if self.is_text_setting(field) && self.settings_editing => {
                let maximum = self.setting_input_limit(field);
                if let Some(input) = self.setting_input_mut(field)
                    && !handle_bounded_input(input, key, maximum)
                {
                    self.notify(format!("该字段最多允许 {maximum} 字节"));
                }
            }
            _ => {}
        }
    }

    fn change_settings_field(&mut self, next: usize) {
        let current = self.active_setting_field();
        if self.settings_editing {
            self.blur_setting_field(current);
        }
        self.settings_editing = false;
        self.settings_field = next.min(self.setting_field_count().saturating_sub(1));
    }

    fn active_setting_field(&self) -> SettingField {
        self.setting_fields()
            .get(self.settings_field)
            .copied()
            .unwrap_or(SettingField::Headers)
    }

    fn setting_fields(&self) -> Vec<SettingField> {
        let mut fields = vec![SettingField::Mode];
        match self.listen_mode {
            ListenMode::Custom => fields.push(SettingField::CustomAddress),
            ListenMode::V4Only => fields.push(SettingField::V4Address),
            ListenMode::V6Only => fields.push(SettingField::V6Address),
            ListenMode::DualStack => {
                fields.push(SettingField::V4Address);
                fields.push(SettingField::V6Address);
            }
        }
        fields.extend([
            SettingField::Port,
            SettingField::ClockSkew,
            SettingField::Headers,
        ]);
        fields
    }

    fn setting_field_count(&self) -> usize {
        self.setting_fields().len()
    }

    fn headers_setting_index(&self) -> usize {
        self.setting_fields()
            .iter()
            .position(|field| *field == SettingField::Headers)
            .unwrap_or_else(|| self.setting_field_count().saturating_sub(1))
    }

    fn clamp_settings_field(&mut self) {
        self.settings_field = self
            .settings_field
            .min(self.setting_field_count().saturating_sub(1));
    }

    fn is_text_setting(&self, field: SettingField) -> bool {
        matches!(
            field,
            SettingField::CustomAddress
                | SettingField::V4Address
                | SettingField::V6Address
                | SettingField::Port
                | SettingField::ClockSkew
        )
    }

    fn setting_input_limit(&self, field: SettingField) -> usize {
        match field {
            SettingField::Port => MAX_PORT_BYTES,
            SettingField::ClockSkew => 2,
            SettingField::CustomAddress | SettingField::V4Address | SettingField::V6Address => {
                MAX_IP_BYTES
            }
            SettingField::Mode | SettingField::Headers => 0,
        }
    }

    fn setting_input(&self, field: SettingField) -> Option<&Input> {
        match field {
            SettingField::CustomAddress => Some(&self.custom_bind_input),
            SettingField::V4Address => Some(&self.bind_v4_input),
            SettingField::V6Address => Some(&self.bind_v6_input),
            SettingField::Port => Some(&self.server_port_input),
            SettingField::ClockSkew => Some(&self.clock_skew_input),
            SettingField::Mode | SettingField::Headers => None,
        }
    }

    fn setting_input_mut(&mut self, field: SettingField) -> Option<&mut Input> {
        match field {
            SettingField::CustomAddress => Some(&mut self.custom_bind_input),
            SettingField::V4Address => Some(&mut self.bind_v4_input),
            SettingField::V6Address => Some(&mut self.bind_v6_input),
            SettingField::Port => Some(&mut self.server_port_input),
            SettingField::ClockSkew => Some(&mut self.clock_skew_input),
            SettingField::Mode | SettingField::Headers => None,
        }
    }

    fn default_for_setting(&self, field: SettingField) -> Option<&'static str> {
        match field {
            SettingField::CustomAddress => Some(DEFAULT_CUSTOM_BIND),
            SettingField::V4Address => Some(DEFAULT_V4_BIND),
            SettingField::V6Address => Some(DEFAULT_V6_BIND),
            SettingField::Port => Some(DEFAULT_SERVER_PORT),
            SettingField::ClockSkew => Some(DEFAULT_CLOCK_SKEW),
            SettingField::Mode | SettingField::Headers => None,
        }
    }

    fn set_setting_input(&mut self, field: SettingField, value: String) {
        if let Some(input) = self.setting_input_mut(field) {
            *input = Input::new(value);
        }
    }

    fn validate_setting_input(&self, field: SettingField) -> Result<(), String> {
        let value = self
            .setting_input(field)
            .map(|input| input.value().trim())
            .unwrap_or_default();
        match field {
            SettingField::CustomAddress => validate_listen_address(value, None),
            SettingField::V4Address => validate_listen_address(value, Some(false)),
            SettingField::V6Address => validate_listen_address(value, Some(true)),
            SettingField::Port => parse_port(value).map(|_| ()),
            SettingField::ClockSkew => {
                let skew = value
                    .parse::<u16>()
                    .map_err(|_| "时钟容差必须是 1 到 60 的整数".to_owned())?;
                if (1..=60).contains(&skew) {
                    Ok(())
                } else {
                    Err("时钟容差必须在 1 到 60 秒之间".into())
                }
            }
            SettingField::Mode | SettingField::Headers => Ok(()),
        }
    }

    fn blur_setting_field(&mut self, field: SettingField) {
        if !self.is_text_setting(field) {
            return;
        }
        let value = self
            .setting_input(field)
            .map(|input| input.value().trim().to_owned())
            .unwrap_or_default();
        let validation = if value.is_empty() {
            Err("设置不能为空".to_owned())
        } else {
            self.set_setting_input(field, value.clone());
            self.validate_setting_input(field)
        };
        if let Err(message) = validation
            && let Some(default) = self.default_for_setting(field)
        {
            self.set_setting_input(field, default.to_owned());
            self.notify(format!("{message}，已恢复默认值"));
        }
    }

    fn confirm_setting_input(&mut self, field: SettingField) {
        if !self.settings_editing {
            self.settings_editing = true;
            return;
        }
        if let Err(message) = self.validate_setting_input(field) {
            self.notify(message);
            return;
        }
        if let Some(value) = self
            .setting_input(field)
            .map(|input| input.value().trim().to_owned())
        {
            self.set_setting_input(field, value);
        }
        self.settings_editing = false;
        self.change_settings_field(self.settings_field + 1);
    }

    fn open_header_editor(&mut self, index: Option<usize>) {
        self.header_edit_index = index;
        self.header_editor_field = 0;
        self.header_inputs = if let Some((name, value)) = index.and_then(|i| self.headers.get(i)) {
            vec![Input::new(name.clone()), Input::new(value.clone())]
        } else {
            vec![Input::default(); 2]
        };
        self.screen = Screen::HeaderEditor;
    }

    fn handle_header_editor(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.screen = Screen::ServerSettings,
            KeyCode::Tab | KeyCode::Down => {
                self.header_editor_field = (self.header_editor_field + 1) % 2
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.header_editor_field = (self.header_editor_field + 1) % 2
            }
            KeyCode::Enter if self.header_editor_field == 0 => self.header_editor_field = 1,
            KeyCode::Enter => {
                let name = self.header_inputs[0].value().trim().to_ascii_lowercase();
                let value = self.header_inputs[1].value().trim().to_owned();
                if let Err(message) = validate_header(&name, &value) {
                    self.notify(message);
                    return;
                }
                let duplicate = self
                    .headers
                    .iter()
                    .enumerate()
                    .any(|(index, (existing, _))| {
                        Some(index) != self.header_edit_index && existing == &name
                    });
                if duplicate {
                    self.notify("Header 名称不能重复".into());
                    return;
                }
                let header_bytes = self
                    .headers
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| Some(*index) != self.header_edit_index)
                    .map(|(_, (existing_name, existing_value))| {
                        existing_name.len().saturating_add(existing_value.len())
                    })
                    .sum::<usize>()
                    .saturating_add(name.len())
                    .saturating_add(value.len());
                if header_bytes > MAX_HEADER_BYTES {
                    self.notify(format!(
                        "自定义 Header 总计最多允许 {MAX_HEADER_BYTES} 字节"
                    ));
                    return;
                }
                if self.header_edit_index.is_none() && self.headers.len() >= MAX_HEADERS {
                    self.notify(format!("自定义 Header 最多允许 {MAX_HEADERS} 项"));
                    return;
                }
                if let Some(index) = self.header_edit_index {
                    self.headers[index] = (name, value);
                    self.header_index = index;
                    self.notify("Header 已模拟修改".into());
                } else {
                    self.headers.push((name, value));
                    self.header_index = self.headers.len() - 1;
                    self.notify("Header 已模拟添加".into());
                }
                self.settings_field = self.headers_setting_index();
                self.screen = Screen::ServerSettings;
            }
            _ => {
                let maximum = if self.header_editor_field == 0 {
                    MAX_HEADER_NAME_BYTES
                } else {
                    MAX_HEADER_VALUE_BYTES
                };
                if !handle_bounded_input(
                    &mut self.header_inputs[self.header_editor_field],
                    key,
                    maximum,
                ) {
                    self.notify(format!("该字段最多允许 {maximum} 字节"));
                }
            }
        }
    }

    fn handle_credentials(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.credential_index = self.credential_index.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.credential_index =
                    (self.credential_index + 1).min(self.clients.len().saturating_sub(1))
            }
            KeyCode::Char('n') if self.hosts.is_empty() => {
                self.notify("请先添加至少一个开机项".into())
            }
            KeyCode::Char('n') if self.clients.len() >= MAX_CLIENTS => {
                self.notify(format!("客户端凭据最多允许 {MAX_CLIENTS} 份"))
            }
            KeyCode::Char('n') => self.open_credential_issue(None),
            KeyCode::Char('e') | KeyCode::Enter if !self.clients.is_empty() => {
                self.open_credential_issue(Some(self.credential_index))
            }
            KeyCode::Char('d') if !self.clients.is_empty() => {
                self.modal = Some(Modal::RevokeCredential)
            }
            KeyCode::Char('4') | KeyCode::Char('r') => self.screen = Screen::ServerRunning,
            KeyCode::Esc | KeyCode::Char('1') => self.screen = Screen::ServerHome,
            KeyCode::Char('q') => self.open_deployment(),
            _ => {}
        }
    }

    fn open_credential_issue(&mut self, index: Option<usize>) {
        self.issue_edit_index = index;
        self.issue_field = 0;
        self.issue_host_index = 0;
        let number = self.clients.len() + 1;
        let label = index.and_then(|i| self.clients.get(i)).map_or_else(
            || format!("portable-client-{number}"),
            |client| client.label.clone(),
        );
        let select_all = index
            .and_then(|i| self.clients.get(i))
            .is_none_or(|client| client.access.starts_with("全部"));
        self.issue_selected = (0..self.hosts.len())
            .map(|host_index| select_all || host_index < 2)
            .collect();
        self.issue_label_input = Input::new(label.clone());
        let output = format!("{label}.credential.toml");
        self.issue_output_input = Input::new(output.clone());
        self.issue_default_label = label;
        self.issue_default_output = output;
        self.screen = Screen::CredentialIssue;
    }

    fn handle_credential_issue(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.finish_credential_issue();
            return;
        }

        match key.code {
            KeyCode::Esc => self.screen = Screen::Credentials,
            KeyCode::Tab => self.change_issue_field((self.issue_field + 1) % 3),
            KeyCode::BackTab => self.change_issue_field((self.issue_field + 2) % 3),
            KeyCode::Up if self.issue_field == 1 => {
                self.issue_host_index = self.issue_host_index.saturating_sub(1)
            }
            KeyCode::Down if self.issue_field == 1 => {
                self.issue_host_index =
                    (self.issue_host_index + 1).min(self.hosts.len().saturating_sub(1))
            }
            KeyCode::Char(' ') if self.issue_field == 1 && !self.hosts.is_empty() => {
                self.issue_selected[self.issue_host_index] =
                    !self.issue_selected[self.issue_host_index]
            }
            KeyCode::Char('a') if self.issue_field == 1 => {
                let select = self.issue_selected.iter().any(|selected| !selected);
                self.issue_selected.fill(select);
            }
            KeyCode::Enter if self.issue_field < 2 => self.change_issue_field(self.issue_field + 1),
            KeyCode::Enter => self.finish_credential_issue(),
            _ if self.issue_field == 0 => {
                if !handle_bounded_input(
                    &mut self.issue_label_input,
                    key,
                    MAX_CREDENTIAL_LABEL_BYTES,
                ) {
                    self.notify(format!(
                        "凭据标签最多允许 {MAX_CREDENTIAL_LABEL_BYTES} 字节"
                    ));
                }
            }
            _ if self.issue_field == 2
                && !handle_bounded_input(
                    &mut self.issue_output_input,
                    key,
                    MAX_OUTPUT_PATH_BYTES,
                ) =>
            {
                self.notify(format!("输出路径最多允许 {MAX_OUTPUT_PATH_BYTES} 字节"));
            }
            _ => {}
        }
    }

    fn change_issue_field(&mut self, next: usize) {
        match self.issue_field {
            0 => normalize_defaulted_input(
                &mut self.issue_label_input,
                self.issue_default_label.as_str(),
            ),
            2 => normalize_defaulted_input(
                &mut self.issue_output_input,
                self.issue_default_output.as_str(),
            ),
            _ => {}
        }
        self.issue_field = next;
    }

    fn finish_credential_issue(&mut self) {
        let label = self.issue_label_input.value().trim().to_owned();
        let output = self.issue_output_input.value().trim().to_owned();
        let allowed = self
            .issue_selected
            .iter()
            .filter(|selected| **selected)
            .count();
        if let Err(message) = validate_credential_form(&label, &output, allowed) {
            self.notify(message);
            return;
        }
        if self.issue_edit_index.is_none() && self.clients.len() >= MAX_CLIENTS {
            self.notify(format!("客户端凭据最多允许 {MAX_CLIENTS} 份"));
            return;
        }
        let access = if allowed == self.hosts.len() {
            format!("全部 {allowed} 台主机")
        } else {
            format!("{allowed} 台主机")
        };
        if let Some(index) = self.issue_edit_index {
            self.clients[index].label = label;
            self.clients[index].access = access;
            self.credential_index = index;
            self.notify(format!("凭据设置已模拟更新：{output}"));
        } else {
            self.clients.push(PreviewClient { label, access });
            self.credential_index = self.clients.len() - 1;
            self.notify(format!("已模拟签发：{output}"));
        }
        self.screen = Screen::Credentials;
    }

    fn handle_server_running(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::PageUp => self.log_scroll = self.log_scroll.saturating_add(6),
            KeyCode::PageDown => self.log_scroll = self.log_scroll.saturating_sub(6),
            KeyCode::End => self.log_scroll = 0,
            KeyCode::Char('c') => self.logs.clear(),
            KeyCode::Esc | KeyCode::Char('q') => self.modal = Some(Modal::StopServer),
            _ => {}
        }
    }

    fn handle_client_connect(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.screen = Screen::Landing,
            KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                self.change_connect_field(1 - self.connect_field)
            }
            KeyCode::Enter => {
                self.normalize_connect_field(0);
                self.normalize_connect_field(1);
                match validate_client_endpoint(
                    self.address_input.value().trim(),
                    self.port_input.value().trim(),
                ) {
                    Ok(()) => {
                        self.screen = Screen::ClientHosts;
                        self.notify("已建立模拟安全连接".into());
                    }
                    Err(message) => self.notify(message),
                }
            }
            _ => {
                if self.connect_field == 0 {
                    if !handle_bounded_input(&mut self.address_input, key, MAX_ENDPOINT_BYTES) {
                        self.notify(format!("服务端地址最多允许 {MAX_ENDPOINT_BYTES} 字节"));
                    }
                } else if !handle_bounded_input(&mut self.port_input, key, MAX_PORT_BYTES) {
                    self.notify("端口最多允许 5 位数字".into());
                }
            }
        }
    }

    fn change_connect_field(&mut self, next: usize) {
        self.normalize_connect_field(self.connect_field);
        self.connect_field = next;
    }

    fn normalize_connect_field(&mut self, field: usize) {
        match field {
            0 => normalize_defaulted_input(&mut self.address_input, DEFAULT_CLIENT_ADDRESS),
            1 => normalize_defaulted_input(&mut self.port_input, DEFAULT_CLIENT_PORT),
            _ => {}
        }
    }

    fn handle_client_hosts(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.client_host_index = self.client_host_index.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.client_host_index =
                    (self.client_host_index + 1).min(self.hosts.len().saturating_sub(1))
            }
            KeyCode::Char(' ') if !self.hosts.is_empty() => {
                self.hosts[self.client_host_index].selected =
                    !self.hosts[self.client_host_index].selected
            }
            KeyCode::Char('a') => {
                let select = self.hosts.iter().any(|host| !host.selected);
                for host in &mut self.hosts {
                    host.selected = select;
                }
            }
            KeyCode::Char('r') => {
                for (index, host) in self.hosts.iter_mut().enumerate() {
                    host.state = match (index + self.next_log) % 3 {
                        0 => HostState::Online,
                        1 => HostState::Offline,
                        _ => HostState::Unknown,
                    };
                }
                self.next_log += 1;
                self.notify("主机状态已模拟刷新".into());
            }
            KeyCode::Enter => {
                let selected = self.hosts.iter().filter(|host| host.selected).count();
                if selected == 0 {
                    self.notify("请先用 Space 选择至少一台主机".into());
                } else {
                    self.begin_wake(selected);
                    self.screen = Screen::Wake;
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::ClientConnect,
            _ => {}
        }
    }

    fn begin_wake(&mut self, selected: usize) {
        self.wake_phase = WakePhase::Sending;
        self.wake_attempt = 1;
        self.wake_started_at = Instant::now();
        self.wake_receipt = false;
        self.wake_online = vec![false; selected];
        for host in &mut self.hosts {
            if host.selected {
                host.state = HostState::Waking;
            }
        }
    }

    fn handle_wake(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('o') if self.wake_phase != WakePhase::Complete => {
                if let Some(index) = self.wake_online.iter().position(|online| !online) {
                    self.wake_online[index] = true;
                }
                if self.wake_online.iter().all(|online| *online) {
                    self.wake_phase = WakePhase::Complete;
                }
            }
            KeyCode::Char('t') if self.wake_attempt == 1 => {
                self.wake_attempt = 2;
                self.wake_phase = WakePhase::Retrying;
                self.wake_started_at = Instant::now();
                self.wake_receipt = false;
                self.wake_online.fill(false);
            }
            KeyCode::Enter if self.wake_phase == WakePhase::Complete => {
                for host in &mut self.hosts {
                    if host.selected {
                        host.state = HostState::Online;
                        host.selected = false;
                    }
                }
                self.screen = Screen::ClientHosts;
            }
            KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::ClientHosts,
            _ => {}
        }
    }

    fn handle_save_exit(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('s') | KeyCode::Enter => {
                self.notify("配置已再次保存；部署命令未执行".into())
            }
            KeyCode::Esc => self.screen = Screen::ServerHome,
            KeyCode::Char('q') => self.modal = Some(Modal::ExitPreview),
            _ => {}
        }
    }

    fn open_deployment(&mut self) {
        self.screen = Screen::SaveExit;
        self.notify("配置已自动保存".into());
    }

    fn tick(&mut self) {
        let now = Instant::now();
        if self.toast.as_ref().is_some_and(|(_, until)| now >= *until) {
            self.toast = None;
        }

        if !self.production
            && self.screen == Screen::ServerRunning
            && now.duration_since(self.last_log_at) >= Duration::from_millis(850)
        {
            self.last_log_at = now;
            let samples = [
                (LogLevel::Info, "connection accepted peer=192.168.0.31"),
                (LogLevel::Info, "client authenticated id=portable-admin"),
                (LogLevel::Info, "request kind=list_hosts hosts=4"),
                (
                    LogLevel::Info,
                    "wake accepted operation=preview target=render-node-02",
                ),
                (
                    LogLevel::Warn,
                    "target still offline target=render-node-02 attempt=1",
                ),
                (
                    LogLevel::Info,
                    "target online target=render-node-02 latency=4.2s",
                ),
                (LogLevel::Info, "connection closed reason=client_done"),
            ];
            let (level, message) = samples[self.next_log % samples.len()];
            self.next_log += 1;
            self.logs.push_back(LogEntry {
                clock: local_clock_hm(),
                level,
                message: message.into(),
            });
            while self.logs.len() > LOG_LIMIT {
                self.logs.pop_front();
            }
        }

        if !self.production && self.screen == Screen::Wake && self.wake_phase != WakePhase::Complete
        {
            let elapsed = now.duration_since(self.wake_started_at);
            if !self.wake_receipt && elapsed >= Duration::from_millis(900) {
                self.wake_receipt = true;
                self.wake_phase = WakePhase::Waiting;
            }
            let online_count = self.wake_online.iter().filter(|online| **online).count() as u64;
            let next_online_at = Duration::from_secs(4 + online_count * 2);
            if self.wake_receipt && elapsed >= next_online_at {
                if let Some(index) = self.wake_online.iter().position(|online| !online) {
                    self.wake_online[index] = true;
                }
                if self.wake_online.iter().all(|online| *online) {
                    self.wake_phase = WakePhase::Complete;
                }
            }
        }
    }

    fn notify(&mut self, message: String) {
        self.toast = Some((message, Instant::now() + Duration::from_secs(3)));
    }

    fn selected_host(&self) -> Option<&PreviewHost> {
        self.hosts.get(self.host_index)
    }

    fn wake_targets(&self) -> impl Iterator<Item = &PreviewHost> {
        self.hosts.iter().filter(|host| host.selected)
    }
}

fn handle_bounded_input(input: &mut Input, key: KeyEvent, maximum_bytes: usize) -> bool {
    let previous = input.clone();
    input.handle_event(&Event::Key(key));
    if input.value().len() > maximum_bytes {
        *input = previous;
        false
    } else {
        true
    }
}

fn normalize_defaulted_input(input: &mut Input, default: &str) {
    let normalized = input.value().trim();
    *input = Input::new(if normalized.is_empty() {
        default.to_owned()
    } else {
        normalized.to_owned()
    });
}

fn validate_host_form(values: &[String]) -> Result<(), String> {
    if values.len() != 5 || values[..4].iter().any(|value| value.trim().is_empty()) {
        return Err("Host ID、名称、MAC 和 IP 都不能为空".into());
    }
    let host_id = &values[0];
    if host_id.len() > MAX_HOST_ID_BYTES
        || !host_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        || !host_id
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        || !host_id
            .chars()
            .last()
            .is_some_and(|character| character.is_ascii_alphanumeric())
    {
        return Err("Host ID 只能使用字母、数字、-、_，且首尾必须是字母或数字".into());
    }
    if values[1].len() > MAX_HOST_NAME_BYTES || values[1].chars().any(char::is_control) {
        return Err("显示名称过长或包含控制字符".into());
    }
    if !valid_mac(&values[2]) {
        return Err("MAC 地址格式无效，应包含 12 个十六进制数字".into());
    }
    let ip = values[3]
        .parse::<IpAddr>()
        .map_err(|_| "IP 地址格式无效".to_owned())?;
    let ip = match ip {
        IpAddr::V6(value) => value.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    let interface = values[4]
        .parse::<u32>()
        .map_err(|_| "IPv6 网卡索引必须是 0 到 4294967295 的整数".to_owned())?;
    let is_lan = match ip {
        IpAddr::V4(value) => value.is_private(),
        IpAddr::V6(value) => {
            value.is_unique_local() || (value.is_unicast_link_local() && interface != 0)
        }
    };
    let is_special = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || match ip {
            IpAddr::V4(value) => {
                value.is_broadcast() || value.is_link_local() || value.octets()[0] == 0
            }
            IpAddr::V6(value) => value.is_unicast_link_local() && interface == 0,
        };
    if is_special || !is_lan {
        return Err("目标 IP 必须是局域网地址；链路本地 IPv6 还必须填写网卡索引".into());
    }
    Ok(())
}

fn valid_mac(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_MAC_BYTES {
        return false;
    }
    let mut compact = String::with_capacity(12);
    for character in value.chars() {
        if character.is_ascii_hexdigit() {
            compact.push(character);
        } else if !matches!(character, '-' | ':' | '.' | ' ') {
            return false;
        }
    }
    if compact.len() != 12
        || !compact
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return false;
    }
    let mut bytes = [0_u8; 6];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let Ok(parsed) = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16) else {
            return false;
        };
        *byte = parsed;
    }
    bytes != [0; 6] && bytes != [0xff; 6] && bytes[0] & 1 == 0
}

fn validate_listen_address(value: &str, ipv6: Option<bool>) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("监听地址不能为空".into());
    }
    let parsed = value
        .parse::<IpAddr>()
        .map_err(|_| "监听地址必须是有效的 IPv4 或 IPv6 地址".to_owned())?;
    match ipv6 {
        Some(true) if !parsed.is_ipv6() => Err("该字段只能填写 IPv6 地址".into()),
        Some(false) if !parsed.is_ipv4() => Err("该字段只能填写 IPv4 地址".into()),
        _ => Ok(()),
    }
}

fn validate_header(name: &str, value: &str) -> Result<(), String> {
    if name.is_empty() || value.is_empty() {
        return Err("Header 名称和值都不能为空".into());
    }
    if name.len() > MAX_HEADER_NAME_BYTES
        || !name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        || !name
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        || !name
            .chars()
            .last()
            .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
    {
        return Err("Header 名称只能使用小写字母、数字和中间连字符".into());
    }
    if name.starts_with("rop-") || name.starts_with("x-rop-") {
        return Err("rop-* 与 x-rop-* 是保留 Header 名称".into());
    }
    if value.len() > MAX_HEADER_VALUE_BYTES
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err("Header 值必须是不超过 256 字节的可打印 ASCII".into());
    }
    Ok(())
}

fn validate_credential_form(label: &str, output: &str, allowed: usize) -> Result<(), String> {
    let label = label.trim();
    let output = output.trim();
    if label.is_empty() {
        return Err("凭据标签不能为空".into());
    }
    if label.len() > MAX_CREDENTIAL_LABEL_BYTES || label.chars().any(char::is_control) {
        return Err("凭据标签过长或包含控制字符".into());
    }
    if allowed == 0 {
        return Err("至少允许一台主机".into());
    }
    if output.is_empty() {
        return Err("输出文件不能为空".into());
    }
    if output.len() > MAX_OUTPUT_PATH_BYTES || output.chars().any(char::is_control) {
        return Err("输出路径过长或包含控制字符".into());
    }
    if !output.ends_with(".credential.toml") {
        return Err("输出文件必须以 .credential.toml 结尾".into());
    }
    Ok(())
}

fn validate_client_endpoint(address: &str, port: &str) -> Result<(), String> {
    if address.is_empty() {
        return Err("服务端地址不能为空".into());
    }
    if address.len() > MAX_ENDPOINT_BYTES || !valid_endpoint_host(address) {
        return Err("服务端地址必须是有效的 IP 或 DNS 主机名，不能包含协议或路径".into());
    }
    parse_port(port)?;
    Ok(())
}

fn valid_endpoint_host(value: &str) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    let hostname = value.strip_suffix('.').unwrap_or(value);
    !hostname.is_empty()
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
                && label
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_alphanumeric())
                && label
                    .chars()
                    .last()
                    .is_some_and(|character| character.is_ascii_alphanumeric())
        })
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| "端口必须是 1024 到 65535 的整数".to_owned())?;
    if port < 1024 {
        return Err("端口必须在 1024 到 65535 之间".into());
    }
    Ok(port)
}

fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Reset)),
        area,
    );

    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area);
        if !app.color_enabled {
            apply_monochrome(frame);
        }
        return;
    }

    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .areas(area);

    render_header(frame, app, header);
    match app.screen {
        Screen::Landing => render_landing(frame, app, body),
        Screen::ServerHome => render_server_home(frame, app, body),
        Screen::HostEditor => render_host_editor(frame, app, body),
        Screen::ServerSettings => render_server_settings(frame, app, body),
        Screen::HeaderEditor => render_header_editor(frame, app, body),
        Screen::Credentials => render_credentials(frame, app, body),
        Screen::CredentialIssue => render_credential_issue(frame, app, body),
        Screen::ServerRunning => render_server_running(frame, app, body),
        Screen::ClientConnect => render_client_connect(frame, app, body),
        Screen::ClientHosts => render_client_hosts(frame, app, body),
        Screen::Wake => render_wake(frame, app, body),
        Screen::SaveExit => render_save_exit(frame, app, body),
    }
    render_footer(frame, app, footer);

    if let Some(modal) = app.modal {
        render_modal(frame, app, modal, area);
    }
    if !app.color_enabled {
        apply_monochrome(frame);
    }
}

fn apply_monochrome(frame: &mut Frame<'_>) {
    for cell in &mut frame.buffer_mut().content {
        let emphasized = cell.bg != Color::Reset;
        cell.fg = Color::Reset;
        cell.bg = Color::Reset;
        if emphasized {
            cell.modifier.insert(Modifier::REVERSED | Modifier::BOLD);
        }
    }
}

fn render_too_small(frame: &mut Frame<'_>, area: Rect) {
    let text = Text::from(vec![
        Line::from(Span::styled(
            "终端尺寸不足",
            Style::default().fg(YELLOW).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "当前 {}×{}，至少需要 {}×{}",
            area.width, area.height, MIN_WIDTH, MIN_HEIGHT
        )),
        Line::from(Span::styled(
            "调整窗口后将自动恢复；按 q 退出",
            Style::default().fg(MUTED),
        )),
    ]);
    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Center)
            .block(panel(" RemoteOpenPower / TUI Preview ")),
        centered_rect(60, 8, area),
    );
}

fn render_header(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let badge = if app.production { "LIVE" } else { "PREVIEW" };
    let section = match app.screen {
        Screen::Landing => "模式选择",
        Screen::ServerHome => "服务端 / 主机",
        Screen::HostEditor => "服务端 / 主机编辑",
        Screen::ServerSettings => "服务端 / 监听与安全",
        Screen::HeaderEditor => "服务端 / Header 编辑",
        Screen::Credentials => "服务端 / 客户端凭据",
        Screen::CredentialIssue => "服务端 / 签发凭据",
        Screen::ServerRunning => "服务端 / 运行",
        Screen::ClientConnect => "客户端 / 连接",
        Screen::ClientHosts => "客户端 / 主机",
        Screen::Wake => "客户端 / 唤醒",
        Screen::SaveExit => "服务端 / 部署",
    };
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(dim());
    if app.screen == Screen::Landing {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(" ● ", Style::default().fg(GREEN)),
                    Span::styled(
                        "RemoteOpenPower",
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  "),
                    Span::styled(badge, Style::default().fg(Color::Black).bg(YELLOW)),
                ]),
                Line::from(Span::styled(
                    "  模式选择",
                    Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
                )),
            ])
            .block(block),
            area,
        );
    } else {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ● ", Style::default().fg(GREEN)),
                Span::styled(
                    "RemoteOpenPower",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  /  ", Style::default().fg(PANEL)),
                Span::styled(section, Style::default().fg(CYAN)),
                Span::raw("  "),
                Span::styled(badge, Style::default().fg(Color::Black).bg(YELLOW)),
            ]))
            .block(block),
            area,
        );
    }
}

fn render_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let compact = area.width < 100;
    let help = match (app.screen, compact) {
        (Screen::Landing, _) => "↑↓ 选择  Enter进入  q退出",
        (Screen::ServerHome, true) => "↑↓选择  a添加 e编辑 d删除  2设置 3凭据 4运行 5部署  q退出",
        (Screen::HostEditor, true) => "Tab字段  Enter继续/保存  Esc取消",
        (Screen::ServerSettings, true) => {
            "1..5切页  Tab/↑↓切换  Enter编辑/确认  Ctrl+S保存  Esc返回"
        }
        (Screen::HeaderEditor, true) => "Tab字段  Enter继续/保存  Esc取消",
        (Screen::Credentials, true) => "1..5切页  ↑↓选择  n签发  e修改  d撤销  Esc返回",
        (Screen::CredentialIssue, true) => "Tab区域  Space选择  Ctrl+S签发  Esc取消",
        (Screen::ServerRunning, true) => "1..5切页  PgUp/PgDn滚动  End跟随  c清屏  q停止",
        (Screen::ClientConnect, true) => "Tab字段  Enter连接  Esc返回",
        (Screen::ClientHosts, true) => "↑↓选择  Space勾选  a全选  r刷新  Enter唤醒  Esc断开",
        (Screen::Wake, true) if app.production => "等待回执/在线  Enter返回  Esc取消",
        (Screen::Wake, true) => "o模拟上线  t模拟重试  Enter返回  Esc取消",
        (Screen::SaveExit, true) => "1..5切页  s再次保存  q退出  Esc返回",
        (Screen::ServerHome, false) => {
            "↑↓ 选择   a 添加   e/Enter 编辑   d 删除   2 设置   3 凭据   4 运行   5 部署   q 进入部署"
        }
        (Screen::HostEditor, false) => "Tab/↑↓ 切换字段   输入编辑   Enter 下一步/保存   Esc 取消",
        (Screen::ServerSettings, false) => {
            "1..5 切页   Tab/↑↓ 切换设置   Enter 编辑/确认   Ctrl+S 保存   Esc 返回"
        }
        (Screen::HeaderEditor, false) => "Tab/↑↓ 切换字段   Enter 继续/保存   Esc 取消",
        (Screen::Credentials, false) => "1..5 切页   ↑↓ 选择   n 签发   e/Enter 修改权限   d 撤销",
        (Screen::CredentialIssue, false) => {
            "Tab 切换区域   Space 选择   Ctrl+S/Enter 签发   Esc 取消"
        }
        (Screen::ServerRunning, false) => {
            "1..5 切页   PgUp/PgDn 滚动   End 跟随   c 清空视图   q/Esc 停止"
        }
        (Screen::ClientConnect, false) => "Tab/↑↓ 切换字段   Enter 连接   Esc 返回",
        (Screen::ClientHosts, false) => {
            "↑↓ 选择   Space 勾选   a 全选   r 刷新   Enter 唤醒   Esc 断开"
        }
        (Screen::Wake, false) if app.production => {
            "等待服务端回执与在线状态   Enter 完成后返回   Esc 取消等待"
        }
        (Screen::Wake, false) => "o 模拟上线   t 模拟超时重试   Enter 完成后返回   Esc 取消等待",
        (Screen::SaveExit, false) => "1..5 切页   s/Enter 再次保存   q 退出预览   Esc 返回",
    };
    let line = if let Some((message, _)) = &app.toast {
        Line::from(vec![
            Span::styled("  ✓ ", Style::default().fg(GREEN)),
            Span::styled(message, Style::default().fg(Color::White)),
        ])
    } else {
        Line::from(Span::styled(
            format!("  {help}"),
            Style::default().fg(MUTED),
        ))
    };
    frame.render_widget(
        Block::default().borders(Borders::TOP).border_style(dim()),
        area,
    );
    let content = Rect::new(area.x, area.y.saturating_add(1), area.width, 1);
    let [message_area, help_area] =
        Layout::horizontal([Constraint::Min(1), Constraint::Length(12)]).areas(content);
    frame.render_widget(Paragraph::new(line), message_area);
    frame.render_widget(
        Paragraph::new("F1  帮助  ")
            .alignment(Alignment::Right)
            .style(Style::default().fg(CYAN)),
        help_area,
    );
}

fn render_landing(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let dashboard = centered_rect(96, 16, area);
    let [main, snapshot] = Layout::vertical([Constraint::Length(12), Constraint::Length(3)])
        .spacing(1)
        .areas(dashboard);
    let [menu, overview] =
        Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)])
            .spacing(1)
            .areas(main);

    frame.render_widget(panel(" 工作区 "), menu);
    let menu_inner = centered_rect(16, 3, menu.inner(Margin::new(1, 1)));
    let items = [("1", "服务模式"), ("2", "终端模式"), ("q", "退出")]
        .into_iter()
        .enumerate()
        .map(|(index, (key, title))| {
            let selected = index == app.landing_index;
            ListItem::new(Line::from(vec![
                Span::styled(
                    if selected { " > " } else { "   " },
                    Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {key} "),
                    Style::default().fg(Color::Black).bg(PANEL),
                ),
                Span::raw("  "),
                Span::styled(
                    title.to_owned(),
                    Style::default()
                        .fg(if selected { CYAN } else { Color::White })
                        .add_modifier(Modifier::BOLD),
                ),
            ]))
        });
    frame.render_widget(List::new(items), menu_inner);

    let overview_rows = match app.landing_index {
        0 => vec![
            (
                "状态",
                app.config_status.clone(),
                if app.config_status == "未初始化" {
                    YELLOW
                } else {
                    GREEN
                },
            ),
            (
                "监听",
                if app.config_status == "未初始化" {
                    "待配置".into()
                } else {
                    listener_summary(app)
                },
                if app.config_status == "未初始化" {
                    YELLOW
                } else {
                    Color::White
                },
            ),
            ("开机项", format!("{} 台", app.hosts.len()), CYAN),
            ("凭据", format!("{} 份", app.clients.len()), CYAN),
            (
                "安全",
                if app.config_status == "未初始化" {
                    "待初始化".into()
                } else {
                    "Noise IK + 便携私钥".into()
                },
                if app.config_status == "未初始化" {
                    YELLOW
                } else {
                    GREEN
                },
            ),
        ],
        1 => vec![
            (
                "服务端",
                if app.config_status == "未初始化" {
                    "待配置".into()
                } else {
                    client_endpoint_summary(app)
                },
                if app.config_status == "未初始化" {
                    YELLOW
                } else {
                    Color::White
                },
            ),
            (
                "连接",
                if app.config_status == "未初始化" {
                    "未配置".into()
                } else {
                    "待连接".into()
                },
                YELLOW,
            ),
            (
                "身份",
                if app.config_status == "未初始化" {
                    "待配对".into()
                } else {
                    "便携私钥".into()
                },
                if app.config_status == "未初始化" {
                    YELLOW
                } else {
                    GREEN
                },
            ),
            ("主机", format!("{} 台可选", app.hosts.len()), CYAN),
            ("策略", "仅服务端授权".into(), MUTED),
        ],
        _ => Vec::new(),
    };
    frame.render_widget(panel(" 预览 "), overview);
    let overview_width = overview_rows
        .iter()
        .map(|(_, value, _)| 12 + display_width(value))
        .max()
        .unwrap_or(0) as u16;
    let overview_height = overview_rows.len() as u16;
    if overview_height > 0 {
        let overview_inner = centered_rect(
            overview_width,
            overview_height,
            overview.inner(Margin::new(1, 1)),
        );
        let overview_lines = overview_rows
            .into_iter()
            .map(|(label, value, color)| landing_row(label, value, color))
            .collect::<Vec<_>>();
        frame.render_widget(Paragraph::new(overview_lines), overview_inner);
    }

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("服务端  ", Style::default().fg(MUTED)),
            Span::styled(
                if app.config_status == "未初始化" {
                    "待配置".into()
                } else {
                    client_endpoint_summary(app)
                },
                Style::default().fg(if app.config_status == "未初始化" {
                    YELLOW
                } else {
                    Color::White
                }),
            ),
            Span::styled("     连接  ", Style::default().fg(MUTED)),
            Span::styled(
                if app.config_status == "未初始化" {
                    "未配置"
                } else {
                    "待连接"
                },
                Style::default().fg(YELLOW),
            ),
            Span::styled("     密钥类型  ", Style::default().fg(MUTED)),
            Span::styled(
                if app.config_status == "未初始化" {
                    "待配对"
                } else {
                    "便携私钥"
                },
                Style::default().fg(if app.config_status == "未初始化" {
                    YELLOW
                } else {
                    GREEN
                }),
            ),
        ]))
        .block(panel(" 连接侧信息 ")),
        snapshot,
    );
}

fn landing_row(label: &str, value: String, color: Color) -> Line<'static> {
    let label_width = display_width(label);
    let padding = " ".repeat(12_usize.saturating_sub(label_width));
    Line::from(vec![
        Span::styled(format!("{label}{padding}"), Style::default().fg(MUTED)),
        Span::styled(value, Style::default().fg(color)),
    ])
}

fn display_width(value: &str) -> usize {
    value
        .chars()
        .map(|character| if character.is_ascii() { 1 } else { 2 })
        .sum()
}

fn render_server_home(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let [nav, content] = Layout::horizontal([Constraint::Length(23), Constraint::Min(1)])
        .spacing(1)
        .areas(area);
    render_server_nav(frame, 0, nav);

    let [summary, table_area, detail] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(7),
        Constraint::Length(5),
    ])
    .spacing(1)
    .areas(content);
    let summary_text = Line::from(vec![
        Span::styled("监听  ", Style::default().fg(MUTED)),
        Span::styled(listener_summary(app), Style::default().fg(Color::White)),
        Span::styled("     主机  ", Style::default().fg(MUTED)),
        Span::styled(app.hosts.len().to_string(), Style::default().fg(CYAN)),
        Span::styled("     客户端  ", Style::default().fg(MUTED)),
        Span::styled(app.clients.len().to_string(), Style::default().fg(CYAN)),
        Span::styled("     配置  ", Style::default().fg(MUTED)),
        Span::styled(&app.config_status, Style::default().fg(GREEN)),
    ]);
    frame.render_widget(
        Paragraph::new(summary_text)
            .block(panel(" 服务概览 "))
            .alignment(Alignment::Left),
        summary,
    );
    render_server_hosts_table(frame, app, table_area);

    let detail_text = if let Some(host) = app.selected_host() {
        vec![
            Line::from(vec![
                Span::styled("名称  ", Style::default().fg(MUTED)),
                Span::raw(&host.name),
                Span::styled("     状态  ", Style::default().fg(MUTED)),
                Span::styled(host.state.label(), Style::default().fg(host.state.color())),
            ]),
            Line::from(vec![
                Span::styled("MAC   ", Style::default().fg(MUTED)),
                Span::raw(&host.mac),
                Span::styled("     IP  ", Style::default().fg(MUTED)),
                Span::raw(&host.ip),
            ]),
            Line::from(vec![
                Span::styled("IPv6 网卡  ", Style::default().fg(MUTED)),
                Span::raw(if host.wol_ipv6_interface == 0 {
                    "自动".to_owned()
                } else {
                    host.wol_ipv6_interface.to_string()
                }),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "尚未添加主机",
            Style::default().fg(MUTED),
        ))]
    };
    frame.render_widget(
        Paragraph::new(detail_text).block(panel(" 当前主机 ")),
        detail,
    );
}

fn render_server_nav(frame: &mut Frame<'_>, selected: usize, area: Rect) {
    let items = [
        ("1", "开机项"),
        ("2", "监听与安全"),
        ("3", "客户端凭据"),
        ("4", "运行服务"),
        ("5", "部署"),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (key, label))| {
        let style = if index == selected {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        ListItem::new(Line::from(vec![
            Span::styled(format!(" {key} "), Style::default().fg(MUTED)),
            Span::styled(label, style),
        ]))
    });
    frame.render_widget(List::new(items).block(panel(" 服务端 ")), area);
}

fn render_server_hosts_table(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let full = area.width >= 92;
    let header = if full {
        Row::new(["#", "HOST ID", "MAC", "IP", "状态"])
    } else {
        Row::new(["#", "HOST ID", "IP", "状态"])
    }
    .style(Style::default().fg(MUTED).add_modifier(Modifier::BOLD))
    .bottom_margin(1);
    let rows = app.hosts.iter().enumerate().map(|(index, host)| {
        let status = Cell::from(host.state.label()).style(Style::default().fg(host.state.color()));
        if full {
            Row::new(vec![
                Cell::from(format!("{}", index + 1)),
                Cell::from(host.id.clone()),
                Cell::from(host.mac.clone()),
                Cell::from(host.ip.clone()),
                status,
            ])
        } else {
            Row::new(vec![
                Cell::from(format!("{}", index + 1)),
                Cell::from(host.id.clone()),
                Cell::from(host.ip.clone()),
                status,
            ])
        }
    });
    let widths: Vec<Constraint> = if full {
        vec![
            Constraint::Length(4),
            Constraint::Percentage(25),
            Constraint::Length(19),
            Constraint::Min(18),
            Constraint::Length(9),
        ]
    } else {
        vec![
            Constraint::Length(4),
            Constraint::Percentage(38),
            Constraint::Min(18),
            Constraint::Length(9),
        ]
    };
    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().fg(Color::Black).bg(CYAN))
        .highlight_symbol("> ")
        .block(panel(" 开机项 "));
    let mut state =
        TableState::default().with_selected((!app.hosts.is_empty()).then_some(app.host_index));
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_host_editor(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let form = centered_rect(72.min(area.width - 2), 19, area);
    frame.render_widget(
        panel(if app.edit_index.is_some() {
            " 修改开机项 "
        } else {
            " 添加开机项 "
        }),
        form,
    );
    let inner = form.inner(Margin::new(2, 1));
    let [fields] = Layout::vertical([Constraint::Min(1)]).areas(inner);
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
    ])
    .split(fields);
    let labels = [
        "Host ID",
        "显示名称",
        "MAC 地址",
        "IP 地址",
        "IPv6 网卡索引 (0=自动)",
    ];
    for (index, row) in rows.iter().enumerate() {
        let border = if app.editor_field == index {
            CYAN
        } else {
            PANEL
        };
        frame.render_widget(
            Paragraph::new(app.editor_inputs[index].value()).block(
                Block::default()
                    .title(format!(" {} ", labels[index]))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Plain)
                    .border_style(Style::default().fg(border)),
            ),
            *row,
        );
    }
}

fn render_server_settings(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let [nav, content] = Layout::horizontal([Constraint::Length(23), Constraint::Min(1)])
        .spacing(1)
        .areas(area);
    render_server_nav(frame, 1, nav);
    let settings_height = (app.setting_field_count() as u16 + 3).min(12);
    let [settings, headers] =
        Layout::vertical([Constraint::Length(settings_height), Constraint::Min(7)])
            .spacing(1)
            .areas(content);

    let setting_rows = app
        .setting_fields()
        .into_iter()
        .map(|field| Row::new([setting_field_label(field), setting_field_value(app, field)]));
    let settings_table = Table::new(
        setting_rows,
        [Constraint::Percentage(42), Constraint::Min(18)],
    )
    .header(
        Row::new(["设置", "当前值"]).style(Style::default().fg(MUTED).add_modifier(Modifier::BOLD)),
    )
    .row_highlight_style(Style::default().fg(Color::Black).bg(CYAN))
    .highlight_symbol("> ")
    .block(panel(if app.settings_editing {
        " 监听设置 / 正在编辑 "
    } else {
        " 监听设置 "
    }));
    let mut settings_state = TableState::default().with_selected(
        (app.settings_field < app.setting_field_count()).then_some(app.settings_field),
    );
    frame.render_stateful_widget(settings_table, settings, &mut settings_state);

    let header_rows = app
        .headers
        .iter()
        .map(|(name, value)| Row::new([name.clone(), value.clone()]));
    let header_block = Block::default()
        .title(" 自定义 Header ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(
            if app.active_setting_field() == SettingField::Headers {
                CYAN
            } else {
                PANEL
            },
        ));
    let header_table = Table::new(
        header_rows,
        [Constraint::Percentage(38), Constraint::Min(16)],
    )
    .header(Row::new(["名称", "值"]).style(Style::default().fg(MUTED).add_modifier(Modifier::BOLD)))
    .row_highlight_style(Style::default().fg(Color::Black).bg(CYAN))
    .highlight_symbol("> ")
    .block(header_block);
    let mut header_state = TableState::default().with_selected(
        (app.active_setting_field() == SettingField::Headers && !app.headers.is_empty())
            .then_some(app.header_index),
    );
    frame.render_stateful_widget(header_table, headers, &mut header_state);
}

fn setting_field_label(field: SettingField) -> String {
    match field {
        SettingField::Mode => "监听模式".into(),
        SettingField::CustomAddress => "自定义监听地址".into(),
        SettingField::V4Address => "IPv4 监听地址".into(),
        SettingField::V6Address => "IPv6 监听地址".into(),
        SettingField::Port => "监听端口".into(),
        SettingField::ClockSkew => "握手时钟容差".into(),
        SettingField::Headers => "自定义 Header".into(),
    }
}

fn setting_field_value(app: &App, field: SettingField) -> String {
    match field {
        SettingField::Mode => app.listen_mode.label().into(),
        SettingField::CustomAddress => app.custom_bind_input.value().into(),
        SettingField::V4Address => app.bind_v4_input.value().into(),
        SettingField::V6Address => app.bind_v6_input.value().into(),
        SettingField::Port => app.server_port_input.value().into(),
        SettingField::ClockSkew => format!("{} 秒", app.clock_skew_input.value()),
        SettingField::Headers => format!("{} 项", app.headers.len()),
    }
}

fn listener_summary(app: &App) -> String {
    let port = app.server_port_input.value();
    if port.trim().is_empty() {
        return "未设置".into();
    }
    match app.listen_mode {
        ListenMode::Custom => endpoint_or_unset(app.custom_bind_input.value(), port),
        ListenMode::V4Only => endpoint_or_unset(app.bind_v4_input.value(), port),
        ListenMode::V6Only => endpoint_or_unset(app.bind_v6_input.value(), port),
        ListenMode::DualStack => format!(
            "v4={}  v6={}",
            endpoint_or_unset(app.bind_v4_input.value(), port),
            endpoint_or_unset(app.bind_v6_input.value(), port),
        ),
    }
}

fn client_endpoint_summary(app: &App) -> String {
    endpoint_or_unset(app.address_input.value(), app.port_input.value())
}

fn endpoint_or_unset(address: &str, port: &str) -> String {
    if address.trim().is_empty() || port.trim().is_empty() {
        "未设置".into()
    } else {
        format_listener_endpoint(address.trim(), port.trim())
    }
}

fn format_listener_endpoint(address: &str, port: &str) -> String {
    if address.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

fn render_header_editor(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let form = centered_rect(68, 10, area);
    frame.render_widget(
        panel(if app.header_edit_index.is_some() {
            " 修改 Header "
        } else {
            " 添加 Header "
        }),
        form,
    );
    let inner = form.inner(Margin::new(2, 1));
    let [name, value] =
        Layout::vertical([Constraint::Length(3), Constraint::Length(3)]).areas(inner);
    render_input(
        frame,
        name,
        "Header 名称",
        app.header_inputs[0].value(),
        app.header_editor_field == 0,
    );
    render_input(
        frame,
        value,
        "Header 值",
        app.header_inputs[1].value(),
        app.header_editor_field == 1,
    );
}

fn render_credentials(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let [nav, content] = Layout::horizontal([Constraint::Length(23), Constraint::Min(1)])
        .spacing(1)
        .areas(area);
    render_server_nav(frame, 2, nav);
    let [summary, table_area] = Layout::vertical([Constraint::Length(3), Constraint::Min(6)])
        .spacing(1)
        .areas(content);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("身份  ", Style::default().fg(MUTED)),
            Span::styled("便携私钥 + PSK", Style::default().fg(GREEN)),
        ]))
        .block(panel(" 配对策略 ")),
        summary,
    );
    let rows = app
        .clients
        .iter()
        .map(|client| Row::new([client.label.clone(), client.access.clone()]));
    let table = Table::new(rows, [Constraint::Percentage(48), Constraint::Min(20)])
        .header(
            Row::new(["客户端身份", "允许范围"])
                .style(Style::default().fg(MUTED).add_modifier(Modifier::BOLD))
                .bottom_margin(1),
        )
        .row_highlight_style(Style::default().fg(Color::Black).bg(CYAN))
        .highlight_symbol("> ")
        .block(panel(" 已签发客户端 "));
    let mut state = TableState::default()
        .with_selected((!app.clients.is_empty()).then_some(app.credential_index));
    frame.render_stateful_widget(table, table_area, &mut state);
}

fn render_credential_issue(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let [identity, hosts, output] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(5),
    ])
    .spacing(1)
    .areas(area);

    let [label] = Layout::vertical([Constraint::Length(3)]).areas(identity);
    render_input(
        frame,
        label,
        "凭据标签",
        app.issue_label_input.value(),
        app.issue_field == 0,
    );

    let host_rows = app.hosts.iter().enumerate().map(|(index, host)| {
        Row::new([
            if app.issue_selected.get(index).copied().unwrap_or(false) {
                "[x]"
            } else {
                "[ ]"
            }
            .into(),
            host.id.clone(),
            host.name.clone(),
            host.ip.clone(),
        ])
    });
    let host_block = Block::default()
        .title(" 允许访问的主机 ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if app.issue_field == 1 { CYAN } else { PANEL }));
    let host_table = Table::new(
        host_rows,
        [
            Constraint::Length(5),
            Constraint::Percentage(30),
            Constraint::Percentage(28),
            Constraint::Min(18),
        ],
    )
    .header(
        Row::new(["", "HOST ID", "名称", "IP"])
            .style(Style::default().fg(MUTED).add_modifier(Modifier::BOLD)),
    )
    .row_highlight_style(Style::default().fg(Color::Black).bg(CYAN))
    .highlight_symbol("> ")
    .block(host_block);
    let mut host_state = TableState::default().with_selected(
        (app.issue_field == 1 && !app.hosts.is_empty()).then_some(app.issue_host_index),
    );
    frame.render_stateful_widget(host_table, hosts, &mut host_state);

    let [path, summary] =
        Layout::vertical([Constraint::Length(3), Constraint::Length(2)]).areas(output);
    render_input(
        frame,
        path,
        "输出文件",
        app.issue_output_input.value(),
        app.issue_field == 2,
    );
    let selected = app
        .issue_selected
        .iter()
        .filter(|selected| **selected)
        .count();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("已选  ", Style::default().fg(MUTED)),
            Span::styled(format!("{selected} 台主机"), Style::default().fg(CYAN)),
        ])),
        summary,
    );
}

fn render_server_running(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let [status, logs] = Layout::vertical([Constraint::Length(6), Constraint::Min(8)])
        .spacing(1)
        .areas(area);
    let uptime = Instant::now().duration_since(app.started_at).as_secs();
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    if app.server_running {
                        "● RUNNING"
                    } else {
                        "○ STOPPED"
                    },
                    Style::default()
                        .fg(if app.server_running { GREEN } else { MUTED })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("     监听  ", Style::default().fg(MUTED)),
                Span::raw(listener_summary(app)),
                Span::styled("     运行时间  ", Style::default().fg(MUTED)),
                Span::raw(format_duration(Duration::from_secs(uptime))),
            ]),
            Line::from(vec![
                Span::styled("活动连接  ", Style::default().fg(MUTED)),
                Span::styled("2", Style::default().fg(CYAN)),
                Span::styled("     主机  ", Style::default().fg(MUTED)),
                Span::styled(app.hosts.len().to_string(), Style::default().fg(CYAN)),
            ]),
        ])
        .block(panel(" 服务状态 ")),
        status,
    );

    let available = logs.height.saturating_sub(2) as usize;
    let skip_from_end = app.log_scroll.min(app.logs.len());
    let end = app.logs.len().saturating_sub(skip_from_end);
    let start = end.saturating_sub(available);
    let lines: Vec<Line<'_>> = app
        .logs
        .iter()
        .skip(start)
        .take(end - start)
        .map(|entry| {
            let (level, color) = match entry.level {
                LogLevel::Info => ("INFO ", Color::White),
                LogLevel::Warn => ("WARN ", YELLOW),
                LogLevel::Error => ("ERROR", Color::Red),
                LogLevel::Fatal => ("FATAL", Color::Red),
            };
            Line::from(vec![
                Span::styled(format!("{:>8} ", entry.clock), Style::default().fg(MUTED)),
                Span::styled(format!("{level:<6}"), Style::default().fg(color)),
                Span::raw(&entry.message),
            ])
        })
        .collect();
    let title = if app.log_scroll == 0 {
        " 实时事件 / FOLLOW "
    } else {
        " 实时事件 / PAUSED "
    };
    frame.render_widget(Paragraph::new(lines).block(panel(title)), logs);
}

fn render_client_connect(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let form = centered_rect(68, 12, area);
    frame.render_widget(panel(" 安全连接 "), form);
    let inner = form.inner(Margin::new(3, 1));
    let [address, port, identity] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(4),
    ])
    .areas(inner);
    render_input(
        frame,
        address,
        "服务端地址",
        app.address_input.value(),
        app.connect_field == 0,
    );
    render_input(
        frame,
        port,
        "服务端端口",
        app.port_input.value(),
        app.connect_field == 1,
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(label_value("凭据", &app.credential_display)),
            Line::from(vec![
                Span::styled("状态        ", Style::default().fg(MUTED)),
                Span::styled(&app.credential_status, Style::default().fg(GREEN)),
            ]),
        ])
        .block(panel(" 客户端身份 ")),
        identity,
    );
}

fn render_client_hosts(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let [connection, table_area, detail] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(7),
        Constraint::Length(4),
    ])
    .spacing(1)
    .areas(area);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "● 已连接",
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::styled("     服务端  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "{}:{}",
                app.address_input.value(),
                app.port_input.value()
            )),
            Span::styled("     身份  ", Style::default().fg(MUTED)),
            Span::raw(&app.connection_display),
        ]))
        .block(panel(" 安全会话 ")),
        connection,
    );
    render_client_hosts_table(frame, app, table_area);
    let selected = app.hosts.iter().filter(|host| host.selected).count();
    let host = app.hosts.get(app.client_host_index);
    let lines = vec![
        Line::from(vec![
            Span::styled("已选择  ", Style::default().fg(MUTED)),
            Span::styled(format!("{selected} 台"), Style::default().fg(CYAN)),
            Span::styled("     当前  ", Style::default().fg(MUTED)),
            Span::raw(host.map_or("-", |host| host.name.as_str())),
        ]),
        Line::from(vec![
            Span::styled("状态    ", Style::default().fg(MUTED)),
            Span::styled(
                host.map_or("-", |host| host.state.label()),
                Style::default().fg(host.map_or(MUTED, |host| host.state.color())),
            ),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines).block(panel(" 选择详情 ")), detail);
}

fn render_client_hosts_table(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let header = Row::new(["", "#", "HOST ID", "状态"])
        .style(Style::default().fg(MUTED).add_modifier(Modifier::BOLD))
        .bottom_margin(1);
    let rows = app.hosts.iter().enumerate().map(|(index, host)| {
        let mark = if host.selected { "[x]" } else { "[ ]" };
        let state = Cell::from(host.state.label()).style(Style::default().fg(host.state.color()));
        Row::new(vec![
            Cell::from(mark),
            Cell::from(format!("{}", index + 1)),
            Cell::from(host.id.clone()),
            state,
        ])
    });
    let widths = [
        Constraint::Length(5),
        Constraint::Length(4),
        Constraint::Min(24),
        Constraint::Length(9),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().fg(Color::Black).bg(CYAN))
        .highlight_symbol("> ")
        .block(panel(" 可用主机 "));
    let mut state = TableState::default()
        .with_selected((!app.hosts.is_empty()).then_some(app.client_host_index));
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_wake(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let [summary, targets, timeline] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(7),
        Constraint::Length(1),
    ])
    .spacing(1)
    .areas(area);
    let elapsed = Instant::now().duration_since(app.wake_started_at).as_secs();
    let remaining = 60_u64.saturating_sub(elapsed);
    let phase = match app.wake_phase {
        WakePhase::Sending => "正在请求服务端执行",
        WakePhase::Waiting => "等待目标上线",
        WakePhase::Retrying => "正在申请唯一一次重发",
        WakePhase::Complete => "唤醒完成",
    };
    let phase_color = if app.wake_phase == WakePhase::Complete {
        GREEN
    } else {
        YELLOW
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    phase,
                    Style::default()
                        .fg(phase_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("     尝试  ", Style::default().fg(MUTED)),
                Span::raw(format!("{} / 2", app.wake_attempt)),
            ]),
            Line::from(vec![
                Span::styled("执行回执  ", Style::default().fg(MUTED)),
                Span::styled(
                    if app.wake_receipt {
                        "已收到"
                    } else {
                        "等待中"
                    },
                    Style::default().fg(if app.wake_receipt { GREEN } else { YELLOW }),
                ),
                Span::styled("     剩余  ", Style::default().fg(MUTED)),
                Span::styled(format!("{remaining:02} 秒"), Style::default().fg(CYAN)),
            ]),
        ])
        .block(panel(" 唤醒进度 ")),
        summary,
    );
    let target_rows = app.wake_targets().enumerate().map(|(index, host)| {
        let online = app.wake_online.get(index).copied().unwrap_or(false);
        Row::new([
            host.id.clone(),
            if online { "ONLINE" } else { "WAITING" }.into(),
        ])
        .style(Style::default().fg(if online { GREEN } else { Color::White }))
    });
    frame.render_widget(
        Table::new(target_rows, [Constraint::Min(24), Constraint::Length(10)])
            .header(
                Row::new(["HOST ID", "状态"])
                    .style(Style::default().fg(MUTED).add_modifier(Modifier::BOLD))
                    .bottom_margin(1),
            )
            .block(panel(" 目标 ")),
        targets,
    );
    let ratio = if app.wake_phase == WakePhase::Complete {
        1.0
    } else {
        (elapsed.min(60) as f64 / 60.0).clamp(0.0, 1.0)
    };
    let [gauge] = Layout::horizontal([Constraint::Length(18)])
        .flex(ratatui::layout::Flex::Center)
        .areas(timeline);
    frame.render_widget(
        Gauge::default()
            .ratio(ratio)
            .label(format!("{remaining:02}s"))
            .gauge_style(Style::default().fg(CYAN).bg(PANEL)),
        gauge,
    );
}

fn render_save_exit(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let [summary, deployment] = Layout::vertical([Constraint::Length(5), Constraint::Min(8)])
        .spacing(1)
        .areas(area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("配置状态  ", Style::default().fg(MUTED)),
                Span::styled("已自动保存", Style::default().fg(GREEN)),
            ]),
            Line::from(vec![
                Span::styled("服务端公钥  ", Style::default().fg(MUTED)),
                Span::raw(if app.server_public_key_display.is_empty() {
                    "未生成"
                } else {
                    app.server_public_key_display.as_str()
                }),
            ]),
            Line::from(vec![
                Span::styled("配置文件    ", Style::default().fg(MUTED)),
                Span::raw(&app.deployment_summary),
            ]),
        ])
        .block(panel(" 部署状态 ")),
        summary,
    );

    #[cfg(windows)]
    let default_deployment_text = Text::from(vec![
        Line::from(Span::styled(
            "Windows 启动指令",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(
            "RemoteOpenPower.exe --server --config C:\\ProgramData\\RemoteOpenPower\\remote-open-power.toml",
        ),
    ]);
    #[cfg(target_os = "linux")]
    let default_deployment_text = Text::from(vec![
        Line::from(Span::styled(
            "Linux 启动指令",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(
            "./RemoteOpenPower --server --config /etc/remote-open-power/remote-open-power.toml",
        ),
        Line::from(""),
        Line::from(Span::styled(
            "systemd 部署",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("sudo install -Dm0755 ./RemoteOpenPower /usr/local/bin/remote-open-power"),
        Line::from("sudo install -d -o root -g remote-open-power -m0750 /etc/remote-open-power"),
        Line::from(
            "sudo install -o root -g remote-open-power -m0640 ./remote-open-power.toml /etc/remote-open-power/remote-open-power.toml",
        ),
        Line::from("sudo systemctl daemon-reload && sudo systemctl enable --now remote-open-power"),
    ]);
    #[cfg(all(unix, not(target_os = "linux")))]
    let default_deployment_text = Text::from(vec![
        Line::from(Span::styled(
            "Unix 启动指令",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("./RemoteOpenPower --server --config ./remote-open-power.toml"),
        Line::from(""),
        Line::from("当前平台不生成 Linux systemd unit。"),
    ]);
    #[cfg(not(any(windows, unix)))]
    let default_deployment_text = Text::from(vec![Line::from("当前平台没有可用的部署模板。")]);
    let deployment_text = if app.deployment_lines.is_empty() {
        default_deployment_text
    } else {
        Text::from(
            app.deployment_lines
                .iter()
                .cloned()
                .map(Line::from)
                .collect::<Vec<_>>(),
        )
    };
    frame.render_widget(
        Paragraph::new(deployment_text)
            .block(panel(" 部署信息 "))
            .wrap(Wrap { trim: false }),
        deployment,
    );
}

fn render_modal(frame: &mut Frame<'_>, app: &App, modal: Modal, area: Rect) {
    if modal == Modal::Help {
        render_help_modal(frame, app, area);
        return;
    }

    let (title, body) = match modal {
        Modal::Help => unreachable!(),
        Modal::DeleteHost => (
            " 删除开机项 ",
            format!(
                "确认删除 {}？",
                app.selected_host()
                    .map_or("当前主机", |host| host.id.as_str())
            ),
        ),
        Modal::DeleteHeader => (
            " 删除 Header ",
            format!(
                "确认删除 {}？",
                app.headers
                    .get(app.header_index)
                    .map_or("当前 Header", |header| header.0.as_str())
            ),
        ),
        Modal::RevokeCredential => (
            " 撤销客户端凭据 ",
            format!(
                "确认撤销 {}？",
                app.clients
                    .get(app.credential_index)
                    .map_or("当前凭据", |client| client.label.as_str())
            ),
        ),
        Modal::StopServer => (
            " 停止服务 ",
            if app.production {
                "确认停止服务监听并返回管理页面？".into()
            } else {
                "确认停止模拟服务并返回管理页面？".into()
            },
        ),
        Modal::ExitPreview => (
            if app.production {
                " 退出 TUI "
            } else {
                " 退出预览 "
            },
            if app.production {
                "确认退出 TUI？".into()
            } else {
                "确认退出 TUI 预览？".into()
            },
        ),
    };
    let popup = centered_rect(54, 9, area);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(body)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .title(title)
                    .title_bottom(Line::from(" Enter/y 确认   Esc/n 取消 ").centered())
                    .borders(Borders::ALL)
                    .border_type(BorderType::Plain)
                    .border_style(Style::default().fg(YELLOW)),
            ),
        popup,
    );
}

fn render_help_modal(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let width = area.width.saturating_sub(6).min(86);
    let height = area.height.saturating_sub(4).min(22);
    let popup = centered_rect(width, height, area);
    frame.render_widget(Clear, popup);

    let mut lines = vec![
        Line::from(Span::styled(
            "当前页面操作",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    let entries: &[(&str, &str)] = match app.screen {
        Screen::Landing => &[
            ("↑ / ↓", "选择服务模式、终端模式或退出"),
            ("Enter", "进入当前选择"),
            ("1 / 2", "直接进入服务模式或终端模式"),
            ("q / Esc", "退出预览"),
        ],
        Screen::ServerHome => &[
            ("↑ / ↓", "选择开机项"),
            ("a / e / d", "添加、编辑或删除开机项"),
            ("1..5", "切换主机、设置、凭据、运行和部署页面"),
            ("Ctrl+S", "保存当前配置"),
            ("q", "进入部署页面"),
        ],
        Screen::HostEditor => &[
            ("Tab / ↑ / ↓", "切换字段"),
            ("Enter", "进入下一字段；最后一项执行校验并保存"),
            ("Esc", "取消修改"),
            (
                "字段限制",
                "Host ID 64、名称 128、MAC 20、IP 45 字节；IPv6 网卡索引 0=自动",
            ),
        ],
        Screen::ServerSettings => &[
            ("Tab / ↑ / ↓", "切换设置；Header 区域内选择记录"),
            (
                "Enter",
                "文本项第一次进入编辑，再次校验并确认；成功后进入下一项",
            ),
            ("← / → / Space", "在自定义、仅v6、仅v4、双栈之间循环选择"),
            (
                "地址字段",
                "自定义显示一行；仅v4/仅v6显示对应地址；双栈分别填写 v4 与 v6",
            ),
            (
                "失去焦点",
                "空白或格式错误的地址恢复对应默认值；有效值去掉首尾空白",
            ),
            ("a / e / d", "添加、编辑或删除 Header"),
            ("Ctrl+S", "保存已经确认的设置，不负责格式校验"),
            ("Esc", "返回开机项页面"),
        ],
        Screen::HeaderEditor => &[
            ("Tab / ↑ / ↓", "切换名称和值"),
            ("Enter", "继续或校验保存"),
            ("Esc", "取消编辑"),
            ("格式", "名称仅小写 token；值仅可打印 ASCII，最多 256 字节"),
        ],
        Screen::Credentials => &[
            ("↑ / ↓", "选择已签发凭据"),
            ("n", "打开完整凭据签发表单"),
            ("e / Enter", "修改所选凭据的标签和主机权限"),
            ("d", "撤销所选凭据"),
            ("Esc", "返回开机项页面"),
        ],
        Screen::CredentialIssue => &[
            ("Tab", "切换标签、主机权限和输出文件"),
            ("↑ / ↓ / Space", "选择并勾选允许访问的主机"),
            ("a", "全选或取消全选"),
            (
                "Ctrl+S / Enter",
                if app.production {
                    "校验后签发或更新权限"
                } else {
                    "校验后模拟签发"
                },
            ),
            ("Esc", "取消签发"),
            ("身份规则", "标签和设备名不参与认证；便携私钥才是身份"),
        ],
        Screen::ServerRunning => &[
            ("PgUp / PgDn", "滚动实时事件"),
            ("End", "恢复跟随最新事件"),
            ("c", "清空本地日志视图"),
            (
                "q / Esc",
                if app.production {
                    "停止服务监听并返回"
                } else {
                    "停止模拟服务并返回"
                },
            ),
        ],
        Screen::ClientConnect => &[
            ("Tab / ↑ / ↓", "切换服务端地址和端口"),
            ("Enter", "校验地址和端口并连接"),
            ("Esc", "返回模式选择"),
        ],
        Screen::ClientHosts => &[
            ("↑ / ↓", "选择主机"),
            ("Space / a", "勾选当前主机或切换全选"),
            (
                "r",
                if app.production {
                    "从服务端刷新状态"
                } else {
                    "模拟刷新状态"
                },
            ),
            ("Enter", "唤醒已勾选主机"),
            ("Esc", "断开并返回连接页面"),
        ],
        Screen::Wake if app.production => &[
            ("Enter", "收到全部在线回执后返回主机列表"),
            ("Esc", "停止本地等待；服务端不会自动重发"),
            ("状态", "回执后本地倒计时 60 秒，超时只申请一次重发"),
        ],
        Screen::Wake => &[
            ("o", "模拟下一台目标上线"),
            ("t", "模拟首次等待超时并申请唯一一次重发"),
            ("Enter", "完成后返回主机列表"),
            ("Esc", "停止本地等待；不会触发重发"),
        ],
        Screen::SaveExit => &[
            ("s / Enter", "再次保存配置"),
            (
                "q",
                if app.production {
                    "退出 TUI"
                } else {
                    "退出预览"
                },
            ),
            ("Esc", "返回服务端管理"),
            ("部署", "页面只展示当前平台信息，不执行任何命令"),
        ],
    };
    lines.extend(entries.iter().map(|(key, description)| {
        Line::from(vec![
            Span::styled(format!("{key:<18}"), Style::default().fg(YELLOW)),
            Span::raw(*description),
        ])
    }));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("终端探测          ", Style::default().fg(MUTED)),
        Span::raw(&app.terminal_note),
    ]));

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .title(" 帮助 / F1 ")
                .title_bottom(Line::from(" F1 / Esc 关闭 ").centered())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(CYAN)),
        ),
        popup,
    );
}

fn render_input(frame: &mut Frame<'_>, area: Rect, label: &str, value: &str, active: bool) {
    frame.render_widget(
        Paragraph::new(value).block(
            Block::default()
                .title(format!(" {label} "))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if active { CYAN } else { PANEL })),
        ),
        area,
    );
}

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(dim())
}

fn dim() -> Style {
    Style::default().fg(PANEL)
}

fn label_value<'a>(label: &'a str, value: &'a str) -> Vec<Span<'a>> {
    let label_width = label
        .chars()
        .map(|character| if character.is_ascii() { 1 } else { 2 })
        .sum::<usize>();
    let padding = " ".repeat(12_usize.saturating_sub(label_width));
    vec![
        Span::styled(format!("{label}{padding}"), Style::default().fg(MUTED)),
        Span::raw(value),
    ]
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let [vertical] = Layout::vertical([Constraint::Length(height)])
        .flex(ratatui::layout::Flex::Center)
        .areas(area);
    let [centered] = Layout::horizontal([Constraint::Length(width)])
        .flex(ratatui::layout::Flex::Center)
        .areas(vertical);
    centered
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

fn local_clock_hm() -> String {
    Local::now().format("%H:%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn draw_at(app: &App, width: u16, height: u16) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, app))
            .expect("render succeeds");
    }

    #[test]
    fn every_screen_renders_at_supported_sizes() {
        let mut app = App::new();
        let screens = [
            Screen::Landing,
            Screen::ServerHome,
            Screen::HostEditor,
            Screen::ServerSettings,
            Screen::HeaderEditor,
            Screen::Credentials,
            Screen::CredentialIssue,
            Screen::ServerRunning,
            Screen::ClientConnect,
            Screen::ClientHosts,
            Screen::Wake,
            Screen::SaveExit,
        ];

        app.hosts[0].selected = true;
        app.begin_wake(1);
        for screen in screens {
            app.screen = screen;
            for (width, height) in [(72, 24), (80, 24), (100, 30), (120, 36)] {
                draw_at(&app, width, height);
            }
        }
    }

    #[test]
    fn narrow_terminal_falls_back_without_panicking() {
        let app = App::new();
        for (width, height) in [(40, 10), (71, 24), (100, 23)] {
            draw_at(&app, width, height);
        }
    }

    #[test]
    fn terminal_size_boundaries_render_on_both_sides_of_the_cutoff() {
        let mut app = App::new();
        for screen in [Screen::Landing, Screen::ServerSettings, Screen::ClientHosts] {
            app.screen = screen;
            for width in [1, MIN_WIDTH - 1, MIN_WIDTH, MIN_WIDTH + 1] {
                for height in [1, MIN_HEIGHT - 1, MIN_HEIGHT, MIN_HEIGHT + 1] {
                    draw_at(&app, width, height);
                }
            }
        }
    }

    #[test]
    fn simulated_logs_stay_bounded() {
        let mut app = App::new();
        for index in 0..(LOG_LIMIT + 20) {
            app.logs.push_back(LogEntry {
                clock: format!("{:02}:{:02}", index / 60, index % 60),
                level: LogLevel::Info,
                message: "test".into(),
            });
            while app.logs.len() > LOG_LIMIT {
                app.logs.pop_front();
            }
        }
        assert_eq!(app.logs.len(), LOG_LIMIT);
        draw_at(&app, 100, 28);
    }

    #[test]
    fn log_clock_is_a_local_wall_clock() {
        let clock = local_clock_hm();
        let Some((hour, minute)) = clock.split_once(':') else {
            panic!("log clock must use HH:MM");
        };
        assert_eq!(hour.len(), 2);
        assert_eq!(minute.len(), 2);
        assert!(hour.parse::<u8>().is_ok_and(|value| value < 24));
        assert!(minute.parse::<u8>().is_ok_and(|value| value < 60));
    }

    fn press(app: &mut App, code: KeyCode) {
        app.handle_event(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)));
    }

    fn press_with(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
        app.handle_event(Event::Key(KeyEvent::new(code, modifiers)));
    }

    fn app_on(screen: Screen) -> App {
        let mut app = App::new();
        match screen {
            Screen::HostEditor => app.open_host_editor(None),
            Screen::HeaderEditor => app.open_header_editor(None),
            Screen::CredentialIssue => app.open_credential_issue(None),
            Screen::Wake => {
                app.hosts[0].selected = true;
                app.begin_wake(1);
                app.screen = Screen::Wake;
            }
            _ => app.screen = screen,
        }
        app
    }

    fn assert_state_invariants(app: &App) {
        assert!(app.landing_index <= 2);
        assert!(app.host_index <= app.hosts.len().saturating_sub(1));
        assert!(app.client_host_index <= app.hosts.len().saturating_sub(1));
        assert!(app.credential_index <= app.clients.len().saturating_sub(1));
        assert!(app.editor_field < 5);
        assert_eq!(app.editor_inputs.len(), 5);
        assert!(app.settings_field < app.setting_field_count());
        assert!(app.header_index <= app.headers.len().saturating_sub(1));
        assert!(app.header_editor_field < 2);
        assert_eq!(app.header_inputs.len(), 2);
        assert!(app.issue_field < 3);
        assert!(app.issue_host_index <= app.hosts.len().saturating_sub(1));
        assert!(app.connect_field < 2);
        assert!((1..=2).contains(&app.wake_attempt));
        assert!(app.hosts.len() <= MAX_HOSTS);
        assert!(app.clients.len() <= MAX_CLIENTS);
        assert!(app.headers.len() <= MAX_HEADERS);
        if app.screen == Screen::CredentialIssue {
            assert_eq!(app.issue_selected.len(), app.hosts.len());
        }
        if app.screen == Screen::Wake {
            assert_eq!(app.wake_online.len(), app.wake_targets().count());
        }
    }

    fn rendered_text(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, app))
            .expect("render succeeds");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .flat_map(|cell| cell.symbol().chars())
            .filter(|character| !character.is_whitespace())
            .collect()
    }

    #[test]
    fn every_screen_handles_common_keys_without_leaving_invalid_state() {
        let screens = [
            Screen::Landing,
            Screen::ServerHome,
            Screen::HostEditor,
            Screen::ServerSettings,
            Screen::HeaderEditor,
            Screen::Credentials,
            Screen::CredentialIssue,
            Screen::ServerRunning,
            Screen::ClientConnect,
            Screen::ClientHosts,
            Screen::Wake,
            Screen::SaveExit,
        ];
        let keys = [
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::PageUp,
            KeyCode::PageDown,
            KeyCode::Backspace,
            KeyCode::Delete,
            KeyCode::Char(' '),
            KeyCode::Char('1'),
            KeyCode::Char('2'),
            KeyCode::Char('3'),
            KeyCode::Char('4'),
            KeyCode::Char('5'),
            KeyCode::Char('a'),
            KeyCode::Char('c'),
            KeyCode::Char('d'),
            KeyCode::Char('e'),
            KeyCode::Char('j'),
            KeyCode::Char('k'),
            KeyCode::Char('n'),
            KeyCode::Char('o'),
            KeyCode::Char('q'),
            KeyCode::Char('r'),
            KeyCode::Char('s'),
            KeyCode::Char('t'),
            KeyCode::Char('y'),
            KeyCode::F(1),
        ];

        for screen in screens {
            for key in &keys {
                let mut app = app_on(screen);
                press(&mut app, *key);
                assert_state_invariants(&app);
                draw_at(&app, MIN_WIDTH, MIN_HEIGHT);
            }

            let mut app = app_on(screen);
            press_with(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
            assert_state_invariants(&app);
            draw_at(&app, MIN_WIDTH, MIN_HEIGHT);
        }
    }

    #[test]
    fn mixed_key_sequences_preserve_state_and_rendering_invariants() {
        let screens = [
            Screen::Landing,
            Screen::ServerHome,
            Screen::HostEditor,
            Screen::ServerSettings,
            Screen::HeaderEditor,
            Screen::Credentials,
            Screen::CredentialIssue,
            Screen::ServerRunning,
            Screen::ClientConnect,
            Screen::ClientHosts,
            Screen::Wake,
            Screen::SaveExit,
        ];
        let keys = [
            KeyCode::Down,
            KeyCode::Up,
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Enter,
            KeyCode::Char(' '),
            KeyCode::Char('a'),
            KeyCode::Char('e'),
            KeyCode::Char('d'),
            KeyCode::Char('n'),
            KeyCode::Char('r'),
            KeyCode::Char('o'),
            KeyCode::Char('t'),
            KeyCode::Char('y'),
            KeyCode::Char('n'),
            KeyCode::Esc,
            KeyCode::F(1),
            KeyCode::F(1),
        ];

        for (seed, screen) in screens.into_iter().enumerate() {
            let mut app = app_on(screen);
            for step in 0..180 {
                let key = keys[(step * 7 + seed * 11) % keys.len()];
                press(&mut app, key);
                assert_state_invariants(&app);
                if step % 15 == 0 {
                    draw_at(&app, MIN_WIDTH, MIN_HEIGHT);
                }
                if app.should_quit {
                    break;
                }
            }
        }
    }

    #[test]
    fn non_key_and_key_release_events_are_ignored() {
        let mut app = App::new();
        app.handle_event(Event::Resize(120, 40));
        app.handle_event(Event::FocusGained);
        app.handle_event(Event::Paste("ignored".into()));
        app.handle_event(Event::Key(KeyEvent::new_with_kind(
            KeyCode::Down,
            KeyModifiers::NONE,
            KeyEventKind::Release,
        )));
        assert_eq!(app.screen, Screen::Landing);
        assert_eq!(app.landing_index, 0);
    }

    #[test]
    fn landing_navigation_clamps_and_exit_requires_confirmation() {
        let mut app = App::new();
        for _ in 0..4 {
            press(&mut app, KeyCode::Up);
        }
        assert_eq!(app.landing_index, 0);
        for _ in 0..5 {
            press(&mut app, KeyCode::Down);
        }
        assert_eq!(app.landing_index, 2);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.modal, Some(Modal::ExitPreview));
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.modal, None);
        assert!(!app.should_quit);
        press(&mut app, KeyCode::Char('q'));
        press(&mut app, KeyCode::Char('y'));
        assert!(app.should_quit);
    }

    #[test]
    fn landing_preview_is_fixed_and_blank_for_exit() {
        let mut app = App::new();
        app.landing_index = 2;
        let output = rendered_text(&app, 100, 30);
        assert!(output.contains("预览"));
        assert!(!output.contains("退出预览"));
        assert!(!output.contains("不会写入磁盘"));
    }

    #[test]
    fn settings_and_header_editor_are_interactive() {
        let mut app = App::new();
        app.screen = Screen::ServerHome;
        press(&mut app, KeyCode::Char('2'));
        assert_eq!(app.screen, Screen::ServerSettings);

        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.listen_mode, ListenMode::Custom);
        assert_eq!(app.setting_field_count(), 5);

        press(&mut app, KeyCode::Tab);
        assert_eq!(app.active_setting_field(), SettingField::CustomAddress);
        press(&mut app, KeyCode::Enter);
        assert!(app.settings_editing);
        app.custom_bind_input = Input::new(" 192.168.0.10 ".into());
        press(&mut app, KeyCode::Enter);
        assert!(!app.settings_editing);
        assert_eq!(app.custom_bind_input.value(), "192.168.0.10");

        app.settings_field = 0;
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.listen_mode, ListenMode::V6Only);
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.listen_mode, ListenMode::V4Only);
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.listen_mode, ListenMode::DualStack);
        assert_eq!(app.setting_field_count(), 6);

        app.settings_field = app.setting_field_count() - 1;
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.screen, Screen::HeaderEditor);
        for character in "region".chars() {
            press(&mut app, KeyCode::Char(character));
        }
        press(&mut app, KeyCode::Enter);
        for character in "east".chars() {
            press(&mut app, KeyCode::Char(character));
        }
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.screen, Screen::ServerSettings);
        assert_eq!(app.headers.last(), Some(&("region".into(), "east".into())));
    }

    #[test]
    fn top_level_server_pages_switch_without_escape() {
        let mut app = App::new();
        app.screen = Screen::ServerSettings;

        press(&mut app, KeyCode::Char('3'));
        assert_eq!(app.screen, Screen::Credentials);
        press(&mut app, KeyCode::Char('4'));
        assert_eq!(app.screen, Screen::ServerRunning);
        press(&mut app, KeyCode::Char('5'));
        assert_eq!(app.screen, Screen::SaveExit);
        press(&mut app, KeyCode::Char('1'));
        assert_eq!(app.screen, Screen::ServerHome);
        press(&mut app, KeyCode::Char('2'));
        assert_eq!(app.screen, Screen::ServerSettings);
    }

    #[test]
    fn credential_issue_collects_explicit_host_permissions() {
        let mut app = App::new();
        app.screen = Screen::Credentials;
        let previous = app.clients.len();
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.screen, Screen::CredentialIssue);

        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Char(' '));
        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.screen, Screen::Credentials);
        assert_eq!(app.clients.len(), previous + 1);
        assert_eq!(
            app.clients.last().map(|client| client.access.as_str()),
            Some("3 台主机")
        );
    }

    #[test]
    fn f1_opens_context_help_and_toggles_closed() {
        let mut app = App::new();
        app.screen = Screen::ServerSettings;
        press(&mut app, KeyCode::F(1));
        assert_eq!(app.modal, Some(Modal::Help));
        draw_at(&app, 80, 26);
        press(&mut app, KeyCode::F(1));
        assert_eq!(app.modal, None);
    }

    #[test]
    fn server_deployment_page_is_reachable_from_menu() {
        let mut app = App::new();
        app.screen = Screen::ServerHome;
        press(&mut app, KeyCode::Char('5'));
        assert_eq!(app.screen, Screen::SaveExit);
        assert_eq!(
            app.toast.as_ref().map(|(message, _)| message.as_str()),
            Some("配置已自动保存")
        );
        draw_at(&app, 100, 30);
    }

    #[test]
    fn bounded_and_required_inputs_are_enforced() {
        let mut input = Input::default();
        for character in "123456".chars() {
            handle_bounded_input(
                &mut input,
                KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
                5,
            );
        }
        assert_eq!(input.value(), "12345");

        assert!(validate_client_endpoint("", "45890").is_err());
        assert!(validate_client_endpoint("https://example.com", "45890").is_err());
        assert!(validate_client_endpoint("bad host", "45890").is_err());
        assert!(validate_client_endpoint("example.com", "0").is_err());
        assert!(validate_client_endpoint("example.com", "15 502").is_err());
        assert!(validate_listen_address("127.0.0.1", Some(false)).is_ok());
        assert!(validate_listen_address("::1", Some(true)).is_ok());
        assert!(validate_listen_address("127.0.0.1", Some(true)).is_err());
        assert!(validate_listen_address("::1", Some(false)).is_err());
        assert!(validate_header("Bad-Name", "value").is_err());
        assert!(validate_header("safe-name", "line\nbreak").is_err());
        assert!(validate_credential_form("", "client.credential.toml", 1).is_err());
        assert!(validate_credential_form(" \t\u{2003} ", "client.credential.toml", 1).is_err());
        assert!(validate_credential_form("portable", "client.toml", 1).is_err());
    }

    #[test]
    fn validator_boundaries_match_the_runtime_configuration() {
        assert!(parse_port("1024").is_ok());
        assert!(parse_port("65535").is_ok());
        for invalid in ["", "0", "1", "1023", "65536", "-1", " 443 ", "４４３"] {
            assert!(
                parse_port(invalid).is_err(),
                "accepted invalid port {invalid:?}"
            );
        }

        for valid in [
            "example.com",
            "example.com.",
            "127.0.0.1",
            "2001:db8::1",
            &format!("{}.com", "a".repeat(63)),
        ] {
            assert!(
                validate_client_endpoint(valid, "65535").is_ok(),
                "rejected endpoint {valid:?}"
            );
        }
        for invalid in [
            "-bad.example",
            "bad-.example",
            "two..dots",
            "host/path",
            "host:443",
            "a b",
            &format!("{}.com", "a".repeat(64)),
        ] {
            assert!(
                validate_client_endpoint(invalid, "443").is_err(),
                "accepted endpoint {invalid:?}"
            );
        }

        for valid in [
            "02-11-22-33-44-55",
            "02:11:22:33:44:55",
            "0211.2233.4455",
            "02 11 22 33 44 55",
        ] {
            assert!(valid_mac(valid), "rejected MAC {valid:?}");
        }
        for invalid in [
            "",
            "00-00-00-00-00-00",
            "ff-ff-ff-ff-ff-ff",
            "01-11-22-33-44-55",
            "02-11-22-33-44",
            "02-11-22-33-44-5z",
            "02/11/22/33/44/55",
        ] {
            assert!(!valid_mac(invalid), "accepted MAC {invalid:?}");
        }

        let valid_host = vec![
            "host-1".to_owned(),
            "主机".to_owned(),
            "02-11-22-33-44-55".to_owned(),
            "192.168.1.10".to_owned(),
            "0".to_owned(),
        ];
        assert!(validate_host_form(&valid_host).is_ok());
        for invalid_ip in [
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "8.8.8.8",
            "::ffff:127.0.0.1",
        ] {
            let mut invalid = valid_host.clone();
            invalid[3] = invalid_ip.into();
            assert!(validate_host_form(&invalid).is_err());
        }

        assert!(validate_header(&"a".repeat(MAX_HEADER_NAME_BYTES), "v").is_ok());
        assert!(validate_header(&"a".repeat(MAX_HEADER_NAME_BYTES + 1), "v").is_err());
        assert!(validate_header("a", &"v".repeat(MAX_HEADER_VALUE_BYTES)).is_ok());
        assert!(validate_header("a", &"v".repeat(MAX_HEADER_VALUE_BYTES + 1)).is_err());
        for name in ["-name", "name-", "rop-test", "x-rop-test", "two--ok?"] {
            assert!(validate_header(name, "value").is_err());
        }

        let mut app = App::new();
        app.clock_skew_input = Input::new("1".into());
        assert!(app.validate_setting_input(SettingField::ClockSkew).is_ok());
        app.clock_skew_input = Input::new("60".into());
        assert!(app.validate_setting_input(SettingField::ClockSkew).is_ok());
        for invalid in ["0", "61", "999", "x"] {
            app.clock_skew_input = Input::new(invalid.into());
            assert!(app.validate_setting_input(SettingField::ClockSkew).is_err());
        }
    }

    #[test]
    fn utf8_input_limits_are_enforced_in_bytes_without_partial_edits() {
        let mut input = Input::new("1234".into());
        assert!(!handle_bounded_input(
            &mut input,
            KeyEvent::new(KeyCode::Char('界'), KeyModifiers::NONE),
            5,
        ));
        assert_eq!(input.value(), "1234");
        assert!(handle_bounded_input(
            &mut input,
            KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE),
            5,
        ));
        assert_eq!(input.value(), "12345");
    }

    #[test]
    fn host_add_edit_delete_and_capacity_boundaries_are_safe() {
        let mut app = App::new();
        let original_count = app.hosts.len();
        app.open_host_editor(None);
        app.editor_inputs = vec![
            Input::new("LAB-WORKSTATION".into()),
            Input::new("重复主机".into()),
            Input::new("02-11-22-33-44-55".into()),
            Input::new("192.168.1.10".into()),
            Input::new("0".into()),
        ];
        app.editor_field = 4;
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen, Screen::HostEditor);
        assert_eq!(app.hosts.len(), original_count);

        app.editor_inputs[0] = Input::new("NEW-HOST".into());
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen, Screen::ServerHome);
        assert_eq!(app.hosts.len(), original_count + 1);
        assert_eq!(
            app.hosts.last().map(|host| host.id.as_str()),
            Some("new-host")
        );

        app.host_index = app.hosts.len() - 1;
        press(&mut app, KeyCode::Char('d'));
        assert_eq!(app.modal, Some(Modal::DeleteHost));
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.hosts.len(), original_count);
        assert!(app.host_index < app.hosts.len());

        let template = app.hosts[0].clone();
        app.hosts = (0..MAX_HOSTS)
            .map(|index| PreviewHost {
                id: format!("host-{index}"),
                ..template.clone()
            })
            .collect();
        app.screen = Screen::ServerHome;
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.screen, Screen::ServerHome);
        assert_eq!(app.hosts.len(), MAX_HOSTS);
    }

    #[test]
    fn setting_focus_ring_and_all_listen_modes_stay_consistent() {
        let mut app = App::new();
        app.screen = Screen::ServerSettings;
        let cases = [
            (
                ListenMode::Custom,
                vec![
                    SettingField::Mode,
                    SettingField::CustomAddress,
                    SettingField::Port,
                    SettingField::ClockSkew,
                    SettingField::Headers,
                ],
            ),
            (
                ListenMode::V6Only,
                vec![
                    SettingField::Mode,
                    SettingField::V6Address,
                    SettingField::Port,
                    SettingField::ClockSkew,
                    SettingField::Headers,
                ],
            ),
            (
                ListenMode::V4Only,
                vec![
                    SettingField::Mode,
                    SettingField::V4Address,
                    SettingField::Port,
                    SettingField::ClockSkew,
                    SettingField::Headers,
                ],
            ),
            (
                ListenMode::DualStack,
                vec![
                    SettingField::Mode,
                    SettingField::V4Address,
                    SettingField::V6Address,
                    SettingField::Port,
                    SettingField::ClockSkew,
                    SettingField::Headers,
                ],
            ),
        ];
        for (mode, fields) in cases {
            app.listen_mode = mode;
            app.settings_field = 0;
            assert_eq!(app.setting_fields(), fields);
            press(&mut app, KeyCode::BackTab);
            assert_eq!(app.active_setting_field(), SettingField::Headers);
            press(&mut app, KeyCode::Tab);
            assert_eq!(app.active_setting_field(), SettingField::Mode);
        }

        app.listen_mode = ListenMode::DualStack;
        let invalid = [
            (SettingField::V4Address, "::1", DEFAULT_V4_BIND),
            (SettingField::V6Address, "127.0.0.1", DEFAULT_V6_BIND),
            (SettingField::Port, "0", DEFAULT_SERVER_PORT),
            (SettingField::ClockSkew, "61", DEFAULT_CLOCK_SKEW),
        ];
        for (field, value, default) in invalid {
            app.set_setting_input(field, value.into());
            app.blur_setting_field(field);
            assert_eq!(app.setting_input(field).map(Input::value), Some(default));
        }
    }

    #[test]
    fn header_editor_rejects_duplicates_and_honors_collection_limit() {
        let mut app = App::new();
        app.open_header_editor(None);
        app.header_inputs = vec![Input::new("SITE-ID".into()), Input::new("other".into())];
        app.header_editor_field = 1;
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen, Screen::HeaderEditor);
        assert_eq!(app.headers.len(), 2);

        app.screen = Screen::ServerSettings;
        app.headers = (0..MAX_HEADERS)
            .map(|index| (format!("header-{index}"), "value".into()))
            .collect();
        app.settings_field = app.headers_setting_index();
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.screen, Screen::ServerSettings);
        assert_eq!(app.headers.len(), MAX_HEADERS);

        app.header_index = MAX_HEADERS - 1;
        press(&mut app, KeyCode::Char('d'));
        press(&mut app, KeyCode::Char('y'));
        assert_eq!(app.headers.len(), MAX_HEADERS - 1);
        assert!(app.header_index < app.headers.len());

        app.headers = (0..15)
            .map(|index| (format!("h{index}"), "v".repeat(256)))
            .collect();
        app.open_header_editor(None);
        app.header_inputs = vec![Input::new("overflow".into()), Input::new("v".repeat(256))];
        app.header_editor_field = 1;
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen, Screen::HeaderEditor);
        assert_eq!(app.headers.len(), 15);
    }

    #[test]
    fn credential_issue_handles_empty_hosts_selection_and_capacity() {
        let mut app = App::new();
        app.hosts.clear();
        app.screen = Screen::Credentials;
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.screen, Screen::Credentials);

        app = App::new();
        app.open_credential_issue(None);
        app.issue_field = 1;
        press(&mut app, KeyCode::Char('a'));
        assert!(app.issue_selected.iter().all(|selected| !selected));
        press(&mut app, KeyCode::Char('a'));
        assert!(app.issue_selected.iter().all(|selected| *selected));
        app.issue_selected.fill(false);
        app.issue_field = 2;
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen, Screen::CredentialIssue);

        let template = app.clients[0].clone();
        app.clients = (0..MAX_CLIENTS)
            .map(|index| PreviewClient {
                label: format!("client-{index}"),
                ..template.clone()
            })
            .collect();
        app.screen = Screen::Credentials;
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.screen, Screen::Credentials);
        assert_eq!(app.clients.len(), MAX_CLIENTS);
    }

    #[test]
    fn client_host_selection_and_empty_catalog_boundaries_are_safe() {
        let mut app = App::new();
        app.screen = Screen::ClientHosts;
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen, Screen::ClientHosts);
        press(&mut app, KeyCode::Char('a'));
        assert!(app.hosts.iter().all(|host| host.selected));
        press(&mut app, KeyCode::Char('a'));
        assert!(app.hosts.iter().all(|host| !host.selected));

        app.hosts.clear();
        app.host_index = 0;
        app.client_host_index = 0;
        for key in [
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Char(' '),
            KeyCode::Char('a'),
            KeyCode::Enter,
        ] {
            press(&mut app, key);
            assert_eq!(app.screen, Screen::ClientHosts);
            draw_at(&app, MIN_WIDTH, MIN_HEIGHT);
        }
    }

    #[test]
    fn wake_retry_resets_attempt_state_and_completion_clears_selection() {
        let mut app = App::new();
        app.hosts[0].selected = true;
        app.hosts[1].selected = true;
        app.begin_wake(2);
        app.screen = Screen::Wake;

        press(&mut app, KeyCode::Char('o'));
        assert_eq!(app.wake_online, vec![true, false]);
        press(&mut app, KeyCode::Char('t'));
        assert_eq!(app.wake_attempt, 2);
        assert_eq!(app.wake_phase, WakePhase::Retrying);
        assert_eq!(app.wake_online, vec![false, false]);
        press(&mut app, KeyCode::Char('t'));
        assert_eq!(app.wake_attempt, 2);
        press(&mut app, KeyCode::Char('o'));
        press(&mut app, KeyCode::Char('o'));
        assert_eq!(app.wake_phase, WakePhase::Complete);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen, Screen::ClientHosts);
        assert!(app.hosts.iter().all(|host| !host.selected));
        assert_eq!(app.hosts[0].state, HostState::Online);
        assert_eq!(app.hosts[1].state, HostState::Online);
    }

    #[test]
    fn tick_transitions_receipt_online_and_log_follow_boundaries() {
        let mut app = App::new();
        app.screen = Screen::ServerRunning;
        app.last_log_at = Instant::now() - Duration::from_millis(850);
        let initial_logs = app.logs.len();
        app.tick();
        assert_eq!(app.logs.len(), initial_logs + 1);

        app.log_scroll = 0;
        press(&mut app, KeyCode::PageUp);
        assert!(app.log_scroll > 0);
        press(&mut app, KeyCode::PageDown);
        assert_eq!(app.log_scroll, 0);
        press(&mut app, KeyCode::End);
        assert_eq!(app.log_scroll, 0);
        press(&mut app, KeyCode::Char('c'));
        assert!(app.logs.is_empty());

        app.hosts[0].selected = true;
        app.begin_wake(1);
        app.screen = Screen::Wake;
        app.wake_started_at = Instant::now() - Duration::from_millis(899);
        app.tick();
        assert!(!app.wake_receipt);
        app.wake_started_at = Instant::now() - Duration::from_millis(900);
        app.tick();
        assert!(app.wake_receipt);
        assert_eq!(app.wake_phase, WakePhase::Waiting);
        app.wake_started_at = Instant::now() - Duration::from_secs(4);
        app.tick();
        assert_eq!(app.wake_phase, WakePhase::Complete);
        assert_eq!(app.wake_online, vec![true]);
    }

    #[test]
    fn empty_wake_and_empty_running_log_views_are_renderable() {
        let mut app = App::new();
        app.hosts.clear();
        app.screen = Screen::ClientHosts;
        draw_at(&app, MIN_WIDTH, MIN_HEIGHT);
        app.screen = Screen::ServerRunning;
        app.logs.clear();
        draw_at(&app, MIN_WIDTH, MIN_HEIGHT);
        app.begin_wake(0);
        app.screen = Screen::Wake;
        draw_at(&app, MIN_WIDTH, MIN_HEIGHT);
        app.tick();
        assert!(app.wake_online.is_empty());
    }

    #[test]
    fn modal_confirm_cancel_and_empty_collection_paths_are_safe() {
        let mut app = App::new();
        let hosts = app.hosts.len();
        app.modal = Some(Modal::DeleteHost);
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.hosts.len(), hosts);
        assert_eq!(app.modal, None);

        app.hosts.clear();
        app.headers.clear();
        app.clients.clear();
        for modal in [
            Modal::DeleteHost,
            Modal::DeleteHeader,
            Modal::RevokeCredential,
        ] {
            app.modal = Some(modal);
            press(&mut app, KeyCode::Enter);
            assert_eq!(app.modal, None);
        }

        app.screen = Screen::ServerRunning;
        app.modal = Some(Modal::StopServer);
        press(&mut app, KeyCode::Char('y'));
        assert_eq!(app.screen, Screen::ServerHome);
    }

    #[test]
    fn maximum_collection_sizes_render_without_overflow_or_panics() {
        let mut app = App::new();
        let host = app.hosts[0].clone();
        app.hosts = (0..MAX_HOSTS)
            .map(|index| PreviewHost {
                id: format!("host-{index:02}"),
                name: "界".repeat(MAX_HOST_NAME_BYTES / 3),
                selected: index % 2 == 0,
                ..host.clone()
            })
            .collect();
        let client = app.clients[0].clone();
        app.clients = (0..MAX_CLIENTS)
            .map(|index| PreviewClient {
                label: format!("client-{index:03}"),
                ..client.clone()
            })
            .collect();
        app.headers = (0..MAX_HEADERS)
            .map(|index| {
                (
                    format!("header-{index}"),
                    "v".repeat(MAX_HEADER_VALUE_BYTES),
                )
            })
            .collect();

        for screen in [
            Screen::ServerHome,
            Screen::ServerSettings,
            Screen::Credentials,
            Screen::ClientHosts,
        ] {
            app.screen = screen;
            draw_at(&app, MIN_WIDTH, MIN_HEIGHT);
            draw_at(&app, 140, 45);
        }
        app.open_credential_issue(None);
        draw_at(&app, MIN_WIDTH, MIN_HEIGHT);
    }

    #[test]
    fn blank_defaulted_fields_restore_when_focus_moves() {
        let mut app = App::new();
        app.screen = Screen::ServerSettings;

        app.listen_mode = ListenMode::DualStack;
        app.bind_v4_input = Input::new(" \t\u{2003} ".into());
        app.settings_field = 1;
        app.settings_editing = true;
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.bind_v4_input.value(), DEFAULT_V4_BIND);

        app.server_port_input = Input::new("  1443  ".into());
        app.settings_field = 3;
        app.settings_editing = true;
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.server_port_input.value(), "1443");

        app.clock_skew_input = Input::new("\r\n\t".into());
        app.settings_field = 4;
        app.settings_editing = true;
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.clock_skew_input.value(), DEFAULT_CLOCK_SKEW);

        app.listen_mode = ListenMode::Custom;
        app.settings_field = 1;
        app.settings_editing = true;
        app.custom_bind_input = Input::new(" 192.168.0.5  ".into());
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.custom_bind_input.value(), "192.168.0.5");

        app.open_credential_issue(None);
        let default_label = app.issue_default_label.clone();
        let default_output = app.issue_default_output.clone();
        app.issue_label_input = Input::new("   ".into());
        app.issue_field = 0;
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.issue_label_input.value(), default_label);
        app.issue_output_input = Input::new("\t".into());
        app.issue_field = 2;
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.issue_output_input.value(), default_output);

        app.screen = Screen::ClientConnect;
        app.address_input = Input::new("\u{2002}".into());
        app.connect_field = 0;
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.address_input.value(), DEFAULT_CLIENT_ADDRESS);
        app.port_input = Input::new(" \t ".into());
        app.connect_field = 1;
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.port_input.value(), DEFAULT_CLIENT_PORT);
    }

    #[test]
    fn setting_enter_edits_then_validates_before_focus_moves() {
        let mut app = App::new();
        app.screen = Screen::ServerSettings;
        app.listen_mode = ListenMode::V6Only;
        app.settings_field = 1;
        assert_eq!(app.active_setting_field(), SettingField::V6Address);

        press(&mut app, KeyCode::Enter);
        assert!(app.settings_editing);
        app.bind_v6_input = Input::new("192.168.1.1".into());
        press(&mut app, KeyCode::Enter);
        assert!(app.settings_editing);
        assert_eq!(app.settings_field, 1);

        app.bind_v6_input = Input::new("2001:db8::10".into());
        press(&mut app, KeyCode::Enter);
        assert!(!app.settings_editing);
        assert_eq!(app.bind_v6_input.value(), "2001:db8::10");
        assert_eq!(app.active_setting_field(), SettingField::Port);
    }

    #[test]
    fn monochrome_mode_removes_all_buffer_colors() {
        let mut app = App::new();
        app.color_enabled = false;
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, &app))
            .expect("render succeeds");
        assert!(
            terminal
                .backend()
                .buffer()
                .content
                .iter()
                .all(|cell| cell.fg == Color::Reset && cell.bg == Color::Reset)
        );
    }
}
