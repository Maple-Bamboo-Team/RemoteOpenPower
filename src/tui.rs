// Production-only presentation and input state.  The standalone preview owns
// a separate fake-data shell and is never included in the release binary.
include!("tui_core.rs");

use crate::{client, config, protocol, security, server};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
};

struct ActualWake {
    operation_id: [u8; 16],
    boot_nonce: [u8; 16],
    catalog_version: u64,
    targets: Vec<String>,
    accepted: HashSet<String>,
    attempt: u8,
    ticket: Option<[u8; 32]>,
    receipt: bool,
    finished: bool,
    receipt_deadline: Instant,
    deadline: Instant,
}

struct ProductionApp {
    app: App,
    config_path: PathBuf,
    config: config::AppConfig,
    client_acl: Vec<config::AllowedClient>,
    client: Option<client::ClientHandle>,
    catalog_version: u64,
    wake: Option<ActualWake>,
    server_started: bool,
    server_shutdown: Option<Arc<AtomicBool>>,
    server_thread: Option<JoinHandle<()>>,
    server_log_rx: Option<Receiver<String>>,
    server_log_guard: Option<server::LogSinkGuard>,
    server_metrics: server::ServerMetrics,
}

/// Run the real terminal application.  All network and credential operations
/// are delegated to the existing client/server modules; this function only
/// coordinates their state with the TUI.
pub fn run(config_path: &Path) -> Result<(), String> {
    let capabilities = TerminalCapabilities::detect();
    if !capabilities.is_terminal {
        return Err("TUI 需要在交互式终端中运行".to_owned());
    }
    if !capabilities.ansi_supported && !cfg!(windows) {
        return Err("当前终端不支持 ANSI 光标控制，无法启动 TUI".to_owned());
    }

    install_panic_hook();
    enable_raw_mode().map_err(|error| format!("无法启用终端模式: {error}"))?;
    let _guard = TerminalGuard;
    let mut output = stdout();
    execute!(output, EnterAlternateScreen, Hide)
        .map_err(|error| format!("无法进入备用屏幕: {error}"))?;
    let backend = CrosstermBackend::new(output);
    let mut terminal =
        Terminal::new(backend).map_err(|error| format!("无法初始化 TUI: {error}"))?;
    terminal
        .clear()
        .map_err(|error| format!("无法清理终端: {error}"))?;

    let mut state = ProductionApp::new(config_path, capabilities)?;
    while !state.app.should_quit {
        state.tick();
        terminal
            .draw(|frame| render(frame, &state.app))
            .map_err(|error| format!("无法绘制 TUI: {error}"))?;
        if event::poll(TICK_RATE).map_err(|error| format!("无法读取终端事件: {error}"))? {
            let input = event::read().map_err(|error| format!("无法读取终端按键: {error}"))?;
            state.handle_event(input);
        }
    }
    state.shutdown();
    Ok(())
}

impl ProductionApp {
    fn new(config_path: &Path, capabilities: TerminalCapabilities) -> Result<Self, String> {
        let config_path = absolute_path(config_path)?;
        let initialized = config_path.is_file();
        let config =
            config::AppConfig::load_unvalidated(&config_path).map_err(|error| error.to_string())?;
        let client_acl = config.security.allowed_clients.clone();
        let mut app = App::with_capabilities(capabilities);
        app.logs.clear();
        app.toast = None;
        match client::discover_credential_path(&config_path) {
            Ok(path) => {
                app.credential_display = path.display().to_string();
                app.credential_status = "已发现凭据文件，连接时将验证".into();
            }
            Err(client::ClientError::CredentialAmbiguous { .. }) => {
                app.credential_display =
                    client::credential_path(&config_path).display().to_string();
                app.credential_status = "发现多个凭据文件，连接前必须清理".into();
            }
            Err(_) => {
                app.credential_display =
                    client::credential_path(&config_path).display().to_string();
                app.credential_status = "未发现凭据文件".into();
            }
        }
        app.connection_display = "未连接".into();
        app.config_status = if initialized {
            "已载入".into()
        } else {
            "未初始化".into()
        };
        let mut state = Self {
            app,
            config_path,
            config,
            client_acl,
            client: None,
            catalog_version: 0,
            wake: None,
            server_started: false,
            server_shutdown: None,
            server_thread: None,
            server_log_rx: None,
            server_log_guard: None,
            server_metrics: server::ServerMetrics::default(),
        };
        state.load_view_from_config();
        if !initialized {
            state.mark_uninitialized_view();
        }
        Ok(state)
    }

    fn mark_uninitialized_view(&mut self) {
        // Keep editable defaults populated, while avoiding presenting them as
        // an active deployment before the first save.
        self.app.listen_mode = ListenMode::DualStack;
        self.app.custom_bind_input = Input::new(DEFAULT_CUSTOM_BIND.into());
        self.app.bind_v4_input = Input::new(DEFAULT_V4_BIND.into());
        self.app.bind_v6_input = Input::new(DEFAULT_V6_BIND.into());
        self.app.server_port_input = Input::new(DEFAULT_SERVER_PORT.into());
        self.app.clock_skew_input = Input::new(DEFAULT_CLOCK_SKEW.into());
        self.app.address_input = Input::new(DEFAULT_CLIENT_ADDRESS.into());
        self.app.port_input = Input::new(DEFAULT_CLIENT_PORT.into());
        self.app.server_public_key_display.clear();
        self.app.deployment_summary = "尚未保存配置".into();
    }

    fn load_view_from_config(&mut self) {
        self.app.hosts = self
            .config
            .hosts
            .iter()
            .map(|host| HostRow {
                id: host.host_id(),
                name: if host.display_name.trim().is_empty() {
                    host.hostname.trim().to_owned()
                } else {
                    host.display_name.trim().to_owned()
                },
                mac: host.mac.trim().to_owned(),
                ip: host.ip.trim().to_owned(),
                wol_ipv6_interface: host.wol_ipv6_interface,
                state: HostState::Unknown,
                selected: false,
            })
            .collect();
        self.app.clients = self
            .client_acl
            .iter()
            .map(|client| {
                let access = if !self.app.hosts.is_empty()
                    && client.allowed_hosts.len() == self.app.hosts.len()
                {
                    format!("全部 {} 台主机", client.allowed_hosts.len())
                } else {
                    format!("{} 台主机", client.allowed_hosts.len())
                };
                ClientRow {
                    label: client.client_id.clone(),
                    access,
                }
            })
            .collect();
        self.app.host_index = self
            .app
            .host_index
            .min(self.app.hosts.len().saturating_sub(1));
        self.app.credential_index = self
            .app
            .credential_index
            .min(self.app.clients.len().saturating_sub(1));

        self.app.headers = self
            .config
            .security
            .custom_headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        self.app.header_index = self
            .app
            .header_index
            .min(self.app.headers.len().saturating_sub(1));
        self.app.server_port_input = Input::new(self.config.server.port.to_string());
        self.app.clock_skew_input = Input::new(
            self.config
                .security
                .clock_skew_seconds
                .clamp(1, 60)
                .to_string(),
        );
        let bind = self.config.server.bind_address.trim();
        match bind.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => {
                self.app.listen_mode = ListenMode::V4Only;
                self.app.bind_v4_input = Input::new(address.to_string());
            }
            Ok(IpAddr::V6(address)) if self.config.server.dual_stack => {
                self.app.listen_mode = ListenMode::DualStack;
                self.app.bind_v6_input = Input::new(address.to_string());
                self.app.bind_v4_input =
                    Input::new(self.config.server.bind_address_v4.trim().to_owned());
            }
            Ok(IpAddr::V6(address)) => {
                self.app.listen_mode = ListenMode::V6Only;
                self.app.bind_v6_input = Input::new(address.to_string());
            }
            Err(_) => {
                self.app.listen_mode = ListenMode::Custom;
                self.app.custom_bind_input = Input::new(bind.to_owned());
            }
        }
        self.app.address_input = Input::new(if self.config.client.address.trim().is_empty() {
            DEFAULT_CLIENT_ADDRESS.to_owned()
        } else {
            self.config.client.address.trim().to_owned()
        });
        self.app.port_input = Input::new(if self.config.client.port == 0 {
            DEFAULT_CLIENT_PORT.to_owned()
        } else {
            self.config.client.port.to_string()
        });
        self.app.server_public_key_display = self
            .config
            .security
            .server_static_public_key
            .strip_prefix("hex:")
            .unwrap_or(&self.config.security.server_static_public_key)
            .to_owned();
        self.app.deployment_summary = format!("配置文件  {}", self.config_path.display());
    }

    fn handle_event(&mut self, input: Event) {
        let Event::Key(key) = input else {
            return;
        };
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            return;
        }

        if self.app.modal == Some(Modal::StopServer) {
            match key.code {
                KeyCode::Enter | KeyCode::Char('y') if key.modifiers.is_empty() => {
                    self.app.modal = None;
                    self.stop_server();
                }
                KeyCode::Esc | KeyCode::Char('n') if key.modifiers.is_empty() => {
                    self.app.modal = None;
                }
                _ => {}
            }
            return;
        }

        if self.app.modal.is_some() {
            let before_screen = self.app.screen;
            let before_modal = self.app.modal;
            self.app.handle_event(Event::Key(key));
            self.persist_after_ui_change(before_screen, before_modal, key);
            return;
        }

        if self.handle_real_action(key) {
            return;
        }

        let before_screen = self.app.screen;
        let before_modal = self.app.modal;
        self.app.handle_event(Event::Key(key));
        self.persist_after_ui_change(before_screen, before_modal, key);
    }

    fn handle_real_action(&mut self, key: KeyEvent) -> bool {
        let plain = key.modifiers.is_empty();

        // Keep page switching available from every top-level server page and
        // attach persistence/deployment side effects to those transitions.
        if plain
            && matches!(
                self.app.screen,
                Screen::ServerSettings
                    | Screen::Credentials
                    | Screen::ServerRunning
                    | Screen::SaveExit
            )
        {
            let before = self.app.screen;
            if before == Screen::Credentials && key.code == KeyCode::Char('4') {
                // The credentials page historically used 4 as the immediate
                // start shortcut. Keep it outside page navigation so a
                // failed start does not leave the UI claiming the service is
                // running.
                self.start_server();
                return true;
            }
            if self.app.navigate_server_page(key) {
                if self.app.screen == Screen::SaveExit || before == Screen::ServerSettings {
                    self.persist_server_with_notice();
                }
                return true;
            }
        }

        match self.app.screen {
            Screen::ServerHome
                if plain && matches!(key.code, KeyCode::Char('4') | KeyCode::Char('r')) =>
            {
                self.start_server();
                true
            }
            Screen::Credentials
                if plain && matches!(key.code, KeyCode::Char('4') | KeyCode::Char('r')) =>
            {
                self.start_server();
                true
            }
            Screen::ServerHome
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('s') =>
            {
                self.persist_server_with_notice();
                true
            }
            Screen::ServerSettings
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('s') =>
            {
                if self.app.settings_editing {
                    self.app
                        .notify("当前设置尚未确认，请先按 Enter 确认".into());
                } else {
                    self.persist_server_with_notice();
                }
                true
            }
            Screen::CredentialIssue
                if (key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('s'))
                    || (plain && key.code == KeyCode::Enter && self.app.issue_field == 2) =>
            {
                self.issue_credential();
                true
            }
            Screen::Credentials
                if plain
                    && matches!(key.code, KeyCode::Char('e') | KeyCode::Enter)
                    && !self.app.clients.is_empty() =>
            {
                self.open_credential_edit();
                true
            }
            Screen::ClientConnect if plain && key.code == KeyCode::Enter => {
                self.connect_client();
                true
            }
            Screen::ClientHosts if plain && key.code == KeyCode::Char('r') => {
                if self.app.connection_phase != ClientConnectionPhase::Connected {
                    self.app.notify("安全连接尚未建立，客户端会自动重试".into());
                } else if let Some(handle) = self.client.as_ref() {
                    let _ = handle.commands.send(client::ClientCommand::Refresh);
                    self.app.notify("正在刷新主机目录".into());
                } else {
                    self.app.notify("尚未建立安全连接".into());
                }
                true
            }
            Screen::ClientHosts if plain && key.code == KeyCode::Enter => {
                self.start_wake();
                true
            }
            Screen::ClientHosts
                if plain && matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) =>
            {
                self.shutdown_client();
                self.app.screen = Screen::ClientConnect;
                true
            }
            Screen::Wake if plain && key.code == KeyCode::Enter => {
                if self.app.wake_phase == WakePhase::Complete {
                    self.app.handle_event(Event::Key(key));
                    self.wake = None;
                }
                true
            }
            Screen::Wake
                if plain && matches!(key.code, KeyCode::Char('o') | KeyCode::Char('t')) =>
            {
                self.app.notify("正在等待服务端回执和目标状态".into());
                true
            }
            Screen::Wake if plain && matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) => {
                self.wake = None;
                self.app.screen = Screen::ClientHosts;
                self.app
                    .notify("已停止等待显示；服务端操作不会自动重发".into());
                true
            }
            Screen::SaveExit
                if plain && matches!(key.code, KeyCode::Char('s') | KeyCode::Enter) =>
            {
                self.persist_server_with_notice();
                true
            }
            _ => false,
        }
    }

    fn persist_after_ui_change(
        &mut self,
        before_screen: Screen,
        before_modal: Option<Modal>,
        key: KeyEvent,
    ) {
        let changed_server_data = (before_screen == Screen::HostEditor
            && self.app.screen == Screen::ServerHome)
            || (before_screen == Screen::HeaderEditor && self.app.screen == Screen::ServerSettings)
            || (before_screen == Screen::ServerSettings && self.app.screen == Screen::ServerHome)
            || (before_modal == Some(Modal::DeleteHost)
                && self.app.modal.is_none()
                && self.app.screen == Screen::ServerHome)
            || (before_modal == Some(Modal::RevokeCredential)
                && self.app.modal.is_none()
                && self.app.screen == Screen::Credentials);
        let entered_deployment =
            self.app.screen == Screen::SaveExit && before_screen != Screen::SaveExit;
        if before_modal == Some(Modal::RevokeCredential)
            && self.app.modal.is_none()
            && self.app.screen == Screen::Credentials
        {
            self.client_acl.retain(|client| {
                self.app
                    .clients
                    .iter()
                    .any(|view| view.label.eq_ignore_ascii_case(&client.client_id))
            });
        }
        if changed_server_data
            || entered_deployment
            || (key.code == KeyCode::Char('q') && self.app.screen == Screen::SaveExit)
        {
            self.persist_server_with_notice();
        }
    }

    fn sync_server_from_view(&mut self) -> Result<usize, String> {
        if self.has_client_settings() {
            return Err("当前配置包含终端模式设置，请使用独立的服务端配置文件".to_owned());
        }
        self.config.ensure_secret();
        self.config
            .ensure_server_identity_material()
            .map_err(|error| error.to_string())?;
        self.config.client = config::ClientConfig::default();
        let previous_hosts = self.config.hosts.clone();
        self.config.hosts = self
            .app
            .hosts
            .iter()
            .map(|host| {
                let host_id = host.id.trim().to_owned();
                let previous = previous_hosts
                    .iter()
                    .find(|candidate| candidate.host_id() == host_id.to_ascii_lowercase());
                let display_name = host.name.trim();
                config::HostConfig {
                    hostname: host_id,
                    display_name: if !display_name.is_empty()
                        && !display_name.eq_ignore_ascii_case(host.id.trim())
                    {
                        display_name.to_owned()
                    } else {
                        String::new()
                    },
                    mac: host.mac.trim().to_owned(),
                    ip: host.ip.trim().to_owned(),
                    wol_port: previous.map_or(9, |value| value.wol_port),
                    probe_timeout_ms: previous.map_or(1_000, |value| value.probe_timeout_ms),
                    probe_port: previous.map_or(0, |value| value.probe_port),
                    wol_ipv6_interface: host.wol_ipv6_interface,
                }
            })
            .collect();
        let removed_permissions = self.reconcile_client_permissions();
        self.config.security.custom_headers = self
            .app
            .headers
            .iter()
            .cloned()
            .collect::<std::collections::BTreeMap<_, _>>();
        self.config.server.port = parse_port(self.app.server_port_input.value().trim())?;
        self.config.security.clock_skew_seconds = self
            .app
            .clock_skew_input
            .value()
            .trim()
            .parse::<u64>()
            .map_err(|_| "时钟容差必须是 1 到 60 的整数".to_owned())?;
        if !(1..=60).contains(&self.config.security.clock_skew_seconds) {
            return Err("时钟容差必须在 1 到 60 秒之间".to_owned());
        }
        match self.app.listen_mode {
            ListenMode::Custom => {
                let value = self.app.custom_bind_input.value().trim();
                validate_listen_address(value, None)?;
                self.config.server.bind_address = value.to_owned();
                self.config.server.dual_stack = false;
            }
            ListenMode::V4Only => {
                let value = self.app.bind_v4_input.value().trim();
                validate_listen_address(value, Some(false))?;
                self.config.server.bind_address = value.to_owned();
                self.config.server.dual_stack = false;
            }
            ListenMode::V6Only => {
                let value = self.app.bind_v6_input.value().trim();
                validate_listen_address(value, Some(true))?;
                self.config.server.bind_address = value.to_owned();
                self.config.server.dual_stack = false;
            }
            ListenMode::DualStack => {
                let value_v6 = self.app.bind_v6_input.value().trim();
                validate_listen_address(value_v6, Some(true))?;
                let value_v4 = self.app.bind_v4_input.value().trim();
                validate_listen_address(value_v4, Some(false))?;
                self.config.server.bind_address = value_v6.to_owned();
                self.config.server.bind_address_v4 = value_v4.to_owned();
                self.config.server.dual_stack = true;
            }
        }
        self.config
            .save(&self.config_path)
            .map_err(|error| error.to_string())?;
        self.app.server_public_key_display = self
            .config
            .security
            .server_static_public_key
            .strip_prefix("hex:")
            .unwrap_or(&self.config.security.server_static_public_key)
            .to_owned();
        Ok(removed_permissions)
    }

    fn reconcile_client_permissions(&mut self) -> usize {
        let valid_host_ids = self
            .app
            .hosts
            .iter()
            .map(|host| host.id.trim().to_ascii_lowercase())
            .collect::<HashSet<_>>();
        let removed_permissions =
            reconcile_client_host_permissions(&mut self.client_acl, &valid_host_ids);
        for view in &mut self.app.clients {
            if let Some(client) = self
                .client_acl
                .iter()
                .find(|client| client.client_id.eq_ignore_ascii_case(&view.label))
            {
                view.access = if !self.app.hosts.is_empty()
                    && client.allowed_hosts.len() == self.app.hosts.len()
                {
                    format!("全部 {} 台主机", client.allowed_hosts.len())
                } else {
                    format!("{} 台主机", client.allowed_hosts.len())
                };
            }
        }
        self.config.security.allowed_clients = self.client_acl.clone();
        removed_permissions
    }

    fn persist_server_with_notice(&mut self) {
        match self.sync_server_from_view() {
            Ok(removed_permissions) => {
                self.app.deployment_summary = format!("配置已保存  {}", self.config_path.display());
                self.app.config_status = "已保存".into();
                if removed_permissions == 0 {
                    self.app.notify("配置已保存".into());
                } else {
                    self.app.notify(format!(
                        "配置已保存，已移除 {removed_permissions} 条失效的主机授权"
                    ));
                }
                if self.app.screen == Screen::SaveExit {
                    self.build_deployment_info();
                }
            }
            Err(error) => self.app.notify(format!("保存失败: {error}")),
        }
    }

    fn connect_client(&mut self) {
        if self.has_server_settings() {
            self.app
                .notify("当前配置包含服务端密钥或主机目录，请使用独立的终端配置文件".into());
            return;
        }
        self.app.normalize_connect_field(0);
        self.app.normalize_connect_field(1);
        let address = self.app.address_input.value().trim().to_owned();
        let port = self.app.port_input.value().trim().to_owned();
        if let Err(error) = validate_client_endpoint(&address, &port) {
            self.app.notify(error);
            return;
        }
        let port_number = match parse_port(&port) {
            Ok(value) => value,
            Err(error) => {
                self.app.notify(error);
                return;
            }
        };
        let mut settings = self.config.clone();
        settings.client.address = address;
        settings.client.port = port_number;
        if let Err(error) = settings.save_client_settings(&self.config_path) {
            self.app.notify(format!("无法保存客户端设置: {error}"));
            return;
        }
        match client::load_runtime(&self.config_path, None, None) {
            Ok(runtime) => {
                self.shutdown_client();
                self.client = Some(client::spawn_client(runtime));
                self.config = settings;
                self.catalog_version = 0;
                self.app.hosts.clear();
                self.app.client_host_index = 0;
                self.app.screen = Screen::ClientHosts;
                self.app.connection_phase = ClientConnectionPhase::Connecting;
                self.app.connection_attempt = 1;
                self.app.connection_display = "第 1 次尝试".into();
                self.app.connection_error_code = None;
                self.app.connection_error_message = None;
                self.app.connection_retry_at = None;
                self.app.credential_status = "凭据已验证，正在连接".into();
                self.app.notify("正在建立安全连接".into());
            }
            Err(error) => self
                .app
                .notify(format!("客户端凭据或连接设置无效: {error}")),
        }
    }

    fn start_wake(&mut self) {
        if self.app.connection_phase != ClientConnectionPhase::Connected {
            self.app.notify("安全连接尚未建立，未发送唤醒请求".into());
            return;
        }
        let Some(handle) = self.client.as_ref() else {
            self.app.notify("尚未建立安全连接".into());
            return;
        };
        let targets = self
            .app
            .hosts
            .iter()
            .filter(|host| host.selected)
            .map(|host| host.id.clone())
            .collect::<Vec<_>>();
        if targets.is_empty() {
            self.app.notify("请先用 Space 选择至少一台主机".into());
            return;
        }
        if self.catalog_version == 0 {
            self.app.notify("主机目录尚未就绪，请稍候".into());
            return;
        }
        let operation_id = client::random_id();
        let boot_nonce = client::random_id();
        if handle
            .commands
            .send(client::ClientCommand::Wake {
                host_ids: targets.clone(),
                catalog_version: self.catalog_version,
                operation_id,
                boot_nonce,
                attempt: 1,
                retry_ticket: None,
            })
            .is_err()
        {
            self.app.notify("客户端 actor 已退出".into());
            return;
        }
        let now = Instant::now();
        self.app.begin_wake(targets.len());
        self.app.screen = Screen::Wake;
        self.wake = Some(ActualWake {
            operation_id,
            boot_nonce,
            catalog_version: self.catalog_version,
            targets,
            accepted: HashSet::new(),
            attempt: 1,
            ticket: None,
            receipt: false,
            finished: false,
            receipt_deadline: now + Duration::from_secs(15),
            deadline: now + Duration::from_secs(60),
        });
    }

    fn issue_credential(&mut self) {
        self.reconcile_client_permissions();
        let label = self.app.issue_label_input.value().trim().to_owned();
        let output = self.app.issue_output_input.value().trim().to_owned();
        let allowed_hosts = self
            .app
            .hosts
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                self.app
                    .issue_selected
                    .get(*index)
                    .copied()
                    .unwrap_or(false)
            })
            .map(|(_, host)| host.id.clone())
            .collect::<Vec<_>>();
        if let Err(error) = validate_credential_form(&label, &output, allowed_hosts.len()) {
            self.app.notify(error);
            return;
        }
        if let Some(index) = self.app.issue_edit_index {
            if index >= self.client_acl.len() {
                self.app.notify("凭据选择已失效，请返回后重试".into());
                self.app.screen = Screen::Credentials;
                return;
            }
            let mut candidate = self.config.clone();
            candidate.security.allowed_clients[index].allowed_hosts = allowed_hosts;
            if let Err(error) = candidate.save(&self.config_path) {
                self.app.notify(format!("无法保存客户端权限: {error}"));
                return;
            }
            self.config = candidate;
            self.client_acl = self.config.security.allowed_clients.clone();
            self.load_view_from_config();
            self.app.credential_index = index.min(self.app.clients.len().saturating_sub(1));
            self.app.screen = Screen::Credentials;
            self.app
                .notify("客户端主机权限已更新，便携私钥保持不变".into());
            return;
        }
        if self.client_acl.len() >= MAX_CLIENTS {
            self.app
                .notify(format!("客户端凭据最多允许 {MAX_CLIENTS} 份"));
            return;
        }
        if let Err(error) = self.config.ensure_server_identity_material() {
            self.app.notify(format!("服务端身份无效: {error}"));
            return;
        }
        self.config.ensure_secret();
        let (static_private_key, static_public_key) = config::generate_identity_pair();
        let public_key = match config::decode_key(&static_public_key) {
            Ok(value) => value,
            Err(error) => {
                self.app.notify(format!("客户端身份生成失败: {error}"));
                return;
            }
        };
        let client_id = security::client_id_from_public_key(&public_key);
        if self
            .client_acl
            .iter()
            .any(|client| client.client_id.eq_ignore_ascii_case(&client_id))
        {
            self.app.notify("该客户端身份已经存在，请重新签发".into());
            return;
        }
        let output_path = self.resolve_credential_output(&output);
        if output_path == self.config_path {
            self.app.notify("凭据文件不能覆盖服务端配置".into());
            return;
        }
        if output_path.exists() {
            self.app.notify("凭据输出文件已存在，请更换文件名".into());
            return;
        }
        let bundle = client::CredentialBundle {
            version: 1,
            client_id: client_id.clone(),
            device_label: label,
            shared_secret: self.config.security.shared_secret.clone(),
            static_private_key,
            static_public_key: static_public_key.clone(),
            pinned_server_static_key: self.config.security.server_static_public_key.clone(),
            custom_headers: self.config.security.custom_headers.clone(),
        };
        if let Err(error) = client::save_credential_bundle(&output_path, &bundle) {
            self.app.notify(format!("无法写入凭据: {error}"));
            return;
        }
        let mut candidate = self.config.clone();
        candidate
            .security
            .allowed_clients
            .push(config::AllowedClient {
                client_id: client_id.clone(),
                static_public_key,
                allowed_hosts,
            });
        if let Err(error) = candidate.save(&self.config_path) {
            let _ = std::fs::remove_file(&output_path);
            self.app.notify(format!("无法保存服务端 ACL: {error}"));
            return;
        }
        self.config = candidate;
        self.client_acl = self.config.security.allowed_clients.clone();
        self.load_view_from_config();
        self.app.credential_index = self.app.clients.len().saturating_sub(1);
        self.app.screen = Screen::Credentials;
        self.app
            .notify(format!("凭据已签发: {}", output_path.display()));
    }

    fn open_credential_edit(&mut self) {
        let index = self.app.credential_index;
        let Some(client) = self.client_acl.get(index) else {
            self.app.notify("没有可编辑的客户端凭据".into());
            return;
        };
        self.app.open_credential_issue(Some(index));
        let allowed = client
            .allowed_hosts
            .iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .collect::<HashSet<_>>();
        self.app.issue_selected = self
            .app
            .hosts
            .iter()
            .map(|host| allowed.contains(&host.id))
            .collect();
    }

    fn resolve_credential_output(&self, value: &str) -> PathBuf {
        let path = Path::new(value);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.config_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .join(path)
        }
    }

    fn start_server(&mut self) {
        self.refresh_server_state();
        if self.server_started {
            self.app.screen = Screen::ServerRunning;
            self.app.notify("服务已在后台运行".into());
            return;
        }
        if let Err(error) = self.sync_server_from_view() {
            self.app.notify(format!("启动前保存失败: {error}"));
            return;
        }
        self.server_log_guard.take();
        let (sender, receiver) = mpsc::channel();
        let guard = server::install_log_sink(sender);
        let path = self.config_path.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_thread = Arc::clone(&shutdown);
        let metrics = server::ServerMetrics::default();
        let metrics_for_thread = metrics.clone();
        let spawn_result = thread::Builder::new()
            .name("rop-server".into())
            .spawn(move || {
                let _ = server::run_server_with_shutdown(
                    &path,
                    None,
                    None,
                    shutdown_for_thread,
                    metrics_for_thread,
                );
            });
        let server_thread = match spawn_result {
            Ok(thread) => thread,
            Err(error) => {
                self.app.notify(format!("无法启动服务线程: {error}"));
                drop(guard);
                return;
            }
        };
        self.server_shutdown = Some(shutdown);
        self.server_thread = Some(server_thread);
        self.server_log_rx = Some(receiver);
        self.server_log_guard = Some(guard);
        self.server_metrics = metrics;
        self.server_started = true;
        self.app.started_at = Instant::now();
        self.app.logs.clear();
        self.app.screen = Screen::ServerRunning;
        self.app.server_phase = ServerPhase::Starting;
        self.app.notify("正在启动服务监听".into());
    }

    fn has_server_settings(&self) -> bool {
        !self
            .config
            .security
            .server_static_private_key
            .trim()
            .is_empty()
            || !self
                .config
                .security
                .server_static_public_key
                .trim()
                .is_empty()
            || !self.config.hosts.is_empty()
            || !self.config.security.allowed_clients.is_empty()
    }

    fn has_client_settings(&self) -> bool {
        !self.config.client.address.trim().is_empty()
            || !self.config.client.client_id.trim().is_empty()
            || !self.config.client.static_private_key.trim().is_empty()
            || !self.config.client.static_public_key.trim().is_empty()
            || !self
                .config
                .client
                .pinned_server_static_key
                .trim()
                .is_empty()
    }

    fn stop_server(&mut self) {
        if let Some(shutdown) = self.server_shutdown.take() {
            shutdown.store(true, Ordering::Release);
        }
        if let Some(thread) = self.server_thread.take() {
            let _ = thread.join();
        }
        self.server_started = false;
        self.app.server_phase = ServerPhase::Stopped;
        self.app.active_connections = 0;
        self.server_metrics = server::ServerMetrics::default();
        self.app.screen = Screen::ServerHome;
        self.app.notify("服务已停止".into());
    }

    fn build_deployment_info(&mut self) {
        self.app.deployment_lines = deployment_lines(&self.config_path);
    }

    fn drain_server_logs(&mut self) {
        let Some(receiver) = self.server_log_rx.as_ref() else {
            return;
        };
        let mut messages = Vec::new();
        while let Ok(message) = receiver.try_recv() {
            messages.push(message);
        }
        for message in messages {
            let (level, text) = message.split_once(' ').map_or(
                (LogLevel::Info, message.as_str()),
                |(level, text)| {
                    let level = match level {
                        "WARN" => LogLevel::Warn,
                        "ERROR" => LogLevel::Error,
                        "FATAL" => LogLevel::Fatal,
                        _ => LogLevel::Info,
                    };
                    (level, text)
                },
            );
            if level == LogLevel::Fatal || text.starts_with("listener bind failed") {
                self.app.server_phase = ServerPhase::Failed;
            }
            self.app.logs.push_back(LogEntry {
                clock: local_clock_hm(),
                level,
                message: text.to_owned(),
            });
            while self.app.logs.len() > LOG_LIMIT {
                self.app.logs.pop_front();
            }
        }
    }

    fn drain_client_events(&mut self) {
        loop {
            let event = self
                .client
                .as_ref()
                .and_then(|handle| handle.events.try_recv().ok());
            let Some(event) = event else {
                break;
            };
            self.apply_client_event(event);
        }
    }

    fn apply_client_event(&mut self, event: client::ClientEvent) {
        match event {
            client::ClientEvent::Connecting { attempt } => {
                if self.wake.is_none() {
                    self.catalog_version = 0;
                    self.app.hosts.clear();
                    self.app.client_host_index = 0;
                }
                self.app.connection_phase = ClientConnectionPhase::Connecting;
                self.app.connection_attempt = attempt;
                self.app.connection_display = format!("第 {attempt} 次尝试");
                self.app.connection_retry_at = None;
            }
            client::ClientEvent::ConnectionFailed {
                attempt,
                code,
                message,
                retry_after,
            } => {
                self.app.connection_phase = ClientConnectionPhase::RetryWaiting;
                self.app.connection_attempt = attempt;
                self.app.connection_display = format!("第 {attempt} 次失败");
                self.app.connection_error_code = Some(code.as_str().to_owned());
                self.app.connection_error_message = Some(single_line_error(&message));
                self.app.connection_retry_at = Some(Instant::now() + retry_after);
            }
            client::ClientEvent::Connected { peer, .. } => {
                self.app.connection_phase = ClientConnectionPhase::Connected;
                self.app.connection_display = format!("{}  已认证", peer);
                self.app.connection_error_code = None;
                self.app.connection_error_message = None;
                self.app.connection_retry_at = None;
                self.app.credential_status = "凭据与服务端身份已验证".into();
                self.app.notify("安全连接已建立".into());
                self.resume_wake_after_reconnect();
            }
            client::ClientEvent::Hosts {
                catalog_version,
                hosts,
            } => {
                if self.wake.is_some() && self.app.screen == Screen::Wake {
                    return;
                }
                self.catalog_version = catalog_version;
                self.app.hosts = hosts
                    .into_iter()
                    .map(|host| {
                        let host_id = host.host_id;
                        HostRow {
                            id: host_id.clone(),
                            name: host_id,
                            mac: String::new(),
                            ip: String::new(),
                            wol_ipv6_interface: 0,
                            state: HostState::Unknown,
                            selected: false,
                        }
                    })
                    .collect();
                self.app.client_host_index = 0;
                self.app
                    .notify(format!("已载入 {} 台主机", self.app.hosts.len()));
            }
            client::ClientEvent::Statuses { statuses, .. } => {
                for status in statuses {
                    if let Some(host) = self
                        .app
                        .hosts
                        .iter_mut()
                        .find(|host| host.id == status.host_id)
                    {
                        host.state = match status.state {
                            protocol::HostState::Online | protocol::HostState::Succeeded => {
                                HostState::Online
                            }
                            protocol::HostState::Offline | protocol::HostState::Failed => {
                                HostState::Offline
                            }
                            protocol::HostState::Waking => HostState::Waking,
                            protocol::HostState::Unknown => HostState::Unknown,
                        };
                    }
                }
            }
            client::ClientEvent::CommandExecuted {
                operation_id,
                attempt,
                retry_ticket,
                deadline_ms,
                results,
            } => {
                let Some(wake) = self.wake.as_mut() else {
                    return;
                };
                if wake.operation_id != operation_id || wake.attempt != attempt {
                    return;
                }
                wake.receipt = true;
                wake.ticket = Some(retry_ticket);
                wake.accepted = results
                    .iter()
                    .filter(|result| result.accepted)
                    .map(|result| result.host_id.clone())
                    .collect();
                let now = Instant::now();
                wake.deadline =
                    now + Duration::from_millis(deadline_ms.saturating_sub(client::now_ms()));
                self.app.wake_receipt = true;
                self.app.wake_phase = WakePhase::Waiting;
                self.app.wake_deadline = wake.deadline;
                self.app.wake_started_at = wake
                    .deadline
                    .checked_sub(Duration::from_secs(60))
                    .unwrap_or(now);
                for result in results {
                    if result.accepted
                        && let Some(host) = self
                            .app
                            .hosts
                            .iter_mut()
                            .find(|host| host.id == result.host_id)
                    {
                        host.state = HostState::Waking;
                    }
                }
                if wake.accepted.is_empty() {
                    self.app.notify("服务端拒绝了全部目标".into());
                    self.app.screen = Screen::ClientHosts;
                    self.wake = None;
                }
            }
            client::ClientEvent::TargetOnline {
                operation_id,
                attempt,
                host_id,
                ..
            } => {
                let Some(wake) = self.wake.as_ref() else {
                    return;
                };
                if wake.operation_id != operation_id
                    || wake.attempt != attempt
                    || !wake.accepted.contains(&host_id)
                {
                    return;
                }
                if let Some(index) = wake.targets.iter().position(|target| target == &host_id)
                    && let Some(online) = self.app.wake_online.get_mut(index)
                {
                    *online = true;
                }
                if let Some(host) = self.app.hosts.iter_mut().find(|host| host.id == host_id) {
                    host.state = HostState::Online;
                }
                if wake.accepted.iter().all(|target| {
                    wake.targets
                        .iter()
                        .position(|item| item == target)
                        .is_some_and(|index| {
                            self.app.wake_online.get(index).copied().unwrap_or(false)
                        })
                }) {
                    self.app.wake_phase = WakePhase::Complete;
                    if let Some(wake) = self.wake.as_mut() {
                        wake.finished = true;
                    }
                }
            }
            client::ClientEvent::Error(error) => self.app.notify(error),
            client::ClientEvent::Disconnected => {
                self.client = None;
                self.wake = None;
                if matches!(self.app.screen, Screen::ClientHosts | Screen::Wake) {
                    self.app.screen = Screen::ClientConnect;
                }
                self.app.connection_phase = ClientConnectionPhase::Disconnected;
                self.app.connection_display = "连接已断开".into();
                self.app.connection_retry_at = None;
                self.app.notify("客户端连接已断开".into());
            }
        }
    }

    fn tick_wake(&mut self) {
        let Some(wake) = self.wake.as_mut() else {
            return;
        };
        if wake.finished || self.app.screen != Screen::Wake {
            return;
        }
        if self.app.connection_phase != ClientConnectionPhase::Connected {
            return;
        }
        let now = Instant::now();
        if !wake.receipt && now >= wake.receipt_deadline {
            self.app.notify("等待服务端执行回执超时".into());
            self.app.screen = Screen::ClientHosts;
            self.wake = None;
            return;
        }
        if wake.receipt && now >= wake.deadline {
            if wake.attempt == 1 {
                let Some(ticket) = wake.ticket else {
                    self.app.notify("服务端未返回重试票据".into());
                    self.app.screen = Screen::ClientHosts;
                    self.wake = None;
                    return;
                };
                let Some(handle) = self.client.as_ref() else {
                    self.app.notify("客户端连接已断开，无法申请重发".into());
                    self.app.screen = Screen::ClientHosts;
                    self.wake = None;
                    return;
                };
                if handle
                    .commands
                    .send(client::ClientCommand::Wake {
                        host_ids: wake.targets.clone(),
                        catalog_version: wake.catalog_version,
                        operation_id: wake.operation_id,
                        boot_nonce: wake.boot_nonce,
                        attempt: 2,
                        retry_ticket: Some(ticket),
                    })
                    .is_err()
                {
                    self.app.notify("客户端 actor 已退出".into());
                    self.app.screen = Screen::ClientHosts;
                    self.wake = None;
                    return;
                }
                wake.attempt = 2;
                wake.receipt = false;
                wake.accepted.clear();
                wake.receipt_deadline = now + Duration::from_secs(15);
                wake.deadline = now + Duration::from_secs(60);
                self.app.wake_attempt = 2;
                self.app.wake_receipt = false;
                self.app.wake_phase = WakePhase::Retrying;
                self.app.wake_started_at = now;
                self.app.wake_deadline = wake.deadline;
                self.app.wake_online.fill(false);
                self.app
                    .notify("一分钟未全部上线，正在申请一次授权重发".into());
            } else {
                self.app.notify("两次等待均已超时".into());
                self.app.screen = Screen::ClientHosts;
                self.wake = None;
            }
        }
    }

    fn resume_wake_after_reconnect(&mut self) {
        let Some(wake) = self.wake.as_ref().filter(|wake| !wake.finished) else {
            return;
        };
        let attempt = wake.attempt;
        let retry_ticket = if wake.attempt == 2 {
            let Some(ticket) = wake.ticket else {
                self.app.notify("重连后缺少第二次尝试票据".into());
                return;
            };
            Some(ticket)
        } else {
            None
        };
        let command = client::ClientCommand::Wake {
            host_ids: wake.targets.clone(),
            catalog_version: wake.catalog_version,
            operation_id: wake.operation_id,
            boot_nonce: wake.boot_nonce,
            attempt,
            retry_ticket,
        };
        let Some(handle) = self.client.as_ref() else {
            return;
        };
        if handle.commands.send(command).is_err() {
            self.app.notify("安全重连后无法恢复唤醒操作".into());
            return;
        }
        let now = Instant::now();
        if let Some(wake) = self.wake.as_mut() {
            wake.receipt = false;
            wake.receipt_deadline = now + Duration::from_secs(15);
        }
        self.app.wake_receipt = false;
        self.app.wake_attempt = attempt;
        self.app.wake_phase = if attempt == 2 {
            WakePhase::Retrying
        } else {
            WakePhase::Sending
        };
        self.app.notify("安全连接已恢复，正在恢复唤醒状态".into());
    }

    fn tick(&mut self) {
        self.app.active_connections = self.server_metrics.active_connections();
        self.app.tick();
        self.drain_server_logs();
        self.refresh_server_state();
        self.drain_client_events();
        self.tick_wake();
    }

    fn refresh_server_state(&mut self) {
        if self.server_started && self.server_metrics.is_listening() {
            self.app.server_phase = ServerPhase::Running;
        }
        let finished = self
            .server_thread
            .as_ref()
            .is_some_and(JoinHandle::is_finished);
        if !finished {
            return;
        }
        if let Some(thread) = self.server_thread.take() {
            let _ = thread.join();
        }
        self.server_started = false;
        self.server_shutdown = None;
        self.app.active_connections = 0;
        if self.app.server_phase != ServerPhase::Stopped {
            self.app.server_phase = ServerPhase::Failed;
        }
    }

    fn shutdown_client(&mut self) {
        if let Some(handle) = self.client.take() {
            let _ = handle.commands.send(client::ClientCommand::Shutdown);
        }
        self.wake = None;
        self.app.connection_phase = ClientConnectionPhase::Disconnected;
        self.app.connection_attempt = 0;
        self.app.connection_display = "未连接".into();
        self.app.connection_error_code = None;
        self.app.connection_error_message = None;
        self.app.connection_retry_at = None;
    }

    fn shutdown(&mut self) {
        self.shutdown_client();
        self.stop_server();
        self.server_log_guard = None;
    }
}

fn reconcile_client_host_permissions(
    clients: &mut [config::AllowedClient],
    valid_host_ids: &HashSet<String>,
) -> usize {
    let mut removed = 0;
    for client in clients {
        let previous = std::mem::take(&mut client.allowed_hosts);
        let mut seen = HashSet::with_capacity(previous.len());
        for host_id in previous {
            let normalized = host_id.trim().to_ascii_lowercase();
            if valid_host_ids.contains(&normalized) && seen.insert(normalized.clone()) {
                client.allowed_hosts.push(normalized);
            } else {
                removed += 1;
            }
        }
    }
    removed
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(|error| format!("无法解析配置路径: {error}"))
    }
}

fn single_line_error(message: &str) -> String {
    let normalized = message.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut characters = normalized.chars();
    let shortened = characters.by_ref().take(240).collect::<String>();
    if characters.next().is_some() {
        format!("{shortened}...")
    } else {
        shortened
    }
}

fn deployment_lines(config_path: &Path) -> Vec<String> {
    let config = config_path.display().to_string();
    #[cfg(windows)]
    {
        let executable = std::env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "RemoteOpenPower.exe".into());
        vec![
            "Windows 前台启动指令".into(),
            format!("\"{executable}\" --server --config \"{config}\""),
            "配置与 PSK 保存在 TOML，不放入命令行或日志。".into(),
        ]
    }
    #[cfg(target_os = "linux")]
    {
        let executable = std::env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "./RemoteOpenPower".into());
        return vec![
            "Linux systemd 部署".into(),
            format!(
                "sudo install -Dm0755 {executable} /usr/local/bin/remote-open-power"
            ),
            "sudo install -d -m0750 -o root -g remote-open-power /etc/remote-open-power".into(),
            format!(
                "sudo install -m0640 -o root -g remote-open-power {config} /etc/remote-open-power/remote-open-power.toml"
            ),
            "将下面内容保存为 /etc/systemd/system/remote-open-power.service".into(),
            "[Unit]".into(),
            "Description=RemoteOpenPower secure Wake-on-LAN daemon".into(),
            "Wants=network-online.target".into(),
            "After=network-online.target".into(),
            "[Service]".into(),
            "Type=simple".into(),
            "User=remote-open-power".into(),
            "Group=remote-open-power".into(),
            "UMask=0077".into(),
            "LogsDirectory=remote-open-power".into(),
            "Environment=REMOTE_OPEN_POWER_LOG_DIR=/var/log/remote-open-power".into(),
            "ExecStart=/usr/local/bin/remote-open-power --server --config=/etc/remote-open-power/remote-open-power.toml".into(),
            "Restart=on-failure".into(),
            "RestartSec=5s".into(),
            "NoNewPrivileges=true".into(),
            "CapabilityBoundingSet=".into(),
            "ProtectSystem=strict".into(),
            "ProtectHome=true".into(),
            "PrivateTmp=true".into(),
            "RestrictAddressFamilies=AF_INET AF_INET6".into(),
            "TasksMax=96".into(),
            "LimitNOFILE=256".into(),
            "LimitCORE=0".into(),
            "[Install]".into(),
            "WantedBy=multi-user.target".into(),
            "sudo systemctl daemon-reload".into(),
            "sudo systemctl enable --now remote-open-power".into(),
            "前台验证: /usr/local/bin/remote-open-power --server --config /etc/remote-open-power/remote-open-power.toml".into(),
            "PSK 保存在配置文件，不放入 ExecStart。".into(),
            "运行日志位于 /var/log/remote-open-power。".into(),
        ];
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        return vec![
            "Unix 前台启动指令".into(),
            format!("./RemoteOpenPower --server --config {config}"),
            "配置与 PSK 保存在 TOML，不放入命令行。".into(),
        ];
    }
    #[cfg(not(any(windows, unix)))]
    {
        vec!["当前平台没有可用的部署模板。".into()]
    }
}

#[cfg(test)]
mod production_tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn test_capabilities() -> TerminalCapabilities {
        TerminalCapabilities {
            is_terminal: true,
            ansi_supported: true,
            color_enabled: false,
            note: "test".into(),
        }
    }

    #[test]
    fn production_view_uses_real_config_defaults_without_fake_rows() {
        let path = std::env::temp_dir().join(format!(
            "remote-open-power-tui-{}-missing.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let state = ProductionApp::new(&path, test_capabilities()).expect("production state");
        assert!(state.app.hosts.is_empty());
        assert!(state.app.clients.is_empty());
        assert!(state.app.logs.is_empty());
        assert_eq!(state.app.credential_status, "未发现凭据文件");
        assert_eq!(state.app.config_status, "未初始化");
        assert_eq!(state.app.listen_mode, ListenMode::DualStack);
        assert_eq!(state.app.bind_v4_input.value(), DEFAULT_V4_BIND);
        assert_eq!(state.app.bind_v6_input.value(), DEFAULT_V6_BIND);
        assert_eq!(state.app.server_port_input.value(), DEFAULT_SERVER_PORT);
        assert_eq!(state.app.clock_skew_input.value(), DEFAULT_CLOCK_SKEW);
        assert_eq!(state.app.address_input.value(), DEFAULT_CLIENT_ADDRESS);
        assert_eq!(state.app.port_input.value(), DEFAULT_CLIENT_PORT);
        assert_eq!(state.app.address_input.value(), "");
        assert_eq!(
            state.app.port_input.value(),
            config::DEFAULT_PORT.to_string()
        );
    }

    #[test]
    fn deployment_output_contains_runtime_config_path() {
        let path = Path::new("C:/ProgramData/RemoteOpenPower/remote-open-power.toml");
        let lines = deployment_lines(path);
        let joined = lines.join("\n");
        assert!(joined.contains(path.to_string_lossy().as_ref()));
        assert!(!joined.contains("shared_secret"));
        assert!(!joined.contains("static_private_key"));
    }

    #[test]
    fn revoke_confirmation_enter_does_not_open_the_credential_editor() {
        let path = std::env::temp_dir().join(format!(
            "remote-open-power-revoke-modal-{}-{}.toml",
            std::process::id(),
            client::now_ms()
        ));
        let _ = std::fs::remove_file(&path);
        let mut state = ProductionApp::new(&path, test_capabilities()).expect("production state");
        state.app.screen = Screen::Credentials;
        state.app.clients.push(ClientRow {
            label: "portable-client".to_owned(),
            access: "全部主机".to_owned(),
        });
        state.app.credential_index = 0;
        state.app.modal = Some(Modal::RevokeCredential);

        state.handle_event(Event::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));

        assert_eq!(state.app.screen, Screen::Credentials);
        assert_eq!(state.app.modal, None);
        assert!(state.app.clients.is_empty());
        assert_eq!(state.app.issue_edit_index, None);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stale_and_duplicate_host_permissions_are_removed_before_save() {
        let mut clients = vec![config::AllowedClient {
            client_id: "portable-client".to_owned(),
            static_public_key: String::new(),
            allowed_hosts: vec![
                "LAB-PC".to_owned(),
                "lab-pc".to_owned(),
                "removed-pc".to_owned(),
                "  ".to_owned(),
            ],
        }];
        let valid = HashSet::from(["lab-pc".to_owned()]);

        let removed = reconcile_client_host_permissions(&mut clients, &valid);

        assert_eq!(removed, 3);
        assert_eq!(clients[0].allowed_hosts, ["lab-pc"]);
    }

    #[test]
    fn server_save_prunes_unknown_host_permissions_instead_of_failing() {
        let path = std::env::temp_dir().join(format!(
            "remote-open-power-stale-acl-{}-{}.toml",
            std::process::id(),
            client::now_ms()
        ));
        let _ = std::fs::remove_file(&path);
        let mut state = ProductionApp::new(&path, test_capabilities()).expect("production state");
        state.app.hosts.push(HostRow {
            id: "current-pc".to_owned(),
            name: "Current PC".to_owned(),
            mac: "02:11:22:33:44:55".to_owned(),
            ip: "192.168.1.10".to_owned(),
            wol_ipv6_interface: 0,
            state: HostState::Unknown,
            selected: false,
        });
        let client_identity = security::Identity::generate().expect("client identity");
        state.client_acl.push(config::AllowedClient {
            client_id: "portable-client".to_owned(),
            static_public_key: format!("hex:{}", hex::encode(client_identity.public)),
            allowed_hosts: vec!["removed-pc".to_owned()],
        });
        state.app.clients.push(ClientRow {
            label: "portable-client".to_owned(),
            access: "1 台主机".to_owned(),
        });

        let removed = state
            .sync_server_from_view()
            .expect("stale ACL is repaired before validation");

        assert_eq!(removed, 1);
        assert!(
            state.config.security.allowed_clients[0]
                .allowed_hosts
                .is_empty()
        );
        assert_eq!(state.app.clients[0].access, "0 台主机");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn running_view_shows_live_connection_count_without_monitor_summary() {
        let mut app = App::with_capabilities(test_capabilities());
        app.screen = Screen::ServerRunning;
        app.server_phase = ServerPhase::Running;
        app.active_connections = 7;
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, &app))
            .expect("render succeeds");
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .flat_map(|cell| cell.symbol().chars())
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(text.contains("活动连接7"));
        assert!(!text.contains("监控任务"));
    }

    #[test]
    fn client_session_does_not_claim_connected_before_event() {
        let mut app = App::with_capabilities(test_capabilities());
        app.screen = Screen::ClientHosts;
        app.connection_phase = ClientConnectionPhase::Connecting;
        app.connection_attempt = 1;
        app.connection_display = "第 1 次尝试".into();
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, &app))
            .expect("render succeeds");
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        let compact = text
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(compact.contains("连接中"), "rendered: {text:?}");
        assert!(!compact.contains("已连接"));
    }

    #[test]
    fn client_connection_failure_is_persistent_and_coded() {
        let mut app = App::with_capabilities(test_capabilities());
        app.screen = Screen::ClientHosts;
        app.connection_phase = ClientConnectionPhase::RetryWaiting;
        app.connection_display = "第 1 次失败".into();
        app.connection_error_code = Some("NET-CONNECT".into());
        app.connection_error_message = Some("连接被拒绝".into());
        app.connection_retry_at = Some(Instant::now() + Duration::from_secs(2));
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, &app))
            .expect("render succeeds");
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        let compact = text
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(compact.contains("等待重连"), "rendered: {text:?}");
        assert!(compact.contains("错误[NET-CONNECT]"));
        assert!(compact.contains("连接被拒绝"));
        assert!(!compact.contains("●已连接"));
    }

    #[test]
    fn wake_page_shows_connection_failure_and_retry_status() {
        let mut app = App::with_capabilities(test_capabilities());
        app.screen = Screen::Wake;
        app.connection_phase = ClientConnectionPhase::RetryWaiting;
        app.connection_error_code = Some("NET-TRANSPORT".into());
        app.connection_error_message = Some("连接被重置".into());
        app.connection_retry_at = Some(Instant::now() + Duration::from_secs(2));
        app.hosts.push(HostRow {
            id: "lab-pc".into(),
            name: "Lab PC".into(),
            mac: String::new(),
            ip: String::new(),
            wol_ipv6_interface: 0,
            state: HostState::Waking,
            selected: true,
        });
        app.begin_wake(1);
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, &app))
            .expect("render succeeds");
        let compact = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .flat_map(|cell| cell.symbol().chars())
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(compact.contains("等待重连"));
        assert!(compact.contains("错误[NET-TRANSPORT]连接被重置"));
        assert!(compact.contains("后重试"));
    }

    #[test]
    fn completed_wake_gauge_is_full_green_and_shows_ok() {
        let (ratio, label, color) = wake_gauge_presentation(WakePhase::Complete, 0, 60);
        assert_eq!(ratio, 1.0);
        assert_eq!(label, "OK");
        assert_eq!(color, GREEN);

        let mut app = App::with_capabilities(test_capabilities());
        app.screen = Screen::Wake;
        app.wake_phase = WakePhase::Complete;
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, &app))
            .expect("render succeeds");
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("OK"));
    }

    #[test]
    fn interrupted_wake_is_preserved_and_resubmitted_after_reconnect() {
        let path = std::env::temp_dir().join(format!(
            "remote-open-power-wake-reconnect-{}-missing.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut state = ProductionApp::new(&path, test_capabilities()).expect("production state");
        let operation_id = [4; 16];
        state.app.screen = Screen::Wake;
        state.app.connection_phase = ClientConnectionPhase::Connected;
        state.app.hosts.push(HostRow {
            id: "lab-pc".into(),
            name: "Lab PC".into(),
            mac: String::new(),
            ip: String::new(),
            wol_ipv6_interface: 0,
            state: HostState::Waking,
            selected: true,
        });
        state.wake = Some(ActualWake {
            operation_id,
            boot_nonce: [5; 16],
            catalog_version: 9,
            targets: vec!["lab-pc".into()],
            accepted: HashSet::from(["lab-pc".into()]),
            attempt: 1,
            ticket: Some([6; 32]),
            receipt: true,
            finished: false,
            receipt_deadline: Instant::now() + Duration::from_secs(15),
            deadline: Instant::now() + Duration::from_secs(50),
        });
        let (commands, command_rx) = mpsc::channel();
        let (_event_tx, events) = mpsc::sync_channel(1);
        state.client = Some(client::ClientHandle { commands, events });

        state.apply_client_event(client::ClientEvent::ConnectionFailed {
            attempt: 1,
            code: client::ClientConnectionErrorCode::Transport,
            message: "connection reset".into(),
            retry_after: Duration::from_secs(2),
        });
        state.apply_client_event(client::ClientEvent::Connecting { attempt: 2 });
        assert!(state.wake.is_some());
        assert_eq!(state.app.hosts.len(), 1);
        state.apply_client_event(client::ClientEvent::Connected {
            peer: "127.0.0.1:45890".parse().unwrap(),
            server_fingerprint: "test".into(),
        });

        let command = command_rx.try_recv().expect("wake recovery request");
        let client::ClientCommand::Wake {
            operation_id: recovered_id,
            attempt,
            retry_ticket,
            host_ids,
            ..
        } = command
        else {
            panic!("expected wake recovery request");
        };
        assert_eq!(recovered_id, operation_id);
        assert_eq!(attempt, 1);
        assert_eq!(retry_ticket, None);
        assert_eq!(host_ids, ["lab-pc"]);
        assert!(!state.wake.as_ref().unwrap().receipt);
    }

    #[test]
    fn disconnected_wake_does_not_advance_to_attempt_two() {
        let path = std::env::temp_dir().join(format!(
            "remote-open-power-wake-paused-{}-missing.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut state = ProductionApp::new(&path, test_capabilities()).expect("production state");
        state.app.screen = Screen::Wake;
        state.app.connection_phase = ClientConnectionPhase::RetryWaiting;
        state.wake = Some(ActualWake {
            operation_id: [7; 16],
            boot_nonce: [8; 16],
            catalog_version: 1,
            targets: vec!["lab-pc".into()],
            accepted: HashSet::from(["lab-pc".into()]),
            attempt: 1,
            ticket: Some([9; 32]),
            receipt: true,
            finished: false,
            receipt_deadline: Instant::now(),
            deadline: Instant::now(),
        });

        state.tick_wake();

        assert_eq!(state.wake.as_ref().unwrap().attempt, 1);
        assert_eq!(state.app.screen, Screen::Wake);
    }

    #[test]
    fn reconnect_discards_the_previous_authenticated_catalog() {
        let path = std::env::temp_dir().join(format!(
            "remote-open-power-reconnect-{}-missing.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut state = ProductionApp::new(&path, test_capabilities()).expect("production state");
        state.catalog_version = 42;
        state.app.hosts.push(HostRow {
            id: "stale".into(),
            name: "Stale".into(),
            mac: String::new(),
            ip: String::new(),
            wol_ipv6_interface: 0,
            state: HostState::Online,
            selected: true,
        });

        state.apply_client_event(client::ClientEvent::Connecting { attempt: 2 });

        assert_eq!(state.catalog_version, 0);
        assert!(state.app.hosts.is_empty());
        assert_eq!(
            state.app.connection_phase,
            ClientConnectionPhase::Connecting
        );
    }

    #[test]
    fn rejected_wake_receipt_does_not_invent_offline_state() {
        let path = std::env::temp_dir().join(format!(
            "remote-open-power-rejected-{}-missing.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut state = ProductionApp::new(&path, test_capabilities()).expect("production state");
        let operation_id = [1; 16];
        state.app.hosts.push(HostRow {
            id: "lab-pc".into(),
            name: "Lab PC".into(),
            mac: String::new(),
            ip: String::new(),
            wol_ipv6_interface: 0,
            state: HostState::Online,
            selected: true,
        });
        state.wake = Some(ActualWake {
            operation_id,
            boot_nonce: [2; 16],
            catalog_version: 1,
            targets: vec!["lab-pc".into()],
            accepted: HashSet::new(),
            attempt: 1,
            ticket: None,
            receipt: false,
            finished: false,
            receipt_deadline: Instant::now() + Duration::from_secs(15),
            deadline: Instant::now() + Duration::from_secs(60),
        });

        state.apply_client_event(client::ClientEvent::CommandExecuted {
            operation_id,
            attempt: 1,
            retry_ticket: [3; 32],
            deadline_ms: 1,
            results: vec![protocol::WakeResult {
                host_id: "lab-pc".into(),
                accepted: false,
                error_code: Some(protocol::WakeErrorCode::RateLimited),
            }],
        });

        assert_eq!(state.app.hosts[0].state, HostState::Online);
    }

    #[test]
    fn host_form_validates_ipv6_interface_index() {
        let mut values = vec![
            "lab-pc".into(),
            "Lab PC".into(),
            "02:11:22:33:44:55".into(),
            "fd00::10".into(),
            "7".into(),
        ];
        assert!(validate_host_form(&values).is_ok());
        values[3] = "fe80::1234".into();
        assert!(validate_host_form(&values).is_ok());
        values[4] = "0".into();
        assert!(validate_host_form(&values).is_err());
        values[3] = "fd00::10".into();
        values[4] = "4294967296".into();
        assert!(validate_host_form(&values).is_err());
        values[4] = "adapter".into();
        assert!(validate_host_form(&values).is_err());
    }

    #[test]
    fn wake_ui_never_invents_online_state() {
        let mut app = App::with_capabilities(test_capabilities());
        app.screen = Screen::ClientHosts;
        app.hosts.push(HostRow {
            id: "lab-pc".into(),
            name: "Lab PC".into(),
            mac: String::new(),
            ip: String::new(),
            wol_ipv6_interface: 0,
            state: HostState::Offline,
            selected: true,
        });
        app.begin_wake(1);
        assert_eq!(app.hosts[0].state, HostState::Offline);
        app.screen = Screen::Wake;
        app.wake_phase = WakePhase::Complete;
        app.handle_event(Event::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert_eq!(app.hosts[0].state, HostState::Offline);
        assert!(!app.hosts[0].selected);
    }

    #[test]
    fn server_starting_is_not_rendered_as_running() {
        let mut app = App::with_capabilities(test_capabilities());
        app.screen = Screen::ServerRunning;
        app.server_phase = ServerPhase::Starting;
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, &app))
            .expect("render succeeds");
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("STARTING"));
        assert!(!text.contains("RUNNING"));
    }
}
