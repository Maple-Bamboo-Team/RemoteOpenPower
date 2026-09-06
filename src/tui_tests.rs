#[cfg(windows)]
#[test]
fn failed_revocation_save_restores_view_and_authorization() {
    use std::os::windows::fs::OpenOptionsExt;
    let directory = crate::test_support::TestDirectory::new();
    let path = directory.0.join("config.toml");
    let mut state = ProductionApp::new(&path, test_capabilities()).unwrap();
    state.sync_server_from_view().unwrap();
    let identity = security::Identity::generate().unwrap();
    state
        .config
        .security
        .allowed_clients
        .push(config::AllowedClient {
            client_id: security::client_id_from_public_key(&identity.public),
            display_label: "Test".into(),
            static_public_key: format!("hex:{}", hex::encode(identity.public)),
            allowed_hosts: Vec::new(),
            issued_credential_file: String::new(),
        });
    state.config.save(&path).unwrap();
    state.client_acl = state.config.security.allowed_clients.clone();
    state.load_view_from_config();
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&path)
        .unwrap();
    state.app.screen = Screen::Credentials;
    state.app.modal = Some(Modal::RevokeCredential);
    state.handle_event(Event::Key(KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    )));
    assert_eq!(state.app.clients.len(), 1);
    assert_eq!(state.client_acl.len(), 1);
    assert_eq!(
        config::AppConfig::load(&path)
            .unwrap()
            .security
            .allowed_clients
            .len(),
        1
    );
    assert_eq!(state.app.config_status, "保存失败");
    assert_eq!(state.app.issue_edit_index, None);
    state.app.screen = Screen::SaveExit;
    let backend = TestBackend::new(120, 35);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, &state.app)).unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .flat_map(|cell| cell.symbol().chars())
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    assert!(text.contains("保存失败"));
    drop(reader);
}

#[test]
fn number_four_starts_from_every_top_level_server_page() {
    let _serial = logging::TEST_SERIAL.lock().unwrap();
    for screen in [
        Screen::ServerHome,
        Screen::ServerSettings,
        Screen::Credentials,
        Screen::SaveExit,
    ] {
        let directory = crate::test_support::TestDirectory::new();
        let mut state =
            ProductionApp::new(&directory.0.join("config.toml"), test_capabilities()).unwrap();
        state.app.listen_mode = ListenMode::V4Only;
        state.app.bind_v4_input = Input::new("127.0.0.1".into());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        state.app.server_port_input = Input::new(listener.local_addr().unwrap().port().to_string());
        drop(listener);
        state.app.screen = screen;
        state.handle_event(Event::Key(KeyEvent::new(
            KeyCode::Char('4'),
            KeyModifiers::NONE,
        )));
        assert!(state.server_thread.is_some());
        assert_eq!(state.app.screen, Screen::ServerRunning);
        state.stop_server();
        assert!(state.server_thread.is_none());
        assert_eq!(state.app.server_phase, ServerPhase::Stopped);
    }
}

#[test]
fn closed_client_event_channel_reports_disconnect() {
    let directory = crate::test_support::TestDirectory::new();
    let mut state =
        ProductionApp::new(&directory.0.join("config.toml"), test_capabilities()).unwrap();
    let (commands, _receiver) = mpsc::channel();
    let (events, receiver) = mpsc::sync_channel(1);
    state.client = Some(client::ClientHandle::from_channels(commands, receiver));
    state.app.connection_phase = ClientConnectionPhase::Connected;
    drop(events);
    state.drain_client_events();
    assert_eq!(
        state.app.connection_phase,
        ClientConnectionPhase::Disconnected
    );
    assert!(state.app.connection_error_code.is_some());
}

#[cfg(windows)]
#[test]
fn powershell_deployment_quotes_literal_arguments() {
    let value = "C:\\a b\\c'd $value `name.toml";
    let script = format!(
        "$value = {}; ConvertTo-Json -InputObject $value -Compress",
        powershell_quote(value)
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<String>(&output.stdout).unwrap(),
        value
    );
    assert!(
        deployment_lines(Path::new(value))
            .iter()
            .any(|line| line.trim_start().starts_with("& '"))
    );
}

#[test]
fn partial_wake_is_not_rendered_as_green_ok() {
    let (ratio, label, color) = wake_gauge_presentation(WakePhase::Partial, 40, 20);
    assert_eq!(ratio, 1.0);
    assert_ne!(label, "OK");
    assert_ne!(color, GREEN);
}

#[test]
fn post_replace_sync_failure_retains_committed_config_and_reports_error() {
    let directory = crate::test_support::TestDirectory::new();
    let path = directory.0.join("config.toml");
    let mut state = ProductionApp::new(&path, test_capabilities()).unwrap();
    state.sync_server_from_view().unwrap();
    let mut candidate = state.config.clone();
    candidate.security.clock_skew_seconds = 17;
    candidate.save(&path).unwrap();
    let error = config::ConfigError::Durability {
        path: path.clone(),
        source: std::io::Error::other("injected directory sync failure"),
    };
    assert!(state.finish_server_save(candidate, Err(error)).is_err());
    assert_eq!(state.config, config::AppConfig::load(path).unwrap());
    assert_eq!(state.app.clock_skew_input.value(), "17");
    assert_eq!(state.app.config_status, "保存失败");
}

#[test]
fn recovered_receipt_preserves_online_rows_and_matches_rejections_by_id() {
    let directory = crate::test_support::TestDirectory::new();
    let mut state =
        ProductionApp::new(&directory.0.join("config.toml"), test_capabilities()).unwrap();
    let first_receipt = Instant::now() - Duration::from_secs(40);
    let deadline = first_receipt + client::WAKE_WAIT_TIMEOUT;
    let operation_id = [1; 16];
    state.app.screen = Screen::Wake;
    state.app.wake_online = vec![false, true, false];
    state.app.hosts = ["rejected", "online", "waiting"]
        .into_iter()
        .map(|id| HostRow {
            id: id.into(),
            name: id.into(),
            mac: String::new(),
            ip: String::new(),
            wol_ipv6_interface: 0,
            selected: true,
            state: if id == "online" {
                HostState::Online
            } else {
                HostState::Unknown
            },
        })
        .collect();
    state.wake = Some(ActualWake {
        operation_id,
        boot_nonce: [2; 16],
        catalog_version: 1,
        targets: vec!["rejected".into(), "online".into(), "waiting".into()],
        progress: crate::wake::Progress {
            created_at: first_receipt,
            accepted: HashSet::from(["online".into(), "waiting".into()]),
            online: HashSet::from(["online".into()]),
            started_at: Some(first_receipt),
            deadline,
        },
        attempt: 1,
        ticket: None,
        receipt: false,
        finished: false,
        receipt_deadline: Instant::now() + client::RECEIPT_TIMEOUT,
        deadline,
    });
    let receipt = client::ClientEvent::CommandExecuted {
        operation_id,
        attempt: 1,
        retry_ticket: [3; 32],
        deadline_ms: 0,
        results: ["waiting", "rejected", "online"]
            .into_iter()
            .map(|id| protocol::WakeResult {
                host_id: id.into(),
                accepted: id != "rejected",
                error_code: (id == "rejected").then_some(protocol::WakeErrorCode::RateLimited),
            })
            .collect(),
    };
    state.apply_client_event(receipt.clone());
    assert_eq!(state.app.wake_rejected, [true, false, false]);
    assert_eq!(state.app.hosts[1].state, HostState::Online);
    assert_eq!(state.app.wake_deadline, deadline);
    assert_eq!(state.app.wake_started_at, first_receipt);
    state.apply_client_event(client::ClientEvent::TargetOnline {
        operation_id,
        attempt: 1,
        host_id: "waiting".into(),
    });
    assert_eq!(state.app.wake_phase, WakePhase::Partial);
    state.apply_client_event(receipt);
    assert_eq!(state.app.wake_phase, WakePhase::Partial);
    assert_eq!(state.app.hosts[2].state, HostState::Online);
}

#[test]
fn expired_wake_cannot_resubmit_after_reconnect() {
    let directory = crate::test_support::TestDirectory::new();
    let mut state =
        ProductionApp::new(&directory.0.join("config.toml"), test_capabilities()).unwrap();
    let now = Instant::now();
    state.wake = Some(ActualWake {
        operation_id: [1; 16],
        boot_nonce: [2; 16],
        catalog_version: 1,
        targets: vec!["lab-pc".into()],
        progress: crate::wake::Progress::new(now - crate::wake::RECOVERY_TIMEOUT),
        attempt: 1,
        ticket: None,
        receipt: false,
        finished: false,
        receipt_deadline: now,
        deadline: now,
    });
    let (commands, receiver) = mpsc::channel();
    let (_event_tx, events) = mpsc::sync_channel(1);
    state.client = Some(client::ClientHandle::from_channels(commands, events));
    state.apply_client_event(client::ClientEvent::Connected {
        peer: "127.0.0.1:45890".parse().unwrap(),
        server_fingerprint: "test".into(),
    });
    assert!(receiver.try_recv().is_err());
    assert_eq!(state.app.wake_phase, WakePhase::Failed);
    assert!(state.wake.as_ref().unwrap().finished);
}
