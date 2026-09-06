use crate::test_support::TestDirectory;

#[test]
fn malformed_secret_config_is_redacted_in_full_fatal_report() {
    let _serial = logging::TEST_SERIAL.lock().unwrap();
    let directory = TestDirectory::new();
    let path = directory.0.join("config.toml");
    crate::config::write_private_toml(
        &path,
        "[security]\nshared_secret = 'FAKE_PSK_MARKER'\nserver_static_private_key = 'FAKE_PRIVATE_MARKER'\nbroken = [\n",
    ).unwrap();
    let (_sink, receiver) = logging::install_sink();
    let result = with_service_logging(&path, || AppConfig::load(&path).map_err(ServerError::from));
    let error = result.unwrap_err();
    let file = std::fs::read_dir(directory.0.join("logs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let report = std::fs::read_to_string(file).unwrap();
    assert!(report.contains("FATAL"));
    assert!(report.contains("byte column"));
    for text in [
        report,
        receiver.drain().join("\n"),
        format!("{error} {error:#?}"),
    ] {
        assert!(!text.contains("FAKE_PSK_MARKER"));
        assert!(!text.contains("FAKE_PRIVATE_MARKER"));
    }
}

#[test]
fn listener_overrides_survive_reload_and_unoverridden_changes_stop_service() {
    let directory = TestDirectory::new();
    let path = directory.0.join("config.toml");
    let (mut config, _) = test_config();
    config.save(&path).unwrap();
    let port = config.server.port;
    let runtime = load_server_runtime(
        &path,
        Some("127.0.0.1".into()),
        Some(port),
        ServerMetrics::default(),
    )
    .unwrap();
    config.server.bind_address = "0.0.0.0".into();
    config.server.port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    config.save(&path).unwrap();
    runtime.refresh_access_policy();
    assert_eq!(
        lock(&runtime.access_policy).snapshot.bind_addrs,
        runtime.snapshot.bind_addrs
    );
    assert!(lock(&runtime.access_policy).source_healthy);

    config.server.bind_address = "127.0.0.1".into();
    config.save(&path).unwrap();
    let runtime = load_server_runtime(&path, None, None, ServerMetrics::default()).unwrap();
    let mut server = RunningServer::start(runtime);
    config.server.port = port;
    config.save(&path).unwrap();
    server.runtime.refresh_access_policy();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !server.worker.as_ref().unwrap().is_finished() {
        assert!(
            Instant::now() < deadline,
            "listener change did not stop service"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let error = server.worker.take().unwrap().join().unwrap().unwrap_err();
    assert!(error.to_string().contains("restart required"));
    assert!(!server.runtime.metrics.is_listening());
}

#[test]
fn reconnect_recovers_receipt_without_another_wake_packet() {
    let (config, client) = test_config();
    let sender = Arc::new(CountingWake(AtomicUsize::new(0)));
    let runtime = ServerRuntime::new_with_components(
        config.clone(),
        configured_handshake(&config).unwrap(),
        sender.clone(),
        Arc::new(OfflineProbe),
    )
    .unwrap();
    let catalog_version = runtime.snapshot.catalog_version;
    let mut server = RunningServer::start(runtime);
    let operation_id = random_id();
    let boot_nonce = random_id();
    let send_wake = |connection: &mut SecureConnection| {
        connection
            .send_client_envelope(&ClientEnvelope {
                version: PROTOCOL_VERSION,
                request_id: operation_id,
                issued_at_ms: unix_ms(),
                headers: Vec::new(),
                operation: ClientOperation::Wake {
                    catalog_version,
                    host_ids: vec!["lab-pc".into()],
                    attempt: 1,
                    boot_nonce,
                    retry_ticket: None,
                },
            })
            .unwrap();
    };
    let mut first = connect_test(&server, &client);
    send_wake(&mut first);
    let original = response(&mut first).unwrap();
    drop(first);
    let mut recovered = connect_test(&server, &client);
    send_wake(&mut recovered);
    let resumed = response(&mut recovered).unwrap();
    let ServerEvent::CommandExecuted {
        retry_ticket,
        results,
        ..
    } = original.event
    else {
        panic!("initial receipt")
    };
    assert!(
        matches!(resumed.event, ServerEvent::CommandExecuted { retry_ticket: resumed_ticket, results: resumed_results, .. } if resumed_ticket == retry_ticket && resumed_results == results)
    );
    assert_eq!(sender.0.load(Ordering::SeqCst), 1);
    server.stop();
}

#[cfg(unix)]
#[test]
fn server_path_resolution_does_not_hide_final_symlink() {
    let directory = TestDirectory::new();
    let path = directory.0.join("config.toml");
    crate::config::write_private_toml(&path, "private").unwrap();
    let alias = directory.0.join("alias.toml");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    let resolved = resolve_server_config_path(&alias).unwrap();
    assert_eq!(resolved, alias);
    assert!(crate::config::read_private_text(&resolved, 100).is_err());
}

fn test_config() -> (AppConfig, crate::security::ClientHandshakeConfig) {
    let mut config = AppConfig::default();
    config.ensure_secret();
    config.ensure_server_identity_material().unwrap();
    config.server.bind_address = "127.0.0.1".into();
    config.server.dual_stack = false;
    config.server.port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    config.hosts.push(HostConfig {
        hostname: "lab-pc".into(),
        display_name: String::new(),
        mac: "02:11:22:33:44:55".into(),
        ip: "192.168.1.10".into(),
        wol_port: 9,
        probe_timeout_ms: 1000,
        probe_port: 0,
        wol_ipv6_interface: 0,
    });
    let client = enroll_test_client(&mut config);
    (config, client)
}

fn enroll_test_client(config: &mut AppConfig) -> crate::security::ClientHandshakeConfig {
    let identity = crate::security::Identity::generate().unwrap();
    let client_id = crate::security::client_id_from_public_key(&identity.public);
    config
        .security
        .allowed_clients
        .push(crate::config::AllowedClient {
            client_id: client_id.clone(),
            display_label: "Regression".into(),
            static_public_key: format!("hex:{}", hex::encode(identity.public)),
            allowed_hosts: vec!["lab-pc".into()],
            issued_credential_file: String::new(),
        });
    crate::security::ClientHandshakeConfig {
        psk: config.secret_key().unwrap(),
        identity,
        client_id,
        pinned_server_key: Some(
            crate::config::decode_key(&config.security.server_static_public_key).unwrap(),
        ),
        clock_skew: Duration::from_secs(config.security.clock_skew_seconds),
        headers: Vec::new(),
    }
}

struct CountingWake(AtomicUsize);

impl WakeSender for CountingWake {
    fn wake(&self, _: &HostConfig) -> Result<(), WakeError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct RunningServer {
    runtime: ServerRuntime,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<(), ServerError>>>,
}

impl RunningServer {
    fn start(runtime: ServerRuntime) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let run = runtime.clone();
        let worker = Some(thread::spawn(move || run.run_with_shutdown(flag)));
        let server = Self {
            runtime,
            shutdown,
            worker,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !server.runtime.metrics.is_listening() {
            assert!(Instant::now() < deadline, "listener startup timed out");
            thread::sleep(Duration::from_millis(5));
        }
        server
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker
                .join()
                .map_err(|_| "test server thread panicked".to_owned())
                .and_then(|result| result.map_err(|error| error.to_string()));
            if let Err(error) = result {
                if thread::panicking() {
                    logging::log(Level::Fatal, format!("test server cleanup: {error}"));
                } else {
                    panic!("test server cleanup: {error}");
                }
            }
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn response(connection: &mut SecureConnection) -> Result<ServerEnvelope, SecurityError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(value) = connection.poll_server_envelope()? {
            return Ok(value);
        }
        assert!(Instant::now() < deadline, "response deadline");
        thread::sleep(Duration::from_millis(5));
    }
}

fn request(connection: &mut SecureConnection, operation: ClientOperation) {
    connection
        .send_client_envelope(&ClientEnvelope {
            version: PROTOCOL_VERSION,
            request_id: random_id(),
            issued_at_ms: unix_ms(),
            headers: Vec::new(),
            operation,
        })
        .unwrap();
}

fn connect_test(
    server: &RunningServer,
    client: &crate::security::ClientHandshakeConfig,
) -> SecureConnection {
    crate::security::client_handshake(
        TcpStream::connect(server.runtime.snapshot.bind_addrs[0]).unwrap(),
        client,
    )
    .unwrap()
    .connection
}

#[test]
fn stopped_server_joins_authenticated_connections_and_cannot_wake() {
    let (config, client) = test_config();
    let sender = Arc::new(CountingWake(AtomicUsize::new(0)));
    let runtime = ServerRuntime::new_with_components(
        config.clone(),
        configured_handshake(&config).unwrap(),
        sender.clone(),
        Arc::new(OfflineProbe),
    )
    .unwrap();
    let mut server = RunningServer::start(runtime);
    let mut connection = connect_test(&server, &client);
    request(&mut connection, ClientOperation::ListHosts);
    assert!(matches!(
        response(&mut connection).unwrap().event,
        ServerEvent::Hosts { .. }
    ));
    server.stop();
    assert!(!server.runtime.metrics.is_listening());
    assert_eq!(server.runtime.metrics.active_connections(), 0);
    assert!(response(&mut connection).is_err());
    assert_eq!(sender.0.load(Ordering::SeqCst), 0);
}

#[test]
fn reloaded_policy_updates_handshake_catalog_target_and_revokes_open_session() {
    let directory = TestDirectory::new();
    let path = directory.0.join("config.toml");
    let (mut config, old_client) = test_config();
    config.save(&path).unwrap();
    let runtime = ServerRuntime::new_with_components(
        config.clone(),
        configured_handshake(&config).unwrap(),
        Arc::new(NoopWakeSender),
        Arc::new(OfflineProbe),
    )
    .unwrap()
    .with_access_policy_source(path.clone());
    let old_catalog = runtime.snapshot.catalog_version;
    let mut server = RunningServer::start(runtime);
    let mut old_connection = connect_test(&server, &old_client);
    request(&mut old_connection, ClientOperation::ListHosts);
    response(&mut old_connection).unwrap();
    let new_client = enroll_test_client(&mut config);
    config.hosts[0].ip = "192.168.1.99".into();
    config.save(&path).unwrap();
    server.runtime.refresh_access_policy();
    {
        let policy = lock(&server.runtime.access_policy);
        assert_ne!(policy.snapshot.catalog_version, old_catalog);
        assert_eq!(policy.snapshot.hosts["lab-pc"].config.ip, "192.168.1.99");
    }
    assert!(response(&mut old_connection).is_err());
    let mut connection = connect_test(&server, &new_client);
    request(&mut connection, ClientOperation::ListHosts);
    assert!(
        matches!(response(&mut connection).unwrap().event, ServerEvent::Hosts { catalog_version, .. } if catalog_version != old_catalog)
    );
    config.security.allowed_clients.clear();
    config.save(&path).unwrap();
    server.runtime.refresh_access_policy();
    assert!(response(&mut connection).is_err());
    server.stop();
}

struct SlowProbe {
    started: AtomicBool,
    release: AtomicBool,
}
impl StatusProbe for SlowProbe {
    fn is_online(&self, _: &HostConfig) -> bool {
        self.started.store(true, Ordering::Release);
        let end = Instant::now() + Duration::from_secs(4);
        while !self.release.load(Ordering::Acquire) && Instant::now() < end {
            thread::sleep(Duration::from_millis(5));
        }
        false
    }
}

#[test]
fn slow_status_probe_does_not_block_wake_receipt() {
    let (config, client) = test_config();
    let probe = Arc::new(SlowProbe {
        started: AtomicBool::new(false),
        release: AtomicBool::new(false),
    });
    let sender = Arc::new(CountingWake(AtomicUsize::new(0)));
    let runtime = ServerRuntime::new_with_components(
        config.clone(),
        configured_handshake(&config).unwrap(),
        sender.clone(),
        probe.clone(),
    )
    .unwrap();
    let catalog_version = runtime.snapshot.catalog_version;
    let mut server = RunningServer::start(runtime);
    let mut connection = connect_test(&server, &client);
    request(
        &mut connection,
        ClientOperation::GetStatuses {
            catalog_version,
            host_ids: vec!["lab-pc".into()],
        },
    );
    let end = Instant::now() + Duration::from_secs(2);
    while !probe.started.load(Ordering::Acquire) {
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(5));
    }
    request(
        &mut connection,
        ClientOperation::Wake {
            catalog_version,
            host_ids: vec!["lab-pc".into()],
            attempt: 1,
            boot_nonce: random_id(),
            retry_ticket: None,
        },
    );
    let receipt = response(&mut connection).unwrap();
    probe.release.store(true, Ordering::Release);
    assert!(
        matches!(receipt.event, ServerEvent::CommandExecuted { results, .. } if results[0].accepted)
    );
    assert_eq!(sender.0.load(Ordering::SeqCst), 1);
    server.stop();
}

#[test]
fn recovered_receipt_renews_retry_lease_but_never_redispatches_or_extends_tombstone() {
    let mut ledger = Ledger::new();
    let now = Instant::now();
    let key = operation_key(5, 5);
    let targets = vec!["lab-pc".into()];
    let WakeBeginResult::New(ticket) =
        ledger.begin_wake_attempt1(key, [1; 32], 1, targets.clone(), [2; 16], now)
    else {
        panic!("new operation");
    };
    let receipt = ServerEnvelope {
        version: PROTOCOL_VERSION,
        request_id: key.operation_id,
        issued_at_ms: unix_ms(),
        headers: vec![],
        event: ServerEvent::CommandExecuted {
            operation_id: key.operation_id,
            attempt: 1,
            retry_ticket: ticket,
            deadline_ms: unix_ms() + 60_000,
            results: vec![WakeResult {
                host_id: "lab-pc".into(),
                accepted: true,
                error_code: None,
            }],
        },
    };
    ledger.complete(key, receipt, now);
    for seconds in [40, 100, 200] {
        assert!(matches!(
            ledger.begin_wake_attempt1(
                key,
                [1; 32],
                1,
                targets.clone(),
                [2; 16],
                now + Duration::from_secs(seconds)
            ),
            WakeBeginResult::Cached(_)
        ));
        assert_eq!(ledger.entries[&key].expires, now + LEDGER_TTL);
    }
    assert!(matches!(
        ledger.begin_wake_attempt2(
            key,
            WakeRetry {
                digest: [1; 32],
                catalog_version: 1,
                host_ids: &targets,
                boot_nonce: [2; 16],
                ticket,
                now: now + Duration::from_secs(260)
            }
        ),
        WakeBeginResult::New(_)
    ));
    let wake = ledger.entries[&key].wake.as_ref().unwrap();
    assert_eq!(wake.attempt, 2);
    assert!(wake.ticket_used);
}

#[cfg(windows)]
#[test]
fn concurrent_config_read_does_not_revoke_authorization() {
    use std::os::windows::fs::OpenOptionsExt;
    let directory = TestDirectory::new();
    let path = directory.0.join("config.toml");
    let (mut config, client) = test_config();
    config.save(&path).unwrap();
    let runtime = ServerRuntime::new_with_components(
        config.clone(),
        configured_handshake(&config).unwrap(),
        Arc::new(NoopWakeSender),
        Arc::new(OfflineProbe),
    )
    .unwrap()
    .with_access_policy_source(path.clone());
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&path)
        .unwrap();
    runtime.refresh_access_policy();
    assert!(runtime.client_is_authorized(&client.identity.public));
    drop(reader);
    let reader = crate::config::open_private_file(&path, 1_000_000, false)
        .unwrap()
        .unwrap();
    config.save(&path).unwrap();
    runtime.refresh_access_policy();
    assert!(runtime.client_is_authorized(&client.identity.public));
    drop(reader);
}
