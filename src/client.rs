//! Client-side connection actor.
//!
//! The CLI communicates with this module through bounded standard channels.
//! No presentation code owns a socket and no wire message contains a MAC,
//! IP address, command or executable path: the daemon resolves opaque host
//! identifiers from its own configuration.

use crate::{
    config::{ConfigError, validate_header},
    protocol::{
        ClientEnvelope, ClientOperation, Header, HostStatus, PROTOCOL_VERSION, ServerEnvelope,
        ServerEvent, WakeResult,
    },
    security::{Identity, SecurityError, client_handshake, fingerprint},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const RECEIPT_TIMEOUT: Duration = Duration::from_secs(15);
pub const WAKE_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
pub const CLIENT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const RECONNECT_DELAYS_SECONDS: [u64; 5] = [2, 5, 10, 20, 30];
const MAX_PENDING_REQUESTS: usize = 16;
const MAX_PENDING_OPERATIONS: usize = 32;
const PENDING_OPERATION_TTL: Duration = Duration::from_secs(180);
const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;
const CREDENTIAL_VERSION: u32 = 1;
const MAX_DEVICE_LABEL_BYTES: usize = 128;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
    #[error("secure connection error: {0}")]
    Security(#[from] SecurityError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid server endpoint")]
    Endpoint,
    #[error(
        "this client has no server-issued credential bundle; provision it before connecting ({path})"
    )]
    EnrollmentRequired { path: PathBuf },
    #[error("invalid or unsafe client credential bundle")]
    Credential,
    #[error(
        "multiple client credential bundles found in {directory}; keep one as {primary} or use a dedicated client directory"
    )]
    CredentialAmbiguous {
        directory: PathBuf,
        primary: PathBuf,
    },
}

/// A server-issued client credential.  It is deliberately kept separate from
/// the general TOML settings so copying a server configuration cannot grant a
/// client the server's private identity.  The bundle must be provisioned by an
/// authenticated enrollment channel or an out-of-band trusted transfer.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialBundle {
    pub version: u32,
    /// Authentication ID derived from `static_public_key`.
    pub client_id: String,
    /// Human-readable provisioning label.  It is a warning/display hint only;
    /// it is never used as an authentication factor.
    #[serde(default)]
    pub device_label: String,
    pub shared_secret: String,
    pub static_private_key: String,
    pub static_public_key: String,
    pub pinned_server_static_key: String,
    #[serde(default)]
    pub custom_headers: BTreeMap<String, String>,
}

impl std::fmt::Debug for CredentialBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialBundle")
            .field("version", &self.version)
            .field("client_id", &self.client_id)
            .field("device_label", &self.device_label)
            .field("shared_secret", &"<redacted>")
            .field("static_private_key", &"<redacted>")
            .field("static_public_key", &self.static_public_key)
            .field("pinned_server_static_key", &self.pinned_server_static_key)
            .field(
                "custom_headers",
                &self.custom_headers.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl CredentialBundle {
    fn validate(&self) -> Result<Identity, ClientError> {
        if self.version != CREDENTIAL_VERSION {
            return Err(ClientError::Credential);
        }
        crate::protocol::validate_id(&self.client_id).map_err(|_| ClientError::Credential)?;
        if self.device_label.len() > MAX_DEVICE_LABEL_BYTES
            || self.device_label.chars().any(char::is_control)
        {
            return Err(ClientError::Credential);
        }
        let identity = Identity::from_hex(&self.static_private_key, &self.static_public_key)
            .map_err(|_| ClientError::Credential)?;
        if self.client_id != crate::security::client_id_from_public_key(&identity.public) {
            return Err(ClientError::Credential);
        }
        crate::config::decode_key(&self.pinned_server_static_key)
            .map(|_| ())
            .map_err(|_| ClientError::Credential)?;
        let mut probe = crate::config::AppConfig::default();
        probe.security.shared_secret = self.shared_secret.clone();
        probe.client.client_id = self.client_id.clone();
        probe.client.static_private_key = self.static_private_key.clone();
        probe.client.static_public_key = self.static_public_key.clone();
        probe.client.pinned_server_static_key = self.pinned_server_static_key.clone();
        probe.security.custom_headers = self.custom_headers.clone();
        probe
            .validate()
            .map_err(|_| ClientError::Credential)
            .map(|_| identity)
    }
}

/// Runtime-only material.  Keep this separate from `ClientConfig` so the CLI
/// can load/save TOML without accidentally passing server credentials around.
pub struct ClientRuntimeConfig {
    pub address: String,
    pub port: u16,
    pub client_id: String,
    pub psk: [u8; 32],
    pub identity: Identity,
    pub pinned_server_key: [u8; 32],
    pub headers: Vec<Header>,
    pub clock_skew: Duration,
    /// Optional provisioning label for operator display.  It is never compared
    /// with the current machine and never changes authorization.
    pub device_label: Option<String>,
}

impl ClientRuntimeConfig {
    fn from_config_with_label(
        config: &crate::config::AppConfig,
        device_label: Option<String>,
    ) -> Result<Self, ClientError> {
        config.validate()?;
        let psk = config.secret_key()?;
        let identity = Identity::from_hex(
            &config.client.static_private_key,
            &config.client.static_public_key,
        )?;
        let pin = crate::config::decode_key(&config.client.pinned_server_static_key)
            .map_err(|_| SecurityError::PinRequired)?;
        if config.client.address.trim().is_empty() {
            return Err(ClientError::Endpoint);
        }
        // The wire identity is always derived from the static public key. A
        // mutable machine or display name is never consulted.
        let client_id = crate::security::client_id_from_public_key(&identity.public);
        let headers = headers_from_map(&config.security.custom_headers)?;
        Ok(Self {
            address: config.client.address.trim().to_owned(),
            port: config.client.port,
            client_id,
            psk,
            identity,
            pinned_server_key: pin,
            headers,
            clock_skew: Duration::from_secs(config.security.clock_skew_seconds.clamp(1, 60)),
            device_label: device_label.filter(|label| !label.trim().is_empty()),
        })
    }
}

pub fn credential_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("credential.toml")
}

/// Locate the single portable credential next to the client settings file
/// without loading secret material.  The primary filename is preferred; an
/// older, differently named bundle is accepted only when it is unambiguous.
pub fn discover_credential_path(config_path: &Path) -> Result<PathBuf, ClientError> {
    let primary = credential_path(config_path);
    if primary.is_file() {
        return Ok(primary);
    }
    let parent = config_path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut candidate = None;
    for entry in std::fs::read_dir(parent).map_err(|_| ClientError::Credential)? {
        let entry = entry.map_err(|_| ClientError::Credential)?;
        let path = entry.path();
        if path == primary {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.ends_with(".credential.toml") {
            continue;
        }
        if candidate.is_some() {
            return Err(ClientError::CredentialAmbiguous {
                directory: parent.to_path_buf(),
                primary,
            });
        }
        candidate = Some(path);
    }
    candidate.ok_or(ClientError::EnrollmentRequired { path: primary })
}

fn load_credential_bundle(path: &Path) -> Result<Option<CredentialBundle>, ClientError> {
    let Some(text) = crate::config::read_private_text(path, MAX_CREDENTIAL_BYTES)
        .map_err(|_| ClientError::Credential)?
    else {
        return Ok(None);
    };
    let bundle: CredentialBundle = toml::from_str(&text).map_err(|_| ClientError::Credential)?;
    Ok(Some(bundle))
}

fn load_portable_bundle(config_path: &Path) -> Result<(PathBuf, CredentialBundle), ClientError> {
    let candidate = discover_credential_path(config_path)?;
    let Some(bundle) = load_credential_bundle(&candidate)? else {
        return Err(ClientError::Credential);
    };
    Ok((candidate, bundle))
}

pub fn save_credential_bundle(path: &Path, bundle: &CredentialBundle) -> Result<(), ClientError> {
    let text = toml::to_string_pretty(bundle).map_err(|_| ClientError::Credential)?;
    if text.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(ClientError::Credential);
    }
    crate::config::write_private_toml(path, &(text + "\n"))?;
    Ok(())
}

/// Delete the server-side enrollment copy only when it still contains the
/// credential belonging to the revoked public key. This prevents a stale or
/// edited path in the server configuration from deleting an unrelated file.
pub fn remove_issued_credential_bundle(
    path: &Path,
    expected_public_key: &str,
) -> Result<bool, ClientError> {
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_none_or(|value| !value.ends_with(".credential.toml"))
    {
        return Err(ClientError::Credential);
    }
    let expected =
        crate::config::decode_key(expected_public_key).map_err(|_| ClientError::Credential)?;
    crate::private_file::remove_verified(path, MAX_CREDENTIAL_BYTES, |text| {
        let bundle: CredentialBundle = toml::from_str(text).map_err(|_| ClientError::Credential)?;
        let identity = bundle.validate()?;
        if identity.public != expected {
            return Err(ClientError::Credential);
        }
        Ok(())
    })
}

fn apply_credential_bundle(
    config: &mut crate::config::AppConfig,
    bundle: CredentialBundle,
) -> Result<Option<String>, ClientError> {
    let identity = bundle.validate()?;
    let client_id = crate::security::client_id_from_public_key(&identity.public);
    let device_label =
        (!bundle.device_label.trim().is_empty()).then(|| bundle.device_label.trim().to_owned());
    config.security.shared_secret = bundle.shared_secret;
    config.client.client_id = client_id;
    config.client.static_private_key = bundle.static_private_key;
    config.client.static_public_key = bundle.static_public_key;
    config.client.pinned_server_static_key = bundle.pinned_server_static_key;
    config.security.custom_headers = bundle.custom_headers;
    Ok(device_label)
}

pub enum ClientCommand {
    Refresh,
    Wake {
        host_ids: Vec<String>,
        catalog_version: u64,
        operation_id: [u8; 16],
        boot_nonce: [u8; 16],
        attempt: u8,
        retry_ticket: Option<[u8; 32]>,
    },
    Shutdown,
}

impl std::fmt::Debug for ClientCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refresh => formatter.write_str("Refresh"),
            Self::Shutdown => formatter.write_str("Shutdown"),
            Self::Wake {
                host_ids,
                catalog_version,
                operation_id,
                attempt,
                ..
            } => formatter
                .debug_struct("Wake")
                .field("host_count", &host_ids.len())
                .field("catalog_version", catalog_version)
                .field("operation_id", &hex::encode(operation_id))
                .field("attempt", attempt)
                .field("retry_ticket", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Clone)]
pub enum ClientEvent {
    Connecting {
        attempt: u32,
    },
    ConnectionFailed {
        attempt: u32,
        code: ClientConnectionErrorCode,
        message: String,
        retry_after: Duration,
    },
    Connected {
        peer: SocketAddr,
        server_fingerprint: String,
    },
    Hosts {
        catalog_version: u64,
        hosts: Vec<crate::protocol::HostSummary>,
    },
    Statuses {
        catalog_version: u64,
        statuses: Vec<HostStatus>,
    },
    CommandExecuted {
        operation_id: [u8; 16],
        attempt: u8,
        retry_ticket: [u8; 32],
        deadline_ms: u64,
        results: Vec<WakeResult>,
    },
    TargetOnline {
        operation_id: [u8; 16],
        attempt: u8,
        host_id: String,
    },
    Error(String),
    Disconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientConnectionErrorCode {
    Resolve,
    Connect,
    Handshake,
    Transport,
    Protocol,
}

impl ClientConnectionErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "NET-RESOLVE",
            Self::Connect => "NET-CONNECT",
            Self::Handshake => "SEC-HANDSHAKE",
            Self::Transport => "NET-TRANSPORT",
            Self::Protocol => "PROTO-STATE",
        }
    }
}

impl std::fmt::Debug for ClientEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connecting { attempt } => formatter
                .debug_struct("Connecting")
                .field("attempt", attempt)
                .finish(),
            Self::ConnectionFailed {
                attempt,
                code,
                retry_after,
                ..
            } => formatter
                .debug_struct("ConnectionFailed")
                .field("attempt", attempt)
                .field("code", code)
                .field("retry_after", retry_after)
                .finish(),
            Self::Connected {
                peer,
                server_fingerprint,
            } => formatter
                .debug_struct("Connected")
                .field("peer", peer)
                .field("server_fingerprint", server_fingerprint)
                .finish(),
            Self::Hosts {
                catalog_version,
                hosts,
            } => formatter
                .debug_struct("Hosts")
                .field("catalog_version", catalog_version)
                .field("host_count", &hosts.len())
                .finish(),
            Self::Statuses {
                catalog_version,
                statuses,
            } => formatter
                .debug_struct("Statuses")
                .field("catalog_version", catalog_version)
                .field("status_count", &statuses.len())
                .finish(),
            Self::CommandExecuted {
                operation_id,
                attempt,
                deadline_ms,
                results,
                ..
            } => formatter
                .debug_struct("CommandExecuted")
                .field("operation_id", &hex::encode(operation_id))
                .field("attempt", attempt)
                .field("deadline_ms", deadline_ms)
                .field("result_count", &results.len())
                .field("retry_ticket", &"<redacted>")
                .finish(),
            Self::TargetOnline {
                operation_id,
                attempt,
                host_id,
                ..
            } => formatter
                .debug_struct("TargetOnline")
                .field("operation_id", &hex::encode(operation_id))
                .field("attempt", attempt)
                .field("host_id", host_id)
                .finish(),
            Self::Error(error) => formatter.debug_tuple("Error").field(error).finish(),
            Self::Disconnected => formatter.write_str("Disconnected"),
        }
    }
}

pub struct ClientHandle {
    pub commands: Sender<ClientCommand>,
    pub events: Receiver<ClientEvent>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ClientHandle {
    pub fn shutdown(&mut self) -> Result<(), ClientError> {
        if let Some(worker) = self.worker.take() {
            // A closed command receiver means the actor has already exited.
            match self.commands.send(ClientCommand::Shutdown) {
                Ok(()) | Err(mpsc::SendError(ClientCommand::Shutdown)) => {}
                Err(_) => unreachable!("only Shutdown was sent"),
            }
            worker
                .join()
                .map_err(|_| io::Error::other("client actor panicked"))?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_channels(
        commands: Sender<ClientCommand>,
        events: Receiver<ClientEvent>,
    ) -> Self {
        Self {
            commands,
            events,
            worker: None,
        }
    }
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            crate::logging::log(
                crate::logging::Level::Fatal,
                format!("client shutdown failed: {error}"),
            );
        }
    }
}

pub fn spawn_client(config: ClientRuntimeConfig) -> Result<ClientHandle, ClientError> {
    let (command_tx, command_rx) = mpsc::channel();
    // A bounded event queue prevents an authenticated peer from growing the
    // client process without limit when the CLI is busy rendering output.
    let (event_tx, event_rx) = mpsc::sync_channel(256);
    let worker = thread::Builder::new()
        .name("rop-client".to_owned())
        .spawn(move || client_actor(config, command_rx, event_tx))?;
    Ok(ClientHandle {
        commands: command_tx,
        events: event_rx,
        worker: Some(worker),
    })
}

fn client_actor(
    config: ClientRuntimeConfig,
    commands: Receiver<ClientCommand>,
    events: SyncSender<ClientEvent>,
) {
    let address = config.address.clone();
    let port = config.port;
    let configured_clock_skew = config.clock_skew;
    let configured_headers = config.headers.clone();
    let handshake = crate::security::ClientHandshakeConfig {
        psk: config.psk,
        identity: config.identity,
        client_id: config.client_id.clone(),
        pinned_server_key: Some(config.pinned_server_key),
        clock_skew: config.clock_skew,
        headers: configured_headers.clone(),
    };
    let mut attempt = 1_u32;
    loop {
        if events
            .try_send(ClientEvent::Connecting { attempt })
            .is_err()
        {
            return;
        }
        let endpoints = match resolve_endpoints(&address, port) {
            Ok(endpoints) => endpoints,
            Err(error) => {
                if !report_connection_failure(
                    &commands,
                    &events,
                    attempt,
                    ClientConnectionErrorCode::Resolve,
                    format!("无法解析服务端地址: {error}"),
                ) {
                    break;
                }
                attempt = attempt.saturating_add(1);
                continue;
            }
        };
        let stream = match connect_endpoints(&endpoints, &commands) {
            Ok(None) => break,
            Ok(Some(stream)) => stream,
            Err(error) => {
                if !report_connection_failure(
                    &commands,
                    &events,
                    attempt,
                    ClientConnectionErrorCode::Connect,
                    format!("无法连接服务端: {error}"),
                ) {
                    break;
                }
                attempt = attempt.saturating_add(1);
                continue;
            }
        };
        let mut secure = match client_handshake(stream, &handshake) {
            Ok(result) => {
                if events
                    .try_send(ClientEvent::Connected {
                        peer: result.connection.peer_addr(),
                        server_fingerprint: fingerprint(&result.server_static_public),
                    })
                    .is_err()
                {
                    return;
                }
                result.connection
            }
            Err(error) => {
                if !report_connection_failure(
                    &commands,
                    &events,
                    attempt,
                    ClientConnectionErrorCode::Handshake,
                    format!("安全握手失败: {error}"),
                ) {
                    break;
                }
                attempt = attempt.saturating_add(1);
                continue;
            }
        };
        attempt = 1;
        match run_connected_client(
            &mut secure,
            &commands,
            &events,
            &configured_headers,
            configured_clock_skew,
        ) {
            ConnectedClientExit::Shutdown => {
                close_connection(&mut secure, "client shutdown");
                break;
            }
            ConnectedClientExit::Lost { code, message } => {
                close_connection(&mut secure, "connection loss");
                if !report_connection_failure(&commands, &events, attempt, code, message) {
                    break;
                }
                attempt = attempt.saturating_add(1);
            }
        }
    }
    send_client_event(
        &events,
        ClientEvent::Disconnected,
        "disconnect notification",
    );
}

enum ConnectedClientExit {
    Shutdown,
    Lost {
        code: ClientConnectionErrorCode,
        message: String,
    },
}

fn run_connected_client(
    secure: &mut crate::security::SecureConnection,
    commands: &Receiver<ClientCommand>,
    events: &SyncSender<ClientEvent>,
    configured_headers: &[Header],
    configured_clock_skew: Duration,
) -> ConnectedClientExit {
    let mut last_activity = Instant::now();
    let mut send_list = true;
    let mut pending = HashMap::<[u8; 16], PendingOperation>::new();
    let mut pending_requests = HashMap::<[u8; 16], PendingRequest>::new();
    while last_activity.elapsed() < CLIENT_IDLE_TIMEOUT {
        let now = Instant::now();
        pending.retain(|_, operation| operation.expires_at > now);
        loop {
            match commands.try_recv() {
                Ok(ClientCommand::Shutdown) => return ConnectedClientExit::Shutdown,
                Ok(ClientCommand::Refresh) => send_list = true,
                Ok(ClientCommand::Wake {
                    host_ids,
                    catalog_version,
                    operation_id,
                    boot_nonce,
                    attempt,
                    retry_ticket,
                }) => {
                    if host_ids.is_empty()
                        || host_ids.len() > crate::protocol::MAX_WAKE_TARGETS
                        || operation_id.iter().all(|byte| *byte == 0)
                    {
                        if !send_client_event(
                            events,
                            ClientEvent::Error("invalid wake request".to_owned()),
                            "invalid wake request",
                        ) {
                            return ConnectedClientExit::Shutdown;
                        }
                        continue;
                    }
                    if pending.len() >= MAX_PENDING_OPERATIONS
                        && !pending.contains_key(&operation_id)
                    {
                        if !send_client_event(
                            events,
                            ClientEvent::Error("too many outstanding wake operations".to_owned()),
                            "wake operation limit",
                        ) {
                            return ConnectedClientExit::Shutdown;
                        }
                        continue;
                    }
                    if let Some(existing) = pending.get(&operation_id)
                        && (attempt < existing.attempt
                            || (attempt == existing.attempt && existing.receipt_seen))
                    {
                        if !send_client_event(
                            events,
                            ClientEvent::Error(
                                "operation_id is already completed or out of order".to_owned(),
                            ),
                            "wake operation ordering",
                        ) {
                            return ConnectedClientExit::Shutdown;
                        }
                        continue;
                    }
                    let pending_targets: HashSet<String> = host_ids.iter().cloned().collect();
                    let envelope = ClientEnvelope {
                        version: PROTOCOL_VERSION,
                        // A stable request ID makes retries idempotent and
                        // lets the actor bind every receipt to one operation.
                        request_id: operation_id,
                        issued_at_ms: now_ms(),
                        headers: configured_headers.to_vec(),
                        operation: ClientOperation::Wake {
                            catalog_version,
                            host_ids,
                            attempt,
                            boot_nonce,
                            retry_ticket,
                        },
                    };
                    if let Err(error) = secure.send_client_envelope(&envelope) {
                        return transport_exit(error);
                    }
                    pending.insert(
                        operation_id,
                        PendingOperation {
                            targets: pending_targets,
                            accepted_targets: None,
                            attempt,
                            ticket: retry_ticket,
                            receipt_seen: false,
                            online: HashSet::new(),
                            deadline_ms: None,
                            expires_at: Instant::now() + PENDING_OPERATION_TTL,
                        },
                    );
                    last_activity = Instant::now();
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return ConnectedClientExit::Shutdown,
            }
        }
        if send_list {
            // A refresh is idempotent from the CLI's perspective.  Do not
            // create an unbounded set of outstanding list requests when a
            // caller repeatedly presses refresh while the peer is slow.
            if pending_requests
                .values()
                .any(|request| matches!(request, PendingRequest::List))
            {
                send_list = false;
            } else {
                let envelope = ClientEnvelope {
                    version: PROTOCOL_VERSION,
                    request_id: random_id(),
                    issued_at_ms: now_ms(),
                    headers: configured_headers.to_vec(),
                    operation: ClientOperation::ListHosts,
                };
                if pending_requests.len() >= MAX_PENDING_REQUESTS {
                    send_client_event(
                        events,
                        ClientEvent::Error("too many outstanding requests".to_owned()),
                        "request limit",
                    );
                    return ConnectedClientExit::Lost {
                        code: ClientConnectionErrorCode::Protocol,
                        message: "客户端待处理请求超过安全上限".to_owned(),
                    };
                }
                pending_requests.insert(envelope.request_id, PendingRequest::List);
                if let Err(error) = secure.send_client_envelope(&envelope) {
                    pending_requests.remove(&envelope.request_id);
                    return transport_exit(error);
                }
                send_list = false;
                last_activity = Instant::now();
            }
        }
        match secure.poll_server_envelope() {
            Ok(Some(envelope)) => {
                last_activity = Instant::now();
                if !handle_server_event(
                    secure,
                    configured_headers,
                    configured_clock_skew,
                    events,
                    envelope,
                    &mut pending,
                    &mut pending_requests,
                ) {
                    return ConnectedClientExit::Lost {
                        code: ClientConnectionErrorCode::Protocol,
                        message: "服务端响应未通过协议状态校验".to_owned(),
                    };
                }
            }
            Ok(None) => {}
            Err(error) => {
                return transport_exit(error);
            }
        }
        thread::sleep(CLIENT_POLL_INTERVAL);
    }
    ConnectedClientExit::Lost {
        code: ClientConnectionErrorCode::Transport,
        message: "安全连接空闲超时".to_owned(),
    }
}

fn transport_exit(error: SecurityError) -> ConnectedClientExit {
    let code = if matches!(error, SecurityError::Protocol(_)) {
        ClientConnectionErrorCode::Protocol
    } else {
        ClientConnectionErrorCode::Transport
    };
    ConnectedClientExit::Lost {
        code,
        message: format!("安全连接中断: {error}"),
    }
}

fn close_connection(secure: &mut crate::security::SecureConnection, context: &'static str) {
    if let Err(error) = secure.close() {
        crate::logging::log(
            crate::logging::Level::Warn,
            format!("secure connection close failed context={context} error={error}"),
        );
    }
}

fn report_connection_failure(
    commands: &Receiver<ClientCommand>,
    events: &SyncSender<ClientEvent>,
    attempt: u32,
    code: ClientConnectionErrorCode,
    message: String,
) -> bool {
    let retry_after = reconnect_delay(attempt);
    if events
        .try_send(ClientEvent::ConnectionFailed {
            attempt,
            code,
            message,
            retry_after,
        })
        .is_err()
    {
        return false;
    }
    wait_for_reconnect(commands, events, retry_after)
}

fn reconnect_delay(attempt: u32) -> Duration {
    let index = attempt
        .saturating_sub(1)
        .min(RECONNECT_DELAYS_SECONDS.len().saturating_sub(1) as u32) as usize;
    Duration::from_secs(RECONNECT_DELAYS_SECONDS[index])
}

fn wait_for_reconnect(
    commands: &Receiver<ClientCommand>,
    events: &SyncSender<ClientEvent>,
    delay: Duration,
) -> bool {
    let deadline = Instant::now() + delay;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        match commands.recv_timeout(remaining) {
            Ok(ClientCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => return false,
            Ok(ClientCommand::Refresh) => {}
            Ok(ClientCommand::Wake { .. }) => {
                if !send_client_event(
                    events,
                    ClientEvent::Error("安全连接尚未建立，未发送唤醒请求".to_owned()),
                    "wake request while disconnected",
                ) {
                    return false;
                }
            }
            Err(RecvTimeoutError::Timeout) => return true,
        }
    }
}

fn handle_server_event(
    secure: &mut crate::security::SecureConnection,
    configured_headers: &[Header],
    configured_clock_skew: Duration,
    events: &SyncSender<ClientEvent>,
    envelope: ServerEnvelope,
    pending: &mut HashMap<[u8; 16], PendingOperation>,
    pending_requests: &mut HashMap<[u8; 16], PendingRequest>,
) -> bool {
    if envelope.headers != configured_headers
        || envelope.issued_at_ms.abs_diff(now_ms())
            > configured_clock_skew.as_millis().min(u64::MAX as u128) as u64
    {
        return reject_server_event(secure, events);
    }
    let request_id = envelope.request_id;
    match envelope.event {
        ServerEvent::Hosts {
            catalog_version,
            hosts,
        } => {
            if !matches!(
                pending_requests.remove(&request_id),
                Some(PendingRequest::List)
            ) {
                return reject_server_event(secure, events);
            }
            let ids: Vec<String> = hosts.iter().map(|host| host.host_id.clone()).collect();
            if !emit_event(
                secure,
                events,
                ClientEvent::Hosts {
                    catalog_version,
                    hosts,
                },
            ) {
                return false;
            }
            if !ids.is_empty() {
                let mut remaining = ids
                    .chunks(crate::protocol::MAX_STATUS_TARGETS)
                    .map(<[String]>::to_vec)
                    .collect::<VecDeque<_>>();
                let first = remaining.pop_front().expect("non-empty host chunks");
                if !send_status_batch(
                    secure,
                    configured_headers,
                    pending_requests,
                    catalog_version,
                    first,
                    remaining,
                ) {
                    send_client_event(
                        events,
                        ClientEvent::Error("failed to request host status".to_owned()),
                        "status request failure",
                    );
                    return false;
                }
            } else {
                if !emit_event(
                    secure,
                    events,
                    ClientEvent::Statuses {
                        catalog_version,
                        statuses: Vec::new(),
                    },
                ) {
                    return false;
                }
            }
        }
        ServerEvent::Statuses {
            catalog_version,
            statuses,
        } => {
            let Some(PendingRequest::Statuses {
                catalog_version: expected_catalog,
                host_ids: expected_hosts,
                mut remaining,
            }) = pending_requests.remove(&request_id)
            else {
                return reject_server_event(secure, events);
            };
            let status_ids: HashSet<String> = statuses
                .iter()
                .map(|status| status.host_id.clone())
                .collect();
            if expected_catalog != catalog_version || status_ids != expected_hosts {
                return reject_server_event(secure, events);
            }
            if !emit_event(
                secure,
                events,
                ClientEvent::Statuses {
                    catalog_version,
                    statuses,
                },
            ) {
                return false;
            }
            if let Some(next) = remaining.pop_front()
                && !send_status_batch(
                    secure,
                    configured_headers,
                    pending_requests,
                    catalog_version,
                    next,
                    remaining,
                )
            {
                return false;
            }
        }
        ServerEvent::CommandExecuted {
            operation_id,
            attempt,
            retry_ticket,
            deadline_ms,
            results,
        } => {
            let Some(operation) = pending.get_mut(&operation_id) else {
                return reject_server_event(secure, events);
            };
            if request_id != operation_id || attempt != operation.attempt {
                return reject_server_event(secure, events);
            }
            if attempt == 2 && operation.ticket != Some(retry_ticket) {
                return reject_server_event(secure, events);
            }
            let now = now_ms();
            let skew_ms = configured_clock_skew.as_millis() as u64;
            if deadline_ms < now.saturating_sub(skew_ms)
                || deadline_ms
                    > now
                        .saturating_add(WAKE_WAIT_TIMEOUT.as_millis() as u64)
                        .saturating_add(skew_ms)
            {
                return reject_server_event(secure, events);
            }
            let result_ids: HashSet<String> = results
                .iter()
                .map(|result| result.host_id.clone())
                .collect();
            if result_ids != operation.targets {
                return reject_server_event(secure, events);
            }
            if operation.receipt_seen {
                // Duplicate authenticated receipts are harmless but should
                // not be surfaced repeatedly to the CLI state machine.
                operation.deadline_ms = Some(deadline_ms);
                return true;
            }
            if attempt == 1 {
                operation.ticket = Some(retry_ticket);
            }
            operation.accepted_targets = Some(
                results
                    .iter()
                    .filter(|result| result.accepted)
                    .map(|result| result.host_id.clone())
                    .collect(),
            );
            operation.receipt_seen = true;
            operation.deadline_ms = Some(deadline_ms);
            if !emit_event(
                secure,
                events,
                ClientEvent::CommandExecuted {
                    operation_id,
                    attempt,
                    retry_ticket,
                    deadline_ms,
                    results,
                },
            ) {
                return false;
            }
        }
        ServerEvent::TargetOnline {
            operation_id,
            attempt,
            host_id,
            observed_at_ms,
        } => {
            let Some(operation) = pending.get(&operation_id) else {
                return reject_server_event(secure, events);
            };
            if request_id != operation_id
                || attempt != operation.attempt
                || !operation
                    .accepted_targets
                    .as_ref()
                    .is_some_and(|targets| targets.contains(&host_id))
                || !operation.receipt_seen
            {
                return reject_server_event(secure, events);
            }
            let now = now_ms();
            if !observation_time_valid(
                observed_at_ms,
                operation.deadline_ms,
                now,
                configured_clock_skew,
            ) {
                return reject_server_event(secure, events);
            }
            let already_online = operation.online.contains(&host_id);
            if already_online {
                return true;
            }
            if let Some(operation) = pending.get_mut(&operation_id) {
                operation.online.insert(host_id.clone());
            }
            if !emit_event(
                secure,
                events,
                ClientEvent::TargetOnline {
                    operation_id,
                    attempt,
                    host_id,
                },
            ) {
                return false;
            }
        }
        ServerEvent::Error { code, retryable } => {
            let known =
                pending_requests.remove(&request_id).is_some() || pending.contains_key(&request_id);
            if !known {
                return reject_server_event(secure, events);
            }
            if !emit_event(
                secure,
                events,
                ClientEvent::Error(format!("server error: {code:?} (retryable={retryable})")),
            ) {
                return false;
            }
        }
    }
    true
}

fn observation_time_valid(observed: u64, deadline: Option<u64>, now: u64, skew: Duration) -> bool {
    let skew = skew.as_millis() as u64;
    let window = WAKE_WAIT_TIMEOUT.as_millis() as u64;
    observed != 0
        && observed <= now.saturating_add(skew)
        && observed >= now.saturating_sub(window.saturating_add(skew))
        && deadline
            .is_some_and(|deadline| observed <= deadline && now <= deadline.saturating_add(skew))
}

fn emit_event(
    secure: &mut crate::security::SecureConnection,
    events: &SyncSender<ClientEvent>,
    event: ClientEvent,
) -> bool {
    if !send_client_event(events, event, "authenticated server event") {
        close_connection(secure, "event queue unavailable");
        return false;
    }
    true
}

fn reject_server_event(
    secure: &mut crate::security::SecureConnection,
    events: &SyncSender<ClientEvent>,
) -> bool {
    close_connection(secure, "protocol rejection");
    send_client_event(
        events,
        ClientEvent::Error("invalid or unsolicited server response".to_owned()),
        "protocol rejection",
    );
    false
}

fn send_client_event(
    events: &SyncSender<ClientEvent>,
    event: ClientEvent,
    context: &'static str,
) -> bool {
    match events.try_send(event) {
        Ok(()) => true,
        Err(std::sync::mpsc::TrySendError::Full(_)) => {
            crate::logging::log(
                crate::logging::Level::Warn,
                format!("client event not delivered context={context} reason=queue full"),
            );
            false
        }
        // Dropping ClientHandle is the consumer's explicit shutdown signal.
        // The actor already treats this as a terminal state, not an error.
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
    }
}

enum PendingRequest {
    List,
    Statuses {
        catalog_version: u64,
        host_ids: HashSet<String>,
        remaining: VecDeque<Vec<String>>,
    },
}

fn send_status_batch(
    secure: &mut crate::security::SecureConnection,
    configured_headers: &[Header],
    pending_requests: &mut HashMap<[u8; 16], PendingRequest>,
    catalog_version: u64,
    host_ids: Vec<String>,
    remaining: VecDeque<Vec<String>>,
) -> bool {
    if pending_requests.len() >= MAX_PENDING_REQUESTS || host_ids.is_empty() {
        close_connection(secure, "status request failure");
        return false;
    }
    let request = ClientEnvelope {
        version: PROTOCOL_VERSION,
        request_id: random_id(),
        issued_at_ms: now_ms(),
        headers: configured_headers.to_vec(),
        operation: ClientOperation::GetStatuses {
            catalog_version,
            host_ids: host_ids.clone(),
        },
    };
    pending_requests.insert(
        request.request_id,
        PendingRequest::Statuses {
            catalog_version,
            host_ids: host_ids.into_iter().collect(),
            remaining,
        },
    );
    if secure.send_client_envelope(&request).is_err() {
        pending_requests.remove(&request.request_id);
        close_connection(secure, "server error response");
        return false;
    }
    true
}

struct PendingOperation {
    targets: HashSet<String>,
    accepted_targets: Option<HashSet<String>>,
    attempt: u8,
    ticket: Option<[u8; 32]>,
    receipt_seen: bool,
    online: HashSet<String>,
    deadline_ms: Option<u64>,
    expires_at: std::time::Instant,
}

pub fn headers_from_map(map: &BTreeMap<String, String>) -> Result<Vec<Header>, ClientError> {
    let mut headers = Vec::with_capacity(map.len());
    for (name, value) in map {
        validate_header(name, value)?;
        headers.push(Header {
            name: name.clone(),
            value: value.clone(),
        });
    }
    Ok(crate::protocol::canonical_headers(headers).map_err(SecurityError::from)?)
}

fn resolve_endpoints(address: &str, port: u16) -> Result<Vec<SocketAddr>, ClientError> {
    if port < 1024 || crate::config::validate_endpoint(address).is_err() {
        return Err(ClientError::Endpoint);
    }
    if let Ok(ip) = address.parse::<IpAddr>() {
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(ClientError::Endpoint);
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let resolved = (address, port)
        .to_socket_addrs()
        .map_err(|_| ClientError::Endpoint)?;
    let mut endpoints = Vec::new();
    for endpoint in
        resolved.filter(|endpoint| !endpoint.ip().is_unspecified() && !endpoint.ip().is_multicast())
    {
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
        if endpoints.len() == 16 {
            break;
        }
    }
    if endpoints.is_empty() {
        Err(ClientError::Endpoint)
    } else {
        Ok(endpoints)
    }
}

fn connect_endpoints(
    endpoints: &[SocketAddr],
    commands: &Receiver<ClientCommand>,
) -> io::Result<Option<TcpStream>> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut last_error = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no resolved server address",
    );
    for (index, endpoint) in endpoints.iter().enumerate() {
        match commands.try_recv() {
            Ok(ClientCommand::Shutdown) | Err(TryRecvError::Disconnected) => return Ok(None),
            Ok(_) | Err(TryRecvError::Empty) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let budget = remaining / (endpoints.len() - index) as u32;
        match TcpStream::connect_timeout(endpoint, budget) {
            Ok(stream) => return Ok(Some(stream)),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

pub fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    if id.iter().all(|byte| *byte == 0) {
        id[0] = 1;
    }
    id
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// Build a client-facing configuration from a TOML file and optional CLI
/// endpoint overrides.  The server private key is intentionally never used.
pub fn load_runtime(
    path: &Path,
    address_override: Option<String>,
    port_override: Option<u16>,
) -> Result<ClientRuntimeConfig, ClientError> {
    let mut config = crate::config::AppConfig::load_unvalidated(path)?;
    // A client process must never ingest a server private identity.  A copied
    // server TOML is rejected rather than silently converted, so an operator
    // cannot accidentally deploy the same signing material in both roles.
    if !config.security.server_static_private_key.trim().is_empty() {
        return Err(ClientError::Credential);
    }
    // The server public key in the settings file is not a client credential;
    // the pinned key comes from the separately provisioned bundle.  Clear all
    // server-side authority before constructing the runtime snapshot.
    config.security.server_static_private_key.clear();
    config.security.server_static_public_key.clear();
    config.security.allowed_clients.clear();
    config.hosts.clear();
    if let Some(address) = address_override {
        config.client.address = address;
    }
    if let Some(port) = port_override {
        config.client.port = port;
    }
    // Always use the role-separated bundle.  Accepting credentials embedded in
    // the general settings file would make a copied TOML a bearer credential.
    let (_credential_file, bundle) = load_portable_bundle(path)?;
    let device_label = apply_credential_bundle(&mut config, bundle)?;
    ClientRuntimeConfig::from_config_with_label(&config, device_label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_fallback_reaches_second_address_and_honors_shutdown() {
        let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
        let first = unavailable.local_addr().unwrap();
        drop(unavailable);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = listener.local_addr().unwrap();
        let (commands, receiver) = mpsc::channel();
        let connected = connect_endpoints(&[first, second], &receiver)
            .unwrap()
            .unwrap();
        assert_eq!(connected.peer_addr().unwrap(), second);
        commands.send(ClientCommand::Shutdown).unwrap();
        assert!(connect_endpoints(&[second], &receiver).unwrap().is_none());
    }

    #[test]
    fn online_observation_respects_configured_clock_skew() {
        let now = 1_000_000;
        for seconds in [1, 5, 30, 60] {
            let skew = Duration::from_secs(seconds);
            let ms = seconds * 1000;
            assert!(observation_time_valid(
                now + ms,
                Some(now + ms + 60_000),
                now,
                skew
            ));
            assert!(!observation_time_valid(
                now + ms + 1,
                Some(now + ms + 60_000),
                now,
                skew
            ));
            assert!(observation_time_valid(now - ms, Some(now - ms), now, skew));
            assert!(!observation_time_valid(
                now - ms - 1,
                Some(now - ms - 1),
                now,
                skew
            ));
            assert!(!observation_time_valid(now + 1, Some(now), now, skew));
        }
    }
    use std::{net::TcpListener, sync::mpsc::RecvTimeoutError};

    #[test]
    fn portable_bundle_rejects_an_id_that_does_not_match_its_key() {
        let (static_private_key, static_public_key) = crate::config::generate_identity_pair();
        let (_, server_public_key) = crate::config::generate_identity_pair();
        let bundle = CredentialBundle {
            version: CREDENTIAL_VERSION,
            client_id: "old-school-laptop".to_owned(),
            device_label: "issued-at-school".to_owned(),
            shared_secret: format!("hex:{}", "11".repeat(32)),
            static_private_key,
            static_public_key,
            pinned_server_static_key: server_public_key,
            custom_headers: BTreeMap::new(),
        };
        assert!(matches!(bundle.validate(), Err(ClientError::Credential)));
    }

    #[test]
    fn runtime_derives_identity_id_and_keeps_label_as_metadata() {
        let (static_private_key, static_public_key) = crate::config::generate_identity_pair();
        let (_, server_public_key) = crate::config::generate_identity_pair();
        let public = crate::config::decode_key(&static_public_key).expect("public key");
        let expected_id = crate::security::client_id_from_public_key(&public);
        let bundle = CredentialBundle {
            version: CREDENTIAL_VERSION,
            client_id: expected_id.clone(),
            device_label: "original-windows-name".to_owned(),
            shared_secret: format!("hex:{}", "22".repeat(32)),
            static_private_key,
            static_public_key,
            pinned_server_static_key: server_public_key,
            custom_headers: BTreeMap::new(),
        };
        let mut config = crate::config::AppConfig::default();
        config.client.address = "127.0.0.1".to_owned();
        let label = apply_credential_bundle(&mut config, bundle).expect("apply bundle");
        let runtime =
            ClientRuntimeConfig::from_config_with_label(&config, label).expect("runtime config");
        assert_eq!(runtime.client_id, expected_id);
        assert_eq!(
            runtime.device_label.as_deref(),
            Some("original-windows-name")
        );
    }

    #[test]
    fn revocation_deletes_only_the_matching_issued_bundle() {
        let directory = std::env::temp_dir().join(format!(
            "remote-open-power-revoke-bundle-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&directory).expect("create credential test directory");
        let path = directory.join("portable.credential.toml");
        let (static_private_key, static_public_key) = crate::config::generate_identity_pair();
        let (_, server_public_key) = crate::config::generate_identity_pair();
        let public = crate::config::decode_key(&static_public_key).expect("client public key");
        let bundle = CredentialBundle {
            version: CREDENTIAL_VERSION,
            client_id: crate::security::client_id_from_public_key(&public),
            device_label: "portable".to_owned(),
            shared_secret: format!("hex:{}", "33".repeat(32)),
            static_private_key,
            static_public_key: static_public_key.clone(),
            pinned_server_static_key: server_public_key,
            custom_headers: BTreeMap::new(),
        };
        save_credential_bundle(&path, &bundle).expect("save credential bundle");

        let (_, unrelated_public_key) = crate::config::generate_identity_pair();
        assert!(matches!(
            remove_issued_credential_bundle(&path, &unrelated_public_key),
            Err(ClientError::Credential)
        ));
        assert!(path.is_file());
        assert!(
            remove_issued_credential_bundle(&path, &static_public_key)
                .expect("remove matching credential")
        );
        assert!(!path.exists());
        std::fs::remove_dir(&directory).expect("remove credential test directory");
    }

    #[test]
    fn reconnect_backoff_is_bounded() {
        assert_eq!(reconnect_delay(1), Duration::from_secs(2));
        assert_eq!(reconnect_delay(2), Duration::from_secs(5));
        assert_eq!(reconnect_delay(5), Duration::from_secs(30));
        assert_eq!(reconnect_delay(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn unreachable_server_reports_failure_then_retries() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve port");
        let port = listener.local_addr().expect("listener address").port();
        drop(listener);
        let runtime = ClientRuntimeConfig {
            address: "127.0.0.1".to_owned(),
            port,
            client_id: "a".repeat(64),
            psk: [7; 32],
            identity: Identity::generate().expect("client identity"),
            pinned_server_key: [9; 32],
            headers: Vec::new(),
            clock_skew: Duration::from_secs(30),
            device_label: None,
        };
        let mut handle = spawn_client(runtime).expect("client worker");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut saw_first_attempt = false;
        let mut saw_failure = false;
        let mut saw_retry = false;
        while Instant::now() < deadline && !saw_retry {
            match handle.events.recv_timeout(Duration::from_millis(250)) {
                Ok(ClientEvent::Connecting { attempt: 1 }) if !saw_failure => {
                    saw_first_attempt = true;
                }
                Ok(ClientEvent::ConnectionFailed {
                    attempt: 1,
                    code: ClientConnectionErrorCode::Connect,
                    retry_after,
                    ..
                }) => {
                    assert_eq!(retry_after, Duration::from_secs(2));
                    saw_failure = true;
                }
                Ok(ClientEvent::Connecting { attempt: 2 }) => saw_retry = true,
                Ok(ClientEvent::Connected { .. }) => panic!("unreachable endpoint connected"),
                Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        handle.shutdown().expect("client shutdown");
        assert!(saw_first_attempt);
        assert!(saw_failure);
        assert!(saw_retry);
    }
}
