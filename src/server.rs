//! Bounded server runtime for the authenticated RemoteOpenPower protocol.
//!
//! The runtime deliberately keeps all authority on the server side.  A client
//! can name only opaque host ids from the authenticated catalog; MAC addresses,
//! IP addresses and operating-system commands never cross this boundary.
//!
//! This module uses the standard-library thread model so it can be embedded by
//! the CLI without imposing an async runtime. The connection and ledger caps
//! are intentionally conservative. The ledger suppresses duplicate work only
//! in the running process; it never schedules a retry. Only an authenticated
//! client request can advance a wake operation from attempt one to attempt two.

use crate::{
    config::{AppConfig, ConfigError, HostConfig},
    logging::{self, Level},
    probe::{PlatformStatusProbe, StatusProbe},
    protocol::{
        ClientEnvelope, ClientOperation, ErrorCode, Header, HostState, HostStatus, HostSummary,
        MAX_FRAME_BYTES, MAX_STATUS_TARGETS, MAX_WAKE_TARGETS, PROTOCOL_VERSION, ServerEnvelope,
        ServerEvent, WakeErrorCode, WakeResult, canonical_headers, decode, encode,
    },
    security::{
        ReplayCache, SecureConnection, SecurityError, ServerHandshakeConfig, fingerprint,
        random_id, server_handshake,
    },
    wol::{PlatformWakeSender, WakeError, WakeSender},
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    io,
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const MAX_CONNECTIONS: usize = 64;
const MAX_CONCURRENT_HANDSHAKES: usize = 16;
const MAX_PENDING_HANDSHAKES_PER_IP: usize = 2;
const MAX_CONNECTIONS_PER_IP: usize = 8;
const MAX_CONNECTIONS_PER_CLIENT: usize = 4;
const _: () = assert!(MAX_PENDING_HANDSHAKES_PER_IP < MAX_CONCURRENT_HANDSHAKES);
const MAX_RATE_KEYS: usize = 2_048;
const HANDSHAKE_RATE_PER_MINUTE: u32 = 12;
const OPERATION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(3_600);
const MAX_APP_PAYLOAD: usize = 32 * 1024;
const REQUEST_SKEW: Duration = Duration::from_secs(60);
const LEDGER_TTL: Duration = Duration::from_secs(15 * 60);
const PENDING_LEDGER_TTL: Duration = Duration::from_secs(2 * 60);
const RETRY_TTL: Duration = Duration::from_secs(90);
const MONITOR_TIMEOUT: Duration = Duration::from_secs(60);
const MONITOR_INTERVAL: Duration = Duration::from_secs(1);
const WAKE_COOLDOWN: Duration = Duration::from_secs(10);
const MAX_LEDGER_ENTRIES: usize = 4_096;
const MAX_LEDGER_ENTRIES_PER_CLIENT: usize = 256;
const MAX_MONITORS_PER_CONNECTION: usize = 4;
const MAX_CONCURRENT_PROBES: usize = 8;
const FRAME_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const KEY_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);
const ACCESS_POLICY_REFRESH_INTERVAL: Duration = Duration::from_millis(250);

// Keep rejection logging useful without allowing an unauthenticated flood to
// turn stdout into an availability or disk-usage attack when redirected.
static LAST_REJECT_LOG_MS: AtomicU64 = AtomicU64::new(0);
static LAST_ACCEPT_LOG_MS: AtomicU64 = AtomicU64::new(0);
static SUPPRESSED_ACCEPT_LOGS: AtomicUsize = AtomicUsize::new(0);
fn log_event(level: &str, message: impl AsRef<str>) {
    let level = match level {
        "INFO" => Level::Info,
        "WARN" => Level::Warn,
        "ERROR" => Level::Error,
        "FATAL" => Level::Fatal,
        _ => Level::Error,
    };
    logging::log(level, message);
}

fn log_rejection(message: impl AsRef<str>) {
    let now = unix_ms();
    let previous = LAST_REJECT_LOG_MS.load(Ordering::Relaxed);
    if now.saturating_sub(previous) < 1_000 {
        return;
    }
    if LAST_REJECT_LOG_MS
        .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        log_event("WARN", message);
    }
}

fn log_accept(peer: SocketAddr) {
    let now = unix_ms();
    let previous = LAST_ACCEPT_LOG_MS.load(Ordering::Relaxed);
    if now.saturating_sub(previous) < 1_000 {
        SUPPRESSED_ACCEPT_LOGS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if LAST_ACCEPT_LOG_MS
        .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        let suppressed = SUPPRESSED_ACCEPT_LOGS.swap(0, Ordering::Relaxed);
        if suppressed == 0 {
            log_event("INFO", format!("accepted peer={peer}"));
        } else {
            log_event(
                "INFO",
                format!("accepted peer={peer} suppressed_accepts={suppressed}"),
            );
        }
    } else {
        SUPPRESSED_ACCEPT_LOGS.fetch_add(1, Ordering::Relaxed);
    }
}

fn short_key(key: &[u8; 32]) -> String {
    fingerprint(key).chars().take(16).collect()
}

fn short_request(request_id: &[u8; 16]) -> String {
    hex::encode(request_id).chars().take(12).collect()
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(value) => value.to_ipv4_mapped().map_or_else(
            || {
                let prefix = u128::from(value) & (u128::MAX << 64);
                IpAddr::V6(std::net::Ipv6Addr::from(prefix))
            },
            IpAddr::V4,
        ),
        IpAddr::V4(_) => ip,
    }
}

fn operation_name(operation: &ClientOperation) -> &'static str {
    match operation {
        ClientOperation::ListHosts => "list-hosts",
        ClientOperation::GetStatuses { .. } => "get-statuses",
        ClientOperation::Wake { attempt: 1, .. } => "wake",
        ClientOperation::Wake { .. } => "wake-retry",
    }
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("configuration error")]
    Config(#[from] ConfigError),
    #[error("security error")]
    Security(#[from] SecurityError),
    #[error("protocol error")]
    Protocol(#[from] crate::protocol::ProtocolError),
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("invalid server configuration: {0}")]
    Invalid(String),
}

#[derive(Clone)]
struct HostEntry {
    id: String,
    config: HostConfig,
}

struct Snapshot {
    bind_addrs: Vec<SocketAddr>,
    dual_stack: bool,
    headers: Vec<Header>,
    hosts: HashMap<String, HostEntry>,
    summaries: Vec<HostSummary>,
    catalog_version: u64,
    max_requests_per_minute: u32,
    clock_skew: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientAccess {
    allowed_hosts: HashSet<String>,
}

struct AccessPolicy {
    clients: HashMap<[u8; 32], ClientAccess>,
    source_healthy: bool,
}

impl AccessPolicy {
    fn new(clients: HashMap<[u8; 32], ClientAccess>) -> Self {
        Self {
            clients,
            source_healthy: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum RateKey {
    HandshakeIp(IpAddr),
    Ip(IpAddr),
    Client([u8; 32]),
}

#[derive(Clone, Copy)]
struct RateBucket {
    started: Instant,
    count: u32,
}

struct RateLimiter {
    buckets: Mutex<HashMap<RateKey, RateBucket>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, key: RateKey, limit: u32, window: Duration) -> bool {
        let now = Instant::now();
        let mut buckets = match self.buckets.lock() {
            Ok(value) => value,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Keep the map bounded even when an attacker rotates source
        // addresses.  Expired buckets carry no useful state.
        buckets.retain(|_, bucket| now.duration_since(bucket.started) < window);
        if buckets.len() >= MAX_RATE_KEYS && !buckets.contains_key(&key) {
            return false;
        }
        let bucket = buckets.entry(key).or_insert(RateBucket {
            started: now,
            count: 0,
        });
        if now.duration_since(bucket.started) >= window {
            bucket.started = now;
            bucket.count = 0;
        }
        if bucket.count >= limit {
            return false;
        }
        bucket.count = bucket.count.saturating_add(1);
        true
    }
}

#[derive(Clone, Default)]
pub struct ServerMetrics {
    active_connections: Arc<AtomicUsize>,
    listening: Arc<AtomicBool>,
}

impl ServerMetrics {
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Acquire)
    }

    pub fn is_listening(&self) -> bool {
        self.listening.load(Ordering::Acquire)
    }

    fn set_listening(&self, listening: bool) {
        self.listening.store(listening, Ordering::Release);
    }
}

struct ListeningGuard(ServerMetrics);

impl Drop for ListeningGuard {
    fn drop(&mut self) {
        self.0.set_listening(false);
    }
}

struct ConnectionLimiter {
    current: Arc<AtomicUsize>,
    limit: usize,
}

impl ConnectionLimiter {
    fn new(limit: usize) -> Self {
        Self::with_counter(limit, Arc::new(AtomicUsize::new(0)))
    }

    fn with_counter(limit: usize, current: Arc<AtomicUsize>) -> Self {
        Self { current, limit }
    }

    fn acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut current = self.current.load(Ordering::Acquire);
        loop {
            if current >= self.limit {
                return None;
            }
            match self.current.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ConnectionPermit(Arc::clone(self))),
                Err(observed) => current = observed,
            }
        }
    }

    fn release(&self) {
        if self
            .current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_sub(1)
            })
            .is_err()
        {
            log_event("ERROR", "connection permit released below zero");
        }
    }
}

struct ConnectionPermit(Arc<ConnectionLimiter>);

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct KeyedConnectionLimiter<K> {
    maximum: usize,
    active: Mutex<HashMap<K, usize>>,
}

impl<K> KeyedConnectionLimiter<K>
where
    K: Copy + Eq + Hash,
{
    fn new(maximum: usize) -> Self {
        Self {
            maximum,
            active: Mutex::new(HashMap::new()),
        }
    }

    fn acquire(self: &Arc<Self>, key: K) -> Option<KeyedConnectionPermit<K>> {
        let mut active = lock(&self.active);
        let count = active.entry(key).or_insert(0);
        if *count >= self.maximum {
            return None;
        }
        *count += 1;
        Some(KeyedConnectionPermit {
            limiter: Arc::clone(self),
            key,
        })
    }

    fn release(&self, key: K) {
        let mut active = lock(&self.active);
        if let Some(count) = active.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&key);
            }
        }
    }
}

struct KeyedConnectionPermit<K>
where
    K: Copy + Eq + Hash,
{
    limiter: Arc<KeyedConnectionLimiter<K>>,
    key: K,
}

impl<K> Drop for KeyedConnectionPermit<K>
where
    K: Copy + Eq + Hash,
{
    fn drop(&mut self) {
        self.limiter.release(self.key);
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct OperationKey {
    client_key: [u8; 32],
    operation_id: [u8; 16],
}

#[derive(Clone)]
struct WakeMeta {
    catalog_version: u64,
    host_ids: Vec<String>,
    boot_nonce: [u8; 16],
    ticket: [u8; 32],
    ticket_expires: Instant,
    ticket_used: bool,
    attempt: u8,
}

struct WakeRetry<'a> {
    digest: [u8; 32],
    catalog_version: u64,
    host_ids: &'a [String],
    boot_nonce: [u8; 16],
    ticket: [u8; 32],
    now: Instant,
}

struct LedgerEntry {
    digest: [u8; 32],
    wake: Option<WakeMeta>,
    response: Option<ServerEnvelope>,
    pending: bool,
    expires: Instant,
}

enum BeginResult {
    New,
    Cached(ServerEnvelope),
    Busy,
    Conflict,
}

enum WakeBeginResult {
    New([u8; 32]),
    Cached(ServerEnvelope),
    Busy,
    Conflict,
    Replay,
}

struct Ledger {
    entries: HashMap<OperationKey, LedgerEntry>,
    tickets: HashMap<[u8; 32], OperationKey>,
}

impl Ledger {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            tickets: HashMap::new(),
        }
    }

    fn prune(&mut self, now: Instant) {
        // A failed worker must not reserve the global ledger forever. Pending
        // work receives a shorter deadline than a completed replay tombstone.
        self.entries.retain(|_, entry| entry.expires > now);
        self.tickets.retain(|ticket, key| {
            self.entries
                .get(key)
                .and_then(|entry| entry.wake.as_ref())
                .is_some_and(|wake| &wake.ticket == ticket && wake.ticket_expires > now)
        });
    }

    fn has_capacity_for(&self, client_key: &[u8; 32]) -> bool {
        self.entries.len() < MAX_LEDGER_ENTRIES
            && self
                .entries
                .keys()
                .filter(|key| &key.client_key == client_key)
                .count()
                < MAX_LEDGER_ENTRIES_PER_CLIENT
    }

    fn begin_request(&mut self, key: OperationKey, digest: [u8; 32], now: Instant) -> BeginResult {
        self.prune(now);
        if let Some(entry) = self.entries.get(&key) {
            if entry.digest != digest {
                return BeginResult::Conflict;
            }
            if entry.pending {
                return BeginResult::Busy;
            }
            if let Some(response) = &entry.response {
                return BeginResult::Cached(response.clone());
            }
            return BeginResult::Busy;
        }
        if !self.has_capacity_for(&key.client_key) {
            return BeginResult::Busy;
        }
        self.entries.insert(
            key,
            LedgerEntry {
                digest,
                wake: None,
                response: None,
                pending: true,
                expires: now + PENDING_LEDGER_TTL,
            },
        );
        BeginResult::New
    }

    fn begin_wake_attempt1(
        &mut self,
        key: OperationKey,
        digest: [u8; 32],
        catalog_version: u64,
        host_ids: Vec<String>,
        boot_nonce: [u8; 16],
        now: Instant,
    ) -> WakeBeginResult {
        self.prune(now);
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.digest != digest {
                return WakeBeginResult::Conflict;
            }
            if entry.pending {
                return WakeBeginResult::Busy;
            }
            if entry.wake.as_ref().is_some_and(|wake| wake.attempt != 1) {
                return WakeBeginResult::Replay;
            }
            if entry
                .wake
                .as_ref()
                .is_some_and(|wake| wake.ticket_expires <= now)
            {
                return WakeBeginResult::Replay;
            }
            if let Some(response) = &entry.response {
                return WakeBeginResult::Cached(response.clone());
            }
            return WakeBeginResult::Busy;
        }
        if !self.has_capacity_for(&key.client_key) {
            return WakeBeginResult::Busy;
        }
        let ticket = random_ticket();
        // This is a transient in-process reservation, not a completed-send
        // record and not a recovery instruction. It only prevents concurrent
        // copies of the same authenticated request from dispatching twice.
        let wake = WakeMeta {
            catalog_version,
            host_ids,
            boot_nonce,
            ticket,
            ticket_expires: now + RETRY_TTL,
            ticket_used: false,
            attempt: 1,
        };
        self.entries.insert(
            key,
            LedgerEntry {
                digest,
                wake: Some(wake),
                response: None,
                pending: true,
                expires: now + PENDING_LEDGER_TTL,
            },
        );
        self.tickets.insert(ticket, key);
        WakeBeginResult::New(ticket)
    }

    fn begin_wake_attempt2(&mut self, key: OperationKey, retry: WakeRetry<'_>) -> WakeBeginResult {
        let WakeRetry {
            digest,
            catalog_version,
            host_ids,
            boot_nonce,
            ticket,
            now,
        } = retry;
        self.prune(now);
        if self.tickets.get(&ticket) != Some(&key) {
            return WakeBeginResult::Replay;
        }
        let Some(entry) = self.entries.get_mut(&key) else {
            return WakeBeginResult::Replay;
        };
        if entry.digest != digest {
            return WakeBeginResult::Conflict;
        }
        if entry.pending {
            return WakeBeginResult::Busy;
        }
        if let Some(response) = &entry.response
            && entry.wake.as_ref().is_some_and(|wake| wake.attempt >= 2)
        {
            return WakeBeginResult::Cached(response.clone());
        }
        let Some(wake) = entry.wake.as_mut() else {
            return WakeBeginResult::Replay;
        };
        if wake.catalog_version != catalog_version
            || wake.host_ids != host_ids
            || wake.boot_nonce != boot_nonce
            || wake.attempt != 1
            || wake.ticket != ticket
            || wake.ticket_used
            || wake.ticket_expires <= now
        {
            return WakeBeginResult::Replay;
        }
        wake.ticket_used = true;
        wake.attempt = 2;
        entry.pending = true;
        entry.response = None;
        entry.expires = now + PENDING_LEDGER_TTL;
        WakeBeginResult::New(ticket)
    }

    fn complete(&mut self, key: OperationKey, response: ServerEnvelope, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&key) {
            // Give the client a full retry window starting when execution has
            // completed and its receipt is ready, rather than when dispatch
            // was merely reserved.
            if let Some(wake) = entry.wake.as_mut()
                && wake.attempt == 1
                && !wake.ticket_used
            {
                wake.ticket_expires = now + RETRY_TTL;
            }
            entry.pending = false;
            entry.response = Some(response);
            entry.expires = now + LEDGER_TTL;
        }
    }
}

#[derive(Clone)]
struct Monitor {
    operation_id: [u8; 16],
    attempt: u8,
    targets: Vec<(String, HostConfig)>,
    online: HashSet<String>,
    next_probe: Instant,
    deadline: Instant,
}

type WakeCooldowns = HashMap<[u8; 32], HashMap<String, Instant>>;

fn client_access_from_config(
    config: &AppConfig,
) -> Result<HashMap<[u8; 32], ClientAccess>, ServerError> {
    let mut clients = HashMap::with_capacity(config.security.allowed_clients.len());
    for client in &config.security.allowed_clients {
        let key = crate::config::decode_key(&client.static_public_key)
            .map_err(|_| ServerError::Invalid("invalid client ACL key".to_owned()))?;
        let allowed_hosts = client
            .allowed_hosts
            .iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .collect();
        clients.insert(key, ClientAccess { allowed_hosts });
    }
    Ok(clients)
}

#[derive(Clone)]
pub struct ServerRuntime {
    snapshot: Arc<Snapshot>,
    handshake: Arc<ServerHandshakeConfig>,
    replay_cache: ReplayCache,
    wake_sender: Arc<dyn WakeSender>,
    probe: Arc<dyn StatusProbe>,
    probe_slots: Arc<ConnectionLimiter>,
    connections: Arc<ConnectionLimiter>,
    handshakes: Arc<ConnectionLimiter>,
    pending_handshakes: Arc<KeyedConnectionLimiter<IpAddr>>,
    ip_connections: Arc<KeyedConnectionLimiter<IpAddr>>,
    client_connections: Arc<KeyedConnectionLimiter<[u8; 32]>>,
    handshake_rates: Arc<RateLimiter>,
    request_rates: Arc<RateLimiter>,
    ledger: Arc<Mutex<Ledger>>,
    last_wake: Arc<Mutex<WakeCooldowns>>,
    access_policy: Arc<Mutex<AccessPolicy>>,
    access_policy_source: Option<Arc<PathBuf>>,
    metrics: ServerMetrics,
}

impl ServerRuntime {
    /// Build a runtime from already validated configuration and dependencies.
    ///
    /// `wake_sender` and `probe` are trait objects so tests can inject bounded,
    /// side-effect-free implementations.  The listener is not opened until
    /// [`Self::run`] is called.
    pub fn new_with_components(
        config: AppConfig,
        handshake: ServerHandshakeConfig,
        wake_sender: Arc<dyn WakeSender>,
        probe: Arc<dyn StatusProbe>,
    ) -> Result<Self, ServerError> {
        Self::new_with_components_and_metrics(
            config,
            handshake,
            wake_sender,
            probe,
            ServerMetrics::default(),
        )
    }

    fn new_with_components_and_metrics(
        config: AppConfig,
        handshake: ServerHandshakeConfig,
        wake_sender: Arc<dyn WakeSender>,
        probe: Arc<dyn StatusProbe>,
        metrics: ServerMetrics,
    ) -> Result<Self, ServerError> {
        config.validate()?;
        if !config.client.address.trim().is_empty()
            || !config.client.client_id.trim().is_empty()
            || !config.client.static_private_key.trim().is_empty()
            || !config.client.static_public_key.trim().is_empty()
            || !config.client.pinned_server_static_key.trim().is_empty()
        {
            return Err(ServerError::Invalid(
                "server runtime requires a server-only configuration".to_owned(),
            ));
        }
        let configured_psk = config.secret_key()?;
        if handshake.psk.iter().all(|byte| *byte == 0) {
            return Err(ServerError::Invalid("PSK cannot be all zero".to_owned()));
        }
        if handshake.psk != configured_psk {
            return Err(ServerError::Invalid(
                "handshake PSK does not match configuration".to_owned(),
            ));
        }
        let configured_server_key =
            crate::config::decode_key(&config.security.server_static_public_key)
                .map_err(|_| ServerError::Invalid("server identity is missing".to_owned()))?;
        if handshake.identity.public != configured_server_key {
            return Err(ServerError::Invalid(
                "handshake identity does not match configuration".to_owned(),
            ));
        }
        if handshake.clock_skew
            != Duration::from_secs(config.security.clock_skew_seconds.clamp(1, 60))
        {
            return Err(ServerError::Invalid(
                "handshake clock policy does not match configuration".to_owned(),
            ));
        }
        if handshake.allowed_clients.len() != config.security.allowed_clients.len() {
            return Err(ServerError::Invalid(
                "handshake ACL does not match configuration".to_owned(),
            ));
        }
        for configured in &config.security.allowed_clients {
            let key = crate::config::decode_key(&configured.static_public_key)
                .map_err(|_| ServerError::Invalid("invalid client ACL key".to_owned()))?;
            let expected_hosts: HashSet<String> = configured
                .allowed_hosts
                .iter()
                .map(|host| host.trim().to_ascii_lowercase())
                .collect();
            let Some(runtime_client) = handshake.allowed_clients.iter().find(|candidate| {
                candidate
                    .client_id
                    .eq_ignore_ascii_case(&configured.client_id)
            }) else {
                return Err(ServerError::Invalid(
                    "handshake ACL client mismatch".to_owned(),
                ));
            };
            if runtime_client.static_public_key != key
                || runtime_client.allowed_hosts != expected_hosts
            {
                return Err(ServerError::Invalid(
                    "handshake ACL entry mismatch".to_owned(),
                ));
            }
        }
        let access_clients = client_access_from_config(&config)?;
        let ip = config
            .server
            .bind_address
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| ServerError::Invalid("bind_address must be an IP literal".to_owned()))?;
        let bind_addrs = if config.server.dual_stack {
            let ipv4 = config
                .server
                .bind_address_v4
                .trim()
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| {
                    ServerError::Invalid(
                        "dual-stack IPv4 bind address must be an IP literal".to_owned(),
                    )
                })?;
            vec![
                SocketAddr::new(IpAddr::V4(ipv4), config.server.port),
                SocketAddr::new(ip, config.server.port),
            ]
        } else {
            vec![SocketAddr::new(ip, config.server.port)]
        };

        let headers = config
            .security
            .custom_headers
            .iter()
            .map(|(name, value)| Header {
                name: name.clone(),
                value: value.clone(),
            })
            .collect::<Vec<_>>();
        let headers = canonical_headers(headers)?;
        if canonical_headers(handshake.headers.clone())? != headers {
            return Err(ServerError::Invalid(
                "handshake and application custom headers differ".to_owned(),
            ));
        }

        let mut hosts = HashMap::with_capacity(config.hosts.len());
        let mut summaries = Vec::with_capacity(config.hosts.len());
        for host in &config.hosts {
            let host = host.clone();
            host.validate(config.security.allow_public_targets)?;
            let id = host.host_id();
            if id.is_empty() || hosts.contains_key(&id) {
                return Err(ServerError::Invalid(
                    "duplicate or empty host id".to_owned(),
                ));
            }
            let summary = directory_summary(&host);
            let entry = HostEntry {
                id: id.clone(),
                config: host,
            };
            hosts.insert(id, entry);
            summaries.push(summary);
        }
        summaries.sort_by(|left, right| left.host_id.cmp(&right.host_id));
        let catalog_version = catalog_version(&summaries);

        Ok(Self {
            snapshot: Arc::new(Snapshot {
                bind_addrs,
                dual_stack: config.server.dual_stack,
                headers,
                hosts,
                summaries,
                catalog_version,
                max_requests_per_minute: config.security.max_requests_per_minute,
                clock_skew: Duration::from_secs(config.security.clock_skew_seconds.min(60)),
            }),
            handshake: Arc::new(handshake),
            replay_cache: ReplayCache::default(),
            wake_sender,
            probe,
            probe_slots: Arc::new(ConnectionLimiter::new(MAX_CONCURRENT_PROBES)),
            connections: Arc::new(ConnectionLimiter::with_counter(
                MAX_CONNECTIONS,
                Arc::clone(&metrics.active_connections),
            )),
            handshakes: Arc::new(ConnectionLimiter::new(MAX_CONCURRENT_HANDSHAKES)),
            pending_handshakes: Arc::new(KeyedConnectionLimiter::new(
                MAX_PENDING_HANDSHAKES_PER_IP,
            )),
            ip_connections: Arc::new(KeyedConnectionLimiter::new(MAX_CONNECTIONS_PER_IP)),
            client_connections: Arc::new(KeyedConnectionLimiter::new(MAX_CONNECTIONS_PER_CLIENT)),
            handshake_rates: Arc::new(RateLimiter::new()),
            request_rates: Arc::new(RateLimiter::new()),
            ledger: Arc::new(Mutex::new(Ledger::new())),
            last_wake: Arc::new(Mutex::new(HashMap::new())),
            access_policy: Arc::new(Mutex::new(AccessPolicy::new(access_clients))),
            access_policy_source: None,
            metrics,
        })
    }

    fn with_access_policy_source(mut self, path: PathBuf) -> Self {
        self.access_policy_source = Some(Arc::new(path));
        self
    }

    fn current_allowed_hosts(&self, client_key: &[u8; 32]) -> Option<HashSet<String>> {
        lock(&self.access_policy)
            .clients
            .get(client_key)
            .map(|access| access.allowed_hosts.clone())
    }

    fn client_is_authorized(&self, client_key: &[u8; 32]) -> bool {
        lock(&self.access_policy).clients.contains_key(client_key)
    }

    fn refresh_access_policy(&self) {
        let Some(path) = self.access_policy_source.as_deref() else {
            return;
        };
        let loaded = self.load_access_policy(path);
        let mut policy = lock(&self.access_policy);
        match loaded {
            Ok(clients) => {
                let changed = !policy.source_healthy || policy.clients != clients;
                policy.clients = clients;
                policy.source_healthy = true;
                let client_count = policy.clients.len();
                drop(policy);
                if changed {
                    log_event(
                        "INFO",
                        format!("access policy reloaded clients={client_count}"),
                    );
                }
            }
            Err(error) => {
                let first_failure = policy.source_healthy;
                policy.clients.clear();
                policy.source_healthy = false;
                drop(policy);
                if first_failure {
                    log_event(
                        "ERROR",
                        format!("access policy reload failed; access revoked error={error}"),
                    );
                }
            }
        }
    }

    fn load_access_policy(
        &self,
        path: &Path,
    ) -> Result<HashMap<[u8; 32], ClientAccess>, ServerError> {
        let config = AppConfig::load(path)?;
        if config.secret_key()? != self.handshake.psk
            || !config.client.address.trim().is_empty()
            || !config.client.client_id.trim().is_empty()
            || !config.client.static_private_key.trim().is_empty()
            || !config.client.static_public_key.trim().is_empty()
            || !config.client.pinned_server_static_key.trim().is_empty()
        {
            return Err(ServerError::Invalid(
                "runtime access policy no longer matches the server trust root".to_owned(),
            ));
        }
        let server_key = crate::config::decode_key(&config.security.server_static_public_key)
            .map_err(|_| ServerError::Invalid("server identity is missing".to_owned()))?;
        if server_key != self.handshake.identity.public {
            return Err(ServerError::Invalid(
                "runtime access policy no longer matches the server identity".to_owned(),
            ));
        }
        let headers = config
            .security
            .custom_headers
            .iter()
            .map(|(name, value)| Header {
                name: name.clone(),
                value: value.clone(),
            })
            .collect::<Vec<_>>();
        if canonical_headers(headers)? != self.snapshot.headers {
            return Err(ServerError::Invalid(
                "runtime access policy no longer matches the protocol headers".to_owned(),
            ));
        }
        client_access_from_config(&config)
    }

    /// Bind and serve forever.  Each accepted connection owns one bounded
    /// worker thread; over-limit peers are closed before a handshake is run.
    pub fn run(&self) -> Result<(), ServerError> {
        self.run_with_shutdown(Arc::new(std::sync::atomic::AtomicBool::new(false)))
    }

    /// Serve until `shutdown` is set.  The ordinary daemon entry point uses
    /// [`Self::run`]; the foreground TUI uses this bounded lifecycle so its
    /// stop action can close the listener instead of merely changing screens.
    pub fn run_with_shutdown(
        &self,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), ServerError> {
        log_event(
            "INFO",
            format!(
                "starting protocol=rop/{PROTOCOL_VERSION} security=Noise_IKpsk0+psk2 hosts={} clients={} dual_stack={}",
                self.snapshot.hosts.len(),
                self.handshake.allowed_clients.len(),
                self.snapshot.dual_stack
            ),
        );
        log_event(
            "WARN",
            "wake retry is client-driven; this server never resends automatically",
        );
        let mut listeners = Vec::with_capacity(self.snapshot.bind_addrs.len());
        for address in &self.snapshot.bind_addrs {
            let listener = match bind_listener(*address, false) {
                Ok(listener) => listener,
                Err(error) => {
                    log_event(
                        "ERROR",
                        format!(
                            "listener bind failed address={address} kind={:?}",
                            error.kind()
                        ),
                    );
                    return Err(ServerError::Io(error));
                }
            };
            listener.set_nonblocking(true)?;
            log_event("INFO", format!("listening on {address}"));
            listeners.push(listener);
        }
        self.metrics.set_listening(true);
        let _listening_guard = ListeningGuard(self.metrics.clone());
        let mut next_access_policy_refresh = Instant::now();
        loop {
            if shutdown.load(Ordering::Acquire) {
                log_event("INFO", "listener stopped by operator");
                return Ok(());
            }
            let now = Instant::now();
            if now >= next_access_policy_refresh {
                self.refresh_access_policy();
                next_access_policy_refresh = now + ACCESS_POLICY_REFRESH_INTERVAL;
            }
            let mut accepted = None;
            for listener in &listeners {
                match listener.accept() {
                    Ok(value) => {
                        accepted = Some(value);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if is_transient_accept_error(&error) => {
                        log_rejection(format!("transient accept failure kind={:?}", error.kind()));
                    }
                    Err(error) => {
                        log_event("ERROR", format!("accept failed kind={:?}", error.kind()));
                        return Err(ServerError::Io(error));
                    }
                }
            }
            let Some((stream, peer)) = accepted else {
                thread::sleep(Duration::from_millis(20));
                continue;
            };
            let peer_ip = normalize_ip(peer.ip());
            if !self.handshake_rates.allow(
                RateKey::HandshakeIp(peer_ip),
                HANDSHAKE_RATE_PER_MINUTE,
                Duration::from_secs(60),
            ) {
                shutdown_stream(&stream, peer);
                log_rejection(format!("handshake rate limited peer={peer}"));
                continue;
            }
            let Some(permit) = self.connections.acquire() else {
                shutdown_stream(&stream, peer);
                log_rejection(format!("connection limit reached peer={peer}"));
                continue;
            };
            let Some(ip_permit) = self.ip_connections.acquire(peer_ip) else {
                shutdown_stream(&stream, peer);
                log_rejection(format!("active connection limit reached peer={peer}"));
                continue;
            };
            let Some(pending_handshake_permit) = self.pending_handshakes.acquire(peer_ip) else {
                shutdown_stream(&stream, peer);
                log_rejection(format!("pending handshake limit reached peer={peer}"));
                continue;
            };
            let Some(handshake_permit) = self.handshakes.acquire() else {
                shutdown_stream(&stream, peer);
                log_rejection(format!("handshake concurrency limit reached peer={peer}"));
                continue;
            };
            log_accept(peer);
            let runtime = self.clone();
            let spawn = thread::Builder::new()
                .name("rop-connection".to_owned())
                .spawn(move || {
                    let _permit = permit;
                    let _ip_permit = ip_permit;
                    runtime.handle_connection(
                        stream,
                        peer,
                        handshake_permit,
                        pending_handshake_permit,
                    );
                });
            // On a failed spawn the closure argument (including the stream and
            // permit) is dropped by `spawn`; the listener remains available for
            // subsequent peers.
            if spawn.is_err() {
                log_event(
                    "ERROR",
                    format!("connection worker spawn failed peer={peer}"),
                );
            }
        }
    }

    fn handle_connection(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        handshake_permit: ConnectionPermit,
        pending_handshake_permit: KeyedConnectionPermit<IpAddr>,
    ) {
        let handshake = match server_handshake(stream, &self.handshake, &self.replay_cache) {
            Ok(value) => value,
            Err(_) => {
                log_rejection(format!("handshake rejected peer={peer}"));
                return;
            }
        };
        drop(handshake_permit);
        drop(pending_handshake_permit);
        let client_key = handshake.client_static_public;
        let replay_nonce = handshake.replay_nonce;
        let Some(_client_permit) = self.client_connections.acquire(client_key) else {
            log_rejection(format!(
                "client connection limit reached peer={peer} key={}",
                short_key(&client_key)
            ));
            return;
        };
        let Some(initial_allowed_hosts) = self.current_allowed_hosts(&client_key) else {
            log_rejection(format!(
                "revoked client rejected peer={peer} key={}",
                short_key(&client_key)
            ));
            return;
        };
        let client_id = handshake.client_id.clone();
        log_event(
            "INFO",
            format!(
                "identity accepted peer={peer} client={} key={} awaiting-key-confirmation",
                client_id,
                short_key(&client_key)
            ),
        );
        let mut connection = handshake.connection;
        let started = Instant::now();
        let mut last_activity = started;
        let mut key_confirmed = false;
        let mut partial_frame_started: Option<Instant> = None;
        let mut monitors = Vec::new();
        loop {
            if (!key_confirmed && started.elapsed() >= KEY_CONFIRM_TIMEOUT)
                || started.elapsed() >= MAX_SESSION_LIFETIME
                || last_activity.elapsed() >= OPERATION_IDLE_TIMEOUT
            {
                break;
            }
            if !self.client_is_authorized(&client_key) {
                log_event(
                    "WARN",
                    format!(
                        "revoked client disconnected peer={peer} client={} key={}",
                        client_id,
                        short_key(&client_key)
                    ),
                );
                break;
            }
            if !self.service_monitors(&mut connection, client_key, &mut monitors) {
                break;
            }
            match connection.poll_payload() {
                Ok(Some(payload)) => {
                    last_activity = Instant::now();
                    partial_frame_started = None;
                    if payload.is_empty()
                        || payload.len() > MAX_APP_PAYLOAD
                        || payload.len() > MAX_FRAME_BYTES
                    {
                        log_rejection(format!(
                            "invalid payload peer={peer} client={} bytes={}",
                            client_id,
                            payload.len()
                        ));
                        break;
                    }
                    let envelope: ClientEnvelope = match decode(&payload) {
                        Ok(value) => value,
                        Err(_) => {
                            log_rejection(format!(
                                "invalid request frame peer={peer} client={}",
                                client_id
                            ));
                            self.send_error_for_shutdown(
                                &mut connection,
                                random_id(),
                                ErrorCode::BadRequest,
                                false,
                            );
                            break;
                        }
                    };
                    if envelope.validate().is_err()
                        || !request_time_valid(envelope.issued_at_ms, self.snapshot.clock_skew)
                    {
                        log_rejection(format!(
                            "request validation failed peer={peer} client={} request={}",
                            client_id,
                            short_request(&envelope.request_id)
                        ));
                        self.send_error_for_shutdown(
                            &mut connection,
                            envelope.request_id,
                            ErrorCode::BadRequest,
                            false,
                        );
                        break;
                    }
                    if !key_confirmed {
                        if !self.replay_cache.confirm(client_key, replay_nonce) {
                            log_rejection(format!(
                                "key confirmation expired peer={peer} client={client_id}"
                            ));
                            break;
                        }
                        key_confirmed = true;
                        log_event(
                            "INFO",
                            format!(
                                "authenticated peer={peer} client={} key={} hosts={}",
                                client_id,
                                short_key(&client_key),
                                initial_allowed_hosts.len()
                            ),
                        );
                    }
                    let ip_allowed = self.request_rates.allow(
                        RateKey::Ip(normalize_ip(peer.ip())),
                        self.snapshot.max_requests_per_minute,
                        Duration::from_secs(60),
                    );
                    let client_allowed = self.request_rates.allow(
                        RateKey::Client(client_key),
                        self.snapshot.max_requests_per_minute,
                        Duration::from_secs(60),
                    );
                    if !ip_allowed || !client_allowed {
                        log_rejection(format!(
                            "request rate limited peer={peer} client={} request={}",
                            client_id,
                            short_request(&envelope.request_id)
                        ));
                        self.send_error_for_shutdown(
                            &mut connection,
                            envelope.request_id,
                            ErrorCode::RateLimited,
                            true,
                        );
                        // Do not keep an authenticated peer around as an
                        // encrypted error-response oracle after its quota is
                        // exhausted.  One bounded notice is sufficient.
                        break;
                    }
                    if matches!(&envelope.operation, ClientOperation::Wake { .. })
                        && monitors.len() >= MAX_MONITORS_PER_CONNECTION
                    {
                        log_rejection(format!(
                            "monitor limit reached peer={peer} client={} request={}",
                            client_id,
                            short_request(&envelope.request_id)
                        ));
                        self.send_error_for_shutdown(
                            &mut connection,
                            envelope.request_id,
                            ErrorCode::Busy,
                            true,
                        );
                        break;
                    }
                    let request_id = envelope.request_id;
                    log_event(
                        "INFO",
                        format!(
                            "request peer={peer} client={} operation={} request={}",
                            client_id,
                            operation_name(&envelope.operation),
                            short_request(&request_id)
                        ),
                    );
                    let is_wake_retry = matches!(
                        &envelope.operation,
                        ClientOperation::Wake { attempt: 2, .. }
                    );
                    let operation_key = OperationKey {
                        client_key,
                        operation_id: request_id,
                    };
                    let Some(allowed_hosts) = self.current_allowed_hosts(&client_key) else {
                        log_event(
                            "WARN",
                            format!(
                                "revoked client request rejected peer={peer} client={} key={}",
                                client_id,
                                short_key(&client_key)
                            ),
                        );
                        break;
                    };
                    match self.process_envelope(
                        &mut connection,
                        client_key,
                        &allowed_hosts,
                        envelope,
                    ) {
                        Ok(Some(monitor)) => {
                            // A retry supersedes the first attempt.  Keep
                            // only the newest monitor so a delayed probe from
                            // attempt 1 cannot produce a stale TargetOnline
                            // event after attempt 2 has been accepted.
                            monitors.retain(|old| {
                                old.operation_id != monitor.operation_id
                                    || old.attempt >= monitor.attempt
                            });
                            monitors.push(monitor);
                            log_event(
                                "INFO",
                                format!(
                                    "monitor scheduled client={} operation={} attempt={}",
                                    client_id,
                                    short_request(&request_id),
                                    monitors.last().map_or(0, |value| value.attempt)
                                ),
                            );
                        }
                        Ok(None) => {
                            // Attempt 2 can legitimately have no monitor when
                            // every sender result was rejected (or when the
                            // response was served from the idempotency cache).
                            // Consult the ledger rather than the wire result:
                            // only an accepted/previously accepted retry may
                            // cancel an older attempt.
                            if is_wake_retry && self.wake_attempt(operation_key) == Some(2) {
                                monitors.retain(|old| {
                                    old.operation_id != request_id || old.attempt >= 2
                                });
                            }
                        }
                        Err(_) => {
                            log_rejection(format!(
                                "request failed client={} request={}",
                                client_id,
                                short_request(&request_id)
                            ));
                            break;
                        }
                    }
                }
                Ok(None) => {
                    if connection.buffered_len() > 0 {
                        let started = partial_frame_started.get_or_insert_with(Instant::now);
                        if started.elapsed() >= FRAME_IDLE_TIMEOUT {
                            log_rejection(format!(
                                "partial frame timeout peer={} client={}",
                                peer, client_id
                            ));
                            break;
                        }
                    } else {
                        partial_frame_started = None;
                    }
                    thread::sleep(monitor_sleep(&monitors));
                }
                Err(_) => {
                    log_rejection(format!(
                        "transport closed peer={} client={}",
                        peer, client_id
                    ));
                    break;
                }
            }
        }
        log_event(
            "INFO",
            format!("connection closed peer={peer} client={client_id}"),
        );
    }

    fn process_envelope(
        &self,
        connection: &mut SecureConnection,
        client_key: [u8; 32],
        allowed_hosts: &HashSet<String>,
        envelope: ClientEnvelope,
    ) -> Result<Option<Monitor>, ServerError> {
        // Custom headers are part of the deployment policy, not merely
        // caller-supplied metadata.  Noise authenticates the transport, but
        // it does not make an arbitrary header set equivalent to the server's
        // configured context.  Reject and close on a mismatch so a valid
        // client key cannot silently downgrade policy or split idempotency
        // namespaces by changing headers.
        if envelope.headers != self.snapshot.headers {
            log_rejection(format!(
                "application headers mismatch client={} request={}",
                short_key(&client_key),
                short_request(&envelope.request_id)
            ));
            self.send_error_for_shutdown(
                connection,
                envelope.request_id,
                ErrorCode::Unauthorized,
                false,
            );
            return Err(ServerError::Invalid(
                "application headers mismatch".to_owned(),
            ));
        }
        let key = OperationKey {
            client_key,
            operation_id: envelope.request_id,
        };
        match envelope.operation.clone() {
            ClientOperation::ListHosts => {
                let digest = request_digest_context(&envelope.headers, b"list", 0, &[], None);
                let begin = {
                    let mut ledger = lock(&self.ledger);
                    ledger.begin_request(key, digest, Instant::now())
                };
                match begin {
                    BeginResult::Cached(response) => {
                        self.send_response(connection, response)?;
                    }
                    BeginResult::Busy => {
                        self.send_error(connection, envelope.request_id, ErrorCode::Busy, true)?;
                    }
                    BeginResult::Conflict => {
                        self.send_error(connection, envelope.request_id, ErrorCode::Replay, false)?;
                    }
                    BeginResult::New => {
                        let hosts = self
                            .snapshot
                            .summaries
                            .iter()
                            .filter(|host| allowed_hosts.contains(&host.host_id))
                            .cloned()
                            .collect::<Vec<_>>();
                        log_event(
                            "INFO",
                            format!(
                                "catalog client={} request={} hosts={}",
                                short_key(&client_key),
                                short_request(&envelope.request_id),
                                hosts.len()
                            ),
                        );
                        let response = self.make_response(
                            envelope.request_id,
                            ServerEvent::Hosts {
                                catalog_version: self.snapshot.catalog_version,
                                hosts,
                            },
                        )?;
                        self.complete_request(key, response.clone());
                        self.send_response(connection, response)?;
                    }
                }
                Ok(None)
            }
            ClientOperation::GetStatuses {
                catalog_version,
                host_ids,
            } => {
                if catalog_version != self.snapshot.catalog_version {
                    self.send_error(
                        connection,
                        envelope.request_id,
                        ErrorCode::StaleCatalog,
                        true,
                    )?;
                    return Ok(None);
                }
                let hosts =
                    match self.authorized_hosts(allowed_hosts, &host_ids, MAX_STATUS_TARGETS) {
                        Ok(value) => value,
                        Err(code) => {
                            self.send_error(connection, envelope.request_id, code, false)?;
                            return Ok(None);
                        }
                    };
                let digest = request_digest_context(
                    &envelope.headers,
                    b"status",
                    catalog_version,
                    &host_ids,
                    None,
                );
                let begin = {
                    let mut ledger = lock(&self.ledger);
                    ledger.begin_request(key, digest, Instant::now())
                };
                match begin {
                    BeginResult::Cached(response) => self.send_response(connection, response)?,
                    BeginResult::Busy => {
                        self.send_error(connection, envelope.request_id, ErrorCode::Busy, true)?
                    }
                    BeginResult::Conflict => {
                        self.send_error(connection, envelope.request_id, ErrorCode::Replay, false)?
                    }
                    BeginResult::New => {
                        let statuses = hosts
                            .iter()
                            .map(|entry| HostStatus {
                                host_id: entry.id.clone(),
                                state: match self.probe_online(&entry.config) {
                                    Some(true) => HostState::Online,
                                    Some(false) => HostState::Offline,
                                    None => HostState::Unknown,
                                },
                                observed_at_ms: unix_ms(),
                            })
                            .collect::<Vec<_>>();
                        log_event(
                            "INFO",
                            format!(
                                "status client={} request={} hosts={}",
                                short_key(&client_key),
                                short_request(&envelope.request_id),
                                statuses.len()
                            ),
                        );
                        let response = self.make_response(
                            envelope.request_id,
                            ServerEvent::Statuses {
                                catalog_version: self.snapshot.catalog_version,
                                statuses,
                            },
                        )?;
                        self.complete_request(key, response.clone());
                        self.send_response(connection, response)?;
                    }
                }
                Ok(None)
            }
            ClientOperation::Wake {
                catalog_version,
                host_ids,
                attempt,
                boot_nonce,
                retry_ticket,
            } => {
                if catalog_version != self.snapshot.catalog_version {
                    self.send_error(
                        connection,
                        envelope.request_id,
                        ErrorCode::StaleCatalog,
                        true,
                    )?;
                    return Ok(None);
                }
                let hosts = match self.authorized_hosts(allowed_hosts, &host_ids, MAX_WAKE_TARGETS)
                {
                    Ok(value) => value,
                    Err(code) => {
                        self.send_error(connection, envelope.request_id, code, false)?;
                        return Ok(None);
                    }
                };
                let mut sorted_ids = host_ids.clone();
                sorted_ids.sort_unstable();
                let digest = request_digest_context(
                    &envelope.headers,
                    b"wake",
                    catalog_version,
                    &sorted_ids,
                    Some(&boot_nonce),
                );
                let now = Instant::now();
                let begin = {
                    let mut ledger = lock(&self.ledger);
                    if attempt == 1 {
                        if retry_ticket.is_some() {
                            WakeBeginResult::Replay
                        } else {
                            ledger.begin_wake_attempt1(
                                key,
                                digest,
                                catalog_version,
                                sorted_ids.clone(),
                                boot_nonce,
                                now,
                            )
                        }
                    } else {
                        match retry_ticket {
                            Some(ticket) => ledger.begin_wake_attempt2(
                                key,
                                WakeRetry {
                                    digest,
                                    catalog_version,
                                    host_ids: &sorted_ids,
                                    boot_nonce,
                                    ticket,
                                    now,
                                },
                            ),
                            None => WakeBeginResult::Replay,
                        }
                    }
                };
                let ticket = match begin {
                    WakeBeginResult::Cached(response) => {
                        let monitor = cached_monitor(&response, &hosts);
                        self.send_response(connection, response)?;
                        return Ok(monitor);
                    }
                    WakeBeginResult::Busy => {
                        self.send_error(connection, envelope.request_id, ErrorCode::Busy, true)?;
                        return Ok(None);
                    }
                    WakeBeginResult::Conflict => {
                        self.send_error(connection, envelope.request_id, ErrorCode::Replay, false)?;
                        return Ok(None);
                    }
                    WakeBeginResult::Replay => {
                        self.send_error(connection, envelope.request_id, ErrorCode::Replay, false)?;
                        return Ok(None);
                    }
                    WakeBeginResult::New(ticket) => ticket,
                };
                if !self.reserve_wake_targets(client_key, &sorted_ids) {
                    log_rejection(format!(
                        "wake cooldown/rate limit client={} request={} targets={}",
                        short_key(&client_key),
                        short_request(&envelope.request_id),
                        sorted_ids.len()
                    ));
                    let response = self.make_response(
                        envelope.request_id,
                        ServerEvent::CommandExecuted {
                            operation_id: envelope.request_id,
                            attempt,
                            retry_ticket: ticket,
                            deadline_ms: unix_ms()
                                .saturating_add(MONITOR_TIMEOUT.as_millis() as u64),
                            results: sorted_ids
                                .iter()
                                .map(|host_id| WakeResult {
                                    host_id: host_id.clone(),
                                    accepted: false,
                                    error_code: Some(WakeErrorCode::RateLimited),
                                })
                                .collect(),
                        },
                    )?;
                    self.complete_request(key, response.clone());
                    self.send_response(connection, response)?;
                    return Ok(None);
                }
                let mut results = Vec::with_capacity(hosts.len());
                log_event(
                    "INFO",
                    format!(
                        "wake dispatch client={} request={} attempt={} targets={}",
                        short_key(&client_key),
                        short_request(&envelope.request_id),
                        attempt,
                        hosts.len()
                    ),
                );
                for entry in &hosts {
                    let result = match self.wake_sender.wake(&entry.config) {
                        Ok(()) => WakeResult {
                            host_id: entry.id.clone(),
                            accepted: true,
                            error_code: None,
                        },
                        Err(WakeError::InvalidTarget) => WakeResult {
                            host_id: entry.id.clone(),
                            accepted: false,
                            error_code: Some(WakeErrorCode::InvalidTarget),
                        },
                        Err(WakeError::Io(_)) => WakeResult {
                            host_id: entry.id.clone(),
                            accepted: false,
                            error_code: Some(WakeErrorCode::SenderUnavailable),
                        },
                    };
                    results.push(result);
                }
                let accepted_count = results.iter().filter(|result| result.accepted).count();
                log_event(
                    "INFO",
                    format!(
                        "wake result client={} request={} accepted={}/{}",
                        short_key(&client_key),
                        short_request(&envelope.request_id),
                        accepted_count,
                        results.len()
                    ),
                );
                let deadline_ms = unix_ms().saturating_add(MONITOR_TIMEOUT.as_millis() as u64);
                let response = self.make_response(
                    envelope.request_id,
                    ServerEvent::CommandExecuted {
                        operation_id: envelope.request_id,
                        attempt,
                        retry_ticket: ticket,
                        deadline_ms,
                        results: results.clone(),
                    },
                )?;
                self.complete_request(key, response.clone());
                self.send_response(connection, response)?;
                let monitor_targets = hosts
                    .into_iter()
                    .zip(results)
                    .filter(|(_, result)| result.accepted)
                    .map(|(entry, _)| (entry.id, entry.config))
                    .collect::<Vec<_>>();
                if monitor_targets.is_empty() {
                    return Ok(None);
                }
                Ok(Some(Monitor {
                    operation_id: envelope.request_id,
                    attempt,
                    targets: monitor_targets,
                    online: HashSet::new(),
                    next_probe: Instant::now(),
                    deadline: Instant::now() + MONITOR_TIMEOUT,
                }))
            }
        }
    }

    fn authorized_hosts(
        &self,
        allowed_hosts: &HashSet<String>,
        host_ids: &[String],
        maximum: usize,
    ) -> Result<Vec<HostEntry>, ErrorCode> {
        if host_ids.is_empty() || host_ids.len() > maximum {
            return Err(ErrorCode::BadRequest);
        }
        let mut seen = HashSet::new();
        let mut output = Vec::with_capacity(host_ids.len());
        for host_id in host_ids {
            if !seen.insert(host_id) || !allowed_hosts.contains(host_id) {
                return Err(ErrorCode::Unauthorized);
            }
            let Some(entry) = self.snapshot.hosts.get(host_id) else {
                return Err(ErrorCode::BadRequest);
            };
            output.push(entry.clone());
        }
        Ok(output)
    }

    fn reserve_wake_targets(&self, client_key: [u8; 32], host_ids: &[String]) -> bool {
        let now = Instant::now();
        let mut last = lock(&self.last_wake);
        reserve_wake_targets_for_client(&mut last, client_key, host_ids, now)
    }

    fn make_response(
        &self,
        request_id: [u8; 16],
        event: ServerEvent,
    ) -> Result<ServerEnvelope, ServerError> {
        let response = ServerEnvelope {
            version: PROTOCOL_VERSION,
            request_id,
            issued_at_ms: unix_ms(),
            headers: self.snapshot.headers.clone(),
            event,
        };
        response.validate()?;
        if encode(&response)?.len() > MAX_APP_PAYLOAD {
            return Err(ServerError::Invalid(
                "response exceeds the authenticated transport limit".to_owned(),
            ));
        }
        Ok(response)
    }

    fn send_response(
        &self,
        connection: &mut SecureConnection,
        mut response: ServerEnvelope,
    ) -> Result<(), ServerError> {
        let now = unix_ms();
        response.issued_at_ms = now;
        response.validate()?;
        let bytes = encode(&response)?;
        if bytes.len() > MAX_APP_PAYLOAD {
            return Err(ServerError::Invalid(
                "response exceeds the authenticated transport limit".to_owned(),
            ));
        }
        connection.send_payload(&bytes)?;
        Ok(())
    }

    fn send_error(
        &self,
        connection: &mut SecureConnection,
        request_id: [u8; 16],
        code: ErrorCode,
        retryable: bool,
    ) -> Result<(), ServerError> {
        let response = self.make_response(request_id, ServerEvent::Error { code, retryable })?;
        self.send_response(connection, response)
    }

    fn send_error_for_shutdown(
        &self,
        connection: &mut SecureConnection,
        request_id: [u8; 16],
        code: ErrorCode,
        retryable: bool,
    ) {
        if let Err(error) = self.send_error(connection, request_id, code, retryable) {
            log_event("WARN", format!("error response could not be sent: {error}"));
        }
    }

    fn complete_request(&self, key: OperationKey, response: ServerEnvelope) {
        let mut ledger = lock(&self.ledger);
        ledger.complete(key, response, Instant::now());
    }

    fn wake_attempt(&self, key: OperationKey) -> Option<u8> {
        let ledger = lock(&self.ledger);
        ledger
            .entries
            .get(&key)
            .and_then(|entry| entry.wake.as_ref())
            .map(|wake| wake.attempt)
    }

    fn service_monitors(
        &self,
        connection: &mut SecureConnection,
        client_key: [u8; 32],
        monitors: &mut Vec<Monitor>,
    ) -> bool {
        let now = Instant::now();
        let mut events = Vec::new();
        for monitor in monitors.iter_mut() {
            if self.wake_attempt(OperationKey {
                client_key,
                operation_id: monitor.operation_id,
            }) != Some(monitor.attempt)
            {
                monitor.deadline = now;
                continue;
            }
            if now < monitor.next_probe {
                continue;
            }
            monitor.next_probe = now + MONITOR_INTERVAL;
            for (host_id, host) in &monitor.targets {
                if monitor.online.contains(host_id) {
                    continue;
                }
                if Instant::now() >= monitor.deadline {
                    break;
                }
                if self.probe_online(host) == Some(true) && Instant::now() < monitor.deadline {
                    monitor.online.insert(host_id.clone());
                    events.push((
                        monitor.operation_id,
                        monitor.attempt,
                        host_id.clone(),
                        monitor.deadline,
                    ));
                }
            }
        }
        monitors.retain(|monitor| {
            Instant::now() < monitor.deadline && monitor.online.len() < monitor.targets.len()
        });
        for (operation_id, attempt, host_id, deadline) in events {
            if !self.client_is_authorized(&client_key) {
                return false;
            }
            if Instant::now() >= deadline {
                continue;
            }
            if self.wake_attempt(OperationKey {
                client_key,
                operation_id,
            }) != Some(attempt)
            {
                continue;
            }
            log_event(
                "INFO",
                format!(
                    "target online operation={} attempt={} host={}",
                    short_request(&operation_id),
                    attempt,
                    host_id
                ),
            );
            let response = match self.make_response(
                operation_id,
                ServerEvent::TargetOnline {
                    operation_id,
                    attempt,
                    host_id,
                    observed_at_ms: unix_ms(),
                },
            ) {
                Ok(value) => value,
                Err(_) => return false,
            };
            if self.send_response(connection, response).is_err() {
                return false;
            }
        }
        true
    }

    fn probe_online(&self, host: &HostConfig) -> Option<bool> {
        let _permit = self.probe_slots.acquire()?;
        Some(self.probe.is_online(host))
    }
}

fn cached_monitor(response: &ServerEnvelope, hosts: &[HostEntry]) -> Option<Monitor> {
    let ServerEvent::CommandExecuted {
        operation_id,
        attempt,
        deadline_ms,
        results,
        ..
    } = &response.event
    else {
        return None;
    };
    let accepted = results
        .iter()
        .filter(|result| result.accepted)
        .map(|result| result.host_id.as_str())
        .collect::<HashSet<_>>();
    let targets = hosts
        .iter()
        .filter(|entry| accepted.contains(entry.id.as_str()))
        .map(|entry| (entry.id.clone(), entry.config.clone()))
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return None;
    }
    let remaining_ms = deadline_ms.saturating_sub(unix_ms());
    if remaining_ms == 0 {
        return None;
    }
    Some(Monitor {
        operation_id: *operation_id,
        attempt: *attempt,
        targets,
        online: HashSet::new(),
        next_probe: Instant::now(),
        deadline: Instant::now()
            + Duration::from_millis(remaining_ms.min(MONITOR_TIMEOUT.as_millis() as u64)),
    })
}

/// Bind through socket2 so the dual-stack policy is explicit on every
/// platform. `TcpListener::bind` otherwise leaves IPV6_V6ONLY at an
/// OS-dependent default, which can silently expose or hide IPv4.
fn bind_listener(address: SocketAddr, dual_stack: bool) -> io::Result<TcpListener> {
    let domain = if address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    #[cfg(windows)]
    set_exclusive_address_use(&socket)?;
    // Deliberately leave address reuse disabled.  In particular on Windows,
    // SO_REUSEADDR can let an unprivileged local process compete for a port
    // that belongs to the daemon and turn startup/reconnect into a MITM.
    if address.is_ipv6() {
        socket.set_only_v6(!dual_stack)?;
    }
    socket.bind(&SockAddr::from(address))?;
    socket.listen(128)?;
    socket.set_nonblocking(false)?;
    Ok(socket.into())
}

#[cfg(windows)]
fn set_exclusive_address_use(socket: &Socket) -> io::Result<()> {
    use std::{ffi::c_char, os::windows::io::AsRawSocket};

    const SOL_SOCKET: i32 = 0xffff;
    // Winsock defines SO_EXCLUSIVEADDRUSE as the bitwise complement of
    // SO_REUSEADDR (4), which is exposed by .NET as SocketOptionName(-5).
    const SO_EXCLUSIVEADDRUSE: i32 = -5;
    const SOCKET_ERROR: i32 = -1;
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(
            socket: usize,
            level: i32,
            option_name: i32,
            option_value: *const c_char,
            option_length: i32,
        ) -> i32;
        fn WSAGetLastError() -> i32;
    }

    let enabled: i32 = 1;
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            std::mem::size_of::<i32>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    } else {
        Ok(())
    }
}

fn is_transient_accept_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        return matches!(
            error.raw_os_error(),
            Some(
                libc::ENETDOWN
                    | libc::EPROTO
                    | libc::ENOPROTOOPT
                    | libc::EHOSTDOWN
                    | libc::ENONET
                    | libc::EHOSTUNREACH
                    | libc::EOPNOTSUPP
                    | libc::ENETUNREACH
            )
        );
    }
    #[cfg(not(unix))]
    false
}

fn shutdown_stream(stream: &TcpStream, peer: SocketAddr) {
    if let Err(error) = stream.shutdown(Shutdown::Both)
        && error.kind() != io::ErrorKind::NotConnected
    {
        log_event(
            "WARN",
            format!("failed to close rejected connection peer={peer} error={error}"),
        );
    }
}

/// Start the server using a TOML configuration path and optional bind/port
/// overrides. Interactive setup is the only credential bootstrap path; daemon
/// startup requires an existing, fully validated file and never writes it.
pub fn run_server(
    config_path: &Path,
    bind_override: Option<String>,
    port_override: Option<u16>,
) -> Result<(), ServerError> {
    with_service_logging(config_path, || {
        run_server_inner(config_path, bind_override, port_override)
    })
}

fn run_server_inner(
    config_path: &Path,
    bind_override: Option<String>,
    port_override: Option<u16>,
) -> Result<(), ServerError> {
    let config_path = resolve_server_config_path(config_path)?;
    let mut config = AppConfig::load(&config_path)?;
    if !config.client.address.trim().is_empty()
        || !config.client.client_id.trim().is_empty()
        || !config.client.static_private_key.trim().is_empty()
        || !config.client.static_public_key.trim().is_empty()
        || !config.client.pinned_server_static_key.trim().is_empty()
    {
        return Err(ServerError::Invalid(
            "server mode requires a server-only configuration file; client settings were found"
                .to_owned(),
        ));
    }
    if let Some(bind) = bind_override {
        let bind = bind.trim().to_owned();
        // An explicit IPv4 endpoint cannot provide an IPv6 dual-stack
        // listener.  Treat the override as an intentional narrowing of the
        // exposure surface instead of making the otherwise valid CLI command
        // fail against the default `dual_stack = true` setting.
        if bind.parse::<std::net::Ipv4Addr>().is_ok() {
            config.server.dual_stack = false;
        }
        config.server.bind_address = bind;
    }
    if let Some(port) = port_override {
        config.server.port = port;
    }
    config.validate()?;

    let psk = config.secret_key()?;
    let identity = crate::security::Identity::from_hex(
        &config.security.server_static_private_key,
        &config.security.server_static_public_key,
    )?;
    let headers = config
        .security
        .custom_headers
        .iter()
        .map(|(name, value)| Header {
            name: name.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    let host_ids = config
        .hosts
        .iter()
        .map(HostConfig::host_id)
        .collect::<HashSet<_>>();
    let handshake = ServerHandshakeConfig::from_config(
        psk,
        identity,
        Duration::from_secs(config.security.clock_skew_seconds),
        headers,
        &config.security.allowed_clients,
        &host_ids,
    )?;
    let runtime = ServerRuntime::new_with_components(
        config,
        handshake,
        Arc::new(PlatformWakeSender),
        Arc::new(PlatformStatusProbe),
    )?
    .with_access_policy_source(config_path);
    runtime.run()
}

/// TUI-only variant of [`run_server`] with an explicit listener lifecycle.
pub fn run_server_with_shutdown(
    config_path: &Path,
    bind_override: Option<String>,
    port_override: Option<u16>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    metrics: ServerMetrics,
) -> Result<(), ServerError> {
    with_service_logging(config_path, || {
        run_server_with_shutdown_inner(config_path, bind_override, port_override, shutdown, metrics)
    })
}

fn run_server_with_shutdown_inner(
    config_path: &Path,
    bind_override: Option<String>,
    port_override: Option<u16>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    metrics: ServerMetrics,
) -> Result<(), ServerError> {
    let config_path = resolve_server_config_path(config_path)?;
    let mut config = AppConfig::load(&config_path)?;
    if !config.client.address.trim().is_empty()
        || !config.client.client_id.trim().is_empty()
        || !config.client.static_private_key.trim().is_empty()
        || !config.client.static_public_key.trim().is_empty()
        || !config.client.pinned_server_static_key.trim().is_empty()
    {
        return Err(ServerError::Invalid(
            "server mode requires a server-only configuration file; client settings were found"
                .to_owned(),
        ));
    }
    if let Some(bind) = bind_override {
        let bind = bind.trim().to_owned();
        if bind.parse::<std::net::Ipv4Addr>().is_ok() {
            config.server.dual_stack = false;
        }
        config.server.bind_address = bind;
    }
    if let Some(port) = port_override {
        config.server.port = port;
    }
    config.validate()?;
    let psk = config.secret_key()?;
    let identity = crate::security::Identity::from_hex(
        &config.security.server_static_private_key,
        &config.security.server_static_public_key,
    )?;
    let headers = config
        .security
        .custom_headers
        .iter()
        .map(|(name, value)| Header {
            name: name.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    let host_ids = config
        .hosts
        .iter()
        .map(HostConfig::host_id)
        .collect::<HashSet<_>>();
    let handshake = ServerHandshakeConfig::from_config(
        psk,
        identity,
        Duration::from_secs(config.security.clock_skew_seconds),
        headers,
        &config.security.allowed_clients,
        &host_ids,
    )?;
    let runtime = ServerRuntime::new_with_components_and_metrics(
        config,
        handshake,
        Arc::new(PlatformWakeSender),
        Arc::new(PlatformStatusProbe),
        metrics,
    )?
    .with_access_policy_source(config_path);
    runtime.run_with_shutdown(shutdown)
}

fn resolve_server_config_path(config_path: &Path) -> Result<PathBuf, ServerError> {
    let current_dir = std::env::current_dir()?;
    resolve_server_config_path_from(config_path, &current_dir)
}

fn resolve_server_config_path_from(
    config_path: &Path,
    current_dir: &Path,
) -> Result<PathBuf, ServerError> {
    let candidate = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        current_dir.join(config_path)
    };
    if !candidate.is_file() {
        return Err(ServerError::Invalid(
            "server configuration is missing; run the interactive server setup first".to_owned(),
        ));
    }
    candidate.canonicalize().map_err(ServerError::Io)
}

fn with_service_logging<T>(
    config_path: &Path,
    operation: impl FnOnce() -> Result<T, ServerError>,
) -> Result<T, ServerError> {
    let directory = logging::directory_for_config(config_path);
    let file_guard = match logging::install_file(&directory) {
        Ok(guard) => guard,
        Err(error) => {
            logging::report(
                Level::Fatal,
                "service log initialization failed",
                &format!("path={}\nerror={error}", directory.display()),
            );
            return Err(ServerError::Io(error));
        }
    };
    logging::log(
        Level::Info,
        format!("service log opened path={}", file_guard.path().display()),
    );
    let result = operation();
    if let Err(error) = &result {
        logging::report(
            Level::Fatal,
            "server terminated unexpectedly",
            &format!("error={error}\ndebug={error:#?}"),
        );
    } else {
        logging::log(Level::Info, "server stopped normally");
    }
    result
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(value) => value,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn random_ticket() -> [u8; 32] {
    let mut ticket = [0u8; 32];
    loop {
        OsRng.fill_bytes(&mut ticket);
        if ticket.iter().any(|byte| *byte != 0) {
            return ticket;
        }
    }
}

fn request_digest_context(
    headers: &[Header],
    tag: &[u8],
    catalog_version: u64,
    host_ids: &[String],
    boot_nonce: Option<&[u8; 16]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"RemoteOpenPower/request-digest/v1\0");
    hasher.update(tag);
    hasher.update([0]);
    hasher.update(catalog_version.to_be_bytes());
    if let Some(boot_nonce) = boot_nonce {
        hasher.update([1]);
        hasher.update(boot_nonce);
    } else {
        hasher.update([0]);
    }
    for header in headers {
        hash_bytes(&mut hasher, header.name.as_bytes());
        hash_bytes(&mut hasher, header.value.as_bytes());
    }
    for host_id in host_ids {
        hash_bytes(&mut hasher, host_id.as_bytes());
    }
    hasher.finalize().into()
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn reserve_wake_targets_for_client(
    last_wake: &mut WakeCooldowns,
    client_key: [u8; 32],
    host_ids: &[String],
    now: Instant,
) -> bool {
    last_wake.retain(|_, targets| {
        targets.retain(|_, value| now.duration_since(*value) < WAKE_COOLDOWN);
        !targets.is_empty()
    });
    let blocked = last_wake.get(&client_key).is_some_and(|targets| {
        host_ids.iter().any(|host_id| {
            targets
                .get(host_id)
                .is_some_and(|value| now.duration_since(*value) < WAKE_COOLDOWN)
        })
    });
    if blocked {
        return false;
    }
    let targets = last_wake.entry(client_key).or_default();
    for host_id in host_ids {
        targets.insert(host_id.clone(), now);
    }
    true
}

fn catalog_version(summaries: &[HostSummary]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"RemoteOpenPower/catalog/v1\0");
    for host in summaries {
        hash_bytes(&mut hasher, host.host_id.as_bytes());
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let value = u64::from_be_bytes(bytes);
    if value == 0 { 1 } else { value }
}

fn directory_summary(host: &HostConfig) -> HostSummary {
    HostSummary {
        host_id: host.host_id(),
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn request_time_valid(issued_at_ms: u64, skew: Duration) -> bool {
    issued_at_ms != 0
        && issued_at_ms.abs_diff(unix_ms()) <= skew.as_millis().min(REQUEST_SKEW.as_millis()) as u64
}

fn monitor_sleep(monitors: &[Monitor]) -> Duration {
    let now = Instant::now();
    let next = monitors
        .iter()
        .map(|monitor| monitor.next_probe.saturating_duration_since(now))
        .min()
        .unwrap_or(Duration::from_millis(20));
    next.min(Duration::from_millis(50))
        .max(Duration::from_millis(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopWakeSender;

    impl WakeSender for NoopWakeSender {
        fn wake(&self, _host: &HostConfig) -> Result<(), WakeError> {
            Ok(())
        }
    }

    struct OfflineProbe;

    impl StatusProbe for OfflineProbe {
        fn is_online(&self, _host: &HostConfig) -> bool {
            false
        }
    }

    #[test]
    fn relative_server_config_path_resolves_from_current_directory() {
        let directory = std::env::temp_dir().join(format!(
            "rop-relative-server-config-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        std::fs::create_dir_all(&directory).expect("create test directory");
        let config_path = directory.join("remote-open-power.toml");
        std::fs::write(&config_path, b"test").expect("create test config");

        let resolved =
            resolve_server_config_path_from(Path::new("remote-open-power.toml"), &directory)
                .expect("relative config path resolves");

        assert!(resolved.is_absolute());
        assert_eq!(
            resolved,
            config_path.canonicalize().expect("canonical test path")
        );
        std::fs::remove_file(&config_path).expect("remove test config");
        std::fs::remove_dir(&directory).expect("remove test directory");
    }

    #[test]
    fn runtime_access_policy_drops_a_revoked_client_key() {
        let key = crate::security::Identity::generate()
            .expect("generate client identity")
            .public;
        let mut config = AppConfig::default();
        config.security.allowed_clients = vec![crate::config::AllowedClient {
            client_id: crate::security::client_id_from_public_key(&key),
            display_label: "Portable client".to_owned(),
            static_public_key: format!("hex:{}", hex::encode(key)),
            allowed_hosts: vec!["lab-pc".to_owned()],
            issued_credential_file: String::new(),
        }];
        let mut policy = AccessPolicy::new(
            client_access_from_config(&config).expect("build initial access policy"),
        );
        assert_eq!(
            policy.clients.get(&key).map(|access| &access.allowed_hosts),
            Some(&HashSet::from(["lab-pc".to_owned()]))
        );

        config.security.allowed_clients.clear();
        policy.clients = client_access_from_config(&config).expect("reload revoked access policy");
        assert!(!policy.clients.contains_key(&key));
    }

    #[test]
    fn saved_credential_revocation_updates_the_live_access_policy() {
        let directory = std::env::temp_dir().join(format!(
            "rop-live-revocation-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        std::fs::create_dir_all(&directory).expect("create test directory");
        let config_path = directory.join("remote-open-power.toml");

        let client_identity = crate::security::Identity::generate().expect("client identity");
        let client_key = client_identity.public;
        let mut config = AppConfig::default();
        config.ensure_secret();
        config
            .ensure_server_identity_material()
            .expect("server identity");
        config.hosts.push(HostConfig {
            hostname: "lab-pc".to_owned(),
            display_name: String::new(),
            mac: "02:11:22:33:44:55".to_owned(),
            ip: "192.168.1.10".to_owned(),
            wol_port: 9,
            probe_timeout_ms: 1_000,
            probe_port: 0,
            wol_ipv6_interface: 0,
        });
        config
            .security
            .allowed_clients
            .push(crate::config::AllowedClient {
                client_id: crate::security::client_id_from_public_key(&client_key),
                display_label: "Portable client".to_owned(),
                static_public_key: format!("hex:{}", hex::encode(client_key)),
                allowed_hosts: vec!["lab-pc".to_owned()],
                issued_credential_file: String::new(),
            });
        config.save(&config_path).expect("save initial config");

        let psk = config.secret_key().expect("server PSK");
        let identity = crate::security::Identity::from_hex(
            &config.security.server_static_private_key,
            &config.security.server_static_public_key,
        )
        .expect("decode server identity");
        let host_ids = HashSet::from(["lab-pc".to_owned()]);
        let handshake = ServerHandshakeConfig::from_config(
            psk,
            identity,
            Duration::from_secs(config.security.clock_skew_seconds),
            Vec::new(),
            &config.security.allowed_clients,
            &host_ids,
        )
        .expect("build handshake policy");
        let runtime = ServerRuntime::new_with_components(
            config.clone(),
            handshake,
            Arc::new(NoopWakeSender),
            Arc::new(OfflineProbe),
        )
        .expect("build server runtime")
        .with_access_policy_source(config_path.canonicalize().expect("canonical config path"));
        assert!(runtime.client_is_authorized(&client_key));

        config.security.allowed_clients.clear();
        config.save(&config_path).expect("save revoked config");
        runtime.refresh_access_policy();
        assert!(!runtime.client_is_authorized(&client_key));

        std::fs::remove_file(&config_path).expect("remove test config");
        std::fs::remove_dir(&directory).expect("remove test directory");
    }

    fn operation_key(client: u8, operation: u16) -> OperationKey {
        let mut operation_id = [0u8; 16];
        operation_id[..2].copy_from_slice(&operation.to_be_bytes());
        OperationKey {
            client_key: [client; 32],
            operation_id,
        }
    }

    fn cached_error(request_id: [u8; 16]) -> ServerEnvelope {
        ServerEnvelope {
            version: PROTOCOL_VERSION,
            request_id,
            issued_at_ms: 1,
            headers: Vec::new(),
            event: ServerEvent::Error {
                code: ErrorCode::Busy,
                retryable: true,
            },
        }
    }

    #[test]
    fn pending_ledger_entries_expire() {
        let now = Instant::now();
        let key = operation_key(1, 1);
        let mut ledger = Ledger::new();
        assert!(matches!(
            ledger.begin_request(key, [7; 32], now),
            BeginResult::New
        ));
        assert!(matches!(
            ledger.begin_request(
                key,
                [7; 32],
                now + PENDING_LEDGER_TTL + Duration::from_secs(1)
            ),
            BeginResult::New
        ));
    }

    #[test]
    fn keyed_connection_quota_releases_on_drop() {
        let limiter = Arc::new(KeyedConnectionLimiter::new(2));
        let first = limiter.acquire([1; 32]).expect("first slot");
        let _second = limiter.acquire([1; 32]).expect("second slot");
        assert!(limiter.acquire([1; 32]).is_none());
        assert!(limiter.acquire([2; 32]).is_some());
        drop(first);
        assert!(limiter.acquire([1; 32]).is_some());
    }

    #[test]
    fn server_metrics_track_live_connection_permits() {
        let metrics = ServerMetrics::default();
        let limiter = Arc::new(ConnectionLimiter::with_counter(
            2,
            Arc::clone(&metrics.active_connections),
        ));
        assert_eq!(metrics.active_connections(), 0);
        let first = limiter.acquire().expect("first connection");
        assert_eq!(metrics.active_connections(), 1);
        let second = limiter.acquire().expect("second connection");
        assert_eq!(metrics.active_connections(), 2);
        assert!(limiter.acquire().is_none());
        drop(first);
        assert_eq!(metrics.active_connections(), 1);
        drop(second);
        assert_eq!(metrics.active_connections(), 0);
    }

    #[test]
    fn server_metrics_only_report_listening_inside_bound_lifetime() {
        let metrics = ServerMetrics::default();
        assert!(!metrics.is_listening());
        metrics.set_listening(true);
        {
            let _guard = ListeningGuard(metrics.clone());
            assert!(metrics.is_listening());
        }
        assert!(!metrics.is_listening());
    }

    #[test]
    fn one_source_cannot_exhaust_global_handshake_capacity() {
        let global = Arc::new(ConnectionLimiter::new(MAX_CONCURRENT_HANDSHAKES));
        let per_ip = Arc::new(KeyedConnectionLimiter::new(MAX_PENDING_HANDSHAKES_PER_IP));
        let attacker = "192.0.2.10".parse::<IpAddr>().expect("attacker IP");
        let legitimate = "192.0.2.20".parse::<IpAddr>().expect("legitimate IP");
        let mut attacker_ip_permits = Vec::new();
        let mut attacker_global_permits = Vec::new();

        for _ in 0..MAX_CONCURRENT_HANDSHAKES {
            let Some(ip_permit) = per_ip.acquire(attacker) else {
                break;
            };
            attacker_ip_permits.push(ip_permit);
            attacker_global_permits.push(global.acquire().expect("global handshake slot"));
        }

        assert_eq!(attacker_ip_permits.len(), MAX_PENDING_HANDSHAKES_PER_IP);
        assert!(per_ip.acquire(attacker).is_none());
        let _legitimate_ip_permit = per_ip
            .acquire(legitimate)
            .expect("another source retains a pending-handshake slot");
        let _legitimate_global_permit = global
            .acquire()
            .expect("one source cannot consume every global handshake slot");
    }

    #[test]
    fn directory_summary_never_contains_network_coordinates() {
        let host = HostConfig {
            hostname: "lab-desktop".to_owned(),
            display_name: "Lab desktop".to_owned(),
            mac: "02:11:22:33:44:55".to_owned(),
            ip: "192.168.1.10".to_owned(),
            wol_port: 9,
            probe_timeout_ms: 1_000,
            probe_port: 0,
            wol_ipv6_interface: 0,
        };
        let summary = directory_summary(&host);
        let wire = encode(&summary).expect("summary encodes");

        assert_eq!(
            serde_json::to_value(&summary).expect("summary serializes"),
            serde_json::json!({ "host_id": "lab-desktop" })
        );
        assert!(
            !wire
                .windows(host.mac.len())
                .any(|part| part == host.mac.as_bytes())
        );
        assert!(
            !wire
                .windows(host.ip.len())
                .any(|part| part == host.ip.as_bytes())
        );
    }

    #[test]
    fn wake_cooldown_is_isolated_by_authenticated_client() {
        let now = Instant::now();
        let targets = vec!["workstation".to_owned()];
        let mut last_wake = HashMap::new();

        assert!(reserve_wake_targets_for_client(
            &mut last_wake,
            [1; 32],
            &targets,
            now,
        ));
        assert!(reserve_wake_targets_for_client(
            &mut last_wake,
            [2; 32],
            &targets,
            now + Duration::from_secs(1),
        ));
        assert!(!reserve_wake_targets_for_client(
            &mut last_wake,
            [1; 32],
            &targets,
            now + Duration::from_secs(1),
        ));
        assert!(reserve_wake_targets_for_client(
            &mut last_wake,
            [1; 32],
            &targets,
            now + WAKE_COOLDOWN,
        ));
    }

    #[test]
    fn ipv4_mapped_addresses_share_the_ipv4_quota_key() {
        let mapped = "::ffff:127.0.0.1".parse::<IpAddr>().expect("mapped IP");
        assert_eq!(
            normalize_ip(mapped),
            "127.0.0.1".parse::<IpAddr>().expect("IPv4")
        );
    }

    #[test]
    fn ipv6_rate_keys_are_aggregated_to_prefix_64() {
        let first = "2001:db8:1:2::1".parse::<IpAddr>().expect("first IPv6");
        let second = "2001:db8:1:2:ffff::9"
            .parse::<IpAddr>()
            .expect("second IPv6");
        assert_eq!(normalize_ip(first), normalize_ip(second));
    }

    #[test]
    fn ledger_quota_is_per_authenticated_client() {
        let now = Instant::now();
        let mut ledger = Ledger::new();
        for operation in 1..=MAX_LEDGER_ENTRIES_PER_CLIENT as u16 {
            assert!(matches!(
                ledger.begin_request(operation_key(1, operation), [operation as u8; 32], now),
                BeginResult::New
            ));
        }
        assert!(matches!(
            ledger.begin_request(operation_key(1, 300), [3; 32], now),
            BeginResult::Busy
        ));
        assert!(matches!(
            ledger.begin_request(operation_key(2, 1), [4; 32], now),
            BeginResult::New
        ));
    }

    #[test]
    fn wake_retry_advances_only_on_explicit_attempt_two() {
        let now = Instant::now();
        let key = operation_key(1, 7);
        let digest = [8; 32];
        let host_ids = vec!["workstation".to_owned()];
        let boot_nonce = [9; 16];
        let mut ledger = Ledger::new();
        let ticket =
            match ledger.begin_wake_attempt1(key, digest, 1, host_ids.clone(), boot_nonce, now) {
                WakeBeginResult::New(ticket) => ticket,
                _ => panic!("attempt one was not reserved"),
            };
        let first_receipt = cached_error(key.operation_id);
        ledger.complete(key, first_receipt.clone(), now);
        assert_eq!(
            ledger
                .entries
                .get(&key)
                .and_then(|entry| entry.wake.as_ref())
                .map(|wake| wake.attempt),
            Some(1)
        );
        assert!(matches!(
            ledger.begin_wake_attempt1(
                key,
                digest,
                1,
                host_ids.clone(),
                boot_nonce,
                now + Duration::from_millis(500),
            ),
            WakeBeginResult::Cached(response) if response == first_receipt
        ));
        assert!(matches!(
            ledger.begin_wake_attempt2(
                key,
                WakeRetry {
                    digest,
                    catalog_version: 1,
                    host_ids: &host_ids,
                    boot_nonce,
                    ticket,
                    now: now + Duration::from_secs(1),
                },
            ),
            WakeBeginResult::New(_)
        ));
        ledger.complete(
            key,
            cached_error(key.operation_id),
            now + Duration::from_secs(1),
        );
        assert!(matches!(
            ledger.begin_wake_attempt1(
                key,
                digest,
                1,
                host_ids,
                boot_nonce,
                now + Duration::from_secs(2),
            ),
            WakeBeginResult::Replay
        ));
    }

    #[test]
    fn retry_ticket_window_starts_when_execution_receipt_is_completed() {
        let now = Instant::now();
        let completed_at = now + Duration::from_secs(30);
        let key = operation_key(1, 8);
        let digest = [10; 32];
        let host_ids = vec!["workstation".to_owned()];
        let boot_nonce = [11; 16];
        let mut ledger = Ledger::new();
        let ticket =
            match ledger.begin_wake_attempt1(key, digest, 1, host_ids.clone(), boot_nonce, now) {
                WakeBeginResult::New(ticket) => ticket,
                _ => panic!("attempt one was not reserved"),
            };

        ledger.complete(key, cached_error(key.operation_id), completed_at);

        assert!(matches!(
            ledger.begin_wake_attempt2(
                key,
                WakeRetry {
                    digest,
                    catalog_version: 1,
                    host_ids: &host_ids,
                    boot_nonce,
                    ticket,
                    now: completed_at + RETRY_TTL - Duration::from_millis(1),
                },
            ),
            WakeBeginResult::New(_)
        ));
    }

    #[test]
    fn maximum_catalog_fits_the_secure_payload_budget() {
        let hosts = (0..crate::protocol::MAX_HOSTS)
            .map(|index| HostSummary {
                host_id: format!("host-{index:02}-{}", "a".repeat(50)),
            })
            .collect();
        let response = ServerEnvelope {
            version: PROTOCOL_VERSION,
            request_id: [1; 16],
            issued_at_ms: 1,
            headers: Vec::new(),
            event: ServerEvent::Hosts {
                catalog_version: 1,
                hosts,
            },
        };
        response.validate().expect("maximum catalog is valid");
        assert!(encode(&response).expect("catalog encodes").len() <= MAX_APP_PAYLOAD);
    }
}
