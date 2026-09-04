//! Persistent application configuration.
//!
//! The configuration deliberately contains data only.  Networking and CLI code
//! consume these types but do not know how they are serialized on disk.

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const CONFIG_VERSION: u32 = 1;
pub const DEFAULT_PORT: u16 = 45_890;
pub const DEFAULT_CONFIG_FILE: &str = "remote-open-power.toml";
pub const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 30;
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 30;
pub const MAX_CONFIG_BYTES: usize = 1_048_576;
pub const MAX_HOSTS: usize = 64;
pub const MAX_CLIENTS: usize = 128;
pub const MAX_HEADERS: usize = 32;
pub const MAX_HEADER_BYTES: usize = 4_096;
pub const MIN_SECRET_BYTES: usize = 32;
pub const MAX_CLIENT_ID_LEN: usize = 64;
pub const MAX_ALLOWED_HOSTS: usize = 256;

fn default_bind_address() -> String {
    "::".to_owned()
}

fn default_bind_address_v4() -> String {
    "0.0.0.0".to_owned()
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_true() -> bool {
    true
}

fn default_clock_skew() -> u64 {
    DEFAULT_CLOCK_SKEW_SECONDS
}

fn default_rate_limit() -> u32 {
    DEFAULT_RATE_LIMIT_PER_MINUTE
}

fn default_wol_port() -> u16 {
    9
}

fn default_probe_timeout() -> u64 {
    1_000
}

fn default_probe_port() -> u16 {
    0
}

fn default_wol_ipv6_interface() -> u32 {
    0
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write config {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid TOML in {path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("cannot serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default = "default_config_version")]
    pub config_version: u32,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub hosts: Vec<HostConfig>,
    #[serde(default)]
    pub client: ClientConfig,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppConfig")
            .field("config_version", &self.config_version)
            .field("server", &self.server)
            .field("security", &self.security)
            .field("hosts", &self.hosts)
            .field("client", &self.client)
            .finish()
    }
}

fn default_config_version() -> u32 {
    CONFIG_VERSION
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut config = Self {
            config_version: CONFIG_VERSION,
            server: ServerConfig::default(),
            security: SecurityConfig::default(),
            hosts: Vec::new(),
            client: ClientConfig::default(),
        };
        config.ensure_secret();
        config
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    /// IPv4 listener used together with `bind_address` when dual-stack mode
    /// is enabled.  Keeping two explicit sockets makes the policy identical
    /// on Windows and Unix instead of relying on IPV6_V6ONLY defaults.
    #[serde(default = "default_bind_address_v4")]
    pub bind_address_v4: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// When enabled, the runtime opens one explicit IPv4 socket and one
    /// explicit IPv6 socket.  This avoids OS-dependent dual-stack behavior.
    #[serde(default = "default_true")]
    pub dual_stack: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            bind_address_v4: default_bind_address_v4(),
            port: default_port(),
            dual_stack: true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// A high-entropy PSK.  Generated values are stored as `hex:<value>`.
    #[serde(default)]
    pub shared_secret: String,
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
    #[serde(default = "default_rate_limit")]
    pub max_requests_per_minute: u32,
    /// Additional authenticated headers carried by every request.
    #[serde(default)]
    pub custom_headers: BTreeMap<String, String>,
    /// Long-term Noise static identity used by the server.  It is generated
    /// on first save and never transmitted in clear text.
    #[serde(default)]
    pub server_static_private_key: String,
    #[serde(default)]
    pub server_static_public_key: String,
    /// When false (the secure default), a client must be explicitly enrolled
    /// in `allowed_clients` before it can list or wake anything.
    #[serde(default)]
    pub allow_unregistered_clients: bool,
    #[serde(default)]
    pub allowed_clients: Vec<AllowedClient>,
    /// Public targets are disabled by default because this daemon is intended
    /// for a LAN and must not become a generic UDP relay/SSRF primitive.
    #[serde(default)]
    pub allow_public_targets: bool,
}

impl fmt::Debug for SecurityConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecurityConfig")
            .field("shared_secret", &"<redacted>")
            .field("clock_skew_seconds", &self.clock_skew_seconds)
            .field("max_requests_per_minute", &self.max_requests_per_minute)
            .field(
                "custom_headers",
                &self.custom_headers.keys().collect::<Vec<_>>(),
            )
            .field("server_static_private_key", &"<redacted>")
            .field("server_static_public_key", &self.server_static_public_key)
            .field(
                "allow_unregistered_clients",
                &self.allow_unregistered_clients,
            )
            .field("allowed_clients", &self.allowed_clients)
            .field("allow_public_targets", &self.allow_public_targets)
            .finish()
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            shared_secret: String::new(),
            clock_skew_seconds: default_clock_skew(),
            max_requests_per_minute: default_rate_limit(),
            custom_headers: BTreeMap::new(),
            server_static_private_key: String::new(),
            server_static_public_key: String::new(),
            allow_unregistered_clients: false,
            allowed_clients: Vec::new(),
            allow_public_targets: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowedClient {
    pub client_id: String,
    pub static_public_key: String,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default)]
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub static_private_key: String,
    #[serde(default)]
    pub static_public_key: String,
    /// Exact hex-encoded server static public key.  Empty means the CLI must
    /// ask for a pin before connecting; there is no silent trust-on-first-use.
    #[serde(default)]
    pub pinned_server_static_key: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            port: default_port(),
            client_id: String::new(),
            static_private_key: String::new(),
            static_public_key: String::new(),
            pinned_server_static_key: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub hostname: String,
    /// Optional local operator label.  The wire protocol continues to expose
    /// the stable host id (`hostname`) and never trusts this display-only
    /// value for authorization or target selection.
    #[serde(default)]
    pub display_name: String,
    pub mac: String,
    pub ip: String,
    #[serde(default = "default_wol_port")]
    pub wol_port: u16,
    #[serde(default = "default_probe_timeout")]
    pub probe_timeout_ms: u64,
    /// `0` probes a small fixed set of common service ports, then ICMP.
    #[serde(default = "default_probe_port")]
    pub probe_port: u16,
    /// IPv6 interface index used for the link-local all-nodes WoL fallback.
    /// `0` lets the operating system choose the route.
    #[serde(default = "default_wol_ipv6_interface")]
    pub wol_ipv6_interface: u32,
}

impl HostConfig {
    pub fn host_id(&self) -> String {
        self.hostname.trim().to_ascii_lowercase()
    }

    pub fn validate(&self, allow_public_targets: bool) -> Result<(), ConfigError> {
        let hostname = self.hostname.trim();
        if !is_valid_hostname(hostname) {
            return Err(ConfigError::Invalid(
                "host name must be an ASCII DNS label (1-64 chars)".to_owned(),
            ));
        }
        crate::protocol::validate_id(&self.host_id()).map_err(|_| {
            ConfigError::Invalid(
                "host name must also be a valid protocol host id (1-64 bytes)".to_owned(),
            )
        })?;
        if self.display_name.len() > 128 || self.display_name.chars().any(char::is_control) {
            return Err(ConfigError::Invalid(
                "display name must be at most 128 bytes and contain no control characters"
                    .to_owned(),
            ));
        }
        parse_mac(&self.mac).map_err(ConfigError::Invalid)?;
        let ip = self.ip.trim().parse::<IpAddr>().map_err(|_| {
            ConfigError::Invalid(format!("{} has an invalid IP address", self.hostname))
        })?;
        let ip = match ip {
            IpAddr::V6(value) => value.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        let scoped_link_local = matches!(
            ip,
            IpAddr::V6(value) if value.is_unicast_link_local() && self.wol_ipv6_interface != 0
        );
        if ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_loopback()
            || match ip {
                IpAddr::V4(value) => {
                    value.is_broadcast() || value.is_link_local() || value.octets()[0] == 0
                }
                IpAddr::V6(value) => value.is_unicast_link_local() && self.wol_ipv6_interface == 0,
            }
            || (!allow_public_targets && !is_lan_ip(ip) && !scoped_link_local)
        {
            return Err(ConfigError::Invalid(format!(
                "{} must use a non-loopback LAN IP; link-local IPv6 also requires an interface index",
                self.hostname
            )));
        }
        if !matches!(self.wol_port, 7 | 9) {
            return Err(ConfigError::Invalid(format!(
                "{} WoL port must be 7 or 9",
                self.hostname
            )));
        }
        if !(100..=5_000).contains(&self.probe_timeout_ms) {
            return Err(ConfigError::Invalid(format!(
                "{} probe timeout must be between 100 and 5000 ms",
                self.hostname
            )));
        }
        // Port zero means the bounded common-port probe set.
        if self.probe_port != 0 && self.probe_port < 1024 {
            return Err(ConfigError::Invalid(format!(
                "{} has an invalid probe port",
                self.hostname
            )));
        }
        Ok(())
    }
}

impl AllowedClient {
    fn validate(&self, host_ids: &std::collections::HashSet<String>) -> Result<(), ConfigError> {
        validate_client_id(&self.client_id)?;
        decode_key(&self.static_public_key)?;
        validate_public_key(&self.static_public_key, "client static public key")?;
        if self.allowed_hosts.len() > MAX_ALLOWED_HOSTS {
            return Err(ConfigError::Invalid(format!(
                "client {} has too many allowed hosts",
                self.client_id
            )));
        }
        let mut seen = std::collections::HashSet::new();
        for host in &self.allowed_hosts {
            let normalized = host.trim().to_ascii_lowercase();
            if !seen.insert(normalized.clone()) || !host_ids.contains(&normalized) {
                return Err(ConfigError::Invalid(format!(
                    "client {} references an unknown or duplicate host",
                    self.client_id
                )));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientConfig")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("client_id", &self.client_id)
            .field("static_private_key", &"<redacted>")
            .field("static_public_key", &self.static_public_key)
            .field("pinned_server_static_key", &self.pinned_server_static_key)
            .finish()
    }
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let config = Self::load_unvalidated(path)?;
        config.validate()?;
        Ok(config)
    }

    /// Read and structurally parse a settings file without requiring role
    /// credentials.  Client bootstrap uses this once, merges a separately
    /// provisioned credential bundle, and then calls `validate` before any
    /// network operation.  This does not relax size, symlink, permission, or
    /// unknown-field checks.
    pub(crate) fn load_unvalidated(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref().to_path_buf();
        let Some(text) = read_private_text(&path, MAX_CONFIG_BYTES as u64).map_err(|source| {
            ConfigError::Read {
                path: path.clone(),
                source,
            }
        })?
        else {
            return Ok(Self::default());
        };
        let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.clone(),
            source: Box::new(source),
        })?;
        Ok(config)
    }

    pub fn save(&mut self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        self.ensure_secret();
        self.validate()?;
        self.config_version = CONFIG_VERSION;
        let path = path.as_ref().to_path_buf();
        let mut text = toml::to_string_pretty(self)?;
        text.push('\n');
        if text.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid(format!(
                "serialized config exceeds {MAX_CONFIG_BYTES} bytes"
            )));
        }
        write_private_toml(&path, &text)
    }

    /// Persist only non-secret client settings.  Long-term client identity and
    /// the PSK stay in the separately provisioned `*.credential.toml` file.
    /// This keeps a normal endpoint configuration safe to copy and lets the
    /// interactive client ask only for an address and port.
    pub fn save_client_settings(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        let mut settings = self.clone();
        settings.config_version = CONFIG_VERSION;
        settings.security.shared_secret.clear();
        settings.security.server_static_private_key.clear();
        settings.security.server_static_public_key.clear();
        settings.security.allowed_clients.clear();
        settings.hosts.clear();
        settings.client.static_private_key.clear();
        settings.client.static_public_key.clear();
        settings.client.pinned_server_static_key.clear();
        if !settings.client.client_id.trim().is_empty() {
            validate_client_id(&settings.client.client_id)?;
            settings.client.client_id = settings.client.client_id.trim().to_ascii_lowercase();
        }
        if settings.client.port < 1024 {
            return Err(ConfigError::Invalid(
                "client port must be 1024 or higher".to_owned(),
            ));
        }
        if !settings.client.address.trim().is_empty() {
            validate_endpoint(&settings.client.address)?;
        }
        for (key, value) in &settings.security.custom_headers {
            validate_header(key, value)?;
        }
        if settings.security.custom_headers.len() > MAX_HEADERS {
            return Err(ConfigError::Invalid(format!(
                "at most {MAX_HEADERS} custom headers are allowed"
            )));
        }
        let header_bytes: usize = settings
            .security
            .custom_headers
            .iter()
            .map(|(key, value)| key.len().saturating_add(value.len()))
            .sum();
        if header_bytes > MAX_HEADER_BYTES {
            return Err(ConfigError::Invalid(format!(
                "custom headers exceed {MAX_HEADER_BYTES} bytes"
            )));
        }
        let mut text = toml::to_string_pretty(&settings)?;
        text.push('\n');
        if text.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid(format!(
                "serialized client settings exceed {MAX_CONFIG_BYTES} bytes"
            )));
        }
        write_private_toml(path.as_ref(), &text)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.config_version != CONFIG_VERSION {
            return Err(ConfigError::Invalid(format!(
                "unsupported config version {}",
                self.config_version
            )));
        }
        if self.server.bind_address.trim().is_empty() || self.server.port == 0 {
            return Err(ConfigError::Invalid(
                "server bind address and port are required".to_owned(),
            ));
        }
        if self.server.port < 1024 {
            return Err(ConfigError::Invalid(
                "server port must be 1024 or higher".to_owned(),
            ));
        }
        let bind_ip = self
            .server
            .bind_address
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::Invalid("bind_address must be an IP literal".to_owned()))?;
        if self.server.dual_stack && !bind_ip.is_ipv6() {
            return Err(ConfigError::Invalid(
                "dual_stack requires an IPv6 bind address".to_owned(),
            ));
        }
        if self.server.dual_stack {
            let _bind_v4 = self
                .server
                .bind_address_v4
                .trim()
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| {
                    ConfigError::Invalid(
                        "dual-stack IPv4 bind address must be an IPv4 literal".to_owned(),
                    )
                })?;
        }
        if self.security.shared_secret.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "security.shared_secret must not be empty".to_owned(),
            ));
        }
        self.secret_key()?;
        if self.security.clock_skew_seconds == 0 || self.security.clock_skew_seconds > 60 {
            return Err(ConfigError::Invalid(
                "clock_skew_seconds must be between 1 and 60".to_owned(),
            ));
        }
        if self.security.max_requests_per_minute == 0 || self.security.max_requests_per_minute > 600
        {
            return Err(ConfigError::Invalid(
                "max_requests_per_minute must be between 1 and 600".to_owned(),
            ));
        }
        for (key, value) in &self.security.custom_headers {
            validate_header(key, value)?;
        }
        if self.security.custom_headers.len() > MAX_HEADERS {
            return Err(ConfigError::Invalid(format!(
                "at most {MAX_HEADERS} custom headers are allowed"
            )));
        }
        let header_bytes: usize = self
            .security
            .custom_headers
            .iter()
            .map(|(key, value)| key.len().saturating_add(value.len()))
            .sum();
        if header_bytes > MAX_HEADER_BYTES {
            return Err(ConfigError::Invalid(format!(
                "custom headers exceed {MAX_HEADER_BYTES} bytes"
            )));
        }
        if self.hosts.len() > MAX_HOSTS {
            return Err(ConfigError::Invalid(format!(
                "at most {MAX_HOSTS} hosts are allowed"
            )));
        }
        if self.security.allowed_clients.len() > MAX_CLIENTS {
            return Err(ConfigError::Invalid(format!(
                "at most {MAX_CLIENTS} clients are allowed"
            )));
        }
        let mut ids = std::collections::HashSet::new();
        for host in &self.hosts {
            host.validate(self.security.allow_public_targets)?;
            if !ids.insert(host.host_id()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate host name: {}",
                    host.hostname
                )));
            }
        }
        let host_ids: std::collections::HashSet<String> =
            self.hosts.iter().map(HostConfig::host_id).collect();
        let mut client_ids = std::collections::HashSet::new();
        let mut client_keys = std::collections::HashSet::new();
        for client in &self.security.allowed_clients {
            client.validate(&host_ids)?;
            if !client_ids.insert(client.client_id.to_ascii_lowercase()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate client id: {}",
                    client.client_id
                )));
            }
            let key = decode_key(&client.static_public_key)?;
            if !client_keys.insert(key) {
                return Err(ConfigError::Invalid(
                    "multiple clients may not share a static public key".to_owned(),
                ));
            }
        }
        if !self.client.client_id.is_empty() {
            validate_client_id(&self.client.client_id)?;
        }
        if self.client.port < 1024 {
            return Err(ConfigError::Invalid(
                "client port must be 1024 or higher".to_owned(),
            ));
        }
        if !self.client.address.is_empty() {
            validate_endpoint(&self.client.address)?;
        }
        for key in [
            &self.security.server_static_private_key,
            &self.security.server_static_public_key,
            &self.client.static_private_key,
            &self.client.static_public_key,
            &self.client.pinned_server_static_key,
        ] {
            if !key.is_empty() {
                decode_key(key)?;
            }
        }
        validate_identity_pair(
            &self.security.server_static_private_key,
            &self.security.server_static_public_key,
            "server",
        )?;
        validate_identity_pair(
            &self.client.static_private_key,
            &self.client.static_public_key,
            "client",
        )?;
        if !self.client.pinned_server_static_key.is_empty()
            && !self.security.server_static_public_key.is_empty()
            && self.client.pinned_server_static_key != self.security.server_static_public_key
        {
            return Err(ConfigError::Invalid(
                "pinned server key does not match the configured server key".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn ensure_secret(&mut self) {
        if self.security.shared_secret.trim().is_empty() {
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            self.security.shared_secret = format!("hex:{}", hex::encode(bytes));
        }
    }

    pub fn ensure_server_identity_material(&mut self) -> Result<(), ConfigError> {
        if self.security.server_static_private_key.is_empty() {
            if !self.security.server_static_public_key.is_empty() {
                return Err(ConfigError::Invalid(
                    "server public key requires its private key".to_owned(),
                ));
            }
            let (private, public) = random_identity_pair();
            self.security.server_static_private_key = private;
            self.security.server_static_public_key = public;
        } else if self.security.server_static_public_key.is_empty() {
            self.security.server_static_public_key =
                derive_public_key(&self.security.server_static_private_key)?;
        }
        Ok(())
    }

    /// Decode the only accepted credential format: exactly 256 bits of random
    /// material encoded as `hex:<64 hex digits>`.  Refusing short passphrases
    /// avoids silently reducing the security of the Noise PSK.
    pub fn secret_key(&self) -> Result<[u8; 32], ConfigError> {
        let raw = self.security.shared_secret.trim();
        let encoded = raw.strip_prefix("hex:").ok_or_else(|| {
            ConfigError::Invalid("shared secret must use hex:<64 hex digits>".to_owned())
        })?;
        let decoded = hex::decode(encoded)
            .map_err(|_| ConfigError::Invalid("shared secret hex is invalid".to_owned()))?;
        if decoded.len() != MIN_SECRET_BYTES {
            return Err(ConfigError::Invalid(
                "shared secret must contain exactly 32 bytes".to_owned(),
            ));
        }
        if decoded.iter().all(|byte| *byte == 0) {
            return Err(ConfigError::Invalid(
                "shared secret cannot be all zero".to_owned(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }
}

/// Open and read a private file through one non-following handle.  All policy
/// checks are performed on that handle, so an attacker cannot replace the
/// directory entry between metadata validation and the actual read.
pub(crate) fn read_private_text(path: &Path, max_bytes: u64) -> io::Result<Option<String>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private file must be a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || (metadata.uid() != effective_uid && metadata.uid() != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private file owner, mode, or link count is unsafe",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private file cannot be a reparse point",
            ));
        }
    }

    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_string(&mut text)?;
    if text.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private file exceeds its size limit",
        ));
    }
    Ok(Some(text))
}

/// Write a private TOML document with a create-new temporary file, flush, and
/// replacement.  Both full server configurations and credential-free client
/// settings use this path so they share the same crash and permission rules.
pub(crate) fn write_private_toml(path: &Path, text: &str) -> Result<(), ConfigError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    fs::create_dir_all(&parent).map_err(|source| ConfigError::Write {
        path: parent.clone(),
        source,
    })?;
    let parent_metadata = fs::symlink_metadata(&parent).map_err(|source| ConfigError::Write {
        path: parent.clone(),
        source,
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(ConfigError::Invalid(
            "config directory must be a regular directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = parent_metadata.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(ConfigError::Invalid(
                "config directory must not be group/world writable".to_owned(),
            ));
        }
    }

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ConfigError::Invalid("config path must have a file name".to_owned()))?;
    let temp_path = parent.join(format!(".{file_name}.{stamp}.{}.tmp", std::process::id()));
    #[cfg(not(windows))]
    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_result = (|| -> Result<(), ConfigError> {
        #[cfg(windows)]
        let mut file =
            create_private_windows_file(&temp_path).map_err(|source| ConfigError::Write {
                path: temp_path.clone(),
                source,
            })?;
        #[cfg(not(windows))]
        let mut file = options
            .open(&temp_path)
            .map_err(|source| ConfigError::Write {
                path: temp_path.clone(),
                source,
            })?;
        file.write_all(text.as_bytes())
            .map_err(|source| ConfigError::Write {
                path: temp_path.clone(),
                source,
            })?;
        file.sync_all().map_err(|source| ConfigError::Write {
            path: temp_path.clone(),
            source,
        })?;
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&temp_path)
                .map_err(|source| ConfigError::Write {
                    path: temp_path.clone(),
                    source,
                })?
                .permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&temp_path, permissions).map_err(|source| ConfigError::Write {
                path: temp_path.clone(),
                source,
            })?;
        }

        // Reject a path alias before replacement. The Windows branch below
        // replaces atomically with write-through instead of deleting the old
        // file first.
        #[cfg(windows)]
        if path.exists() {
            let current = fs::symlink_metadata(path).map_err(|source| ConfigError::Write {
                path: path.to_path_buf(),
                source,
            })?;
            if current.file_type().is_symlink() || !current.is_file() {
                return Err(ConfigError::Invalid(
                    "refusing to replace a non-regular config path".to_owned(),
                ));
            }
        }
        #[cfg(windows)]
        move_file_replace(&temp_path, path).map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        #[cfg(not(windows))]
        fs::rename(&temp_path, path).map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        #[cfg(unix)]
        if let Ok(directory) = OpenOptions::new().read(true).open(&parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

#[cfg(windows)]
fn create_private_windows_file(path: &Path) -> io::Result<fs::File> {
    use std::{
        ffi::c_void,
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        ptr,
    };

    const SDDL_REVISION_1: u32 = 1;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
    const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
    const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor: *const u16,
            revision: u32,
            security_descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut SecurityAttributes,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut c_void,
        ) -> *mut c_void;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    // OW is the file owner assigned by CreateFileW. Supplying the protected
    // descriptor at creation prevents a broad parent ACL from being observable
    // even for the brief interval between create and a later SetSecurityInfo.
    let descriptor_text: Vec<u16> = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)\0"
        .encode_utf16()
        .collect();
    let mut descriptor = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut attributes = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        security_descriptor: descriptor,
        inherit_handle: 0,
    };
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_WRITE,
            0,
            &mut attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
            ptr::null_mut(),
        )
    };
    let create_error = if handle == INVALID_HANDLE_VALUE {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    unsafe {
        LocalFree(descriptor);
    }
    if let Some(error) = create_error {
        return Err(error);
    }
    Ok(unsafe { fs::File::from_raw_handle(handle.cast()) })
}

#[cfg(windows)]
fn move_file_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn validate_header(key: &str, value: &str) -> Result<(), ConfigError> {
    let valid_key = !key.is_empty()
        && key.len() <= 32
        && key.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'-')
        })
        && key
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && key
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
    let valid_value = !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        && !value.starts_with(' ')
        && !value.ends_with(' ');
    if !valid_key || !valid_value {
        return Err(ConfigError::Invalid(format!(
            "invalid custom header `{key}`"
        )));
    }
    let normalized_key = key.to_ascii_lowercase();
    if normalized_key.starts_with("rop-") || normalized_key.starts_with("x-rop-") {
        return Err(ConfigError::Invalid(
            "rop-/x-rop-* headers are reserved by the protocol".to_owned(),
        ));
    }
    Ok(())
}

pub fn parse_mac(input: &str) -> Result<[u8; 6], String> {
    let compact: String = input
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .collect();
    if compact.len() != 12 || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("invalid MAC address: {input}"));
    }
    let mut mac = [0u8; 6];
    for (index, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("invalid MAC address: {input}"))?;
    }
    if mac == [0; 6] || mac == [0xff; 6] || mac[0] & 1 != 0 {
        return Err(format!("invalid MAC address: {input}"));
    }
    Ok(mac)
}

fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty()
        || hostname.len() > crate::protocol::MAX_ID_BYTES
        || hostname.starts_with('.')
        || hostname.ends_with('.')
    {
        return false;
    }
    hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn is_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => value.is_private(),
        IpAddr::V6(value) => value.is_unique_local(),
    }
}

fn validate_client_id(client_id: &str) -> Result<(), ConfigError> {
    let normalized = client_id.trim().to_ascii_lowercase();
    if client_id.trim() != client_id || normalized.len() > MAX_CLIENT_ID_LEN {
        return Err(ConfigError::Invalid(
            "client_id must be a canonical 1-64 byte identifier".to_owned(),
        ));
    }
    crate::protocol::validate_id(&normalized).map_err(|_| {
        ConfigError::Invalid("client_id must be a canonical 1-64 byte identifier".to_owned())
    })
}

fn validate_endpoint(address: &str) -> Result<(), ConfigError> {
    if address.len() > 255
        || address.is_empty()
        || address
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(ConfigError::Invalid(
            "client address contains invalid characters".to_owned(),
        ));
    }
    Ok(())
}

pub fn decode_key(value: &str) -> Result<[u8; 32], ConfigError> {
    let encoded = value
        .strip_prefix("hex:")
        .ok_or_else(|| ConfigError::Invalid("key must use hex:<64 hex digits>".to_owned()))?;
    let bytes =
        hex::decode(encoded).map_err(|_| ConfigError::Invalid("key hex is invalid".to_owned()))?;
    if bytes.len() != 32 {
        return Err(ConfigError::Invalid(
            "key must contain exactly 32 bytes".to_owned(),
        ));
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ConfigError::Invalid("key cannot be all zero".to_owned()));
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    Ok(output)
}

fn validate_public_key(value: &str, label: &str) -> Result<(), ConfigError> {
    let bytes = decode_key(value)?;
    let probe = x25519_dalek::StaticSecret::from([7u8; 32])
        .diffie_hellman(&x25519_dalek::PublicKey::from(bytes));
    if probe.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ConfigError::Invalid(format!(
            "{label} is a low-order point"
        )));
    }
    Ok(())
}

fn random_identity_pair() -> (String, String) {
    let mut private = [0u8; 32];
    OsRng.fill_bytes(&mut private);
    let secret = x25519_dalek::StaticSecret::from(private);
    let public = x25519_dalek::PublicKey::from(&secret);
    (
        format!("hex:{}", hex::encode(private)),
        format!("hex:{}", hex::encode(public.as_bytes())),
    )
}

/// Generate a fresh X25519 identity for a single enrolled client.  The
/// private half is returned only to the caller so it can be written to the
/// client credential bundle; it is never put in a server handshake config.
pub fn generate_identity_pair() -> (String, String) {
    random_identity_pair()
}

fn derive_public_key(private: &str) -> Result<String, ConfigError> {
    let bytes = decode_key(private)?;
    let secret = x25519_dalek::StaticSecret::from(bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(format!("hex:{}", hex::encode(public.as_bytes())))
}

fn validate_identity_pair(private: &str, public: &str, name: &str) -> Result<(), ConfigError> {
    if private.is_empty() && public.is_empty() {
        return Ok(());
    }
    if private.is_empty() || public.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{name} static key pair must contain both private and public keys"
        )));
    }
    let expected = derive_public_key(private)?;
    if expected != public {
        return Err(ConfigError::Invalid(format!(
            "{name} static public key does not match its private key"
        )));
    }
    validate_public_key(public, &format!("{name} static public key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_is_usable() {
        let config = AppConfig::default();
        assert_eq!(config.secret_key().expect("key").len(), 32);
    }

    #[test]
    fn mac_parser_accepts_common_forms() {
        assert_eq!(parse_mac("AA:bb:cc:dd:ee:ff").unwrap()[0], 0xaa);
        assert_eq!(parse_mac("aabb.ccdd.eeff").unwrap()[5], 0xff);
        assert!(parse_mac("bad").is_err());
    }

    #[test]
    fn mapped_loopback_is_not_a_valid_target() {
        let host = HostConfig {
            hostname: "mapped-loopback".to_owned(),
            display_name: String::new(),
            mac: "02:11:22:33:44:55".to_owned(),
            ip: "::ffff:127.0.0.1".to_owned(),
            wol_port: 9,
            probe_timeout_ms: 1_000,
            probe_port: 0,
            wol_ipv6_interface: 0,
        };
        assert!(host.validate(true).is_err());
    }

    #[test]
    fn link_local_ipv6_requires_an_explicit_interface() {
        let mut host = HostConfig {
            hostname: "link-local".to_owned(),
            display_name: String::new(),
            mac: "02:11:22:33:44:55".to_owned(),
            ip: "fe80::1234".to_owned(),
            wol_port: 9,
            probe_timeout_ms: 1_000,
            probe_port: 0,
            wol_ipv6_interface: 0,
        };
        assert!(host.validate(false).is_err());
        host.wol_ipv6_interface = 7;
        assert!(host.validate(false).is_ok());
    }

    #[test]
    fn host_id_longer_than_wire_limit_is_rejected_during_config_validation() {
        let host = HostConfig {
            hostname: "a".repeat(crate::protocol::MAX_ID_BYTES + 1),
            display_name: String::new(),
            mac: "02:11:22:33:44:55".to_owned(),
            ip: "192.168.1.10".to_owned(),
            wol_port: 9,
            probe_timeout_ms: 1_000,
            probe_port: 0,
            wol_ipv6_interface: 0,
        };

        assert!(matches!(host.validate(false), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn config_and_wire_reject_the_same_reserved_client_ids() {
        for client_id in [".", "..", "_client", "client_"] {
            assert!(validate_client_id(client_id).is_err());
        }
        assert!(validate_client_id("Portable-Client_01").is_ok());
    }
}
