//! Secure TCP channel based on the Noise Protocol Framework.
//!
//! `snow` owns the cryptographic handshake and transport primitives.  This
//! module owns only framing, protocol binding, identity pinning and replay
//! guards.  No caller can send an application payload before the handshake is
//! complete and the peer identity has been authorized.

use crate::{
    config::{AllowedClient, decode_key},
    protocol::{
        ClientEnvelope, Header, MAX_ID_BYTES, PROTOCOL_VERSION, ProtocolError, ServerEnvelope,
        canonical_headers, decode, encode,
    },
};
use rand::{RngCore, rngs::OsRng};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, Visitor},
};
use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, TransportState};
use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::Zeroize;

// IK authenticates the initiator's static key in the first encrypted
// handshake message and requires the client to pin the responder key before
// connecting. PSK modifiers at positions 0 and 2 make both the first flight
// and the completed transcript depend on independently derived PSK material.
pub const NOISE_PATTERN: &str = "Noise_IKpsk0+psk2_25519_ChaChaPoly_BLAKE2s";
pub const PROLOGUE: &[u8] = b"RemoteOpenPower/tcp/v1/noise-ikpsk0+psk2";
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_HANDSHAKE_RECORD_BYTES: usize = 8 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_REPLAY_ENTRIES: usize = 8 * 1024;
pub const MAX_REPLAY_ENTRIES_PER_CLIENT: usize = 64;
pub const MAX_PENDING_REPLAYS_PER_CLIENT: usize = 4;
pub const REPLAY_TTL: Duration = Duration::from_secs(180);
pub const PENDING_REPLAY_TTL: Duration = Duration::from_secs(6);

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("Noise handshake failed")]
    Handshake,
    #[error("secure transport failed")]
    Transport,
    #[error("secure frame is too large")]
    FrameTooLarge,
    #[error("secure sequence is invalid")]
    Sequence,
    #[error("secure session is expired or replayed")]
    Replay,
    #[error("peer identity is not pinned/authorized")]
    Unauthorized,
    #[error("peer identity pin is required")]
    PinRequired,
    #[error("handshake timestamp is outside the allowed window")]
    Expired,
    #[error("invalid identity key")]
    Identity,
    #[error("protocol error")]
    Protocol(#[from] ProtocolError),
}

#[derive(PartialEq, Eq)]
pub struct Identity {
    pub(crate) private: [u8; 32],
    pub(crate) public: [u8; 32],
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("private", &"<redacted>")
            .field("public", &fingerprint(&self.public))
            .finish()
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.private.zeroize();
        self.public.zeroize();
    }
}

impl Identity {
    pub fn from_hex(private: &str, public: &str) -> Result<Self, SecurityError> {
        let private = decode_key(private).map_err(|_| SecurityError::Identity)?;
        let public = decode_key(public).map_err(|_| SecurityError::Identity)?;
        let secret = x25519_dalek::StaticSecret::from(private);
        let derived = x25519_dalek::PublicKey::from(&secret);
        if derived.as_bytes() != &public {
            return Err(SecurityError::Identity);
        }
        Ok(Self { private, public })
    }

    #[cfg(test)]
    pub fn generate() -> Result<Self, SecurityError> {
        let params = NOISE_PATTERN.parse().map_err(|_| SecurityError::Identity)?;
        let keypair = Builder::new(params)
            .generate_keypair()
            .map_err(|_| SecurityError::Identity)?;
        let private: [u8; 32] = keypair
            .private
            .as_slice()
            .try_into()
            .map_err(|_| SecurityError::Identity)?;
        let public: [u8; 32] = keypair
            .public
            .as_slice()
            .try_into()
            .map_err(|_| SecurityError::Identity)?;
        Ok(Self { private, public })
    }

    #[cfg(test)]
    pub fn private_hex(&self) -> String {
        format!("hex:{}", hex::encode(self.private))
    }

    #[cfg(test)]
    pub fn public_hex(&self) -> String {
        format!("hex:{}", hex::encode(self.public))
    }
}

pub struct ClientHandshakeConfig {
    pub psk: [u8; 32],
    pub identity: Identity,
    pub client_id: String,
    pub pinned_server_key: Option<[u8; 32]>,
    pub clock_skew: Duration,
    pub headers: Vec<Header>,
}

impl std::fmt::Debug for ClientHandshakeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientHandshakeConfig")
            .field("psk", &"<redacted>")
            .field("identity", &self.identity)
            .field("client_id", &self.client_id)
            .field(
                "pinned_server_key",
                &self.pinned_server_key.map(|key| fingerprint(&key)),
            )
            .field("clock_skew", &self.clock_skew)
            .field("header_count", &self.headers.len())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct AllowedClientAuth {
    pub client_id: String,
    pub static_public_key: [u8; 32],
    /// An empty set denies access to every host.
    pub allowed_hosts: HashSet<String>,
}

pub struct ServerHandshakeConfig {
    pub psk: [u8; 32],
    pub identity: Identity,
    pub clock_skew: Duration,
    pub headers: Vec<Header>,
    pub allowed_clients: Vec<AllowedClientAuth>,
}

impl std::fmt::Debug for ServerHandshakeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerHandshakeConfig")
            .field("psk", &"<redacted>")
            .field("identity", &self.identity)
            .field("clock_skew", &self.clock_skew)
            .field("header_count", &self.headers.len())
            .field("allowed_client_count", &self.allowed_clients.len())
            .finish()
    }
}

impl ServerHandshakeConfig {
    pub fn from_config(
        psk: [u8; 32],
        identity: Identity,
        clock_skew: Duration,
        headers: Vec<Header>,
        clients: &[AllowedClient],
        host_ids: &HashSet<String>,
    ) -> Result<Self, SecurityError> {
        if psk.iter().all(|byte| *byte == 0) {
            return Err(SecurityError::Identity);
        }
        validate_public_key_bytes(&identity.public)?;
        let headers = canonical_headers(headers)?;
        let mut allowed_clients = Vec::with_capacity(clients.len());
        let mut client_ids = HashSet::new();
        let mut client_keys = HashSet::new();
        for client in clients {
            let normalized_id = client.client_id.trim().to_ascii_lowercase();
            validate_client_id(&normalized_id)?;
            if !client_ids.insert(normalized_id.clone()) {
                return Err(SecurityError::Unauthorized);
            }
            let key = decode_key(&client.static_public_key).map_err(|_| SecurityError::Identity)?;
            validate_public_key_bytes(&key)?;
            if !client_keys.insert(key) {
                return Err(SecurityError::Unauthorized);
            }
            let mut allowed_hosts = HashSet::new();
            for host in &client.allowed_hosts {
                let id = host.trim().to_ascii_lowercase();
                if !host_ids.contains(&id) {
                    return Err(SecurityError::Unauthorized);
                }
                allowed_hosts.insert(id);
            }
            allowed_clients.push(AllowedClientAuth {
                client_id: normalized_id,
                static_public_key: key,
                allowed_hosts,
            });
        }
        Ok(Self {
            psk,
            identity,
            clock_skew: clamp_clock_skew(clock_skew),
            headers,
            allowed_clients,
        })
    }
}

// A deliberately small, bounded nonce cache.  It protects the expensive
// handshake from captured first messages and complements Noise's fresh DH.
#[derive(Clone, Default)]
pub struct ReplayCache {
    entries: Arc<Mutex<ReplayMap>>,
}

type ReplayMap = HashMap<([u8; 32], [u8; 32]), ReplayEntry>;

#[derive(Clone, Copy)]
struct ReplayEntry {
    expires: Instant,
    confirmed: bool,
}

impl ReplayCache {
    #[cfg(test)]
    pub fn check_and_insert(&self, client_key: [u8; 32], nonce: [u8; 32]) -> bool {
        self.reserve(client_key, nonce) && self.confirm(client_key, nonce)
    }

    fn reserve(&self, client_key: [u8; 32], nonce: [u8; 32]) -> bool {
        let now = Instant::now();
        let mut entries = match self.entries.lock() {
            Ok(value) => value,
            Err(poisoned) => poisoned.into_inner(),
        };
        entries.retain(|_, entry| entry.expires > now);
        if entries.contains_key(&(client_key, nonce)) {
            return false;
        }
        // Keep one authenticated principal from consuming the entire global
        // cache.  A full cache fails closed; it never evicts a live nonce,
        // which would make a captured handshake usable again.
        let client_entries = entries.keys().filter(|(key, _)| *key == client_key).count();
        if client_entries >= MAX_REPLAY_ENTRIES_PER_CLIENT {
            return false;
        }
        let pending_entries = entries
            .iter()
            .filter(|((key, _), entry)| *key == client_key && !entry.confirmed)
            .count();
        if pending_entries >= MAX_PENDING_REPLAYS_PER_CLIENT {
            return false;
        }
        if entries.len() >= MAX_REPLAY_ENTRIES {
            // Never evict a live entry on behalf of an unauthenticated peer.
            // The caller should apply source/handshake rate limiting and retry
            // after the TTL expires.
            return false;
        }
        entries.insert(
            (client_key, nonce),
            ReplayEntry {
                expires: now + PENDING_REPLAY_TTL,
                confirmed: false,
            },
        );
        true
    }

    pub fn confirm(&self, client_key: [u8; 32], nonce: [u8; 32]) -> bool {
        let now = Instant::now();
        let mut entries = match self.entries.lock() {
            Ok(value) => value,
            Err(poisoned) => poisoned.into_inner(),
        };
        entries.retain(|_, entry| entry.expires > now);
        let Some(entry) = entries.get_mut(&(client_key, nonce)) else {
            return false;
        };
        entry.confirmed = true;
        entry.expires = now + REPLAY_TTL;
        true
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ClientHello {
    version: u16,
    client_nonce: [u8; 32],
    issued_at_ms: u64,
    #[serde(deserialize_with = "deserialize_client_id")]
    client_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ServerHello {
    version: u16,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    session_id: [u8; 16],
    issued_at_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct SecureRecord {
    version: u8,
    direction: u8,
    session_id: [u8; 16],
    seq: u64,
    #[serde(deserialize_with = "deserialize_payload")]
    payload: Vec<u8>,
}

fn deserialize_client_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct ClientIdVisitor;

    impl<'de> Visitor<'de> for ClientIdVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "an ASCII client identifier up to {MAX_ID_BYTES} bytes"
            )
        }

        fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty() || value.len() > MAX_ID_BYTES {
                return Err(E::custom("client identifier limit exceeded"));
            }
            Ok(value.to_owned())
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty() || value.len() > MAX_ID_BYTES {
                return Err(E::custom("client identifier limit exceeded"));
            }
            Ok(value.to_owned())
        }
    }

    deserializer.deserialize_str(ClientIdVisitor)
}

fn deserialize_payload<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct PayloadVisitor;

    impl<'de> Visitor<'de> for PayloadVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "a secure payload up to {} bytes",
                MAX_RECORD_BYTES / 2
            )
        }

        fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.len() > MAX_RECORD_BYTES / 2 {
                return Err(E::custom("secure payload limit exceeded"));
            }
            Ok(value.to_vec())
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.len() > MAX_RECORD_BYTES / 2 {
                return Err(E::custom("secure payload limit exceeded"));
            }
            Ok(value.to_vec())
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.len() > MAX_RECORD_BYTES / 2 {
                return Err(E::custom("secure payload limit exceeded"));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_bytes(PayloadVisitor)
}

pub struct ClientHandshakeResult {
    pub connection: SecureConnection,
    pub server_static_public: [u8; 32],
}

pub struct ServerHandshakeResult {
    pub connection: SecureConnection,
    pub client_id: String,
    pub client_static_public: [u8; 32],
    pub replay_nonce: [u8; 32],
}

pub struct SecureConnection {
    stream: TcpStream,
    transport: TransportState,
    session_id: [u8; 16],
    outbound_direction: u8,
    inbound_direction: u8,
    send_seq: u64,
    recv_seq: u64,
    read_buffer: Vec<u8>,
    peer_addr: SocketAddr,
    closed: bool,
}

impl std::fmt::Debug for SecureConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecureConnection")
            .field("session_id", &hex::encode(self.session_id))
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .field("peer_addr", &self.peer_addr)
            .finish()
    }
}

impl SecureConnection {
    fn fail<T>(&mut self, error: SecurityError) -> Result<T, SecurityError> {
        if let Err(shutdown_error) = self.close() {
            crate::logging::log(
                crate::logging::Level::Warn,
                format!("secure connection shutdown failed: {shutdown_error}"),
            );
        }
        Err(error)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Number of bytes currently buffered for the next record.  Callers use
    /// this to enforce an absolute deadline for a peer that starts a frame
    /// and then drips bytes indefinitely.
    pub fn buffered_len(&self) -> usize {
        self.read_buffer.len()
    }

    pub fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        match self.stream.shutdown(std::net::Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub fn send_payload(&mut self, payload: &[u8]) -> Result<(), SecurityError> {
        if self.closed {
            return Err(SecurityError::Transport);
        }
        if payload.is_empty() || payload.len() > MAX_RECORD_BYTES / 2 {
            return Err(SecurityError::FrameTooLarge);
        }
        let seq = self.send_seq;
        let next = match seq.checked_add(1) {
            Some(next) => next,
            None => return self.fail(SecurityError::Sequence),
        };
        let record = SecureRecord {
            version: 1,
            direction: self.outbound_direction,
            session_id: self.session_id,
            seq,
            payload: payload.to_vec(),
        };
        let plain = encode(&record)?;
        let mut encrypted = vec![0u8; plain.len().saturating_add(64)];
        let length = match self.transport.write_message(&plain, &mut encrypted) {
            Ok(length) => length,
            Err(_) => {
                self.closed = true;
                return Err(SecurityError::Transport);
            }
        };
        if length == 0 || length > MAX_RECORD_BYTES {
            return self.fail(SecurityError::FrameTooLarge);
        }
        // Prefix and body share one absolute deadline. A peer that reads one
        // tiny window at a time cannot reset the timeout and pin this worker.
        let result = write_record_bounded(
            &mut self.stream,
            &encrypted[..length],
            MAX_RECORD_BYTES,
            Instant::now() + WRITE_TIMEOUT,
        );
        if result.is_err() {
            // Noise has already consumed its nonce.  Never reuse this state
            // after a partial/failed write.
            self.closed = true;
        }
        result?;
        self.send_seq = next;
        Ok(())
    }

    pub fn send_client_envelope(&mut self, envelope: &ClientEnvelope) -> Result<(), SecurityError> {
        envelope.validate()?;
        let bytes = encode(envelope)?;
        self.send_payload(&bytes)
    }

    /// Poll a nonblocking socket.  Partial TCP records stay in `read_buffer`
    /// and are never interpreted until the complete bounded frame is present.
    pub fn poll_payload(&mut self) -> Result<Option<Vec<u8>>, SecurityError> {
        if self.closed {
            return Err(SecurityError::Transport);
        }
        let mut chunk = [0u8; 8 * 1024];
        loop {
            // Stop reading as soon as the first complete record is buffered.
            // This keeps subsequent coalesced TCP records queued for the next
            // poll instead of counting them against the current frame limit.
            if self.read_buffer.len() >= 4 {
                let length = u32::from_be_bytes([
                    self.read_buffer[0],
                    self.read_buffer[1],
                    self.read_buffer[2],
                    self.read_buffer[3],
                ]) as usize;
                if length == 0 || length > MAX_RECORD_BYTES {
                    return self.fail(SecurityError::FrameTooLarge);
                }
                let total = match 4usize.checked_add(length) {
                    Some(total) => total,
                    None => return self.fail(SecurityError::FrameTooLarge),
                };
                if self.read_buffer.len() >= total {
                    break;
                }
            }

            let remaining = (MAX_RECORD_BYTES + 4).saturating_sub(self.read_buffer.len());
            if remaining == 0 {
                return self.fail(SecurityError::FrameTooLarge);
            }
            let read_size = remaining.min(chunk.len());
            match self.stream.read(&mut chunk[..read_size]) {
                Ok(0) => {
                    return self.fail(SecurityError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed",
                    )));
                }
                Ok(length) => {
                    self.read_buffer.extend_from_slice(&chunk[..length]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return self.fail(SecurityError::Io(error)),
            }
        }
        if self.read_buffer.len() < 4 {
            return Ok(None);
        }
        let length = u32::from_be_bytes([
            self.read_buffer[0],
            self.read_buffer[1],
            self.read_buffer[2],
            self.read_buffer[3],
        ]) as usize;
        if length == 0 || length > MAX_RECORD_BYTES {
            return self.fail(SecurityError::FrameTooLarge);
        }
        let total = match 4usize.checked_add(length) {
            Some(total) => total,
            None => return self.fail(SecurityError::FrameTooLarge),
        };
        if self.read_buffer.len() < total {
            return Ok(None);
        }
        let encrypted = self.read_buffer[4..total].to_vec();
        self.read_buffer.drain(..total);
        let mut plain = vec![0u8; MAX_RECORD_BYTES];
        let plain_length = self
            .transport
            .read_message(&encrypted, &mut plain)
            .map_err(|_| SecurityError::Transport)
            .inspect_err(|_| {
                self.closed = true;
            })?;
        let record: SecureRecord = match decode(&plain[..plain_length]) {
            Ok(record) => record,
            Err(error) => {
                self.closed = true;
                return Err(error.into());
            }
        };
        if record.version != 1
            || record.direction != self.inbound_direction
            || record.session_id != self.session_id
            || record.seq != self.recv_seq
            || record.payload.is_empty()
            || record.payload.len() > MAX_RECORD_BYTES / 2
        {
            self.closed = true;
            return Err(SecurityError::Sequence);
        }
        self.recv_seq = match self.recv_seq.checked_add(1) {
            Some(next) => next,
            None => return self.fail(SecurityError::Sequence),
        };
        Ok(Some(record.payload))
    }

    pub fn poll_server_envelope(&mut self) -> Result<Option<ServerEnvelope>, SecurityError> {
        let payload = match self.poll_payload()? {
            Some(payload) => payload,
            None => return Ok(None),
        };
        let envelope: ServerEnvelope = match decode(&payload) {
            Ok(envelope) => envelope,
            Err(error) => return self.fail(error.into()),
        };
        if let Err(error) = envelope.validate() {
            return self.fail(error.into());
        }
        Ok(Some(envelope))
    }
}

pub fn client_handshake(
    mut stream: TcpStream,
    config: &ClientHandshakeConfig,
) -> Result<ClientHandshakeResult, SecurityError> {
    prepare_stream(&stream)?;
    validate_client_id(&config.client_id)?;
    canonical_headers(config.headers.clone())?;
    let expected = config.pinned_server_key.ok_or(SecurityError::PinRequired)?;
    validate_public_key_bytes(&expected)?;
    // Clamp here as well as in
    // `ServerHandshakeConfig::from_config` to prevent an accidental
    // `Duration::MAX` from disabling freshness checks.
    let clock_skew = clamp_clock_skew(config.clock_skew);
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    // IK requires the pinned responder key at construction time.  The client
    // identity and ID are authenticated/encrypted in message one.
    let mut state = build_noise(&config.psk, &config.identity, true, Some(&expected))?;
    let mut client_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut client_nonce);
    let hello = ClientHello {
        version: PROTOCOL_VERSION,
        client_nonce,
        issued_at_ms: unix_ms(),
        client_id: config.client_id.clone(),
    };
    validate_client_hello(&hello, clock_skew)?;
    let mut noise = vec![0u8; MAX_HANDSHAKE_RECORD_BYTES];
    let hello_bytes = encode(&hello)?;
    let length = state
        .write_message(&hello_bytes, &mut noise)
        .map_err(|_| SecurityError::Handshake)?;
    write_handshake(&mut stream, 1, &noise[..length], deadline)?;

    let incoming = read_handshake(&mut stream, 2, deadline)?;
    let mut payload = vec![0u8; MAX_HANDSHAKE_RECORD_BYTES];
    validate_ephemeral_prefix(&incoming)?;
    let payload_length = state
        .read_message(&incoming, &mut payload)
        .map_err(|_| SecurityError::Handshake)?;
    let reply: ServerHello =
        decode(&payload[..payload_length]).map_err(|_| SecurityError::Handshake)?;
    validate_server_hello(&reply, client_nonce, clock_skew)?;

    if !state.is_handshake_finished() {
        return Err(SecurityError::Handshake);
    }
    let remote = state.get_remote_static().ok_or(SecurityError::Handshake)?;
    let server_static_public: [u8; 32] = remote.try_into().map_err(|_| SecurityError::Handshake)?;
    if server_static_public != expected {
        return Err(SecurityError::Unauthorized);
    }
    let transport = state
        .into_transport_mode()
        .map_err(|_| SecurityError::Handshake)?;
    let peer_addr = stream.peer_addr()?;
    stream.set_nonblocking(true)?;
    Ok(ClientHandshakeResult {
        connection: SecureConnection {
            stream,
            transport,
            session_id: reply.session_id,
            outbound_direction: 0,
            inbound_direction: 1,
            send_seq: 0,
            recv_seq: 0,
            read_buffer: Vec::with_capacity(8 * 1024),
            peer_addr,
            closed: false,
        },
        server_static_public,
    })
}

pub fn server_handshake(
    mut stream: TcpStream,
    config: &ServerHandshakeConfig,
    replay_cache: &ReplayCache,
) -> Result<ServerHandshakeResult, SecurityError> {
    prepare_stream(&stream)?;
    canonical_headers(config.headers.clone())?;
    let clock_skew = clamp_clock_skew(config.clock_skew);
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut state = build_noise(&config.psk, &config.identity, false, None)?;
    let incoming = read_handshake(&mut stream, 1, deadline)?;
    validate_ephemeral_prefix(&incoming)?;
    let mut payload = vec![0u8; MAX_HANDSHAKE_RECORD_BYTES];
    let payload_length = state
        .read_message(&incoming, &mut payload)
        .map_err(|_| SecurityError::Handshake)?;
    let hello: ClientHello =
        decode(&payload[..payload_length]).map_err(|_| SecurityError::Handshake)?;
    validate_client_hello(&hello, clock_skew)?;
    validate_client_id(&hello.client_id)?;
    let remote = state.get_remote_static().ok_or(SecurityError::Handshake)?;
    let client_static_public: [u8; 32] = remote.try_into().map_err(|_| SecurityError::Handshake)?;
    // Reject low-order authenticated points before they reach any ACL or
    // bootstrap branch, avoiding a known-zero X25519 DH result.
    validate_public_key_bytes(&client_static_public)?;
    let authorized_client_id = authorize_client(&hello.client_id, &client_static_public, config)?;

    // The IK first message has already authenticated the client static key
    // and the ACL decision above is complete.  Reserve the client nonce
    // before doing any response work so a captured/replayed first message
    // cannot make the server spend resources or emit a fresh ServerHello.
    // Inserting only after authentication also prevents unauthenticated
    // traffic from occupying the bounded replay cache.
    if !replay_cache.reserve(client_static_public, hello.client_nonce) {
        return Err(SecurityError::Replay);
    }

    let mut server_nonce = [0u8; 32];
    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut server_nonce);
    OsRng.fill_bytes(&mut session_id);
    let reply = ServerHello {
        version: PROTOCOL_VERSION,
        client_nonce: hello.client_nonce,
        server_nonce,
        session_id,
        issued_at_ms: unix_ms(),
    };
    let reply_bytes = encode(&reply)?;
    let mut noise = vec![0u8; MAX_HANDSHAKE_RECORD_BYTES];
    let length = state
        .write_message(&reply_bytes, &mut noise)
        .map_err(|_| SecurityError::Handshake)?;
    write_handshake(&mut stream, 2, &noise[..length], deadline)?;

    if !state.is_handshake_finished() {
        return Err(SecurityError::Handshake);
    }
    let transport = state
        .into_transport_mode()
        .map_err(|_| SecurityError::Handshake)?;
    let peer_addr = stream.peer_addr()?;
    stream.set_nonblocking(true)?;
    Ok(ServerHandshakeResult {
        connection: SecureConnection {
            stream,
            transport,
            session_id,
            outbound_direction: 1,
            inbound_direction: 0,
            send_seq: 0,
            recv_seq: 0,
            read_buffer: Vec::with_capacity(8 * 1024),
            peer_addr,
            closed: false,
        },
        client_id: authorized_client_id,
        client_static_public,
        replay_nonce: hello.client_nonce,
    })
}

fn authorize_client(
    client_id: &str,
    static_public: &[u8; 32],
    config: &ServerHandshakeConfig,
) -> Result<String, SecurityError> {
    if let Some(client) = config
        .allowed_clients
        .iter()
        .find(|client| client.static_public_key == *static_public)
    {
        if client.client_id != client_id
            || client.client_id != client_id_from_public_key(static_public)
        {
            return Err(SecurityError::Unauthorized);
        }
        return Ok(client.client_id.clone());
    }
    Err(SecurityError::Unauthorized)
}

fn validate_client_id(client_id: &str) -> Result<(), SecurityError> {
    crate::protocol::validate_id(client_id).map_err(|_| SecurityError::Handshake)
}

fn validate_public_key_bytes(key: &[u8; 32]) -> Result<(), SecurityError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(SecurityError::Identity);
    }
    let probe = x25519_dalek::StaticSecret::from([7u8; 32])
        .diffie_hellman(&x25519_dalek::PublicKey::from(*key));
    if probe.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(SecurityError::Identity);
    }
    Ok(())
}

fn build_noise(
    psk: &[u8; 32],
    identity: &Identity,
    initiator: bool,
    remote_public: Option<&[u8; 32]>,
) -> Result<HandshakeState, SecurityError> {
    if psk.iter().all(|byte| *byte == 0) {
        return Err(SecurityError::Identity);
    }
    validate_public_key_bytes(&identity.public)?;
    let derived =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(identity.private));
    if derived.as_bytes() != &identity.public {
        return Err(SecurityError::Identity);
    }
    let params = NOISE_PATTERN
        .parse()
        .map_err(|_| SecurityError::Handshake)?;
    let mut psk0 = derive_noise_psk(psk, b"psk0");
    let mut psk2 = derive_noise_psk(psk, b"psk2");
    let mut builder = Builder::new(params)
        .local_private_key(&identity.private)
        .map_err(|_| SecurityError::Identity)?
        .psk(0, &psk0)
        .map_err(|_| SecurityError::Handshake)?
        .psk(2, &psk2)
        .map_err(|_| SecurityError::Handshake)?
        .prologue(PROLOGUE)
        .map_err(|_| SecurityError::Handshake)?;
    if let Some(remote_public) = remote_public {
        builder = builder
            .remote_public_key(remote_public)
            .map_err(|_| SecurityError::Identity)?;
    }
    let result = if initiator {
        builder
            .build_initiator()
            .map_err(|_| SecurityError::Handshake)
    } else {
        builder
            .build_responder()
            .map_err(|_| SecurityError::Handshake)
    };
    psk0.zeroize();
    psk2.zeroize();
    result
}

fn derive_noise_psk(psk: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROLOGUE);
    hasher.update(label);
    hasher.update(psk);
    hasher.finalize().into()
}

fn prepare_stream(stream: &TcpStream) -> Result<(), SecurityError> {
    stream.set_nodelay(true)?;
    // Nonblocking I/O plus one absolute deadline prevents a slowloris peer
    // from extending the handshake by sending a byte before every timeout.
    stream.set_nonblocking(true)?;
    Ok(())
}

fn write_handshake(
    stream: &mut TcpStream,
    phase: u8,
    payload: &[u8],
    deadline: Instant,
) -> Result<(), SecurityError> {
    if payload.is_empty() || payload.len() > MAX_HANDSHAKE_RECORD_BYTES {
        return Err(SecurityError::FrameTooLarge);
    }
    let mut frame = Vec::with_capacity(payload.len() + 1);
    frame.push(phase);
    frame.extend_from_slice(payload);
    write_record_bounded(stream, &frame, MAX_HANDSHAKE_RECORD_BYTES + 1, deadline)
}

fn write_record_bounded(
    stream: &mut TcpStream,
    payload: &[u8],
    max: usize,
    deadline: Instant,
) -> Result<(), SecurityError> {
    if payload.is_empty() || payload.len() > max {
        return Err(SecurityError::FrameTooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| SecurityError::FrameTooLarge)?;
    write_all_deadline(stream, &length.to_be_bytes(), deadline)?;
    write_all_deadline(stream, payload, deadline)?;
    Ok(())
}

fn read_handshake(
    stream: &mut TcpStream,
    expected_phase: u8,
    deadline: Instant,
) -> Result<Vec<u8>, SecurityError> {
    let mut length_bytes = [0u8; 4];
    read_exact_deadline(stream, &mut length_bytes, deadline)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if !(2..=MAX_HANDSHAKE_RECORD_BYTES + 1).contains(&length) {
        return Err(SecurityError::FrameTooLarge);
    }
    let mut frame = vec![0u8; length];
    read_exact_deadline(stream, &mut frame, deadline)?;
    if frame[0] != expected_phase || frame.len() < 2 {
        return Err(SecurityError::Handshake);
    }
    Ok(frame[1..].to_vec())
}

fn write_all_deadline(
    stream: &mut TcpStream,
    mut data: &[u8],
    deadline: Instant,
) -> Result<(), SecurityError> {
    while !data.is_empty() {
        if Instant::now() >= deadline {
            return Err(SecurityError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "write deadline",
            )));
        }
        match stream.write(data) {
            Ok(0) => {
                return Err(SecurityError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "closed",
                )));
            }
            Ok(written) => data = &data[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(SecurityError::Io(error)),
        }
    }
    Ok(())
}

fn read_exact_deadline(
    stream: &mut TcpStream,
    mut data: &mut [u8],
    deadline: Instant,
) -> Result<(), SecurityError> {
    while !data.is_empty() {
        if Instant::now() >= deadline {
            return Err(SecurityError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "handshake deadline",
            )));
        }
        match stream.read(data) {
            Ok(0) => {
                return Err(SecurityError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed",
                )));
            }
            Ok(read) => data = &mut data[read..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(SecurityError::Io(error)),
        }
    }
    Ok(())
}

fn validate_client_hello(hello: &ClientHello, skew: Duration) -> Result<(), SecurityError> {
    if hello.version != PROTOCOL_VERSION
        || hello.client_nonce.iter().all(|byte| *byte == 0)
        || validate_client_id(&hello.client_id).is_err()
        || !within_skew(hello.issued_at_ms, unix_ms(), skew)
    {
        return Err(SecurityError::Expired);
    }
    Ok(())
}

fn validate_server_hello(
    hello: &ServerHello,
    client_nonce: [u8; 32],
    skew: Duration,
) -> Result<(), SecurityError> {
    if hello.version != PROTOCOL_VERSION
        || hello.client_nonce != client_nonce
        || hello.server_nonce.iter().all(|byte| *byte == 0)
        || hello.session_id.iter().all(|byte| *byte == 0)
        || !within_skew(hello.issued_at_ms, unix_ms(), skew)
    {
        return Err(SecurityError::Handshake);
    }
    Ok(())
}

fn validate_ephemeral_prefix(frame: &[u8]) -> Result<(), SecurityError> {
    // Every IK handshake message starts with the sender's 32-byte X25519
    // ephemeral public key.  Reject low-order/all-zero points before snow's
    // resolver performs a DH operation; this closes the all-zero-DH failure
    // mode present in generic resolvers.
    if frame.len() < 32 {
        return Err(SecurityError::Handshake);
    }
    let key: [u8; 32] = frame[..32]
        .try_into()
        .map_err(|_| SecurityError::Handshake)?;
    validate_public_key_bytes(&key)
}

fn within_skew(timestamp_ms: u64, now_ms: u64, skew: Duration) -> bool {
    let skew_ms = skew.as_millis().min(u64::MAX as u128) as u64;
    timestamp_ms.abs_diff(now_ms) <= skew_ms
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn clamp_clock_skew(value: Duration) -> Duration {
    value.clamp(Duration::from_secs(1), Duration::from_secs(60))
}

pub fn fingerprint(public: &[u8; 32]) -> String {
    let digest = Sha256::digest(public);
    hex::encode(digest)
}

/// Stable portable client identifier.  It is a full SHA-256 digest of the
/// static public key, encoded as lowercase hex so it remains a valid protocol
/// identifier and can be copied between operating systems without ambiguity.
pub fn client_id_from_public_key(public: &[u8; 32]) -> String {
    fingerprint(public)
}

pub fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trip_and_pin_fingerprint() {
        let identity = Identity::generate().expect("identity");
        let restored = Identity::from_hex(&identity.private_hex(), &identity.public_hex()).unwrap();
        assert_eq!(identity, restored);
        assert_eq!(fingerprint(&identity.public).len(), 64);
    }

    #[test]
    fn replay_cache_rejects_nonce_reuse() {
        let cache = ReplayCache::default();
        assert!(cache.check_and_insert([8; 32], [9; 32]));
        assert!(!cache.check_and_insert([8; 32], [9; 32]));
    }

    #[test]
    fn unconfirmed_replay_reservations_are_per_client_and_bounded() {
        let cache = ReplayCache::default();
        for nonce in 1..=MAX_PENDING_REPLAYS_PER_CLIENT as u8 {
            assert!(cache.reserve([1; 32], [nonce; 32]));
        }
        assert!(!cache.reserve([1; 32], [9; 32]));
        assert!(cache.reserve([2; 32], [9; 32]));
        assert!(cache.confirm([1; 32], [1; 32]));
        assert!(cache.reserve([1; 32], [9; 32]));
    }

    #[test]
    fn ik_handshake_round_trip() {
        use std::net::TcpListener;

        let server_identity = Identity::generate().expect("server identity");
        let client_identity = Identity::generate().expect("client identity");
        let server_public = server_identity.public;
        let client_public = client_identity.public;
        let client_id = client_id_from_public_key(&client_public);
        let psk = [42u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server_config = ServerHandshakeConfig {
            psk,
            identity: server_identity,
            clock_skew: Duration::from_secs(30),
            headers: Vec::new(),
            allowed_clients: vec![AllowedClientAuth {
                client_id: client_id.clone(),
                static_public_key: client_public,
                allowed_hosts: HashSet::new(),
            }],
        };
        let replay = ReplayCache::default();
        let server_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server_handshake(stream, &server_config, &replay).expect("server handshake")
        });
        let stream = TcpStream::connect(address).expect("connect");
        let client_config = ClientHandshakeConfig {
            psk,
            identity: client_identity,
            client_id,
            pinned_server_key: Some(server_public),
            clock_skew: Duration::from_secs(30),
            headers: Vec::new(),
        };
        let client = client_handshake(stream, &client_config).expect("client handshake");
        let server = server_thread.join().expect("server thread");
        assert_eq!(client.server_static_public, server_public);
        assert_eq!(server.client_static_public, client_public);
    }

    #[test]
    fn portable_key_id_rejects_a_mismatched_acl_identity() {
        use std::net::TcpListener;

        let server_identity = Identity::generate().expect("server identity");
        let client_identity = Identity::generate().expect("client identity");
        let server_public = server_identity.public;
        let client_public = client_identity.public;
        let psk = [44u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server_config = ServerHandshakeConfig {
            psk,
            identity: server_identity,
            clock_skew: Duration::from_secs(30),
            headers: Vec::new(),
            allowed_clients: vec![AllowedClientAuth {
                client_id: "school-laptop".to_owned(),
                static_public_key: client_public,
                allowed_hosts: HashSet::new(),
            }],
        };
        let replay = ReplayCache::default();
        let server_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server_handshake(stream, &server_config, &replay)
        });
        let stream = TcpStream::connect(address).expect("connect");
        let client_config = ClientHandshakeConfig {
            psk,
            identity: client_identity,
            client_id: client_id_from_public_key(&client_public),
            pinned_server_key: Some(server_public),
            clock_skew: Duration::from_secs(30),
            headers: Vec::new(),
        };
        assert!(client_handshake(stream, &client_config).is_err());
        assert!(server_thread.join().expect("server thread").is_err());
    }

    #[test]
    fn coalesced_payloads_are_independent_and_bad_typed_payload_closes() {
        use std::{io::Write, net::TcpListener, thread};

        let server_identity = Identity::generate().expect("server identity");
        let client_identity = Identity::generate().expect("client identity");
        let server_public = server_identity.public;
        let client_public = client_identity.public;
        let client_id = client_id_from_public_key(&client_public);
        let psk = [43u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server_config = ServerHandshakeConfig {
            psk,
            identity: server_identity,
            clock_skew: Duration::from_secs(30),
            headers: Vec::new(),
            allowed_clients: vec![AllowedClientAuth {
                client_id: client_id.clone(),
                static_public_key: client_public,
                allowed_hosts: HashSet::new(),
            }],
        };
        let replay = ReplayCache::default();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server_handshake(stream, &server_config, &replay).expect("server handshake")
        });
        let client_stream = TcpStream::connect(address).expect("connect");
        let client_config = ClientHandshakeConfig {
            psk,
            identity: client_identity,
            client_id,
            pinned_server_key: Some(server_public),
            clock_skew: Duration::from_secs(30),
            headers: Vec::new(),
        };
        let client_result =
            client_handshake(client_stream, &client_config).expect("client handshake");
        let server_result = server_thread.join().expect("server thread");
        let mut client = client_result.connection;
        let mut server = server_result.connection;

        // Put both records on the wire before the first poll.  TCP may split
        // them, but the receiver must produce exactly one logical payload per
        // call either way and must never reject a legal coalesced read.
        client.send_payload(b"one").expect("first payload");
        client.send_payload(b"two").expect("second payload");

        let first = poll_payload_until(&mut server);
        let second = poll_payload_until(&mut server);
        assert_eq!(first, b"one");
        assert_eq!(second, b"two");

        // The transport is authenticated, but this is not a valid typed
        // envelope.  It must poison the connection rather than leaving an
        // actor alive with an ambiguous sequence state.
        client.send_payload(&[0xff]).expect("malformed payload");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match server.poll_server_envelope() {
                Err(SecurityError::Protocol(_)) => break,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                other => panic!("unexpected malformed-envelope result: {other:?}"),
            }
        }
        assert!(server.closed);
        assert!(matches!(
            server.poll_server_envelope(),
            Err(SecurityError::Transport)
        ));

        // Keep the stream write path exercised after the test's direct socket
        // setup on platforms that buffer aggressively.
        client.stream.flush().expect("flush test client stream");
    }

    fn poll_payload_until(connection: &mut SecureConnection) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match connection.poll_payload() {
                Ok(Some(payload)) => return payload,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(None) => panic!("timed out waiting for payload"),
                Err(error) => panic!("unexpected payload error: {error:?}"),
            }
        }
    }
}
