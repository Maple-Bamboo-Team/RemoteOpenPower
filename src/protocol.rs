//! Versioned, bounded application messages.
//!
//! This module has no sockets and no side effects.  It is intentionally the
//! only place that defines operations which can cross the trust boundary.

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};
use std::{collections::HashSet, marker::PhantomData};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_HOSTS: usize = 64;
pub const MAX_REQUEST_TARGETS: usize = 128;
pub const MAX_STATUS_TARGETS: usize = 8;
pub const MAX_HEADERS: usize = 32;
pub const MAX_HEADER_BYTES: usize = 4 * 1024;
pub const MAX_ID_BYTES: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported protocol version")]
    Version,
    #[error("message exceeds protocol limits")]
    Limit,
    #[error("invalid identifier")]
    Identifier,
    #[error("invalid or duplicate header")]
    Header,
    #[error("invalid operation")]
    Operation,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl std::fmt::Debug for Header {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Header")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

// `postcard` exposes a sequence length through `SeqAccess::size_hint`.  The
// standard Vec visitor uses that hint for `with_capacity` before validating
// any element, so a hostile varint can otherwise trigger an oversized
// allocation inside an otherwise small frame.  All wire lists use this
// visitor (and therefore reject the count before allocating).
fn deserialize_bounded_vec<'de, D, T, const LIMIT: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const LIMIT: usize>(PhantomData<T>);

    impl<'de, T, const LIMIT: usize> Visitor<'de> for BoundedVecVisitor<T, LIMIT>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence with at most {LIMIT} elements")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let hint = sequence.size_hint().unwrap_or(0);
            if hint > LIMIT {
                return Err(de::Error::custom("sequence limit exceeded"));
            }
            let mut values = Vec::with_capacity(hint);
            while let Some(value) = sequence.next_element()? {
                if values.len() >= LIMIT {
                    return Err(de::Error::custom("sequence limit exceeded"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor::<T, LIMIT>(PhantomData))
}

fn deserialize_headers<'de, D>(deserializer: D) -> Result<Vec<Header>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, Header, MAX_HEADERS>(deserializer)
}

fn deserialize_target_ids<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, String, MAX_REQUEST_TARGETS>(deserializer)
}

fn deserialize_host_summaries<'de, D>(deserializer: D) -> Result<Vec<HostSummary>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, HostSummary, MAX_HOSTS>(deserializer)
}

fn deserialize_statuses<'de, D>(deserializer: D) -> Result<Vec<HostStatus>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, HostStatus, MAX_HOSTS>(deserializer)
}

fn deserialize_wake_results<'de, D>(deserializer: D) -> Result<Vec<WakeResult>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, WakeResult, MAX_REQUEST_TARGETS>(deserializer)
}

pub fn canonical_headers(mut headers: Vec<Header>) -> Result<Vec<Header>, ProtocolError> {
    if headers.len() > MAX_HEADERS {
        return Err(ProtocolError::Limit);
    }
    headers.sort_by(|left, right| left.name.cmp(&right.name));
    let mut seen = HashSet::new();
    let mut total = 0usize;
    for header in &mut headers {
        if !is_header_name(&header.name) || !is_header_value(&header.value) {
            return Err(ProtocolError::Header);
        }
        header.name.make_ascii_lowercase();
        if header.name.starts_with("rop-") || header.name.starts_with("x-rop-") {
            return Err(ProtocolError::Header);
        }
        if !seen.insert(header.name.clone()) {
            return Err(ProtocolError::Header);
        }
        total = total
            .checked_add(header.name.len())
            .and_then(|value| value.checked_add(header.value.len()))
            .ok_or(ProtocolError::Limit)?;
    }
    if total > MAX_HEADER_BYTES {
        return Err(ProtocolError::Limit);
    }
    // Sorting after lower-casing makes the signed/encrypted representation
    // deterministic even when a caller supplied mixed-case names.
    headers.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(headers)
}

fn is_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_header_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with(' ')
        && !value.ends_with(' ')
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

pub fn validate_id(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || matches!(value, "." | "..")
        || !value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(ProtocolError::Identifier);
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientEnvelope {
    pub version: u16,
    pub request_id: [u8; 16],
    pub issued_at_ms: u64,
    #[serde(deserialize_with = "deserialize_headers")]
    pub headers: Vec<Header>,
    pub operation: ClientOperation,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum ClientOperation {
    ListHosts,
    GetStatuses {
        catalog_version: u64,
        #[serde(deserialize_with = "deserialize_target_ids")]
        host_ids: Vec<String>,
    },
    Wake {
        catalog_version: u64,
        #[serde(deserialize_with = "deserialize_target_ids")]
        host_ids: Vec<String>,
        attempt: u8,
        boot_nonce: [u8; 16],
        retry_ticket: Option<[u8; 32]>,
    },
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerEnvelope {
    pub version: u16,
    pub request_id: [u8; 16],
    pub issued_at_ms: u64,
    #[serde(deserialize_with = "deserialize_headers")]
    pub headers: Vec<Header>,
    pub event: ServerEvent,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum ServerEvent {
    Hosts {
        catalog_version: u64,
        #[serde(deserialize_with = "deserialize_host_summaries")]
        hosts: Vec<HostSummary>,
    },
    Statuses {
        catalog_version: u64,
        #[serde(deserialize_with = "deserialize_statuses")]
        statuses: Vec<HostStatus>,
    },
    CommandExecuted {
        operation_id: [u8; 16],
        attempt: u8,
        retry_ticket: [u8; 32],
        // Bounds TargetOnline observations emitted by the server. The client
        // owns its retry timer and starts a fresh local 60-second window only
        // after receiving this execution receipt.
        deadline_ms: u64,
        #[serde(deserialize_with = "deserialize_wake_results")]
        results: Vec<WakeResult>,
    },
    TargetOnline {
        operation_id: [u8; 16],
        attempt: u8,
        host_id: String,
        observed_at_ms: u64,
    },
    Error {
        code: ErrorCode,
        retryable: bool,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostSummary {
    pub host_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostStatus {
    pub host_id: String,
    pub state: HostState,
    pub observed_at_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum HostState {
    Online,
    Offline,
    Unknown,
    Waking,
    Succeeded,
    Failed,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WakeResult {
    pub host_id: String,
    pub accepted: bool,
    pub error_code: Option<WakeErrorCode>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum WakeErrorCode {
    InvalidTarget,
    RateLimited,
    SenderUnavailable,
    Internal,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Replay,
    RateLimited,
    StaleCatalog,
    Busy,
    Internal,
}

impl ClientEnvelope {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::Version);
        }
        if self.request_id.iter().all(|byte| *byte == 0)
            || self.issued_at_ms == 0
            || self.headers != canonical_headers(self.headers.clone())?
        {
            return Err(ProtocolError::Operation);
        }
        match &self.operation {
            ClientOperation::ListHosts => {}
            ClientOperation::GetStatuses {
                catalog_version,
                host_ids,
            } => {
                validate_catalog_and_targets(*catalog_version, host_ids)?;
            }
            ClientOperation::Wake {
                catalog_version,
                host_ids,
                attempt,
                boot_nonce,
                retry_ticket,
            } => {
                validate_catalog_and_targets(*catalog_version, host_ids)?;
                if !matches!(attempt, 1 | 2) {
                    return Err(ProtocolError::Operation);
                }
                if boot_nonce.iter().all(|byte| *byte == 0) {
                    return Err(ProtocolError::Operation);
                }
                if (*attempt == 1 && retry_ticket.is_some())
                    || (*attempt == 2 && retry_ticket.is_none())
                {
                    return Err(ProtocolError::Operation);
                }
            }
        }
        Ok(())
    }
}

// These wire objects may contain a bearer retry ticket.  Keep Debug useful
// for diagnostics without allowing accidental logs to disclose credentials.
impl std::fmt::Debug for ClientEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientEnvelope")
            .field("version", &self.version)
            .field("request_id", &hex::encode(self.request_id))
            .field("issued_at_ms", &self.issued_at_ms)
            .field("header_count", &self.headers.len())
            .field("operation", &self.operation)
            .finish()
    }
}

impl std::fmt::Debug for ClientOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ListHosts => formatter.write_str("ListHosts"),
            Self::GetStatuses {
                catalog_version,
                host_ids,
            } => formatter
                .debug_struct("GetStatuses")
                .field("catalog_version", catalog_version)
                .field("host_count", &host_ids.len())
                .finish(),
            Self::Wake {
                catalog_version,
                host_ids,
                attempt,
                ..
            } => formatter
                .debug_struct("Wake")
                .field("catalog_version", catalog_version)
                .field("host_count", &host_ids.len())
                .field("attempt", attempt)
                .field("boot_nonce", &"<redacted>")
                .field("retry_ticket", &"<redacted>")
                .finish(),
        }
    }
}

impl std::fmt::Debug for ServerEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerEnvelope")
            .field("version", &self.version)
            .field("request_id", &hex::encode(self.request_id))
            .field("issued_at_ms", &self.issued_at_ms)
            .field("header_count", &self.headers.len())
            .field("event", &self.event)
            .finish()
    }
}

impl std::fmt::Debug for ServerEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
                observed_at_ms,
            } => formatter
                .debug_struct("TargetOnline")
                .field("operation_id", &hex::encode(operation_id))
                .field("attempt", attempt)
                .field("host_id", host_id)
                .field("observed_at_ms", observed_at_ms)
                .finish(),
            Self::Error { code, retryable } => formatter
                .debug_struct("Error")
                .field("code", code)
                .field("retryable", retryable)
                .finish(),
        }
    }
}

impl ServerEnvelope {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::Version);
        }
        if self.request_id.iter().all(|byte| *byte == 0)
            || self.issued_at_ms == 0
            || self.headers != canonical_headers(self.headers.clone())?
        {
            return Err(ProtocolError::Operation);
        }
        match &self.event {
            ServerEvent::Hosts {
                catalog_version,
                hosts,
            } => {
                if *catalog_version == 0 || hosts.len() > MAX_HOSTS {
                    return Err(ProtocolError::Limit);
                }
                let mut ids = HashSet::new();
                for host in hosts {
                    validate_id(&host.host_id)?;
                    if !ids.insert(&host.host_id) {
                        return Err(ProtocolError::Limit);
                    }
                }
            }
            ServerEvent::Statuses {
                catalog_version,
                statuses,
            } => {
                if *catalog_version == 0 || statuses.len() > MAX_HOSTS {
                    return Err(ProtocolError::Limit);
                }
                let mut ids = HashSet::new();
                for status in statuses {
                    validate_id(&status.host_id)?;
                    if !ids.insert(&status.host_id) || status.observed_at_ms == 0 {
                        return Err(ProtocolError::Limit);
                    }
                }
            }
            ServerEvent::CommandExecuted {
                operation_id,
                attempt,
                retry_ticket,
                deadline_ms,
                results,
            } => {
                if operation_id.iter().all(|byte| *byte == 0)
                    || operation_id != &self.request_id
                    || retry_ticket.iter().all(|byte| *byte == 0)
                    || *deadline_ms == 0
                    || results.len() > MAX_REQUEST_TARGETS
                    || results.is_empty()
                    || !matches!(attempt, 1 | 2)
                {
                    return Err(ProtocolError::Limit);
                }
                let mut ids = HashSet::new();
                for result in results {
                    validate_id(&result.host_id)?;
                    if !ids.insert(&result.host_id)
                        || (result.accepted && result.error_code.is_some())
                        || (!result.accepted && result.error_code.is_none())
                    {
                        return Err(ProtocolError::Limit);
                    }
                }
            }
            ServerEvent::TargetOnline {
                operation_id,
                host_id,
                attempt,
                observed_at_ms,
            } => {
                validate_id(host_id)?;
                if operation_id.iter().all(|byte| *byte == 0)
                    || operation_id != &self.request_id
                    || !matches!(attempt, 1 | 2)
                    || *observed_at_ms == 0
                {
                    return Err(ProtocolError::Operation);
                }
            }
            ServerEvent::Error { .. } => {}
        }
        Ok(())
    }
}

fn validate_catalog_and_targets(
    catalog_version: u64,
    host_ids: &[String],
) -> Result<(), ProtocolError> {
    if catalog_version == 0 || host_ids.is_empty() || host_ids.len() > MAX_REQUEST_TARGETS {
        return Err(ProtocolError::Operation);
    }
    let mut ids = HashSet::new();
    for host_id in host_ids {
        validate_id(host_id)?;
        if !ids.insert(host_id) {
            return Err(ProtocolError::Operation);
        }
    }
    Ok(())
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| ProtocolError::Limit)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::Limit);
    }
    Ok(bytes)
}

pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::Limit);
    }
    let (value, rest) = postcard::take_from_bytes(bytes).map_err(|_| ProtocolError::Operation)?;
    if !rest.is_empty() {
        return Err(ProtocolError::Operation);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_are_canonical_and_bounded() {
        let headers = canonical_headers(vec![Header {
            name: "trace-id".into(),
            value: "abc".into(),
        }])
        .unwrap();
        assert_eq!(headers[0].name, "trace-id");
        assert!(
            canonical_headers(vec![Header {
                name: "Trace-Id".into(),
                value: "abc".into(),
            }])
            .is_err()
        );
    }

    #[test]
    fn operation_cannot_carry_network_targets() {
        let operation = ClientOperation::Wake {
            catalog_version: 1,
            host_ids: vec!["desk".into()],
            attempt: 1,
            boot_nonce: [1; 16],
            retry_ticket: None,
        };
        let envelope = ClientEnvelope {
            version: PROTOCOL_VERSION,
            request_id: [1; 16],
            issued_at_ms: 1,
            headers: Vec::new(),
            operation,
        };
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn overlong_host_id_is_rejected_at_the_wire_boundary() {
        let envelope = ServerEnvelope {
            version: PROTOCOL_VERSION,
            request_id: [1; 16],
            issued_at_ms: 1,
            headers: Vec::new(),
            event: ServerEvent::Hosts {
                catalog_version: 1,
                hosts: vec![HostSummary {
                    host_id: "a".repeat(MAX_ID_BYTES + 1),
                }],
            },
        };

        assert_eq!(envelope.validate(), Err(ProtocolError::Identifier));
    }
}
