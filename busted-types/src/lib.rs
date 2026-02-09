//! The data contract between kernel and userspace for
//! [Busted](https://github.com/barakber/busted), the eBPF-based LLM/AI communication
//! monitor.
//!
//! When an eBPF probe fires inside the kernel — a TCP connection closes, an SSL handshake
//! begins, a decrypted payload is captured — it needs to hand that event to userspace. The
//! two sides share no heap, no allocator, and no serde. They share *these structs*: flat,
//! `#[repr(C)]`, fixed-size types that the eBPF verifier can prove safe and that Rust can
//! read directly out of a ring buffer with zero copies.
//!
//! # Why this crate exists
//!
//! eBPF programs run under extreme constraints: a 512-byte stack, no dynamic allocation,
//! and a static verifier that rejects any code it can't prove terminates and stays in
//! bounds. That means no `String`, no `Vec`, no trait objects. Every field must be a
//! primitive or a fixed-length array, and every struct must be `Copy` and `#[repr(C)]` so
//! the kernel and userspace agree on layout byte-for-byte.
//!
//! At the same time, the userspace agent needs to enrich these raw events with container
//! metadata, classifier results, ML predictions, and human-readable formatting before
//! forwarding them to the UI and SIEM sinks. Cramming all of that into `no_std` types
//! would be painful and pointless.
//!
//! `busted-types` solves this by serving two audiences from one crate:
//!
//! - **eBPF side** (`no_std`, default) — just the wire types, nothing else.
//! - **Userspace side** (`user` feature) — adds `aya::Pod` impls, serde, IP-to-string
//!   helpers, and the enriched [`processed::ProcessedEvent`] that the rest of the system
//!   consumes.
//!
//! # How data flows
//!
//! ```text
//! ┌──────────────┐     #[repr(C)]      ┌──────────────┐     ProcessedEvent     ┌─────────┐
//! │  eBPF probes │ ──── structs ──────▶ │ busted-agent │ ──── (NDJSON) ──────▶ │ UI/SIEM │
//! │  (kernel)    │     via RingBuf      │ (userspace)  │     via Unix socket   │         │
//! └──────────────┘                      └──────────────┘                       └─────────┘
//! ```
//!
//! The eBPF probes write [`NetworkEvent`], [`TlsHandshakeEvent`], or [`TlsDataEvent`]
//! into a shared ring buffer. The agent reads them out (using aya's `Pod` trait, enabled
//! by the `user` feature), enriches them into a [`processed::ProcessedEvent`], and
//! serializes that as NDJSON over a Unix socket.
//!
//! # Feature Flags
//!
//! - **`user`** — Enables userspace-only functionality:
//!   - [`aya::Pod`] trait implementations for all event types (required by aya map APIs)
//!   - [`serde::Serialize`] / [`serde::Deserialize`] on [`processed::ProcessedEvent`]
//!   - Helper methods for IP address conversion, string extraction, etc.
//!     (in the [`userspace`] module)
//!
//! # Core Types
//!
//! | Type | Description |
//! |------|-------------|
//! | [`NetworkEvent`] | TCP/UDP network event captured by kprobes |
//! | [`TlsHandshakeEvent`] | TLS SNI extracted from `SSL_ctrl` uprobe |
//! | [`TlsDataEvent`] | Decrypted TLS payload from `SSL_write`/`SSL_read` uprobes |
//! | [`TlsConnKey`] | Composite key `(pid, ssl_ptr)` for the TLS verdict map |
//! | [`AgentIdentity`] | Identity record for processes communicating with LLM providers |
//! | [`processed::ProcessedEvent`] | Enriched event for UI/SIEM consumption (requires `user` feature) |

#![cfg_attr(not(feature = "user"), no_std)]

/// Maximum length for process names.
pub const TASK_COMM_LEN: usize = 16;

/// Maximum length for container IDs
pub const CONTAINER_ID_LEN: usize = 64;

/// Maximum length for cgroup paths
pub const CGROUP_PATH_LEN: usize = 128;

/// Event types for LLM/AI communication monitoring
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum EventType {
    /// TCP connection attempt
    TcpConnect = 1,
    /// Data sent
    DataSent = 2,
    /// Data received
    DataReceived = 3,
    /// Connection closed
    ConnectionClosed = 4,
    /// DNS query (UDP to port 53)
    DnsQuery = 5,
    /// TLS handshake (SNI extraction)
    TlsHandshake = 6,
    /// TLS plaintext data write (SSL_write capture)
    TlsDataWrite = 7,
    /// TLS plaintext data read (SSL_read capture)
    TlsDataRead = 8,
}

/// Network protocol family
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum AddressFamily {
    Ipv4 = 2,  // AF_INET
    Ipv6 = 10, // AF_INET6
    Unknown = 0,
}

/// IP address (supports both IPv4 and IPv6)
#[repr(C)]
#[derive(Clone, Copy)]
pub union IpAddress {
    pub ipv4: u32,
    pub ipv6: [u8; 16],
}

impl IpAddress {
    pub const fn zero() -> Self {
        IpAddress { ipv4: 0 }
    }
}

/// Maximum length for SNI hostnames
pub const SNI_MAX_LEN: usize = 128;

/// Maximum payload bytes captured per TLS read/write.
/// 16 KB — enough to capture HTTP headers + most of the JSON body.
/// The eBPF probe uses a PerCpuArray (not the stack) so this is safe.
pub const TLS_PAYLOAD_MAX: usize = 16384;

/// TLS handshake event captured by eBPF uprobe on SSL_ctrl
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsHandshakeEvent {
    /// Event type (always 6 = TlsHandshake)
    pub event_type: u8,
    pub _pad: [u8; 3],
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// Timestamp (nanoseconds since boot)
    pub timestamp_ns: u64,
    /// Process/command name
    pub comm: [u8; TASK_COMM_LEN],
    /// SNI hostname
    pub sni: [u8; SNI_MAX_LEN],
}

impl Default for TlsHandshakeEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsHandshakeEvent {
    pub const fn new() -> Self {
        TlsHandshakeEvent {
            event_type: 6,
            _pad: [0; 3],
            pid: 0,
            tid: 0,
            timestamp_ns: 0,
            comm: [0; TASK_COMM_LEN],
            sni: [0; SNI_MAX_LEN],
        }
    }
}

/// Composite key for TLS connection verdict map: (PID, SSL pointer)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsConnKey {
    pub pid: u32,
    pub _pad: u32,
    pub ssl_ptr: u64,
}

impl Default for TlsConnKey {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConnKey {
    pub const fn new() -> Self {
        TlsConnKey {
            pid: 0,
            _pad: 0,
            ssl_ptr: 0,
        }
    }
}

/// TLS plaintext data captured by eBPF uprobes on SSL_write/SSL_read
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsDataEvent {
    /// Event type: 7=write, 8=read (at byte offset 0 for dispatch)
    pub event_type: u8,
    /// Direction: 0=write, 1=read
    pub direction: u8,
    /// Actual bytes captured (may be less than TLS_PAYLOAD_MAX)
    pub payload_len: u16,
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    pub _pad: u32,
    /// SSL struct pointer — unique connection identifier
    pub ssl_ptr: u64,
    /// Timestamp (nanoseconds since boot)
    pub timestamp_ns: u64,
    /// Process/command name
    pub comm: [u8; TASK_COMM_LEN],
    /// 1 if this is the first data on this connection
    pub is_first_chunk: u8,
    pub _pad2: [u8; 3],
    /// Captured plaintext payload
    pub payload: [u8; TLS_PAYLOAD_MAX],
}

impl Default for TlsDataEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsDataEvent {
    pub const fn new() -> Self {
        TlsDataEvent {
            event_type: 7,
            direction: 0,
            payload_len: 0,
            pid: 0,
            tid: 0,
            _pad: 0,
            ssl_ptr: 0,
            timestamp_ns: 0,
            comm: [0; TASK_COMM_LEN],
            is_first_chunk: 0,
            _pad2: [0; 3],
            payload: [0; TLS_PAYLOAD_MAX],
        }
    }
}

/// Network event captured by eBPF
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Cgroup ID
    pub cgroup_id: u64,

    /// Event type
    pub event_type: u8,
    /// Address family (IPv4 or IPv6)
    pub family: u16,

    /// Source port
    pub sport: u16,
    /// Destination port
    pub dport: u16,

    /// Source IP address
    pub saddr: IpAddress,
    /// Destination IP address
    pub daddr: IpAddress,

    /// Number of bytes transferred
    pub bytes: u64,
    /// Timestamp (nanoseconds)
    pub timestamp_ns: u64,

    /// Process/command name
    pub comm: [u8; TASK_COMM_LEN],

    /// Container ID (if running in container)
    pub container_id: [u8; CONTAINER_ID_LEN],

    /// Cgroup path
    pub cgroup: [u8; CGROUP_PATH_LEN],
}

impl Default for NetworkEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkEvent {
    pub const fn new() -> Self {
        NetworkEvent {
            pid: 0,
            tid: 0,
            uid: 0,
            gid: 0,
            cgroup_id: 0,
            event_type: 0,
            family: 0,
            sport: 0,
            dport: 0,
            saddr: IpAddress::zero(),
            daddr: IpAddress::zero(),
            bytes: 0,
            timestamp_ns: 0,
            comm: [0; TASK_COMM_LEN],
            container_id: [0; CONTAINER_ID_LEN],
            cgroup: [0; CGROUP_PATH_LEN],
        }
    }
}

/// Identity information for an AI agent
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AgentIdentity {
    /// Process ID
    pub pid: u32,
    /// User ID
    pub uid: u32,
    /// Cgroup ID
    pub cgroup_id: u64,
    /// Executable hash (first 32 bytes of SHA256)
    pub exec_hash: [u8; 32],
    /// Process name
    pub comm: [u8; TASK_COMM_LEN],
    /// Container ID
    pub container_id: [u8; CONTAINER_ID_LEN],
    /// Creation timestamp
    pub created_at_ns: u64,
}

impl Default for AgentIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentIdentity {
    pub const fn new() -> Self {
        AgentIdentity {
            pid: 0,
            uid: 0,
            cgroup_id: 0,
            exec_hash: [0; 32],
            comm: [0; TASK_COMM_LEN],
            container_id: [0; CONTAINER_ID_LEN],
            created_at_ns: 0,
        }
    }
}

/// Classification result for LLM communication
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum LlmProvider {
    Unknown = 0,
    OpenAI = 1,
    Anthropic = 2,
    Google = 3,
    Azure = 4,
    AWS = 5,
    Cohere = 6,
    HuggingFace = 7,
    Local = 8,
}

/// Policy decision
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum PolicyDecision {
    Allow = 0,
    Deny = 1,
    Audit = 2,
}

#[cfg(feature = "user")]
mod pod_impls {
    use super::*;
    // SAFETY: All types are #[repr(C)], Copy, and contain only primitive/array fields.
    unsafe impl aya::Pod for NetworkEvent {}
    unsafe impl aya::Pod for AgentIdentity {}
    unsafe impl aya::Pod for TlsHandshakeEvent {}
    unsafe impl aya::Pod for TlsConnKey {}
    unsafe impl aya::Pod for TlsDataEvent {}
}

/// Enriched event types for userspace consumption (requires `user` feature).
#[cfg(feature = "user")]
pub mod processed {
    use serde::{Deserialize, Serialize};

    /// Enriched event ready for UI display, SIEM export, and policy evaluation.
    ///
    /// Produced by the agent from raw eBPF events after classification, ML analysis,
    /// and container/Kubernetes enrichment. Serialized as NDJSON over the Unix socket
    /// to the UI and SIEM sinks.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ProcessedEvent {
        /// Event type string (e.g. `"TCP_CONNECT"`, `"TLS_DATA_WRITE"`).
        pub event_type: String,
        /// Human-readable timestamp (`HH:MM:SS.mmm`).
        pub timestamp: String,
        /// Process ID.
        pub pid: u32,
        /// User ID.
        pub uid: u32,
        /// Process/command name.
        pub process_name: String,
        /// Source IP address (string).
        pub src_ip: String,
        /// Source port.
        pub src_port: u16,
        /// Destination IP address (string).
        pub dst_ip: String,
        /// Destination port.
        pub dst_port: u16,
        /// Bytes transferred.
        pub bytes: u64,
        /// LLM provider name from IP/SNI classification.
        pub provider: Option<String>,
        /// Policy decision (`"allow"`, `"audit"`, `"deny"`).
        pub policy: Option<String>,
        /// Short container ID (first 12 hex chars).
        pub container_id: String,
        /// Cgroup ID from the kernel.
        #[serde(default)]
        pub cgroup_id: u64,
        /// Requests per second for this PID.
        #[serde(default)]
        pub request_rate: Option<f64>,
        /// Cumulative bytes for this PID's session.
        #[serde(default)]
        pub session_bytes: Option<u64>,
        /// Kubernetes pod name.
        #[serde(default)]
        pub pod_name: Option<String>,
        /// Kubernetes namespace.
        #[serde(default)]
        pub pod_namespace: Option<String>,
        /// Kubernetes service account.
        #[serde(default)]
        pub service_account: Option<String>,
        /// ML classifier confidence (0.0-1.0).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ml_confidence: Option<f64>,
        /// ML-predicted provider name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ml_provider: Option<String>,
        /// ML behavioral class (e.g. `"LlmApi(OpenAI)"`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub behavior_class: Option<String>,
        /// HDBSCAN cluster ID (-1 = noise).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cluster_id: Option<i32>,
        /// TLS SNI hostname.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sni: Option<String>,
        /// TLS content class (e.g. `"LlmApi"`, `"Mcp"`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tls_protocol: Option<String>,
        /// TLS classification details (provider, endpoint, model).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tls_details: Option<String>,
        /// Decrypted TLS payload (lossy UTF-8).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tls_payload: Option<String>,
        /// Content class from `busted-classifier`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub content_class: Option<String>,
        /// LLM provider from content classification.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub llm_provider: Option<String>,
        /// LLM API endpoint identifier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub llm_endpoint: Option<String>,
        /// LLM model name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub llm_model: Option<String>,
        /// MCP method name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mcp_method: Option<String>,
        /// MCP method category.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mcp_category: Option<String>,
        /// SDK/agent name and version.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agent_sdk: Option<String>,
        /// Behavioral signature hash.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agent_fingerprint: Option<u64>,
        /// Content classifier confidence (0.0-1.0).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub classifier_confidence: Option<f32>,
        /// Whether PII was detected in the payload.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pii_detected: Option<bool>,

        // --- Parsed LLM request fields (from protocol-specific parsers) ---
        /// The most recent user message text from the parsed LLM request.
        /// This is the primary field for content-based policy rules.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub llm_user_message: Option<String>,
        /// System prompt / instructions from the LLM request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub llm_system_prompt: Option<String>,
        /// All conversation messages as JSON array (serialized Vec<LlmMessage>).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub llm_messages_json: Option<String>,
        /// Whether the request is streaming.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub llm_stream: Option<bool>,
    }
}

// ---- Tests for no_std core (no `user` feature needed) ----
#[cfg(test)]
mod tests {
    use super::*;

    // -- Constructor tests: new() returns zero-initialized structs --

    #[test]
    fn network_event_new_is_zeroed() {
        let e = NetworkEvent::new();
        assert_eq!(e.pid, 0);
        assert_eq!(e.tid, 0);
        assert_eq!(e.uid, 0);
        assert_eq!(e.gid, 0);
        assert_eq!(e.cgroup_id, 0);
        assert_eq!(e.event_type, 0);
        assert_eq!(e.family, 0);
        assert_eq!(e.sport, 0);
        assert_eq!(e.dport, 0);
        assert_eq!(e.bytes, 0);
        assert_eq!(e.timestamp_ns, 0);
        assert_eq!(e.comm, [0u8; TASK_COMM_LEN]);
        assert_eq!(e.container_id, [0u8; CONTAINER_ID_LEN]);
        assert_eq!(e.cgroup, [0u8; CGROUP_PATH_LEN]);
    }

    #[test]
    fn tls_handshake_event_new_defaults() {
        let e = TlsHandshakeEvent::new();
        assert_eq!(e.event_type, 6);
        assert_eq!(e._pad, [0; 3]);
        assert_eq!(e.pid, 0);
        assert_eq!(e.tid, 0);
        assert_eq!(e.timestamp_ns, 0);
        assert_eq!(e.comm, [0u8; TASK_COMM_LEN]);
        assert_eq!(e.sni, [0u8; SNI_MAX_LEN]);
    }

    #[test]
    fn tls_data_event_new_defaults() {
        let e = TlsDataEvent::new();
        assert_eq!(e.event_type, 7);
        assert_eq!(e.direction, 0);
        assert_eq!(e.payload_len, 0);
        assert_eq!(e.pid, 0);
        assert_eq!(e.tid, 0);
        assert_eq!(e.ssl_ptr, 0);
        assert_eq!(e.timestamp_ns, 0);
        assert_eq!(e.is_first_chunk, 0);
        assert_eq!(e.payload, [0u8; TLS_PAYLOAD_MAX]);
    }

    #[test]
    fn tls_conn_key_new_defaults() {
        let k = TlsConnKey::new();
        assert_eq!(k.pid, 0);
        assert_eq!(k._pad, 0);
        assert_eq!(k.ssl_ptr, 0);
    }

    #[test]
    fn agent_identity_new_defaults() {
        let a = AgentIdentity::new();
        assert_eq!(a.pid, 0);
        assert_eq!(a.uid, 0);
        assert_eq!(a.cgroup_id, 0);
        assert_eq!(a.exec_hash, [0u8; 32]);
        assert_eq!(a.comm, [0u8; TASK_COMM_LEN]);
        assert_eq!(a.container_id, [0u8; CONTAINER_ID_LEN]);
        assert_eq!(a.created_at_ns, 0);
    }

    // -- Default == new --

    #[test]
    fn network_event_default_equals_new() {
        let d = NetworkEvent::default();
        let n = NetworkEvent::new();
        assert_eq!(d.pid, n.pid);
        assert_eq!(d.event_type, n.event_type);
        assert_eq!(d.bytes, n.bytes);
    }

    #[test]
    fn tls_handshake_default_equals_new() {
        let d = TlsHandshakeEvent::default();
        let n = TlsHandshakeEvent::new();
        assert_eq!(d.event_type, n.event_type);
        assert_eq!(d.pid, n.pid);
    }

    #[test]
    fn tls_data_default_equals_new() {
        let d = TlsDataEvent::default();
        let n = TlsDataEvent::new();
        assert_eq!(d.event_type, n.event_type);
        assert_eq!(d.payload_len, n.payload_len);
    }

    #[test]
    fn tls_conn_key_default_equals_new() {
        let d = TlsConnKey::default();
        let n = TlsConnKey::new();
        assert_eq!(d.pid, n.pid);
        assert_eq!(d.ssl_ptr, n.ssl_ptr);
    }

    #[test]
    fn agent_identity_default_equals_new() {
        let d = AgentIdentity::default();
        let n = AgentIdentity::new();
        assert_eq!(d.pid, n.pid);
        assert_eq!(d.created_at_ns, n.created_at_ns);
    }

    // -- IpAddress --

    #[test]
    fn ip_address_zero() {
        let ip = IpAddress::zero();
        assert_eq!(unsafe { ip.ipv4 }, 0);
    }

    // -- Enum discriminants --

    #[test]
    fn event_type_discriminants() {
        assert_eq!(EventType::TcpConnect as u8, 1);
        assert_eq!(EventType::DataSent as u8, 2);
        assert_eq!(EventType::DataReceived as u8, 3);
        assert_eq!(EventType::ConnectionClosed as u8, 4);
        assert_eq!(EventType::DnsQuery as u8, 5);
        assert_eq!(EventType::TlsHandshake as u8, 6);
        assert_eq!(EventType::TlsDataWrite as u8, 7);
        assert_eq!(EventType::TlsDataRead as u8, 8);
    }

    #[test]
    fn address_family_discriminants() {
        assert_eq!(AddressFamily::Ipv4 as u16, 2);
        assert_eq!(AddressFamily::Ipv6 as u16, 10);
        assert_eq!(AddressFamily::Unknown as u16, 0);
    }

    #[test]
    fn llm_provider_discriminants() {
        assert_eq!(LlmProvider::Unknown as u8, 0);
        assert_eq!(LlmProvider::OpenAI as u8, 1);
        assert_eq!(LlmProvider::Anthropic as u8, 2);
        assert_eq!(LlmProvider::Google as u8, 3);
        assert_eq!(LlmProvider::Azure as u8, 4);
        assert_eq!(LlmProvider::AWS as u8, 5);
        assert_eq!(LlmProvider::Cohere as u8, 6);
        assert_eq!(LlmProvider::HuggingFace as u8, 7);
        assert_eq!(LlmProvider::Local as u8, 8);
    }

    #[test]
    fn policy_decision_discriminants() {
        assert_eq!(PolicyDecision::Allow as u8, 0);
        assert_eq!(PolicyDecision::Deny as u8, 1);
        assert_eq!(PolicyDecision::Audit as u8, 2);
    }

    // -- Constants --

    #[test]
    fn constants_correct() {
        assert_eq!(TASK_COMM_LEN, 16);
        assert_eq!(CONTAINER_ID_LEN, 64);
        assert_eq!(CGROUP_PATH_LEN, 128);
        assert_eq!(SNI_MAX_LEN, 128);
        assert_eq!(TLS_PAYLOAD_MAX, 16384);
    }

    // -- Field mutation (validates #[repr(C)] has no overlap) --

    #[test]
    fn network_event_field_mutation() {
        let mut e = NetworkEvent::new();
        e.pid = 42;
        e.tid = 100;
        e.uid = 1000;
        e.gid = 1000;
        e.cgroup_id = 0xdeadbeef;
        e.event_type = 1;
        e.family = 2;
        e.sport = 12345;
        e.dport = 443;
        e.bytes = 1024;
        e.timestamp_ns = 999_999_999;
        assert_eq!(e.pid, 42);
        assert_eq!(e.tid, 100);
        assert_eq!(e.uid, 1000);
        assert_eq!(e.gid, 1000);
        assert_eq!(e.cgroup_id, 0xdeadbeef);
        assert_eq!(e.event_type, 1);
        assert_eq!(e.family, 2);
        assert_eq!(e.sport, 12345);
        assert_eq!(e.dport, 443);
        assert_eq!(e.bytes, 1024);
        assert_eq!(e.timestamp_ns, 999_999_999);
    }

    #[test]
    fn tls_data_event_field_mutation() {
        let mut e = TlsDataEvent::new();
        e.event_type = 8;
        e.direction = 1;
        e.payload_len = 256;
        e.pid = 99;
        e.ssl_ptr = 0xCAFEBABE;
        e.is_first_chunk = 1;
        assert_eq!(e.event_type, 8);
        assert_eq!(e.direction, 1);
        assert_eq!(e.payload_len, 256);
        assert_eq!(e.pid, 99);
        assert_eq!(e.ssl_ptr, 0xCAFEBABE);
        assert_eq!(e.is_first_chunk, 1);
    }
}

/// Userspace helper methods for eBPF event types (requires `user` feature).
#[cfg(feature = "user")]
pub mod userspace {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    impl TlsHandshakeEvent {
        /// Get SNI hostname as string
        pub fn sni_str(&self) -> &str {
            let len = self
                .sni
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(self.sni.len());
            std::str::from_utf8(&self.sni[..len]).unwrap_or("<invalid>")
        }

        /// Get process name as string
        pub fn process_name(&self) -> &str {
            let len = self
                .comm
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(self.comm.len());
            std::str::from_utf8(&self.comm[..len]).unwrap_or("<invalid>")
        }
    }

    impl TlsDataEvent {
        /// Get the captured payload bytes (up to payload_len)
        pub fn payload_bytes(&self) -> &[u8] {
            let len = (self.payload_len as usize).min(crate::TLS_PAYLOAD_MAX);
            &self.payload[..len]
        }

        /// Get process name as string
        pub fn process_name(&self) -> &str {
            let len = self
                .comm
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(self.comm.len());
            std::str::from_utf8(&self.comm[..len]).unwrap_or("<invalid>")
        }
    }

    impl NetworkEvent {
        /// Get source IP as std::net::IpAddr
        pub fn source_ip(&self) -> IpAddr {
            match self.family {
                2 => IpAddr::V4(Ipv4Addr::from(u32::from_be(unsafe { self.saddr.ipv4 }))),
                10 => IpAddr::V6(Ipv6Addr::from(unsafe { self.saddr.ipv6 })),
                _ => IpAddr::V4(Ipv4Addr::from(0)),
            }
        }

        /// Get destination IP as std::net::IpAddr
        pub fn dest_ip(&self) -> IpAddr {
            match self.family {
                2 => IpAddr::V4(Ipv4Addr::from(u32::from_be(unsafe { self.daddr.ipv4 }))),
                10 => IpAddr::V6(Ipv6Addr::from(unsafe { self.daddr.ipv6 })),
                _ => IpAddr::V4(Ipv4Addr::from(0)),
            }
        }

        /// Get process name as string
        pub fn process_name(&self) -> &str {
            let len = self
                .comm
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(self.comm.len());
            std::str::from_utf8(&self.comm[..len]).unwrap_or("<invalid>")
        }

        /// Get container ID as string
        pub fn container_id_str(&self) -> &str {
            let len = self
                .container_id
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(self.container_id.len());
            std::str::from_utf8(&self.container_id[..len]).unwrap_or("")
        }
    }
}
