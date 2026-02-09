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

/// Maximum payload bytes captured per TLS read/write
pub const TLS_PAYLOAD_MAX: usize = 512;

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
