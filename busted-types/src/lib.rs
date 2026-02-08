#![cfg_attr(not(feature = "user"), no_std)]

/// Maximum length for process names
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

impl NetworkEvent {
    pub const fn new() -> Self {
        NetworkEvent {
            pid: 0,
            tid: 0,
            uid: 0,
            gid: 0,
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
pub mod userspace {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
            let len = self.comm.iter().position(|&c| c == 0).unwrap_or(self.comm.len());
            std::str::from_utf8(&self.comm[..len]).unwrap_or("<invalid>")
        }

        /// Get container ID as string
        pub fn container_id_str(&self) -> &str {
            let len = self.container_id.iter().position(|&c| c == 0).unwrap_or(self.container_id.len());
            std::str::from_utf8(&self.container_id[..len]).unwrap_or("")
        }
    }
}
