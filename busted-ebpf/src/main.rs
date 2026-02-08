#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, lsm, map, uprobe},
    maps::{HashMap, RingBuf},
    programs::{LsmContext, ProbeContext},
};
use aya_log_ebpf::info;
use busted_types::{AgentIdentity, NetworkEvent, TlsHandshakeEvent, SNI_MAX_LEN, TASK_COMM_LEN};

/// Ring buffer for sending events to userspace (256KB shared buffer)
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262144, 0);

/// Map to store known AI agent identities
#[map]
static AGENT_IDENTITIES: HashMap<u32, AgentIdentity> = HashMap::with_max_entries(1024, 0);

/// Map to store policy decisions per process
#[map]
static POLICY_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Helper to get process name
#[inline(always)]
fn get_process_name() -> [u8; TASK_COMM_LEN] {
    match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => {
            let mut comm = [0u8; TASK_COMM_LEN];
            comm[0] = b'?';
            comm
        }
    }
}

/// Fill common event fields (pid, tid, uid, gid, cgroup_id, timestamp, comm)
#[inline(always)]
fn fill_common_fields(event: &mut NetworkEvent) {
    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = (pid_tgid & 0xFFFFFFFF) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFFFFFF) as u32;
    event.gid = (uid_gid >> 32) as u32;

    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = get_process_name();

    // Zero container/cgroup path fields (resolved in userspace)
    event.cgroup[0] = 0;
    event.container_id[0] = 0;
}

/// Read socket info from a `struct sock *` pointer.
///
/// Uses stable sock_common field offsets (Linux 5.4+, x86_64):
///   0: skc_daddr (u32) - destination IPv4, network byte order
///   4: skc_rcv_saddr (u32) - source IPv4, network byte order
///  12: skc_dport (u16) - destination port, network byte order
///  14: skc_num (u16) - source port, host byte order
///  16: skc_family (u16) - AF_INET=2, AF_INET6=10
///  56: skc_v6_daddr (16 bytes) - destination IPv6
///  72: skc_v6_rcv_saddr (16 bytes) - source IPv6
#[inline(always)]
fn read_sock_info(sock_ptr: *const u8, event: &mut NetworkEvent) {
    // Read address family
    if let Ok(family) = unsafe { bpf_probe_read_kernel(sock_ptr.add(16) as *const u16) } {
        event.family = family;
    }

    // Read destination port (network byte order -> convert to host)
    if let Ok(dport) = unsafe { bpf_probe_read_kernel(sock_ptr.add(12) as *const u16) } {
        event.dport = u16::from_be(dport);
    }

    // Read source port (already in host byte order)
    if let Ok(sport) = unsafe { bpf_probe_read_kernel(sock_ptr.add(14) as *const u16) } {
        event.sport = sport;
    }

    if event.family == 10 {
        // AF_INET6: read 16-byte IPv6 addresses
        if let Ok(daddr) = unsafe { bpf_probe_read_kernel(sock_ptr.add(56) as *const [u8; 16]) } {
            event.daddr.ipv6 = daddr;
        }
        if let Ok(saddr) = unsafe { bpf_probe_read_kernel(sock_ptr.add(72) as *const [u8; 16]) } {
            event.saddr.ipv6 = saddr;
        }
    } else {
        // AF_INET: read 4-byte IPv4 addresses
        if let Ok(daddr) = unsafe { bpf_probe_read_kernel(sock_ptr as *const u32) } {
            event.daddr.ipv4 = daddr;
        }
        if let Ok(saddr) = unsafe { bpf_probe_read_kernel(sock_ptr.add(4) as *const u32) } {
            event.saddr.ipv4 = saddr;
        }
    }
}

// ---------------------------------------------------------------------------
// Kprobes
// ---------------------------------------------------------------------------

/// Probe on tcp_connect to capture outgoing TCP connections
#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_connect(ctx: ProbeContext) -> Result<u32, u32> {
    let mut event = NetworkEvent::new();
    fill_common_fields(&mut event);
    event.event_type = 1; // TcpConnect

    if let Some(sock_ptr) = ctx.arg::<*const u8>(0) {
        read_sock_info(sock_ptr, &mut event);
    }

    EVENTS.output(&event, 0).ok();

    info!(&ctx, "TCP connect from PID {} ({})", event.pid, event.comm[0]);

    Ok(0)
}

/// Probe on tcp_sendmsg to capture data sent
#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let mut event = NetworkEvent::new();
    fill_common_fields(&mut event);
    event.event_type = 2; // DataSent

    if let Some(sock_ptr) = ctx.arg::<*const u8>(0) {
        read_sock_info(sock_ptr, &mut event);
    }

    if let Some(size) = ctx.arg::<u64>(2) {
        event.bytes = size;
    }

    EVENTS.output(&event, 0).ok();

    Ok(0)
}

/// Probe on tcp_recvmsg to capture data received
#[kprobe]
pub fn tcp_recvmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_recvmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_recvmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let mut event = NetworkEvent::new();
    fill_common_fields(&mut event);
    event.event_type = 3; // DataReceived

    if let Some(sock_ptr) = ctx.arg::<*const u8>(0) {
        read_sock_info(sock_ptr, &mut event);
    }

    if let Some(len) = ctx.arg::<u64>(2) {
        event.bytes = len;
    }

    EVENTS.output(&event, 0).ok();

    Ok(0)
}

/// Probe on tcp_close to capture connection teardowns
#[kprobe]
pub fn tcp_close(ctx: ProbeContext) -> u32 {
    match try_tcp_close(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_close(ctx: ProbeContext) -> Result<u32, u32> {
    let mut event = NetworkEvent::new();
    fill_common_fields(&mut event);
    event.event_type = 4; // ConnectionClosed

    if let Some(sock_ptr) = ctx.arg::<*const u8>(0) {
        read_sock_info(sock_ptr, &mut event);
    }

    // No bytes field for close events
    EVENTS.output(&event, 0).ok();

    Ok(0)
}

/// Probe on udp_sendmsg to capture DNS queries (dport 53)
#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_udp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_udp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let mut event = NetworkEvent::new();

    if let Some(sock_ptr) = ctx.arg::<*const u8>(0) {
        read_sock_info(sock_ptr, &mut event);
    }

    // Only emit events for DNS traffic (destination port 53)
    if event.dport != 53 {
        return Ok(0);
    }

    fill_common_fields(&mut event);
    event.event_type = 5; // DnsQuery

    if let Some(size) = ctx.arg::<u64>(2) {
        event.bytes = size;
    }

    EVENTS.output(&event, 0).ok();

    Ok(0)
}

// ---------------------------------------------------------------------------
// Uprobes (TLS SNI extraction)
// ---------------------------------------------------------------------------

/// SSL_CTRL_SET_TLSEXT_HOSTNAME command code
const SSL_CTRL_SET_TLSEXT_HOSTNAME: i32 = 55;

/// Uprobe on OpenSSL SSL_ctrl to extract SNI hostname.
/// SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
/// When cmd == 55 (SSL_CTRL_SET_TLSEXT_HOSTNAME), parg is the hostname string.
#[uprobe]
pub fn ssl_ctrl_sni(ctx: ProbeContext) -> u32 {
    match try_ssl_ctrl_sni(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_ctrl_sni(ctx: ProbeContext) -> Result<u32, u32> {
    // arg1: cmd (int) — only process SSL_CTRL_SET_TLSEXT_HOSTNAME (55)
    let cmd: i32 = match ctx.arg(1) {
        Some(v) => v,
        None => return Ok(0),
    };
    if cmd != SSL_CTRL_SET_TLSEXT_HOSTNAME {
        return Ok(0);
    }

    // arg3: parg (*const u8) — pointer to hostname string
    let hostname_ptr: *const u8 = match ctx.arg(3) {
        Some(v) => v,
        None => return Ok(0),
    };
    if hostname_ptr.is_null() {
        return Ok(0);
    }

    let mut event = TlsHandshakeEvent::new();

    // Read hostname from user space
    let mut sni_buf = [0u8; SNI_MAX_LEN];
    match unsafe { bpf_probe_read_user_str_bytes(hostname_ptr, &mut sni_buf) } {
        Ok(s) => {
            let len = s.len().min(SNI_MAX_LEN);
            event.sni[..len].copy_from_slice(&s[..len]);
        }
        Err(_) => return Ok(0),
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = (pid_tgid & 0xFFFFFFFF) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = get_process_name();

    EVENTS.output(&event, 0).ok();

    info!(&ctx, "TLS SNI from PID {}", event.pid);

    Ok(0)
}

// ---------------------------------------------------------------------------
// LSM hook for policy enforcement
// ---------------------------------------------------------------------------

/// LSM hook on socket_connect for optional blocking of connections.
/// Returns 0 to allow, -1 (EPERM) to deny.
/// Only denies if the PID has value 1 (Deny) in POLICY_MAP.
#[lsm(hook = "socket_connect")]
pub fn lsm_socket_connect(ctx: LsmContext) -> i32 {
    match try_lsm_socket_connect(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // On error, allow
    }
}

fn try_lsm_socket_connect(_ctx: LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Check policy map for this PID
    if let Some(decision) = unsafe { POLICY_MAP.get(&pid) } {
        if *decision == 1 {
            // Deny
            return Ok(-1); // -EPERM
        }
    }

    // Allow by default
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
