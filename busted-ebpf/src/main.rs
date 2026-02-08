#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_kernel,
    },
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use busted_types::{AgentIdentity, NetworkEvent, TASK_COMM_LEN};

/// Ring buffer for sending events to userspace
#[map]
static EVENTS: PerfEventArray<NetworkEvent> = PerfEventArray::new(0);

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

/// Helper to read cgroup path (simplified for now)
#[inline(always)]
fn get_cgroup_info(event: &mut NetworkEvent) {
    event.cgroup[0] = 0;
    event.container_id[0] = 0;
}

/// Read socket info from a `struct sock *` pointer.
///
/// Uses stable sock_common field offsets (Linux 5.4+):
///   0: skc_daddr (u32) - destination IPv4, network byte order
///   4: skc_rcv_saddr (u32) - source IPv4, network byte order
///  12: skc_dport (u16) - destination port, network byte order
///  14: skc_num (u16) - source port, host byte order
///  16: skc_family (u16) - AF_INET=2, AF_INET6=10
#[inline(always)]
fn read_sock_info(sock_ptr: *const u8, event: &mut NetworkEvent) {
    // Read address family
    if let Ok(family) = unsafe { bpf_probe_read_kernel(sock_ptr.add(16) as *const u16) } {
        event.family = family;
    }

    // Read destination IPv4 address (network byte order)
    if let Ok(daddr) = unsafe { bpf_probe_read_kernel(sock_ptr as *const u32) } {
        event.daddr.ipv4 = daddr;
    }

    // Read source IPv4 address (network byte order)
    if let Ok(saddr) = unsafe { bpf_probe_read_kernel(sock_ptr.add(4) as *const u32) } {
        event.saddr.ipv4 = saddr;
    }

    // Read destination port (network byte order -> convert to host)
    if let Ok(dport) = unsafe { bpf_probe_read_kernel(sock_ptr.add(12) as *const u16) } {
        event.dport = u16::from_be(dport);
    }

    // Read source port (already in host byte order)
    if let Ok(sport) = unsafe { bpf_probe_read_kernel(sock_ptr.add(14) as *const u16) } {
        event.sport = sport;
    }
}

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

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = (pid_tgid & 0xFFFFFFFF) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFFFFFF) as u32;
    event.gid = (uid_gid >> 32) as u32;

    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = get_process_name();
    get_cgroup_info(&mut event);

    event.event_type = 1; // TcpConnect

    // Extract socket info from first argument (struct sock *)
    if let Some(sock_ptr) = ctx.arg::<*const u8>(0) {
        read_sock_info(sock_ptr, &mut event);
    }

    EVENTS.output(&ctx, &event, 0);

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

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = (pid_tgid & 0xFFFFFFFF) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFFFFFF) as u32;
    event.gid = (uid_gid >> 32) as u32;

    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = get_process_name();
    get_cgroup_info(&mut event);

    event.event_type = 2; // DataSent

    // Extract socket info from first argument (struct sock *)
    if let Some(sock_ptr) = ctx.arg::<*const u8>(0) {
        read_sock_info(sock_ptr, &mut event);
    }

    // Extract size from third argument (size_t size)
    if let Some(size) = ctx.arg::<u64>(2) {
        event.bytes = size;
    }

    EVENTS.output(&ctx, &event, 0);

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

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = (pid_tgid & 0xFFFFFFFF) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFFFFFF) as u32;
    event.gid = (uid_gid >> 32) as u32;

    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = get_process_name();
    get_cgroup_info(&mut event);

    event.event_type = 3; // DataReceived

    // Extract socket info from first argument (struct sock *)
    if let Some(sock_ptr) = ctx.arg::<*const u8>(0) {
        read_sock_info(sock_ptr, &mut event);
    }

    // Extract requested buffer size from third argument (size_t len)
    if let Some(len) = ctx.arg::<u64>(2) {
        event.bytes = len;
    }

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
