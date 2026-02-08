#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_CURRENT_CPU,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns},
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use busted_types::{AgentIdentity, NetworkEvent, TASK_COMM_LEN};

/// Ring buffer for sending events to userspace
#[map]
static EVENTS: PerfEventArray<NetworkEvent> = PerfEventArray::with_max_entries(1024, 0);

/// Map to store known AI agent identities
#[map]
static AGENT_IDENTITIES: HashMap<u32, AgentIdentity> = HashMap::with_max_entries(1024, 0);

/// Map to store policy decisions per process
#[map]
static POLICY_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Helper to get process name
#[inline(always)]
fn get_process_name(comm: &mut [u8; TASK_COMM_LEN]) {
    if let Err(_) = bpf_get_current_comm(comm) {
        comm[0] = b'?';
        comm[1] = 0;
    }
}

/// Helper to read cgroup path (simplified for now)
#[inline(always)]
fn get_cgroup_info(event: &mut NetworkEvent) {
    // This is a placeholder - in production you'd read from cgroup filesystem
    // or use helpers to extract cgroup ID
    event.cgroup[0] = 0;
    event.container_id[0] = 0;
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

    // Get process metadata
    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = (pid_tgid & 0xFFFFFFFF) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFFFFFF) as u32;
    event.gid = (uid_gid >> 32) as u32;

    // Get timestamp
    event.timestamp_ns = bpf_ktime_get_ns();

    // Get process name
    get_process_name(&mut event.comm);

    // Get cgroup/container info
    get_cgroup_info(&mut event);

    // Event type
    event.event_type = 1; // TcpConnect

    // TODO: Extract socket info from tcp_connect arguments
    // This requires reading kernel structures which depends on kernel version
    // For now, we'll emit the event with process info

    // Send event to userspace
    EVENTS.output(&ctx, &event, BPF_F_CURRENT_CPU as u64);

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

    event.timestamp_ns = bpf_ktime_get_ns();
    get_process_name(&mut event.comm);
    get_cgroup_info(&mut event);

    event.event_type = 2; // DataSent

    // TODO: Extract size from tcp_sendmsg arguments

    EVENTS.output(&ctx, &event, BPF_F_CURRENT_CPU as u64);

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

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFFFFFF) as u32;

    event.timestamp_ns = bpf_ktime_get_ns();
    get_process_name(&mut event.comm);

    event.event_type = 3; // DataReceived

    EVENTS.output(&ctx, &event, BPF_F_CURRENT_CPU as u64);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
