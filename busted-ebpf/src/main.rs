#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, lsm, map, tracepoint, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, ProbeContext, RetProbeContext, TracePointContext},
};
use aya_log_ebpf::info;
use busted_types::{
    AgentIdentity, FileAccessEvent, FileDataEvent, NetworkEvent, TlsConnKey, TlsDataEvent,
    TlsHandshakeEvent, FILE_DATA_MAX, FILE_PATH_MAX, SNI_MAX_LEN, TASK_COMM_LEN, TLS_PAYLOAD_MAX,
};

/// Ring buffer for sending events to userspace (512KB shared buffer)
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4194304, 0); // 4 MB (TLS events are ~16KB each)

/// Map to store known AI agent identities
#[map]
static AGENT_IDENTITIES: HashMap<u32, AgentIdentity> = HashMap::with_max_entries(1024, 0);

/// Map to store policy decisions per process
#[map]
static POLICY_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Per-CPU scratch buffer for TlsDataEvent (avoids 512-byte stack overflow)
#[map]
static TLS_SCRATCH: PerCpuArray<TlsDataEvent> = PerCpuArray::with_max_entries(1, 0);

/// Stash SSL_read args between uprobe entry and uretprobe return.
/// Key: TID (u64), Value: SslReadArgs
#[map]
static SSL_READ_ARGS: HashMap<u64, SslReadArgs> = HashMap::with_max_entries(4096, 0);

/// Connection verdict: userspace writes back after first-chunk analysis.
/// Key: TlsConnKey (pid, ssl_ptr), Value: 0=new, 1=interesting, 2=boring
#[map]
static TLS_CONN_VERDICT: HashMap<TlsConnKey, u8> = HashMap::with_max_entries(8192, 0);

/// PIDs of interest for file-access monitoring.
/// Userspace populates this with PIDs identified as AI-related (via TLS classification
/// or /proc scan for known process names like `claude`, `cursor`, `aider`, etc.).
#[map]
static INTERESTING_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

/// Stash path between sys_enter_openat and sys_exit_openat.
/// Key: TID (u64), Value: OpenatStash (path + length + flags)
#[map]
static OPENAT_STASH: HashMap<u64, OpenatStash> = HashMap::with_max_entries(256, 0);

/// Map open file descriptors to their file paths.
/// Key: FdPathKey (pid, fd), Value: OpenatStash (path + length)
#[map]
static FD_PATHS: HashMap<FdPathKey, OpenatStash> = HashMap::with_max_entries(4096, 0);

/// Stash read() args between sys_enter_read and sys_exit_read.
/// Key: TID (u64), Value: FileReadArgs (buf_ptr, fd)
#[map]
static FILE_READ_ARGS: HashMap<u64, FileReadArgs> = HashMap::with_max_entries(256, 0);

/// Per-CPU scratch buffer for FileAccessEvent (avoids stack overflow)
#[map]
static FILE_ACCESS_SCRATCH: PerCpuArray<FileAccessEvent> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU scratch buffer for FileDataEvent (too large for eBPF stack)
#[map]
static FILE_DATA_SCRATCH: PerCpuArray<FileDataEvent> = PerCpuArray::with_max_entries(1, 0);

/// Stashed path from sys_enter_openat, consumed by sys_exit_openat.
#[repr(C)]
#[derive(Clone, Copy)]
struct OpenatStash {
    path: [u8; FILE_PATH_MAX],
    path_len: u16,
    flags: u8,
    _pad: [u8; 5],
}

/// Composite key for fd-to-path map: (pid, fd).
#[repr(C)]
#[derive(Clone, Copy)]
struct FdPathKey {
    pid: u32,
    fd: i32,
}

/// Stashed read() args between entry and exit probes.
#[repr(C)]
#[derive(Clone, Copy)]
struct FileReadArgs {
    buf_ptr: u64,
    fd: i32,
    _pad: u32,
}

/// SSL_read args stashed between uprobe entry and uretprobe return.
/// For SSL_read_ex, readbytes_ptr is the pointer to the `size_t *readbytes` out-param.
#[repr(C)]
#[derive(Clone, Copy)]
struct SslReadArgs {
    ssl_ptr: u64,
    buf_ptr: u64,
    /// 0 for SSL_read (use return value for byte count),
    /// non-zero for SSL_read_ex (read *readbytes_ptr for byte count).
    readbytes_ptr: u64,
}

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

    info!(
        &ctx,
        "TCP connect from PID {} ({})", event.pid, event.comm[0]
    );

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
// Uprobes (TLS plaintext capture: SSL_write, SSL_read, SSL_free)
// ---------------------------------------------------------------------------

/// Verdict constant: connection is boring, skip future data
const VERDICT_BORING: u8 = 2;
/// Verdict constant: policy denied — kill the process on next SSL call
const VERDICT_KILL: u8 = 3;

/// Uprobe on SSL_write(SSL *ssl, const void *buf, int num)
/// Captures outgoing plaintext data before encryption.
#[uprobe]
pub fn ssl_write_entry(ctx: ProbeContext) -> u32 {
    match try_ssl_write_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_write_entry(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return Ok(0),
    };
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return Ok(0),
    };
    let num: i32 = match ctx.arg(2) {
        Some(v) => v,
        None => return Ok(0),
    };
    if num <= 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key = TlsConnKey {
        pid,
        _pad: 0,
        ssl_ptr,
    };

    // Check verdict: BORING → skip, KILL → terminate the process
    if let Some(verdict) = unsafe { TLS_CONN_VERDICT.get(&key) } {
        if *verdict == VERDICT_KILL {
            unsafe { aya_ebpf_bindings::helpers::bpf_send_signal(9) }; // SIGKILL
            return Ok(0);
        }
        if *verdict == VERDICT_BORING {
            return Ok(0);
        }
    }

    // Get scratch buffer
    let scratch = match TLS_SCRATCH.get_ptr_mut(0) {
        Some(p) => unsafe { &mut *p },
        None => return Ok(0),
    };

    scratch.event_type = 7; // TlsDataWrite
    scratch.direction = 0;
    scratch.pid = pid;
    scratch.tid = (pid_tgid & 0xFFFFFFFF) as u32;
    scratch.ssl_ptr = ssl_ptr;
    scratch.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    scratch.comm = get_process_name();

    // Is this the first data on this connection?
    let is_first = unsafe { TLS_CONN_VERDICT.get(&key) }.is_none();
    scratch.is_first_chunk = if is_first { 1 } else { 0 };

    // Mark as "pending" in eBPF so subsequent calls don't also claim first-chunk.
    // Userspace will overwrite with INTERESTING(1) or BORING(2) after analysis.
    if is_first {
        let pending: u8 = 0;
        let _ = TLS_CONN_VERDICT.insert(&key, &pending, 0);
    }

    // Read payload from user buffer (only read actual_len bytes)
    let actual_len = (num as usize).min(TLS_PAYLOAD_MAX);
    let ret = unsafe {
        aya_ebpf_bindings::helpers::bpf_probe_read_user(
            scratch.payload.as_mut_ptr() as *mut core::ffi::c_void,
            actual_len as u32,
            buf_ptr as *const core::ffi::c_void,
        )
    };
    if ret < 0 {
        return Ok(0);
    }
    scratch.payload_len = actual_len as u16;

    EVENTS.output(scratch, 0).ok();

    Ok(0)
}

/// Uprobe on SSL_read(SSL *ssl, void *buf, int num) — entry
/// Stashes args for the uretprobe to read the buffer after data is written.
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) -> u32 {
    match try_ssl_read_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_read_entry(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return Ok(0),
    };
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return Ok(0),
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Check verdict: if BORING, don't stash
    let key = TlsConnKey {
        pid,
        _pad: 0,
        ssl_ptr,
    };
    if let Some(verdict) = unsafe { TLS_CONN_VERDICT.get(&key) } {
        if *verdict == VERDICT_BORING {
            return Ok(0);
        }
    }

    // Stash args keyed by TID (readbytes_ptr=0 means use return value for byte count)
    let tid = pid_tgid & 0xFFFFFFFF;
    let args = SslReadArgs {
        ssl_ptr,
        buf_ptr,
        readbytes_ptr: 0,
    };
    let _ = SSL_READ_ARGS.insert(&tid, &args, 0);

    Ok(0)
}

/// Uprobe on SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) — entry
/// Like ssl_read_entry but also stashes the readbytes out-pointer (arg3).
#[uprobe]
pub fn ssl_read_ex_entry(ctx: ProbeContext) -> u32 {
    match try_ssl_read_ex_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_read_ex_entry(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return Ok(0),
    };
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return Ok(0),
    };
    let readbytes_ptr: u64 = match ctx.arg(3) {
        Some(v) => v,
        None => return Ok(0),
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Check verdict: if BORING, don't stash
    let key = TlsConnKey {
        pid,
        _pad: 0,
        ssl_ptr,
    };
    if let Some(verdict) = unsafe { TLS_CONN_VERDICT.get(&key) } {
        if *verdict == VERDICT_BORING {
            return Ok(0);
        }
    }

    // Stash args keyed by TID (readbytes_ptr != 0 signals _ex variant)
    let tid = pid_tgid & 0xFFFFFFFF;
    let args = SslReadArgs {
        ssl_ptr,
        buf_ptr,
        readbytes_ptr,
    };
    let _ = SSL_READ_ARGS.insert(&tid, &args, 0);

    Ok(0)
}

/// Uretprobe on SSL_read / SSL_read_ex — return
/// Reads the buffer that SSL_read filled using the stashed pointer.
/// For SSL_read_ex, reads *readbytes_ptr to get byte count (return value is just 0/1).
#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_ret(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_read_ret(ctx: RetProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid & 0xFFFFFFFF;

    // Look up and remove stashed args
    let args = match unsafe { SSL_READ_ARGS.get(&tid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = SSL_READ_ARGS.remove(&tid);

    // Determine bytes read:
    // - SSL_read: return value IS the byte count (> 0 means success)
    // - SSL_read_ex: return value is 1=success, 0=failure; actual byte count is at *readbytes_ptr
    let retval: i32 = match ctx.ret() {
        Some(v) => v,
        None => return Ok(0),
    };
    if retval <= 0 {
        return Ok(0);
    }

    let bytes_read = if args.readbytes_ptr != 0 {
        // SSL_read_ex: read the size_t value from *readbytes_ptr
        let mut nbytes: usize = 0;
        let ret = unsafe {
            aya_ebpf_bindings::helpers::bpf_probe_read_user(
                &mut nbytes as *mut usize as *mut core::ffi::c_void,
                core::mem::size_of::<usize>() as u32,
                args.readbytes_ptr as *const core::ffi::c_void,
            )
        };
        if ret < 0 || nbytes == 0 {
            return Ok(0);
        }
        nbytes as i32
    } else {
        // SSL_read: return value is the byte count
        retval
    };

    let pid = (pid_tgid >> 32) as u32;

    // Check verdict again: BORING → skip, KILL → terminate
    let key = TlsConnKey {
        pid,
        _pad: 0,
        ssl_ptr: args.ssl_ptr,
    };
    if let Some(verdict) = unsafe { TLS_CONN_VERDICT.get(&key) } {
        if *verdict == VERDICT_KILL {
            unsafe { aya_ebpf_bindings::helpers::bpf_send_signal(9) }; // SIGKILL
            return Ok(0);
        }
        if *verdict == VERDICT_BORING {
            return Ok(0);
        }
    }

    // Get scratch buffer
    let scratch = match TLS_SCRATCH.get_ptr_mut(0) {
        Some(p) => unsafe { &mut *p },
        None => return Ok(0),
    };

    scratch.event_type = 8; // TlsDataRead
    scratch.direction = 1;
    scratch.pid = pid;
    scratch.tid = tid as u32;
    scratch.ssl_ptr = args.ssl_ptr;
    scratch.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    scratch.comm = get_process_name();

    let is_first = unsafe { TLS_CONN_VERDICT.get(&key) }.is_none();
    scratch.is_first_chunk = if is_first { 1 } else { 0 };

    if is_first {
        let pending: u8 = 0;
        let _ = TLS_CONN_VERDICT.insert(&key, &pending, 0);
    }

    let actual_len = (bytes_read as usize).min(TLS_PAYLOAD_MAX);
    let ret = unsafe {
        aya_ebpf_bindings::helpers::bpf_probe_read_user(
            scratch.payload.as_mut_ptr() as *mut core::ffi::c_void,
            actual_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        )
    };
    if ret < 0 {
        return Ok(0);
    }
    scratch.payload_len = actual_len as u16;

    EVENTS.output(scratch, 0).ok();

    Ok(0)
}

/// Uprobe on SSL_free(SSL *ssl) — cleanup verdict map entry
#[uprobe]
pub fn ssl_free_cleanup(ctx: ProbeContext) -> u32 {
    match try_ssl_free_cleanup(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_free_cleanup(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return Ok(0),
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Remove verdict entry to prevent map leaks
    let key = TlsConnKey {
        pid,
        _pad: 0,
        ssl_ptr,
    };
    let _ = TLS_CONN_VERDICT.remove(&key);

    // Clean up any stale SSL_READ_ARGS for this TID
    let tid = pid_tgid & 0xFFFFFFFF;
    let _ = SSL_READ_ARGS.remove(&tid);

    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoint: file access monitoring (sys_enter_openat)
// ---------------------------------------------------------------------------

/// Max scan depth for path pattern matching.
/// 64 bytes covers realistic AI config paths (typical patterns appear within
/// the first 20-30 bytes, e.g. /home/user/.claude/settings.json).
/// Kept low to stay well under the eBPF verifier's 1M instruction limit.
const PATH_SCAN_MAX: usize = 64;

/// Check if a file path matches any AI-related pattern.
///
/// Uses a single flat loop (no nested loops) to avoid eBPF verifier
/// state explosion. All 6 patterns are checked inline at each position
/// using byte-by-byte comparisons with explicit bounds guards.
///
/// Patterns: .claude, CLAUDE.md, .cursor, .env, skills/, .anthropic
#[inline(always)]
fn path_matches_ai_pattern(path: &[u8; FILE_PATH_MAX], path_len: usize) -> bool {
    let len = if path_len < FILE_PATH_MAX {
        path_len
    } else {
        FILE_PATH_MAX
    };
    if len < 4 {
        return false;
    }

    let mut i: usize = 0;
    while i < len && i < PATH_SCAN_MAX {
        let c = path[i];

        // Patterns starting with '.'
        if c == b'.' {
            // .env (4 bytes)
            if i + 3 < FILE_PATH_MAX
                && i + 3 < len
                && path[i + 1] == b'e'
                && path[i + 2] == b'n'
                && path[i + 3] == b'v'
            {
                return true;
            }
            // .claude (7 bytes)
            if i + 6 < FILE_PATH_MAX
                && i + 6 < len
                && path[i + 1] == b'c'
                && path[i + 2] == b'l'
                && path[i + 3] == b'a'
                && path[i + 4] == b'u'
                && path[i + 5] == b'd'
                && path[i + 6] == b'e'
            {
                return true;
            }
            // .cursor (7 bytes)
            if i + 6 < FILE_PATH_MAX
                && i + 6 < len
                && path[i + 1] == b'c'
                && path[i + 2] == b'u'
                && path[i + 3] == b'r'
                && path[i + 4] == b's'
                && path[i + 5] == b'o'
                && path[i + 6] == b'r'
            {
                return true;
            }
            // .anthropic (10 bytes)
            if i + 9 < FILE_PATH_MAX
                && i + 9 < len
                && path[i + 1] == b'a'
                && path[i + 2] == b'n'
                && path[i + 3] == b't'
                && path[i + 4] == b'h'
                && path[i + 5] == b'r'
                && path[i + 6] == b'o'
                && path[i + 7] == b'p'
                && path[i + 8] == b'i'
                && path[i + 9] == b'c'
            {
                return true;
            }
        }

        // CLAUDE.md (9 bytes) — starts with 'C'
        if c == b'C'
            && i + 8 < FILE_PATH_MAX
            && i + 8 < len
            && path[i + 1] == b'L'
            && path[i + 2] == b'A'
            && path[i + 3] == b'U'
            && path[i + 4] == b'D'
            && path[i + 5] == b'E'
            && path[i + 6] == b'.'
            && path[i + 7] == b'm'
            && path[i + 8] == b'd'
        {
            return true;
        }

        // skills/ (7 bytes) — starts with 's'
        if c == b's'
            && i + 6 < FILE_PATH_MAX
            && i + 6 < len
            && path[i + 1] == b'k'
            && path[i + 2] == b'i'
            && path[i + 3] == b'l'
            && path[i + 4] == b'l'
            && path[i + 5] == b's'
            && path[i + 6] == b'/'
        {
            return true;
        }

        i += 1;
    }
    false
}

/// Tracepoint on sys_enter_openat to capture file access events.
///
/// Emits a FileAccessEvent to the ring buffer when either:
/// 1. The calling PID is in the INTERESTING_PIDS map (known AI process), or
/// 2. The filename matches an AI-related path pattern.
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let pid_interesting = unsafe { INTERESTING_PIDS.get(&pid) }.is_some();

    // Read the filename pointer from the tracepoint args.
    // sys_enter_openat args: (dfd: int, filename: const char *, flags: int, mode: umode_t)
    // In the tracepoint format, filename is at offset 24 (after __syscall_nr + padding + dfd).
    let filename_ptr: u64 = match unsafe { ctx.read_at::<u64>(24) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    if filename_ptr == 0 {
        return Ok(0);
    }

    // Use per-CPU scratch buffer to avoid stack overflow (FileAccessEvent is ~240 bytes).
    let event_ptr = FILE_ACCESS_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    let event = unsafe { &mut *event_ptr };

    // Zero path and read filename from userspace
    event.path = [0u8; FILE_PATH_MAX];
    match unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.path) } {
        Ok(s) => {
            event.path_len = s.len() as u16;
        }
        Err(_) => return Ok(0),
    }

    let path_len = (event.path_len as usize).min(FILE_PATH_MAX);

    // If PID is not interesting, check the path pattern
    if !pid_interesting && !path_matches_ai_pattern(&event.path, path_len) {
        return Ok(0);
    }

    // Read flags from tracepoint args (offset 32)
    let flags: i32 = unsafe { ctx.read_at::<i32>(32) }.unwrap_or(0);
    event.flags = (flags & 0x03) as u8; // O_ACCMODE mask
    event.event_type = 9; // FILE_ACCESS

    event.pid = pid;
    event.tid = (pid_tgid & 0xFFFFFFFF) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFFFFFF) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.comm = get_process_name();

    EVENTS.output(event, 0).ok();

    // Stash path for sys_exit_openat to pick up (so we can map fd → path)
    let tid = pid_tgid & 0xFFFFFFFF;
    let stash = OpenatStash {
        path: event.path,
        path_len: event.path_len,
        flags: event.flags,
        _pad: [0u8; 5],
    };
    let _ = OPENAT_STASH.insert(&tid, &stash, 0);

    Ok(0)
}

// ---------------------------------------------------------------------------
// Tracepoints: file data capture (read/write content)
// ---------------------------------------------------------------------------

/// sys_exit_openat: get returned fd, populate FD_PATHS
#[tracepoint]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    match try_sys_exit_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_openat(_ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid & 0xFFFFFFFF;
    let pid = (pid_tgid >> 32) as u32;

    // Look up and remove stashed openat args
    let stash = match unsafe { OPENAT_STASH.get(&tid) } {
        Some(s) => *s,
        None => return Ok(0),
    };
    let _ = OPENAT_STASH.remove(&tid);

    // Read return value (fd) at offset 16 in sys_exit tracepoint
    let ret_fd: i64 = match unsafe { _ctx.read_at::<i64>(16) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    // Negative return = error, skip
    if ret_fd < 0 {
        return Ok(0);
    }

    // Insert (pid, fd) → path into FD_PATHS
    let key = FdPathKey {
        pid,
        fd: ret_fd as i32,
    };
    let _ = FD_PATHS.insert(&key, &stash, 0);

    Ok(0)
}

/// sys_enter_write: capture write buffer for tracked fds
#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    match try_sys_enter_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_write(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Early exit: PID not interesting
    if unsafe { INTERESTING_PIDS.get(&pid) }.is_none() {
        return Ok(0);
    }

    // sys_enter_write args: (fd: unsigned int, buf: const char *, count: size_t)
    // Offsets: fd at 16, buf at 24, count at 32
    let fd: i32 = match unsafe { ctx.read_at::<i32>(16) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    let key = FdPathKey { pid, fd };
    let stash = match unsafe { FD_PATHS.get(&key) } {
        Some(s) => *s,
        None => return Ok(0),
    };

    let buf_ptr: u64 = match unsafe { ctx.read_at::<u64>(24) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    let count: u64 = match unsafe { ctx.read_at::<u64>(32) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    if buf_ptr == 0 || count == 0 {
        return Ok(0);
    }

    // Get scratch buffer
    let scratch = match FILE_DATA_SCRATCH.get_ptr_mut(0) {
        Some(p) => unsafe { &mut *p },
        None => return Ok(0),
    };

    scratch.event_type = 10;
    scratch.direction = 0; // write
    scratch.path_len = stash.path_len;
    scratch._pad = 0;
    scratch.pid = pid;
    scratch.tid = (pid_tgid & 0xFFFFFFFF) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    scratch.uid = (uid_gid & 0xFFFFFFFF) as u32;
    scratch.fd = fd;
    scratch.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    scratch.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    scratch.comm = get_process_name();
    scratch.path = stash.path;

    let actual_len = (count as usize).min(FILE_DATA_MAX);
    let ret = unsafe {
        aya_ebpf_bindings::helpers::bpf_probe_read_user(
            scratch.payload.as_mut_ptr() as *mut core::ffi::c_void,
            actual_len as u32,
            buf_ptr as *const core::ffi::c_void,
        )
    };
    if ret < 0 {
        return Ok(0);
    }
    scratch.payload_len = actual_len as u16;

    EVENTS.output(scratch, 0).ok();

    Ok(0)
}

/// sys_enter_read: stash args for exit probe
#[tracepoint]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    match try_sys_enter_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_read(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Early exit: PID not interesting
    if unsafe { INTERESTING_PIDS.get(&pid) }.is_none() {
        return Ok(0);
    }

    // sys_enter_read args: (fd: unsigned int, buf: char *, count: size_t)
    // Offsets: fd at 16, buf at 24
    let fd: i32 = match unsafe { ctx.read_at::<i32>(16) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    let key = FdPathKey { pid, fd };
    if unsafe { FD_PATHS.get(&key) }.is_none() {
        return Ok(0);
    }

    let buf_ptr: u64 = match unsafe { ctx.read_at::<u64>(24) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    let tid = pid_tgid & 0xFFFFFFFF;
    let args = FileReadArgs {
        buf_ptr,
        fd,
        _pad: 0,
    };
    let _ = FILE_READ_ARGS.insert(&tid, &args, 0);

    Ok(0)
}

/// sys_exit_read: read filled buffer and emit event
#[tracepoint]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    match try_sys_exit_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_read(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid & 0xFFFFFFFF;
    let pid = (pid_tgid >> 32) as u32;

    // Look up and remove stashed args
    let args = match unsafe { FILE_READ_ARGS.get(&tid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = FILE_READ_ARGS.remove(&tid);

    // Read return value (bytes read) at offset 16
    let ret_val: i64 = match unsafe { ctx.read_at::<i64>(16) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    if ret_val <= 0 {
        return Ok(0);
    }

    // Look up file path
    let key = FdPathKey { pid, fd: args.fd };
    let stash = match unsafe { FD_PATHS.get(&key) } {
        Some(s) => *s,
        None => return Ok(0),
    };

    // Get scratch buffer
    let scratch = match FILE_DATA_SCRATCH.get_ptr_mut(0) {
        Some(p) => unsafe { &mut *p },
        None => return Ok(0),
    };

    scratch.event_type = 10;
    scratch.direction = 1; // read
    scratch.path_len = stash.path_len;
    scratch._pad = 0;
    scratch.pid = pid;
    scratch.tid = tid as u32;
    let uid_gid = bpf_get_current_uid_gid();
    scratch.uid = (uid_gid & 0xFFFFFFFF) as u32;
    scratch.fd = args.fd;
    scratch.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    scratch.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    scratch.comm = get_process_name();
    scratch.path = stash.path;

    let actual_len = (ret_val as usize).min(FILE_DATA_MAX);
    let ret = unsafe {
        aya_ebpf_bindings::helpers::bpf_probe_read_user(
            scratch.payload.as_mut_ptr() as *mut core::ffi::c_void,
            actual_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        )
    };
    if ret < 0 {
        return Ok(0);
    }
    scratch.payload_len = actual_len as u16;

    EVENTS.output(scratch, 0).ok();

    Ok(0)
}

/// sys_enter_close: remove fd from FD_PATHS
#[tracepoint]
pub fn sys_enter_close(ctx: TracePointContext) -> u32 {
    match try_sys_enter_close(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_close(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Early exit: PID not interesting
    if unsafe { INTERESTING_PIDS.get(&pid) }.is_none() {
        return Ok(0);
    }

    // sys_enter_close args: (fd: unsigned int) at offset 16
    let fd: i32 = match unsafe { ctx.read_at::<i32>(16) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    let key = FdPathKey { pid, fd };
    let _ = FD_PATHS.remove(&key);

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
