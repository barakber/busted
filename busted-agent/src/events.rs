use busted_types::agentic::{AgenticAction, BustedEvent, NetworkEventKind, ProcessInfo};
use busted_types::NetworkEvent;

/// Create a BustedEvent from a raw network event.
pub fn from_network_event(
    event: &NetworkEvent,
    provider: Option<&str>,
    policy: Option<&str>,
) -> BustedEvent {
    let kind = match event.event_type {
        1 => NetworkEventKind::Connect,
        2 => NetworkEventKind::DataSent,
        3 => NetworkEventKind::DataReceived,
        4 => NetworkEventKind::Close,
        5 => NetworkEventKind::DnsQuery,
        _ => NetworkEventKind::Connect,
    };

    BustedEvent {
        timestamp: format_timestamp(event.timestamp_ns),
        process: ProcessInfo {
            pid: event.pid,
            uid: event.uid,
            name: event.process_name().to_string(),
            container_id: event.container_id_str().to_string(),
            cgroup_id: event.cgroup_id,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: format!("{}:net", event.pid),
        identity: None,
        policy: policy.map(|s| s.to_string()),
        action: AgenticAction::Network {
            kind,
            src_ip: event.source_ip().to_string(),
            src_port: event.sport,
            dst_ip: event.dest_ip().to_string(),
            dst_port: event.dport,
            bytes: event.bytes,
            sni: None,
            provider: provider.map(|s| s.to_string()),
        },
    }
}

/// Create a BustedEvent shell for a TLS session action.
/// The `action` field is set by the caller (from actions.rs).
pub fn from_tls_session(
    pid: u32,
    process_name: &str,
    session_id: &str,
    _sni: Option<&str>,
    action: AgenticAction,
) -> BustedEvent {
    BustedEvent {
        timestamp: format_timestamp_now(),
        process: ProcessInfo {
            pid,
            uid: 0,
            name: process_name.to_string(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: session_id.to_string(),
        identity: None,
        policy: None,
        action,
    }
}

pub fn format_timestamp(ns: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    // bpf_ktime_get_ns returns time since boot, not epoch.
    // Convert by computing the boot offset from current wall clock.
    let boot_offset = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_sub(Duration::from_nanos(ns));

    let wall_ns = boot_offset.as_nanos() as u64 + ns;
    let secs = wall_ns / 1_000_000_000;
    let subsec = (wall_ns % 1_000_000_000) as u32;

    let total_secs = secs;
    let hours = (total_secs / 3600) % 24;
    let minutes = (total_secs / 60) % 60;
    let seconds = total_secs % 60;
    let millis = subsec / 1_000_000;

    format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
}

pub fn format_timestamp_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;

    format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
}
