use busted_types::{NetworkEvent, TlsDataEvent};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct ProcessedEvent {
    pub event_type: String,
    pub timestamp: String,
    pub pid: u32,
    pub uid: u32,
    pub process_name: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub bytes: u64,
    pub provider: Option<String>,
    pub policy: Option<String>,
    pub container_id: String,
    pub cgroup_id: u64,
    pub request_rate: Option<f64>,
    pub session_bytes: Option<u64>,
    pub pod_name: Option<String>,
    pub pod_namespace: Option<String>,
    pub service_account: Option<String>,
    #[cfg(feature = "ml")]
    pub behavior: Option<crate::ml::BehaviorIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_details: Option<String>,
    /// Raw decrypted TLS payload (lossy UTF-8)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_payload: Option<String>,
}

impl ProcessedEvent {
    pub fn from_network_event(
        event: &NetworkEvent,
        provider: Option<&str>,
        policy: Option<&str>,
    ) -> Self {
        let event_type = match event.event_type {
            1 => "TCP_CONNECT",
            2 => "DATA_SENT",
            3 => "DATA_RECEIVED",
            4 => "CONNECTION_CLOSED",
            5 => "DNS_QUERY",
            _ => "UNKNOWN",
        };

        ProcessedEvent {
            event_type: event_type.to_string(),
            timestamp: format_timestamp(event.timestamp_ns),
            pid: event.pid,
            uid: event.uid,
            process_name: event.process_name().to_string(),
            src_ip: event.source_ip().to_string(),
            src_port: event.sport,
            dst_ip: event.dest_ip().to_string(),
            dst_port: event.dport,
            bytes: event.bytes,
            provider: provider.map(|s| s.to_string()),
            policy: policy.map(|s| s.to_string()),
            container_id: event.container_id_str().to_string(),
            cgroup_id: event.cgroup_id,
            request_rate: None,
            session_bytes: None,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
            #[cfg(feature = "ml")]
            behavior: None,
            sni: None,
            tls_protocol: None,
            tls_details: None,
            tls_payload: None,
        }
    }

    /// Create a ProcessedEvent from a TLS data capture event.
    pub fn from_tls_data_event(
        event: &TlsDataEvent,
        protocol: Option<String>,
        details: Option<String>,
    ) -> Self {
        let event_type = match event.event_type {
            7 => "TLS_DATA_WRITE",
            8 => "TLS_DATA_READ",
            _ => "UNKNOWN",
        };

        let payload = String::from_utf8_lossy(event.payload_bytes()).to_string();

        ProcessedEvent {
            event_type: event_type.to_string(),
            timestamp: format_timestamp(event.timestamp_ns),
            pid: event.pid,
            uid: 0,
            process_name: event.process_name().to_string(),
            src_ip: String::new(),
            src_port: 0,
            dst_ip: String::new(),
            dst_port: 0,
            bytes: event.payload_len as u64,
            provider: protocol.clone(),
            policy: None,
            container_id: String::new(),
            cgroup_id: 0,
            request_rate: None,
            session_bytes: None,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
            #[cfg(feature = "ml")]
            behavior: None,
            sni: None,
            tls_protocol: protocol,
            tls_details: details,
            tls_payload: Some(payload),
        }
    }
}

fn format_timestamp(ns: u64) -> String {
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
