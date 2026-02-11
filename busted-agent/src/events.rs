use busted_types::processed::ProcessedEvent;
use busted_types::NetworkEvent;
#[cfg(feature = "tls")]
use busted_types::TlsDataEvent;

pub fn from_network_event(
    event: &NetworkEvent,
    provider: Option<&str>,
    policy: Option<&str>,
) -> ProcessedEvent {
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
        ml_confidence: None,
        ml_provider: None,
        behavior_class: None,
        cluster_id: None,
        sni: None,
        tls_protocol: None,
        tls_details: None,
        tls_payload: None,
        content_class: None,
        llm_provider: None,
        llm_endpoint: None,
        llm_model: None,
        mcp_method: None,
        mcp_category: None,
        agent_sdk: None,
        agent_fingerprint: None,
        classifier_confidence: None,
        pii_detected: None,
        llm_user_message: None,
        llm_system_prompt: None,
        llm_messages_json: None,
        llm_stream: None,
        identity_id: None,
        identity_instance: None,
        identity_confidence: None,
        identity_narrative: None,
        identity_timeline: None,
        identity_timeline_len: None,
        agent_sdk_hash: None,
        agent_model_hash: None,
    }
}

/// Create a ProcessedEvent from a TLS data capture event with classification.
#[cfg(feature = "tls")]
pub fn from_tls_data_event(
    event: &TlsDataEvent,
    classification: &busted_classifier::Classification,
) -> ProcessedEvent {
    let event_type = match event.event_type {
        7 => "TLS_DATA_WRITE",
        8 => "TLS_DATA_READ",
        _ => "UNKNOWN",
    };

    let payload = crate::tls::payload_to_string(event.payload_bytes());

    let tls_protocol = classification.content_class_str().map(|s| s.to_string());
    let tls_details = classification
        .provider()
        .map(|p| {
            let mut detail = p.to_string();
            if let Some(ep) = classification.endpoint() {
                detail.push_str(&format!(" ({})", ep));
            }
            if let Some(m) = classification.model() {
                detail.push_str(&format!(" model={}", m));
            }
            detail
        })
        .or_else(|| classification.mcp_method().map(|m| format!("MCP {}", m)));

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
        provider: classification.provider().map(|s| s.to_string()),
        policy: None,
        container_id: String::new(),
        cgroup_id: 0,
        request_rate: None,
        session_bytes: None,
        pod_name: None,
        pod_namespace: None,
        service_account: None,
        ml_confidence: None,
        ml_provider: None,
        behavior_class: None,
        cluster_id: None,
        sni: None,
        tls_protocol,
        tls_details,
        tls_payload: Some(payload),
        content_class: classification.content_class_str().map(|s| s.to_string()),
        llm_provider: classification.provider().map(|s| s.to_string()),
        llm_endpoint: classification.endpoint().map(|s| s.to_string()),
        llm_model: classification.model().map(|s| s.to_string()),
        mcp_method: classification.mcp_method().map(|s| s.to_string()),
        mcp_category: classification.mcp_category_str(),
        agent_sdk: classification.sdk_string(),
        agent_fingerprint: classification.signature_hash(),
        classifier_confidence: Some(classification.confidence),
        pii_detected: Some(classification.pii_flags.any()),
        llm_user_message: None,
        llm_system_prompt: None,
        llm_messages_json: None,
        llm_stream: None,
        identity_id: None,
        identity_instance: None,
        identity_confidence: None,
        identity_narrative: None,
        identity_timeline: None,
        identity_timeline_len: None,
        agent_sdk_hash: classification.sdk_hash(),
        agent_model_hash: classification.model_hash(),
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
