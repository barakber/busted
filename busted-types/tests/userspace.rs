//! Integration tests for busted-types userspace helpers (requires `user` feature).

use busted_types::*;

// ---- IP parsing ----

#[test]
fn source_ip_ipv4_loopback() {
    let mut e = NetworkEvent::new();
    e.family = 2; // AF_INET
    e.saddr = IpAddress {
        ipv4: u32::to_be(0x7f000001),
    }; // 127.0.0.1
    assert_eq!(e.source_ip().to_string(), "127.0.0.1");
}

#[test]
fn source_ip_ipv4_broadcast() {
    let mut e = NetworkEvent::new();
    e.family = 2;
    e.saddr = IpAddress {
        ipv4: u32::to_be(0xFFFFFFFF),
    }; // 255.255.255.255
    assert_eq!(e.source_ip().to_string(), "255.255.255.255");
}

#[test]
fn dest_ip_ipv6_localhost() {
    let mut e = NetworkEvent::new();
    e.family = 10; // AF_INET6
    let mut addr = [0u8; 16];
    addr[15] = 1; // ::1
    e.daddr = IpAddress { ipv6: addr };
    assert_eq!(e.dest_ip().to_string(), "::1");
}

#[test]
fn source_ip_unknown_family_fallback() {
    let mut e = NetworkEvent::new();
    e.family = 99; // unknown
    assert_eq!(e.source_ip().to_string(), "0.0.0.0");
}

#[test]
fn dest_ip_unknown_family_fallback() {
    let e = NetworkEvent::new(); // family=0
    assert_eq!(e.dest_ip().to_string(), "0.0.0.0");
}

#[test]
fn ip_byte_order_correctness() {
    let mut e = NetworkEvent::new();
    e.family = 2;
    // Store 192.168.1.1 in network byte order (big-endian)
    e.daddr = IpAddress {
        ipv4: u32::to_be(0xC0A80101),
    };
    assert_eq!(e.dest_ip().to_string(), "192.168.1.1");
}

// ---- process_name() for NetworkEvent ----

#[test]
fn network_event_process_name_normal() {
    let mut e = NetworkEvent::new();
    let name = b"curl\0";
    e.comm[..name.len()].copy_from_slice(name);
    assert_eq!(e.process_name(), "curl");
}

#[test]
fn network_event_process_name_full_length() {
    let mut e = NetworkEvent::new();
    // Fill entire comm buffer with no null terminator
    e.comm = *b"0123456789abcdef";
    assert_eq!(e.process_name(), "0123456789abcdef");
}

#[test]
fn network_event_process_name_empty() {
    let e = NetworkEvent::new();
    assert_eq!(e.process_name(), "");
}

#[test]
fn network_event_process_name_invalid_utf8() {
    let mut e = NetworkEvent::new();
    e.comm[0] = 0xFF;
    e.comm[1] = 0xFE;
    e.comm[2] = 0x00;
    assert_eq!(e.process_name(), "<invalid>");
}

// ---- process_name() for TlsHandshakeEvent ----

#[test]
fn tls_handshake_process_name_normal() {
    let mut e = TlsHandshakeEvent::new();
    let name = b"python3\0";
    e.comm[..name.len()].copy_from_slice(name);
    assert_eq!(e.process_name(), "python3");
}

#[test]
fn tls_handshake_process_name_full_no_null() {
    let mut e = TlsHandshakeEvent::new();
    e.comm = *b"very_long_proces";
    assert_eq!(e.process_name(), "very_long_proces");
}

#[test]
fn tls_handshake_process_name_empty() {
    let e = TlsHandshakeEvent::new();
    assert_eq!(e.process_name(), "");
}

#[test]
fn tls_handshake_process_name_invalid_utf8() {
    let mut e = TlsHandshakeEvent::new();
    e.comm[0] = 0x80;
    e.comm[1] = 0x00;
    assert_eq!(e.process_name(), "<invalid>");
}

// ---- process_name() for TlsDataEvent ----

#[test]
fn tls_data_process_name_normal() {
    let mut e = TlsDataEvent::new();
    let name = b"node\0";
    e.comm[..name.len()].copy_from_slice(name);
    assert_eq!(e.process_name(), "node");
}

#[test]
fn tls_data_process_name_invalid_utf8() {
    let mut e = TlsDataEvent::new();
    e.comm[0] = 0xFF;
    e.comm[1] = 0x00;
    assert_eq!(e.process_name(), "<invalid>");
}

// ---- container_id_str() ----

#[test]
fn container_id_str_normal() {
    let mut e = NetworkEvent::new();
    let id = b"abc123def456\0";
    e.container_id[..id.len()].copy_from_slice(id);
    assert_eq!(e.container_id_str(), "abc123def456");
}

#[test]
fn container_id_str_empty() {
    let e = NetworkEvent::new();
    assert_eq!(e.container_id_str(), "");
}

#[test]
fn container_id_str_full_length() {
    let mut e = NetworkEvent::new();
    // Fill entire buffer with hex chars, no null
    for (i, b) in e.container_id.iter_mut().enumerate() {
        *b = b'a' + (i % 6) as u8;
    }
    assert_eq!(e.container_id_str().len(), CONTAINER_ID_LEN);
}

// ---- sni_str() ----

#[test]
fn sni_str_normal() {
    let mut e = TlsHandshakeEvent::new();
    let sni = b"api.openai.com\0";
    e.sni[..sni.len()].copy_from_slice(sni);
    assert_eq!(e.sni_str(), "api.openai.com");
}

#[test]
fn sni_str_empty() {
    let e = TlsHandshakeEvent::new();
    assert_eq!(e.sni_str(), "");
}

#[test]
fn sni_str_full_length() {
    let mut e = TlsHandshakeEvent::new();
    for (i, b) in e.sni.iter_mut().enumerate() {
        *b = b'a' + (i % 26) as u8;
    }
    assert_eq!(e.sni_str().len(), SNI_MAX_LEN);
}

#[test]
fn sni_str_invalid_utf8() {
    let mut e = TlsHandshakeEvent::new();
    e.sni[0] = 0xFF;
    e.sni[1] = 0xFE;
    e.sni[2] = 0x00;
    assert_eq!(e.sni_str(), "<invalid>");
}

// ---- payload_bytes() ----

#[test]
fn payload_bytes_normal() {
    let mut e = TlsDataEvent::new();
    e.payload[0] = b'H';
    e.payload[1] = b'i';
    e.payload_len = 2;
    assert_eq!(e.payload_bytes(), b"Hi");
}

#[test]
fn payload_bytes_zero_len() {
    let e = TlsDataEvent::new();
    assert_eq!(e.payload_bytes().len(), 0);
}

#[test]
fn payload_bytes_max_len() {
    let mut e = TlsDataEvent::new();
    e.payload_len = TLS_PAYLOAD_MAX as u16;
    assert_eq!(e.payload_bytes().len(), TLS_PAYLOAD_MAX);
}

#[test]
fn payload_bytes_overflow_clamps_to_max() {
    let mut e = TlsDataEvent::new();
    e.payload_len = 20000; // exceeds TLS_PAYLOAD_MAX (16384)
    assert_eq!(e.payload_bytes().len(), TLS_PAYLOAD_MAX);
}

#[test]
fn payload_bytes_u16_max_clamps() {
    let mut e = TlsDataEvent::new();
    e.payload_len = u16::MAX;
    assert_eq!(e.payload_bytes().len(), TLS_PAYLOAD_MAX);
}

// ---- ProcessedEvent serde ----

#[test]
fn processed_event_serde_round_trip() {
    let pe = processed::ProcessedEvent {
        event_type: "TCP_CONNECT".into(),
        timestamp: "12:34:56.789".into(),
        pid: 42,
        uid: 1000,
        process_name: "curl".into(),
        src_ip: "127.0.0.1".into(),
        src_port: 54321,
        dst_ip: "93.184.216.34".into(),
        dst_port: 443,
        bytes: 1024,
        provider: Some("OpenAI".into()),
        policy: Some("allow".into()),
        container_id: "abc123".into(),
        cgroup_id: 99,
        request_rate: Some(1.5),
        session_bytes: Some(4096),
        pod_name: None,
        pod_namespace: None,
        service_account: None,
        ml_confidence: Some(0.95),
        ml_provider: Some("OpenAI".into()),
        behavior_class: Some("LlmApi(OpenAI)".into()),
        cluster_id: Some(3),
        sni: Some("api.openai.com".into()),
        tls_protocol: Some("LlmApi".into()),
        tls_details: Some("OpenAI chat_completions gpt-4".into()),
        tls_payload: Some("POST /v1/chat...".into()),
        content_class: Some("LlmApi".into()),
        llm_provider: Some("OpenAI".into()),
        llm_endpoint: Some("chat_completions".into()),
        llm_model: Some("gpt-4".into()),
        mcp_method: None,
        mcp_category: None,
        agent_sdk: Some("openai-python/1.12.0".into()),
        agent_fingerprint: Some(0xDEADBEEF),
        classifier_confidence: Some(0.9),
        pii_detected: Some(false),
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
    };

    let json = serde_json::to_string(&pe).unwrap();
    let de: processed::ProcessedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(de.pid, 42);
    assert_eq!(de.process_name, "curl");
    assert_eq!(de.ml_confidence, Some(0.95));
    assert_eq!(de.llm_model.as_deref(), Some("gpt-4"));
}

#[test]
fn processed_event_skip_serializing_none_fields() {
    let pe = processed::ProcessedEvent {
        event_type: "TCP_CONNECT".into(),
        timestamp: "00:00:00.000".into(),
        pid: 1,
        uid: 0,
        process_name: "test".into(),
        src_ip: "0.0.0.0".into(),
        src_port: 0,
        dst_ip: "0.0.0.0".into(),
        dst_port: 0,
        bytes: 0,
        provider: None,
        policy: None,
        container_id: "".into(),
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
    };

    let json = serde_json::to_string(&pe).unwrap();
    // Fields with skip_serializing_if should not appear when None
    assert!(!json.contains("ml_confidence"));
    assert!(!json.contains("ml_provider"));
    assert!(!json.contains("behavior_class"));
    assert!(!json.contains("cluster_id"));
    assert!(!json.contains("sni"));
    assert!(!json.contains("content_class"));
    assert!(!json.contains("llm_provider"));
    assert!(!json.contains("pii_detected"));
}

#[test]
fn processed_event_deserialize_missing_optional_fields() {
    let json = r#"{"event_type":"TEST","timestamp":"00:00","pid":1,"uid":0,"process_name":"x","src_ip":"0","src_port":0,"dst_ip":"0","dst_port":0,"bytes":0,"provider":null,"policy":null,"container_id":""}"#;
    let pe: processed::ProcessedEvent = serde_json::from_str(json).unwrap();
    assert_eq!(pe.pid, 1);
    assert_eq!(pe.cgroup_id, 0); // #[serde(default)]
    assert!(pe.ml_confidence.is_none());
    assert!(pe.sni.is_none());
    assert!(pe.content_class.is_none());
}

#[test]
fn processed_event_all_optional_fields_set() {
    let pe = processed::ProcessedEvent {
        event_type: "TLS_DATA_WRITE".into(),
        timestamp: "12:00:00.000".into(),
        pid: 100,
        uid: 500,
        process_name: "python3".into(),
        src_ip: "10.0.0.1".into(),
        src_port: 45000,
        dst_ip: "104.18.7.192".into(),
        dst_port: 443,
        bytes: 2048,
        provider: Some("Anthropic".into()),
        policy: Some("audit".into()),
        container_id: "deadbeef".into(),
        cgroup_id: 12345,
        request_rate: Some(2.0),
        session_bytes: Some(8192),
        pod_name: Some("my-pod".into()),
        pod_namespace: Some("default".into()),
        service_account: Some("sa".into()),
        ml_confidence: Some(0.8),
        ml_provider: Some("Anthropic".into()),
        behavior_class: Some("LlmApi(Anthropic)".into()),
        cluster_id: Some(1),
        sni: Some("api.anthropic.com".into()),
        tls_protocol: Some("LlmApi".into()),
        tls_details: Some("details".into()),
        tls_payload: Some("payload".into()),
        content_class: Some("LlmApi".into()),
        llm_provider: Some("Anthropic".into()),
        llm_endpoint: Some("messages".into()),
        llm_model: Some("claude-3-opus".into()),
        mcp_method: Some("tools/call".into()),
        mcp_category: Some("Tools".into()),
        agent_sdk: Some("anthropic-typescript/0.20.0".into()),
        agent_fingerprint: Some(0xCAFE),
        classifier_confidence: Some(0.95),
        pii_detected: Some(true),
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
    };

    let json = serde_json::to_string(&pe).unwrap();
    // All optional fields should appear
    assert!(json.contains("ml_confidence"));
    assert!(json.contains("cluster_id"));
    assert!(json.contains("mcp_method"));
    assert!(json.contains("pii_detected"));

    let de: processed::ProcessedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(de.mcp_method.as_deref(), Some("tools/call"));
    assert_eq!(de.pii_detected, Some(true));
}
