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

// ---- FileAccessEvent helpers ----

#[test]
fn file_access_event_path_str_normal() {
    let mut e = busted_types::FileAccessEvent::new();
    let path = b"/home/user/.claude/settings.json\0";
    e.path[..path.len()].copy_from_slice(path);
    e.path_len = (path.len() - 1) as u16; // exclude null
    assert_eq!(e.path_str(), "/home/user/.claude/settings.json");
}

#[test]
fn file_access_event_path_str_empty() {
    let e = busted_types::FileAccessEvent::new();
    assert_eq!(e.path_str(), "");
}

#[test]
fn file_access_event_process_name() {
    let mut e = busted_types::FileAccessEvent::new();
    let name = b"claude\0";
    e.comm[..name.len()].copy_from_slice(name);
    assert_eq!(e.process_name(), "claude");
}

#[test]
fn file_access_event_mode_str() {
    let mut e = busted_types::FileAccessEvent::new();
    e.flags = 0;
    assert_eq!(e.mode_str(), "read");
    e.flags = 1;
    assert_eq!(e.mode_str(), "write");
    e.flags = 2;
    assert_eq!(e.mode_str(), "readwrite");
    e.flags = 0x42; // O_CREAT | O_RDWR — low 2 bits = 2
    assert_eq!(e.mode_str(), "readwrite");
}

// ---- FileDataEvent helpers ----

#[test]
fn file_data_event_path_str_normal() {
    let mut e = busted_types::FileDataEvent::new();
    let path = b"/home/user/.claude/settings.json\0";
    e.path[..path.len()].copy_from_slice(path);
    e.path_len = (path.len() - 1) as u16;
    assert_eq!(e.path_str(), "/home/user/.claude/settings.json");
}

#[test]
fn file_data_event_path_str_empty() {
    let e = busted_types::FileDataEvent::new();
    assert_eq!(e.path_str(), "");
}

#[test]
fn file_data_event_process_name() {
    let mut e = busted_types::FileDataEvent::new();
    let name = b"claude\0";
    e.comm[..name.len()].copy_from_slice(name);
    assert_eq!(e.process_name(), "claude");
}

#[test]
fn file_data_event_direction_str() {
    let mut e = busted_types::FileDataEvent::new();
    e.direction = 0;
    assert_eq!(e.direction_str(), "write");
    e.direction = 1;
    assert_eq!(e.direction_str(), "read");
    e.direction = 99;
    assert_eq!(e.direction_str(), "unknown");
}

#[test]
fn file_data_event_payload_bytes() {
    let mut e = busted_types::FileDataEvent::new();
    e.payload[0] = b'{';
    e.payload[1] = b'}';
    e.payload_len = 2;
    assert_eq!(e.payload_bytes(), b"{}");
}

#[test]
fn file_data_event_payload_bytes_overflow_clamps() {
    let mut e = busted_types::FileDataEvent::new();
    e.payload_len = u16::MAX;
    assert_eq!(e.payload_bytes().len(), busted_types::FILE_DATA_MAX);
}

// ---- BustedEvent serde ----

#[test]
fn busted_event_prompt_serde_round_trip() {
    use busted_types::agentic::*;

    let ev = BustedEvent {
        timestamp: "12:34:56.789".into(),
        process: ProcessInfo {
            pid: 42,
            uid: 1000,
            name: "curl".into(),
            container_id: "abc123".into(),
            cgroup_id: 99,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "42:cafe".into(),
        identity: None,
        policy: Some("allow".into()),
        action: AgenticAction::Prompt {
            provider: "OpenAI".into(),
            model: Some("gpt-4".into()),
            user_message: Some("Hello".into()),
            system_prompt: None,
            stream: true,
            sdk: Some("openai-python/1.12.0".into()),
            bytes: 1024,
            sni: Some("api.openai.com".into()),
            endpoint: Some("chat_completions".into()),
            fingerprint: Some(0xDEADBEEF),
            pii_detected: Some(false),
            confidence: Some(0.9),
            sdk_hash: None,
            model_hash: None,
        },
    };

    let json = serde_json::to_string(&ev).unwrap();
    let de: BustedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(de.process.pid, 42);
    assert_eq!(de.process.name, "curl");
    assert_eq!(de.provider(), Some("OpenAI"));
    assert_eq!(de.model(), Some("gpt-4"));
}

#[test]
fn busted_event_skip_serializing_none_fields() {
    use busted_types::agentic::*;

    let ev = BustedEvent {
        timestamp: "00:00:00.000".into(),
        process: ProcessInfo {
            pid: 1,
            uid: 0,
            name: "test".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1:net".into(),
        identity: None,
        policy: None,
        action: AgenticAction::Network {
            kind: NetworkEventKind::Connect,
            src_ip: "0.0.0.0".into(),
            src_port: 0,
            dst_ip: "0.0.0.0".into(),
            dst_port: 0,
            bytes: 0,
            sni: None,
            provider: None,
        },
    };

    let json = serde_json::to_string(&ev).unwrap();
    // Optional fields that are None/empty should not appear
    assert!(!json.contains("identity"));
    assert!(!json.contains("policy"));
    assert!(!json.contains("sni"));
    assert!(!json.contains("provider"));
    assert!(!json.contains("pod_name"));
}

#[test]
fn busted_event_deserialize_minimal_prompt() {
    let json = r#"{"timestamp":"00:00","process":{"pid":1,"uid":0,"name":"x"},"session_id":"1:0","action":{"type":"Prompt","provider":"OpenAI","bytes":0,"stream":false}}"#;
    let ev: busted_types::agentic::BustedEvent = serde_json::from_str(json).unwrap();
    assert_eq!(ev.process.pid, 1);
    assert_eq!(ev.provider(), Some("OpenAI"));
    assert!(ev.identity.is_none());
    assert!(ev.policy.is_none());
}

#[test]
fn busted_event_action_type_tag() {
    use busted_types::agentic::*;

    let ev = BustedEvent {
        timestamp: "12:00:00.000".into(),
        process: ProcessInfo {
            pid: 100,
            uid: 500,
            name: "python3".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "100:beef".into(),
        identity: Some(IdentityInfo {
            id: 42,
            instance: "100:deadbeef:99".into(),
            confidence: 0.85,
            match_type: Some("CompositeMatch(0.85)".into()),
            narrative: None,
            timeline: None,
            timeline_len: None,
            prompt_fingerprint: None,
            behavioral_digest: None,
            capability_hash: None,
            graph_node_count: None,
            graph_edge_count: None,
        }),
        policy: Some("audit".into()),
        action: AgenticAction::ToolCall {
            tool_name: "search_docs".into(),
            input_json: Some(r#"{"query":"test"}"#.into()),
            provider: "Anthropic".into(),
        },
    };

    let json = serde_json::to_string(&ev).unwrap();
    // The discriminated union should have "type":"ToolCall"
    assert!(json.contains(r#""type":"ToolCall"#));
    assert!(json.contains("search_docs"));
    assert!(json.contains("identity"));

    let de: BustedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(de.action_type(), "ToolCall");
    assert_eq!(de.provider(), Some("Anthropic"));
    assert!(de.identity.is_some());
    assert_eq!(de.identity.unwrap().confidence, 0.85);
}

#[test]
fn busted_event_file_access_serde_round_trip() {
    use busted_types::agentic::*;

    let ev = BustedEvent {
        timestamp: "12:34:56.789".into(),
        process: ProcessInfo {
            pid: 99,
            uid: 1000,
            name: "claude".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "99:file".into(),
        identity: None,
        policy: Some("audit".into()),
        action: AgenticAction::FileAccess {
            path: "/home/user/.claude/settings.json".into(),
            mode: "read".into(),
            reason: Some("path_pattern:.claude".into()),
        },
    };

    let json = serde_json::to_string(&ev).unwrap();
    assert!(json.contains(r#""type":"FileAccess"#));
    assert!(json.contains(".claude/settings.json"));

    let de: BustedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(de.action_type(), "FileAccess");
    assert_eq!(de.event_type(), "FILE_ACCESS");
    assert_eq!(de.file_path(), Some("/home/user/.claude/settings.json"));
    assert_eq!(de.bytes(), 0);
    assert_eq!(de.content_class(), Some("FileAccess"));
}

#[test]
fn busted_event_file_access_skip_none_reason() {
    use busted_types::agentic::*;

    let ev = BustedEvent {
        timestamp: "00:00:00.000".into(),
        process: ProcessInfo {
            pid: 1,
            uid: 0,
            name: "test".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1:file".into(),
        identity: None,
        policy: None,
        action: AgenticAction::FileAccess {
            path: "/tmp/test".into(),
            mode: "write".into(),
            reason: None,
        },
    };

    let json = serde_json::to_string(&ev).unwrap();
    assert!(!json.contains("reason"));
}

#[test]
fn busted_event_file_data_serde_round_trip() {
    use busted_types::agentic::*;

    let ev = BustedEvent {
        timestamp: "12:34:56.789".into(),
        process: ProcessInfo {
            pid: 99,
            uid: 1000,
            name: "claude".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "99:file".into(),
        identity: None,
        policy: Some("audit".into()),
        action: AgenticAction::FileData {
            path: "/home/user/.claude/settings.json".into(),
            direction: "read".into(),
            content: r#"{"theme":"dark"}"#.into(),
            bytes: 16,
            truncated: None,
        },
    };

    let json = serde_json::to_string(&ev).unwrap();
    assert!(json.contains(r#""type":"FileData"#));
    assert!(json.contains("settings.json"));
    assert!(!json.contains("truncated")); // None → skipped

    let de: BustedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(de.action_type(), "FileData");
    assert_eq!(de.event_type(), "FILE_DATA");
    assert_eq!(de.file_path(), Some("/home/user/.claude/settings.json"));
    assert_eq!(de.bytes(), 16);
    assert_eq!(de.content_class(), Some("FileData"));
}

#[test]
fn busted_event_file_data_truncated_flag() {
    use busted_types::agentic::*;

    let ev = BustedEvent {
        timestamp: "00:00:00.000".into(),
        process: ProcessInfo {
            pid: 1,
            uid: 0,
            name: "test".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1:file".into(),
        identity: None,
        policy: None,
        action: AgenticAction::FileData {
            path: "/tmp/big.log".into(),
            direction: "read".into(),
            content: "partial data...".into(),
            bytes: 4096,
            truncated: Some(true),
        },
    };

    let json = serde_json::to_string(&ev).unwrap();
    assert!(json.contains("truncated"));

    let de: BustedEvent = serde_json::from_str(&json).unwrap();
    match &de.action {
        AgenticAction::FileData { truncated, .. } => assert_eq!(*truncated, Some(true)),
        _ => panic!("expected FileData"),
    }
}
