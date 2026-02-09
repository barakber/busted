use busted_types::processed::ProcessedEvent;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Scenario {
    process_name: &'static str,
    pid: u32,
    provider: &'static str,
    model: Option<&'static str>,
    sdk: Option<&'static str>,
    sni: &'static str,
    dst_ip: &'static str,
    dst_port: u16,
    mcp_method: Option<&'static str>,
    mcp_category: Option<&'static str>,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        process_name: "python3",
        pid: 1234,
        provider: "OpenAI",
        model: Some("gpt-4o"),
        sdk: Some("openai-python/1.40.0"),
        sni: "api.openai.com",
        dst_ip: "104.18.7.192",
        dst_port: 443,
        mcp_method: None,
        mcp_category: None,
    },
    Scenario {
        process_name: "node",
        pid: 2345,
        provider: "Anthropic",
        model: Some("claude-3.5-sonnet"),
        sdk: Some("anthropic-typescript/0.25.0"),
        sni: "api.anthropic.com",
        dst_ip: "160.79.104.25",
        dst_port: 443,
        mcp_method: None,
        mcp_category: None,
    },
    Scenario {
        process_name: "python3",
        pid: 3456,
        provider: "MCP",
        model: None,
        sdk: None,
        sni: "localhost",
        dst_ip: "127.0.0.1",
        dst_port: 3000,
        mcp_method: Some("tools/call"),
        mcp_category: Some("tool_use"),
    },
    Scenario {
        process_name: "curl",
        pid: 4567,
        provider: "Ollama",
        model: Some("llama3"),
        sdk: Some("curl/8.4.0"),
        sni: "localhost",
        dst_ip: "127.0.0.1",
        dst_port: 11434,
        mcp_method: None,
        mcp_category: None,
    },
    Scenario {
        process_name: "java",
        pid: 5678,
        provider: "Azure",
        model: Some("gpt-4"),
        sdk: Some("openai-java/0.8.0"),
        sni: "myapp.openai.azure.com",
        dst_ip: "13.91.100.50",
        dst_port: 443,
        mcp_method: None,
        mcp_category: None,
    },
    Scenario {
        process_name: "python3",
        pid: 6789,
        provider: "Google",
        model: Some("gemini-pro"),
        sdk: None,
        sni: "generativelanguage.googleapis.com",
        dst_ip: "142.250.80.42",
        dst_port: 443,
        mcp_method: None,
        mcp_category: None,
    },
    Scenario {
        process_name: "node",
        pid: 7890,
        provider: "Groq",
        model: Some("llama3-70b"),
        sdk: None,
        sni: "api.groq.com",
        dst_ip: "104.18.2.30",
        dst_port: 443,
        mcp_method: None,
        mcp_category: None,
    },
    Scenario {
        process_name: "python3",
        pid: 1234,
        provider: "OpenAI",
        model: Some("text-embedding-3-small"),
        sdk: Some("openai-python/1.40.0"),
        sni: "api.openai.com",
        dst_ip: "104.18.7.192",
        dst_port: 443,
        mcp_method: None,
        mcp_category: None,
    },
];

fn now_timestamp() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs();
    let hours = (total_secs / 3600) % 24;
    let minutes = (total_secs / 60) % 60;
    let seconds = total_secs % 60;
    let millis = dur.subsec_millis();
    format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
}

fn make_event(scenario: &Scenario, event_type: &str, bytes: u64) -> ProcessedEvent {
    let is_tls = event_type.starts_with("TLS_DATA_");
    ProcessedEvent {
        event_type: event_type.to_string(),
        timestamp: now_timestamp(),
        pid: scenario.pid,
        uid: 1000,
        process_name: scenario.process_name.to_string(),
        src_ip: "192.168.1.100".to_string(),
        src_port: 40000 + (scenario.pid as u16 % 10000),
        dst_ip: scenario.dst_ip.to_string(),
        dst_port: scenario.dst_port,
        bytes,
        provider: Some(scenario.provider.to_string()),
        policy: Some("audit".to_string()),
        container_id: String::new(),
        cgroup_id: 0,
        request_rate: Some(2.5),
        session_bytes: Some(bytes),
        pod_name: None,
        pod_namespace: None,
        service_account: None,
        ml_confidence: None,
        ml_provider: None,
        behavior_class: None,
        cluster_id: None,
        sni: Some(scenario.sni.to_string()),
        tls_protocol: if is_tls {
            Some("LLM_API".to_string())
        } else {
            None
        },
        tls_details: if is_tls {
            scenario
                .model
                .map(|m| format!("{} model={}", scenario.provider, m))
        } else {
            None
        },
        tls_payload: None,
        content_class: if is_tls {
            Some("LLM_API".to_string())
        } else {
            None
        },
        llm_provider: Some(scenario.provider.to_string()),
        llm_endpoint: if is_tls {
            Some("/v1/chat/completions".to_string())
        } else {
            None
        },
        llm_model: scenario.model.map(|s| s.to_string()),
        mcp_method: scenario.mcp_method.map(|s| s.to_string()),
        mcp_category: scenario.mcp_category.map(|s| s.to_string()),
        agent_sdk: scenario.sdk.map(|s| s.to_string()),
        agent_fingerprint: Some(0xdeadbeef),
        classifier_confidence: if is_tls { Some(0.95) } else { None },
        pii_detected: if is_tls { Some(false) } else { None },
    }
}

pub fn start(tx: mpsc::Sender<ProcessedEvent>) {
    std::thread::spawn(move || {
        let mut cycle = 0usize;
        loop {
            let scenario = &SCENARIOS[cycle % SCENARIOS.len()];

            // TCP_CONNECT
            let event = make_event(scenario, "TCP_CONNECT", 0);
            if tx.send(event).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));

            // TLS_DATA_WRITE (request)
            let request_bytes = 256 + (cycle as u64 * 37) % 512;
            let event = make_event(scenario, "TLS_DATA_WRITE", request_bytes);
            if tx.send(event).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));

            // TLS_DATA_READ (response)
            let response_bytes = 1024 + (cycle as u64 * 73) % 4096;
            let event = make_event(scenario, "TLS_DATA_READ", response_bytes);
            if tx.send(event).is_err() {
                return;
            }

            cycle += 1;

            // 300-500ms between scenarios
            let delay = 300 + (cycle * 29) % 200;
            std::thread::sleep(Duration::from_millis(delay as u64));
        }
    });
}
