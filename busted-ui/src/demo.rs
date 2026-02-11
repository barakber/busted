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
    user_message: Option<&'static str>,
    system_prompt: Option<&'static str>,
    stream: bool,
    pii: bool,
    policy: &'static str,
    identity_narrative: Option<&'static str>,
    identity_timeline: Option<&'static str>,
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
        user_message: Some("Analyze the quarterly revenue data and identify the top 3 growth drivers compared to last quarter. Focus on the SaaS segment."),
        system_prompt: Some("You are a financial analyst specializing in SaaS metrics. Always cite specific numbers."),
        stream: true,
        pii: false,
        policy: "audit",
        identity_narrative: Some("Financial analysis assistant processing quarterly reports"),
        identity_timeline: Some("09:00 init -> 09:01 load_data -> 14:23 analyze_revenue"),
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
        user_message: Some("Review the pull request diff and suggest improvements. Pay attention to error handling and edge cases in the auth middleware."),
        system_prompt: Some("You are a senior software engineer conducting code reviews. Be constructive and specific."),
        stream: false,
        pii: false,
        policy: "allow",
        identity_narrative: Some("Code review bot integrated with GitHub CI pipeline"),
        identity_timeline: Some("PR #482 opened -> webhook -> review_request"),
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
        mcp_category: Some("Tools"),
        user_message: None,
        system_prompt: None,
        stream: false,
        pii: false,
        policy: "audit",
        identity_narrative: Some("MCP tool orchestrator invoking local tools"),
        identity_timeline: Some("tools/list -> tools/call:search -> tools/call:summarize"),
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
        user_message: Some("Translate the following error log from Japanese to English and summarize the root cause."),
        system_prompt: None,
        stream: false,
        pii: false,
        policy: "allow",
        identity_narrative: None,
        identity_timeline: None,
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
        user_message: Some("Generate a JIRA ticket description for the payment processing timeout bug affecting checkout in EU regions."),
        system_prompt: Some("You are a project management assistant. Write clear, actionable ticket descriptions."),
        stream: true,
        pii: false,
        policy: "audit",
        identity_narrative: Some("Enterprise ticketing integration via Azure OpenAI"),
        identity_timeline: Some("alert_trigger -> triage -> generate_ticket"),
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
        user_message: Some("Classify the sentiment of these 50 customer support tickets and group them by urgency level."),
        system_prompt: Some("You are a customer support analyst. Classify tickets as positive/neutral/negative and urgency as low/medium/high/critical."),
        stream: false,
        pii: false,
        policy: "allow",
        identity_narrative: Some("Batch sentiment classifier for support queue"),
        identity_timeline: Some("fetch_tickets -> classify_batch -> write_results"),
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
        user_message: Some("Write a Python script to parse CSV files and generate a summary report with statistics."),
        system_prompt: None,
        stream: true,
        pii: false,
        policy: "audit",
        identity_narrative: None,
        identity_timeline: None,
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
        user_message: None,
        system_prompt: None,
        stream: false,
        pii: false,
        policy: "allow",
        identity_narrative: Some("Embedding pipeline for document search index"),
        identity_timeline: Some("load_docs -> chunk -> embed -> store_vectors"),
    },
    Scenario {
        process_name: "node",
        pid: 8901,
        provider: "OpenAI",
        model: Some("gpt-4o"),
        sdk: Some("openai-node/4.52.0"),
        sni: "api.openai.com",
        dst_ip: "104.18.7.192",
        dst_port: 443,
        mcp_method: None,
        mcp_category: None,
        user_message: Some("Here is John Smith's SSN 123-45-6789 and his medical records from Dr. Wilson. Please summarize his health history."),
        system_prompt: Some("You are a medical records assistant."),
        stream: false,
        pii: true,
        policy: "deny",
        identity_narrative: Some("Unauthorized medical data pipeline leaking PII"),
        identity_timeline: Some("scrape_records -> extract_pii -> send_to_llm"),
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
    let is_write = event_type == "TLS_DATA_WRITE";
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
        policy: Some(scenario.policy.to_string()),
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
        pii_detected: if is_tls { Some(scenario.pii) } else { None },
        llm_user_message: if is_write {
            scenario.user_message.map(|s| s.to_string())
        } else {
            None
        },
        llm_system_prompt: if is_write {
            scenario.system_prompt.map(|s| s.to_string())
        } else {
            None
        },
        llm_messages_json: None,
        llm_stream: if is_tls { Some(scenario.stream) } else { None },
        identity_id: None,
        identity_instance: None,
        identity_confidence: None,
        identity_narrative: if is_tls {
            scenario.identity_narrative.map(|s| s.to_string())
        } else {
            None
        },
        identity_timeline: if is_tls {
            scenario.identity_timeline.map(|s| s.to_string())
        } else {
            None
        },
        identity_timeline_len: if is_tls {
            scenario.identity_timeline.map(|s| s.split(" -> ").count())
        } else {
            None
        },
        agent_sdk_hash: None,
        agent_model_hash: None,
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
