use busted_types::agentic::{
    AgenticAction, BustedEvent, IdentityInfo, NetworkEventKind, ProcessInfo,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::event::AppEvent;

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
    tool_name: Option<&'static str>,
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
        user_message: Some("Analyze the quarterly revenue data and identify the top 3 growth drivers compared to last quarter."),
        system_prompt: Some("You are a financial analyst specializing in SaaS metrics."),
        stream: true,
        pii: false,
        policy: "audit",
        identity_narrative: Some("Financial analysis assistant processing quarterly reports"),
        tool_name: None,
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
        user_message: Some("Review the pull request diff and suggest improvements for the auth middleware."),
        system_prompt: Some("You are a senior software engineer conducting code reviews."),
        stream: false,
        pii: false,
        policy: "allow",
        identity_narrative: Some("Code review bot integrated with GitHub CI pipeline"),
        tool_name: Some("code_review"),
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
        tool_name: None,
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
        user_message: Some("Translate the following error log from Japanese to English."),
        system_prompt: None,
        stream: false,
        pii: false,
        policy: "allow",
        identity_narrative: None,
        tool_name: None,
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
        user_message: Some("Generate a JIRA ticket for the payment processing timeout bug."),
        system_prompt: Some("You are a project management assistant."),
        stream: true,
        pii: false,
        policy: "audit",
        identity_narrative: Some("Enterprise ticketing integration via Azure OpenAI"),
        tool_name: Some("create_ticket"),
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
        user_message: Some("Classify the sentiment of these 50 customer support tickets."),
        system_prompt: Some("You are a customer support analyst."),
        stream: false,
        pii: false,
        policy: "allow",
        identity_narrative: Some("Batch sentiment classifier for support queue"),
        tool_name: None,
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
        user_message: Some("Write a Python script to parse CSV files and generate a summary."),
        system_prompt: None,
        stream: true,
        pii: false,
        policy: "audit",
        identity_narrative: None,
        tool_name: None,
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
        tool_name: None,
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
        user_message: Some("Here is John Smith's SSN 123-45-6789 and his medical records. Please summarize."),
        system_prompt: Some("You are a medical records assistant."),
        stream: false,
        pii: true,
        policy: "deny",
        identity_narrative: Some("Unauthorized medical data pipeline leaking PII"),
        tool_name: None,
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
    format!("{hours:02}:{minutes:02}:{seconds:02}.{millis:03}")
}

fn make_process(scenario: &Scenario) -> ProcessInfo {
    ProcessInfo {
        pid: scenario.pid,
        uid: 1000,
        name: scenario.process_name.to_string(),
        container_id: String::new(),
        cgroup_id: 0,
        pod_name: None,
        pod_namespace: None,
        service_account: None,
    }
}

fn make_identity(scenario: &Scenario) -> Option<IdentityInfo> {
    scenario
        .identity_narrative
        .as_ref()
        .map(|narrative| IdentityInfo {
            id: scenario.pid as u64 * 0x1234567,
            instance: format!("pid:{}", scenario.pid),
            confidence: 0.85,
            match_type: Some("CompositeMatch(0.85)".into()),
            narrative: Some(narrative.to_string()),
            timeline: None,
            timeline_len: Some(5),
            prompt_fingerprint: None,
            behavioral_digest: None,
            capability_hash: None,
            graph_node_count: Some(12),
            graph_edge_count: Some(18),
        })
}

fn session_id(scenario: &Scenario) -> String {
    format!("{}:{:x}", scenario.pid, scenario.pid as u64 * 0xBEEF)
}

fn make_connect(scenario: &Scenario) -> BustedEvent {
    BustedEvent {
        timestamp: now_timestamp(),
        process: make_process(scenario),
        session_id: session_id(scenario),
        identity: None,
        policy: None,
        action: AgenticAction::Network {
            kind: NetworkEventKind::Connect,
            src_ip: "192.168.1.100".into(),
            src_port: 40000 + (scenario.pid as u16 % 10000),
            dst_ip: scenario.dst_ip.into(),
            dst_port: scenario.dst_port,
            bytes: 0,
            sni: Some(scenario.sni.into()),
            provider: Some(scenario.provider.into()),
        },
    }
}

fn make_prompt(scenario: &Scenario, bytes: u64) -> BustedEvent {
    BustedEvent {
        timestamp: now_timestamp(),
        process: make_process(scenario),
        session_id: session_id(scenario),
        identity: make_identity(scenario),
        policy: Some(scenario.policy.into()),
        action: AgenticAction::Prompt {
            provider: scenario.provider.into(),
            model: scenario.model.map(|s| s.into()),
            user_message: scenario.user_message.map(|s| s.into()),
            system_prompt: scenario.system_prompt.map(|s| s.into()),
            stream: scenario.stream,
            sdk: scenario.sdk.map(|s| s.into()),
            bytes,
            sni: Some(scenario.sni.into()),
            endpoint: Some("/v1/chat/completions".into()),
            fingerprint: Some(0xdeadbeef),
            pii_detected: Some(scenario.pii),
            confidence: Some(0.95),
            sdk_hash: None,
            model_hash: None,
        },
    }
}

fn make_response(scenario: &Scenario, bytes: u64) -> BustedEvent {
    BustedEvent {
        timestamp: now_timestamp(),
        process: make_process(scenario),
        session_id: session_id(scenario),
        identity: make_identity(scenario),
        policy: Some(scenario.policy.into()),
        action: AgenticAction::Response {
            provider: scenario.provider.into(),
            model: scenario.model.map(|s| s.into()),
            bytes,
            sni: Some(scenario.sni.into()),
            confidence: Some(0.95),
        },
    }
}

fn make_tool_call(scenario: &Scenario) -> BustedEvent {
    BustedEvent {
        timestamp: now_timestamp(),
        process: make_process(scenario),
        session_id: session_id(scenario),
        identity: make_identity(scenario),
        policy: Some(scenario.policy.into()),
        action: AgenticAction::ToolCall {
            tool_name: scenario.tool_name.unwrap_or("unknown").into(),
            input_json: Some(r#"{"query": "recent changes"}"#.into()),
            provider: scenario.provider.into(),
        },
    }
}

fn make_mcp_request(scenario: &Scenario) -> BustedEvent {
    BustedEvent {
        timestamp: now_timestamp(),
        process: make_process(scenario),
        session_id: session_id(scenario),
        identity: make_identity(scenario),
        policy: Some(scenario.policy.into()),
        action: AgenticAction::McpRequest {
            method: scenario.mcp_method.unwrap_or("tools/call").into(),
            category: scenario.mcp_category.map(|s| s.into()),
            params_preview: Some(r#"{"name": "search_docs"}"#.into()),
        },
    }
}

fn make_mcp_response(scenario: &Scenario) -> BustedEvent {
    BustedEvent {
        timestamp: now_timestamp(),
        process: make_process(scenario),
        session_id: session_id(scenario),
        identity: make_identity(scenario),
        policy: Some(scenario.policy.into()),
        action: AgenticAction::McpResponse {
            method: scenario.mcp_method.unwrap_or("tools/call").into(),
            result_preview: Some(r#"{"content": [{"text": "Found 3 results"}]}"#.into()),
        },
    }
}

fn make_file_access(
    process_name: &str,
    pid: u32,
    path: &str,
    mode: &str,
    reason: &str,
) -> BustedEvent {
    BustedEvent {
        timestamp: now_timestamp(),
        process: ProcessInfo {
            pid,
            uid: 1000,
            name: process_name.to_string(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: format!("{pid}:file"),
        identity: None,
        policy: Some("audit".into()),
        action: AgenticAction::FileAccess {
            path: path.to_string(),
            mode: mode.to_string(),
            reason: Some(reason.to_string()),
        },
    }
}

fn make_file_data(
    process_name: &str,
    pid: u32,
    path: &str,
    direction: &str,
    content: &str,
) -> BustedEvent {
    BustedEvent {
        timestamp: now_timestamp(),
        process: ProcessInfo {
            pid,
            uid: 1000,
            name: process_name.to_string(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: format!("{pid}:file"),
        identity: None,
        policy: Some("audit".into()),
        action: AgenticAction::FileData {
            path: path.to_string(),
            direction: direction.to_string(),
            content: content.to_string(),
            bytes: content.len() as u64,
            truncated: None,
        },
    }
}

fn make_pii_detected(scenario: &Scenario) -> BustedEvent {
    BustedEvent {
        timestamp: now_timestamp(),
        process: make_process(scenario),
        session_id: session_id(scenario),
        identity: make_identity(scenario),
        policy: Some("deny".into()),
        action: AgenticAction::PiiDetected {
            direction: "write".into(),
            pii_types: Some(vec!["ssn".into(), "medical_record".into()]),
        },
    }
}

pub async fn start(tx: mpsc::UnboundedSender<AppEvent>) {
    let mut cycle = 0usize;
    loop {
        let scenario = &SCENARIOS[cycle % SCENARIOS.len()];

        // 1. Connect
        let _ = tx.send(AppEvent::Busted(Box::new(make_connect(scenario))));
        sleep(Duration::from_millis(50)).await;

        // 2. MCP or Prompt
        if scenario.mcp_method.is_some() {
            let _ = tx.send(AppEvent::Busted(Box::new(make_mcp_request(scenario))));
            sleep(Duration::from_millis(100)).await;
            let _ = tx.send(AppEvent::Busted(Box::new(make_mcp_response(scenario))));
        } else {
            let request_bytes = 256 + (cycle as u64 * 37) % 512;
            let _ = tx.send(AppEvent::Busted(Box::new(make_prompt(
                scenario,
                request_bytes,
            ))));
            sleep(Duration::from_millis(100)).await;

            // 3. Optional tool call
            if scenario.tool_name.is_some() {
                let _ = tx.send(AppEvent::Busted(Box::new(make_tool_call(scenario))));
                sleep(Duration::from_millis(80)).await;
            }

            // 4. PII detection
            if scenario.pii {
                let _ = tx.send(AppEvent::Busted(Box::new(make_pii_detected(scenario))));
                sleep(Duration::from_millis(50)).await;
            }

            // 5. Response
            let response_bytes = 1024 + (cycle as u64 * 73) % 4096;
            let _ = tx.send(AppEvent::Busted(Box::new(make_response(
                scenario,
                response_bytes,
            ))));
        }

        // Occasional file-access events (every 3rd cycle)
        if cycle % 3 == 0 {
            let _ = tx.send(AppEvent::Busted(Box::new(make_file_access(
                "claude",
                9901,
                "/home/user/.claude/settings.json",
                "read",
                "path_pattern:.claude",
            ))));
            sleep(Duration::from_millis(30)).await;

            // File data: show content read from settings
            let _ = tx.send(AppEvent::Busted(Box::new(make_file_data(
                "claude",
                9901,
                "/home/user/.claude/settings.json",
                "read",
                r#"{"theme":"dark","model":"claude-sonnet-4-5-20250929","permissions":{"allow_network":true}}"#,
            ))));
            sleep(Duration::from_millis(30)).await;
        }
        if cycle % 5 == 0 {
            let _ = tx.send(AppEvent::Busted(Box::new(make_file_access(
                "cursor",
                9902,
                "/home/user/project/CLAUDE.md",
                "read",
                "path_pattern:CLAUDE.md",
            ))));
            sleep(Duration::from_millis(30)).await;
        }

        cycle += 1;

        // 300-500ms between scenarios
        let delay = 300 + (cycle * 29) % 200;
        sleep(Duration::from_millis(delay as u64)).await;
    }
}
