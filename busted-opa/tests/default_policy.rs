//! Tests for the shipped `policies/default.rego`.
//!
//! These verify that the default policy behaves as documented:
//! - Allow all traffic by default
//! - Audit traffic to known LLM providers
//! - Deny traffic with PII in LLM payloads
//! - Reasons explain what triggered the decision

use busted_opa::{Action, PolicyEngine};
use busted_types::agentic::{AgenticAction, BustedEvent, NetworkEventKind, ProcessInfo};

fn default_engine() -> PolicyEngine {
    let policy_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policies");
    PolicyEngine::new(&policy_dir).expect("default policy should load")
}

/// Minimal event: Network with no provider — pure background traffic.
fn bare_event() -> BustedEvent {
    BustedEvent {
        timestamp: "00:00:00.000".into(),
        process: ProcessInfo {
            pid: 1,
            uid: 0,
            name: "nginx".into(),
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
            kind: NetworkEventKind::DataSent,
            src_ip: "10.0.0.1".into(),
            src_port: 80,
            dst_ip: "10.0.0.2".into(),
            dst_port: 8080,
            bytes: 64,
            sni: None,
            provider: None,
        },
    }
}

/// Network event with a provider set.
fn network_event_with_provider(provider: &str) -> BustedEvent {
    BustedEvent {
        timestamp: "00:00:00.000".into(),
        process: ProcessInfo {
            pid: 1,
            uid: 0,
            name: "nginx".into(),
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
            kind: NetworkEventKind::DataSent,
            src_ip: "10.0.0.1".into(),
            src_port: 80,
            dst_ip: "10.0.0.2".into(),
            dst_port: 8080,
            bytes: 64,
            sni: None,
            provider: Some(provider.into()),
        },
    }
}

/// Prompt event — used for PII tests since pii_detected is Prompt-only.
fn prompt_event(provider: &str, pii: Option<bool>) -> BustedEvent {
    BustedEvent {
        timestamp: "00:00:00.000".into(),
        process: ProcessInfo {
            pid: 1,
            uid: 0,
            name: "python3".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1:abc".into(),
        identity: None,
        policy: None,
        action: AgenticAction::Prompt {
            provider: provider.into(),
            model: None,
            user_message: None,
            system_prompt: None,
            stream: false,
            sdk: None,
            bytes: 512,
            sni: None,
            endpoint: None,
            fingerprint: None,
            pii_detected: pii,
            confidence: None,
            sdk_hash: None,
            model_hash: None,
        },
    }
}

/// McpRequest event.
fn mcp_event(method: &str) -> BustedEvent {
    BustedEvent {
        timestamp: "00:00:00.000".into(),
        process: ProcessInfo {
            pid: 1,
            uid: 0,
            name: "mcp-client".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1:mcp".into(),
        identity: None,
        policy: None,
        action: AgenticAction::McpRequest {
            method: method.into(),
            category: None,
            params_preview: None,
        },
    }
}

// =====================================================================
// Default action: allow
// =====================================================================

#[test]
fn default_allows_plain_traffic() {
    let mut engine = default_engine();
    let d = engine.evaluate(&bare_event()).unwrap();
    assert_eq!(d.action, Action::Allow);
    assert!(d.reasons.is_empty());
}

#[test]
fn default_allows_non_llm_http() {
    let mut engine = default_engine();
    let mut event = bare_event();
    if let AgenticAction::Network {
        ref mut dst_port,
        ref mut bytes,
        ..
    } = event.action
    {
        *dst_port = 443;
        *bytes = 4096;
    }
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Allow);
}

// =====================================================================
// Audit: provider detected (Network action)
// =====================================================================

#[test]
fn default_audits_provider_openai() {
    let mut engine = default_engine();
    let event = network_event_with_provider("OpenAI");
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(
        d.reasons.iter().any(|r| r.contains("OpenAI")),
        "reasons should mention OpenAI: {:?}",
        d.reasons
    );
}

#[test]
fn default_audits_provider_anthropic() {
    let mut engine = default_engine();
    let event = network_event_with_provider("Anthropic");
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("Anthropic")));
}

#[test]
fn default_audits_provider_google() {
    let mut engine = default_engine();
    let event = network_event_with_provider("Google");
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
}

#[test]
fn default_audits_provider_deepseek() {
    let mut engine = default_engine();
    let event = network_event_with_provider("DeepSeek");
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
}

// =====================================================================
// Audit: Prompt action (always _is_llm_traffic via action.type == "Prompt")
// =====================================================================

#[test]
fn default_audits_prompt_action() {
    let mut engine = default_engine();
    let event = prompt_event("Mistral", None);
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("Mistral")));
}

// =====================================================================
// Audit: McpRequest action
// =====================================================================

#[test]
fn default_audits_mcp_request() {
    let mut engine = default_engine();
    let event = mcp_event("tools/call");
    let d = engine.evaluate(&event).unwrap();
    // McpRequest is _is_llm_traffic, so audit
    assert_eq!(d.action, Action::Audit);
}

// =====================================================================
// Deny: PII in LLM traffic (Prompt with pii_detected = true)
// =====================================================================

#[test]
fn default_denies_pii_with_provider() {
    let mut engine = default_engine();
    let event = prompt_event("OpenAI", Some(true));
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(
        d.reasons.iter().any(|r| r.contains("PII")),
        "reasons should mention PII: {:?}",
        d.reasons
    );
}

#[test]
fn default_denies_pii_with_anthropic() {
    let mut engine = default_engine();
    let event = prompt_event("Anthropic", Some(true));
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("PII")));
}

#[test]
fn default_pii_false_does_not_deny() {
    let mut engine = default_engine();
    let event = prompt_event("OpenAI", Some(false));
    let d = engine.evaluate(&event).unwrap();
    // pii_detected == false is NOT the same as true
    assert_eq!(d.action, Action::Audit);
}

#[test]
fn default_pii_null_does_not_deny() {
    let mut engine = default_engine();
    let event = prompt_event("OpenAI", None);
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
}

// =====================================================================
// MCP-specific reasons
// =====================================================================

#[test]
fn default_mcp_method_in_reasons() {
    let mut engine = default_engine();
    let event = mcp_event("tools/call");
    let d = engine.evaluate(&event).unwrap();
    assert!(
        d.reasons.iter().any(|r| r.contains("tools/call")),
        "reasons should mention MCP method: {:?}",
        d.reasons
    );
}

// =====================================================================
// Reason content: verify dynamic string interpolation
// =====================================================================

#[test]
fn default_reason_provider_string_interpolated() {
    let mut engine = default_engine();
    let event = network_event_with_provider("Groq");
    let d = engine.evaluate(&event).unwrap();
    assert!(d
        .reasons
        .iter()
        .any(|r| r == "Traffic to LLM provider: Groq"));
}

// =====================================================================
// Reload the default policy directory
// =====================================================================

#[test]
fn default_policy_reload_works() {
    let mut engine = default_engine();
    let d1 = engine.evaluate(&bare_event()).unwrap();
    engine.reload().unwrap();
    let d2 = engine.evaluate(&bare_event()).unwrap();
    assert_eq!(d1.action, d2.action);
}

// =====================================================================
// All fields populated — no crash
// =====================================================================

#[test]
fn default_all_fields_populated_no_crash() {
    let mut engine = default_engine();
    let event = BustedEvent {
        timestamp: "23:59:59.999".into(),
        process: ProcessInfo {
            pid: 99999,
            uid: 65534,
            name: "full-test-binary".into(),
            container_id: "abc123def456".into(),
            cgroup_id: 12345678,
            pod_name: Some("ai-gateway-pod-xyz".into()),
            pod_namespace: Some("ml-production".into()),
            service_account: Some("ai-service-account".into()),
        },
        session_id: "99999:abc".into(),
        identity: None,
        policy: Some("custom-policy-v2".into()),
        action: AgenticAction::Prompt {
            provider: "Anthropic".into(),
            model: Some("claude-3-opus".into()),
            user_message: Some("Hello world".into()),
            system_prompt: Some("You are a helpful assistant".into()),
            stream: false,
            sdk: Some("anthropic-python/0.25.0".into()),
            bytes: 999_999,
            sni: Some("api.anthropic.com".into()),
            endpoint: Some("/v1/messages".into()),
            fingerprint: Some(0xabc123),
            pii_detected: Some(false),
            confidence: Some(0.98),
            sdk_hash: None,
            model_hash: None,
        },
    };
    let d = engine.evaluate(&event).unwrap();
    // With provider set and pii_detected=false, should be Audit
    assert_eq!(d.action, Action::Audit);
    assert!(!d.reasons.is_empty());
}

// =====================================================================
// Empty string provider vs None (Network action)
// =====================================================================

#[test]
fn default_empty_string_provider() {
    let mut engine = default_engine();

    // provider = Some("") — serde serializes as `"provider": ""`
    // In Rego, "" != null, so _is_llm_traffic fires via input.action.provider != null
    let mut event_empty = bare_event();
    if let AgenticAction::Network {
        ref mut provider, ..
    } = event_empty.action
    {
        *provider = Some(String::new());
    }
    let d_empty = engine.evaluate(&event_empty).unwrap();

    // provider = None — serde skips the field entirely
    let d_none = engine.evaluate(&bare_event()).unwrap();

    // None should be Allow; empty string triggers _is_llm_traffic (provider != null)
    assert_eq!(d_none.action, Action::Allow);
    assert_eq!(
        d_empty.action,
        Action::Audit,
        "empty string provider should still be considered non-null by Rego"
    );
}

// =====================================================================
// u64::MAX bytes — no crash
// =====================================================================

#[test]
fn default_bytes_u64_max_no_crash() {
    let mut engine = default_engine();
    let mut event = bare_event();
    if let AgenticAction::Network { ref mut bytes, .. } = event.action {
        *bytes = u64::MAX;
    }
    let d = engine.evaluate(&event).unwrap();
    // No provider, so should still be Allow regardless of byte count
    assert_eq!(d.action, Action::Allow);

    // Also test with provider to ensure audit path handles large bytes
    if let AgenticAction::Network {
        ref mut provider, ..
    } = event.action
    {
        *provider = Some("OpenAI".into());
    }
    let d2 = engine.evaluate(&event).unwrap();
    assert_eq!(d2.action, Action::Audit);
}

// =====================================================================
// Network event without PII fields does not trigger PII deny
// =====================================================================

#[test]
fn default_allows_network_event_regardless_of_pii_absence() {
    let mut engine = default_engine();
    // Network events have no pii_detected field; provider alone should audit, not deny
    let event = network_event_with_provider("OpenAI");
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
}

// =====================================================================
// McpResponse action
// =====================================================================

#[test]
fn default_allows_mcp_response_without_provider() {
    let mut engine = default_engine();
    let event = BustedEvent {
        timestamp: "00:00:00.000".into(),
        process: ProcessInfo {
            pid: 1,
            uid: 0,
            name: "mcp-client".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1:mcp".into(),
        identity: None,
        policy: None,
        action: AgenticAction::McpResponse {
            method: "tools/list".into(),
            result_preview: None,
        },
    };
    let d = engine.evaluate(&event).unwrap();
    // McpResponse has method field, which triggers the MCP reason and _is_llm_traffic
    // is not triggered (no provider, not Prompt, not McpRequest)
    // But method field triggers the reason rule since input.action.method != null
    // However _is_llm_traffic only checks McpRequest type, not McpResponse
    // So this should be Allow (method reason fires but no _is_llm_traffic match for decision)
    assert_eq!(d.action, Action::Allow);
}

// =====================================================================
// ToolCall action has provider — should audit
// =====================================================================

#[test]
fn default_audits_toolcall_with_provider() {
    let mut engine = default_engine();
    let event = BustedEvent {
        timestamp: "00:00:00.000".into(),
        process: ProcessInfo {
            pid: 1,
            uid: 0,
            name: "agent".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1:tool".into(),
        identity: None,
        policy: None,
        action: AgenticAction::ToolCall {
            tool_name: "search".into(),
            input_json: None,
            provider: "OpenAI".into(),
        },
    };
    let d = engine.evaluate(&event).unwrap();
    // ToolCall has provider field (non-optional String), so _is_llm_traffic fires
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("OpenAI")));
}

// =====================================================================
// Response action has provider — should audit
// =====================================================================

#[test]
fn default_audits_response_with_provider() {
    let mut engine = default_engine();
    let event = BustedEvent {
        timestamp: "00:00:00.000".into(),
        process: ProcessInfo {
            pid: 1,
            uid: 0,
            name: "agent".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1:resp".into(),
        identity: None,
        policy: None,
        action: AgenticAction::Response {
            provider: "Anthropic".into(),
            model: Some("claude-3-opus".into()),
            bytes: 1024,
            sni: None,
            confidence: None,
        },
    };
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("Anthropic")));
}
