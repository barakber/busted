//! Tests for the shipped `policies/default.rego`.
//!
//! These verify that the default policy behaves as documented:
//! - Allow all traffic by default
//! - Audit traffic to known LLM providers
//! - Deny traffic with PII in LLM payloads
//! - Reasons explain what triggered the decision

use busted_opa::{Action, PolicyEngine};
use busted_types::processed::ProcessedEvent;

fn default_engine() -> PolicyEngine {
    let policy_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policies");
    PolicyEngine::new(&policy_dir).expect("default policy should load")
}

fn bare_event() -> ProcessedEvent {
    ProcessedEvent {
        event_type: "TCP_SENDMSG".into(),
        timestamp: "00:00:00.000".into(),
        pid: 1,
        uid: 0,
        process_name: "nginx".into(),
        src_ip: "10.0.0.1".into(),
        src_port: 80,
        dst_ip: "10.0.0.2".into(),
        dst_port: 8080,
        bytes: 64,
        provider: None,
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
    event.dst_port = 443;
    event.bytes = 4096;
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Allow);
}

#[test]
fn default_allows_pii_without_provider() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.pii_detected = Some(true);
    // No provider, no llm_provider, no content_class — not LLM traffic
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Allow);
}

// =====================================================================
// Audit: provider detected (IP/SNI)
// =====================================================================

#[test]
fn default_audits_provider_openai() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
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
    let mut event = bare_event();
    event.provider = Some("Anthropic".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("Anthropic")));
}

#[test]
fn default_audits_provider_google() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.provider = Some("Google".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
}

#[test]
fn default_audits_provider_deepseek() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.provider = Some("DeepSeek".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
}

// =====================================================================
// Audit: llm_provider detected (content classification)
// =====================================================================

#[test]
fn default_audits_llm_provider_from_classifier() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.llm_provider = Some("Mistral".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("Mistral")));
}

// =====================================================================
// Audit: content_class == "LlmApi"
// =====================================================================

#[test]
fn default_audits_content_class_llmapi() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.content_class = Some("LlmApi".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
}

#[test]
fn default_allows_content_class_generic_http() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.content_class = Some("GenericHttp".into());
    let d = engine.evaluate(&event).unwrap();
    // GenericHttp is not LLM traffic
    assert_eq!(d.action, Action::Allow);
}

// =====================================================================
// Deny: PII in LLM traffic
// =====================================================================

#[test]
fn default_denies_pii_with_provider() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.pii_detected = Some(true);
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(
        d.reasons.iter().any(|r| r.contains("PII")),
        "reasons should mention PII: {:?}",
        d.reasons
    );
}

#[test]
fn default_denies_pii_with_llm_provider() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.llm_provider = Some("Anthropic".into());
    event.pii_detected = Some(true);
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("PII")));
}

#[test]
fn default_denies_pii_with_content_class_llmapi() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.content_class = Some("LlmApi".into());
    event.pii_detected = Some(true);
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
}

#[test]
fn default_pii_false_does_not_deny() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.pii_detected = Some(false);
    let d = engine.evaluate(&event).unwrap();
    // pii_detected == false is NOT the same as true
    assert_eq!(d.action, Action::Audit);
}

#[test]
fn default_pii_null_does_not_deny() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.pii_detected = None;
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
}

// =====================================================================
// MCP-specific reasons
// =====================================================================

#[test]
fn default_mcp_method_in_reasons() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.mcp_method = Some("tools/call".into());
    let d = engine.evaluate(&event).unwrap();
    assert!(
        d.reasons.iter().any(|r| r.contains("tools/call")),
        "reasons should mention MCP method: {:?}",
        d.reasons
    );
}

#[test]
fn default_mcp_without_provider_is_allowed() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.mcp_method = Some("tools/list".into());
    // No provider, no llm_provider, no LlmApi content_class
    let d = engine.evaluate(&event).unwrap();
    // MCP method alone doesn't make it LLM traffic in the default policy
    assert_eq!(d.action, Action::Allow);
}

// =====================================================================
// Reason content: verify dynamic string interpolation
// =====================================================================

#[test]
fn default_reason_provider_string_interpolated() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.provider = Some("Groq".into());
    let d = engine.evaluate(&event).unwrap();
    assert!(d
        .reasons
        .iter()
        .any(|r| r == "Traffic to LLM provider: Groq"));
}

#[test]
fn default_reason_llm_provider_string_interpolated() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.llm_provider = Some("Cohere".into());
    let d = engine.evaluate(&event).unwrap();
    assert!(d
        .reasons
        .iter()
        .any(|r| r == "Content classified as LLM API call to: Cohere"));
}

// =====================================================================
// Both provider and llm_provider set
// =====================================================================

#[test]
fn default_both_provider_and_llm_provider_audits_with_both_reasons() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.llm_provider = Some("OpenAI".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    // Should have both reason strings
    assert!(d
        .reasons
        .iter()
        .any(|r| r.contains("Traffic to LLM provider")));
    assert!(d
        .reasons
        .iter()
        .any(|r| r.contains("Content classified as LLM API call")));
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
// content_class "Mcp" behavior with default.rego
// =====================================================================

#[test]
fn default_audits_content_class_mcp() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.content_class = Some("Mcp".into());
    let d = engine.evaluate(&event).unwrap();
    // "Mcp" is NOT "LlmApi", so _is_llm_traffic is not triggered by content_class alone.
    // Without provider or llm_provider, this should be Allow.
    assert_eq!(d.action, Action::Allow);
}

// =====================================================================
// content_class "LlmStream" behavior with default.rego
// =====================================================================

#[test]
fn default_audits_content_class_llm_stream() {
    let mut engine = default_engine();
    let mut event = bare_event();
    event.content_class = Some("LlmStream".into());
    let d = engine.evaluate(&event).unwrap();
    // "LlmStream" is NOT "LlmApi", so _is_llm_traffic is not triggered by content_class alone.
    // Without provider or llm_provider, this should be Allow.
    assert_eq!(d.action, Action::Allow);
}

// =====================================================================
// All fields populated — no crash
// =====================================================================

#[test]
fn default_all_fields_populated_no_crash() {
    let mut engine = default_engine();
    let event = ProcessedEvent {
        event_type: "TLS_DATA_WRITE".into(),
        timestamp: "23:59:59.999".into(),
        pid: 99999,
        uid: 65534,
        process_name: "full-test-binary".into(),
        src_ip: "192.168.100.200".into(),
        src_port: 60000,
        dst_ip: "203.0.113.50".into(),
        dst_port: 8443,
        bytes: 999_999,
        provider: Some("Anthropic".into()),
        policy: Some("custom-policy-v2".into()),
        container_id: "abc123def456".into(),
        cgroup_id: 12345678,
        request_rate: Some(42.5),
        session_bytes: Some(1_000_000),
        pod_name: Some("ai-gateway-pod-xyz".into()),
        pod_namespace: Some("ml-production".into()),
        service_account: Some("ai-service-account".into()),
        ml_confidence: Some(0.99),
        ml_provider: Some("Anthropic".into()),
        behavior_class: Some("llm_api_call".into()),
        cluster_id: Some(7),
        sni: Some("api.anthropic.com".into()),
        tls_protocol: Some("TLSv1.3".into()),
        tls_details: Some("ECDHE-RSA-AES256-GCM-SHA384".into()),
        tls_payload: Some("POST /v1/messages HTTP/1.1".into()),
        content_class: Some("LlmApi".into()),
        llm_provider: Some("Anthropic".into()),
        llm_endpoint: Some("/v1/messages".into()),
        llm_model: Some("claude-3-opus".into()),
        mcp_method: Some("tools/call".into()),
        mcp_category: Some("tool_execution".into()),
        agent_sdk: Some("anthropic-python/0.25.0".into()),
        agent_fingerprint: Some(0xabc123),
        classifier_confidence: Some(0.98),
        pii_detected: Some(false),
        llm_user_message: Some("Hello world".into()),
        llm_system_prompt: Some("You are a helpful assistant".into()),
        llm_messages_json: Some(r#"[{"role":"user","content":"hi"}]"#.into()),
        llm_stream: Some(false),
        identity_id: None,
        identity_instance: None,
        identity_confidence: None,
        identity_narrative: None,
        identity_timeline: None,
        identity_timeline_len: None,
        agent_sdk_hash: None,
        agent_model_hash: None,
    };
    let d = engine.evaluate(&event).unwrap();
    // With provider set and pii_detected=false, should be Audit
    assert_eq!(d.action, Action::Audit);
    assert!(!d.reasons.is_empty());
}

// =====================================================================
// Empty string provider vs None
// =====================================================================

#[test]
fn default_empty_string_provider() {
    let mut engine = default_engine();

    // provider = Some("") — serde serializes as `"provider": ""`
    // In Rego, "" != null, so _is_llm_traffic fires via input.provider != null
    let mut event_empty = bare_event();
    event_empty.provider = Some(String::new());
    let d_empty = engine.evaluate(&event_empty).unwrap();

    // provider = None — serde serializes as `"provider": null`
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
    event.bytes = u64::MAX;
    let d = engine.evaluate(&event).unwrap();
    // No provider, so should still be Allow regardless of byte count
    assert_eq!(d.action, Action::Allow);

    // Also test with provider to ensure audit path handles large bytes
    event.provider = Some("OpenAI".into());
    let d2 = engine.evaluate(&event).unwrap();
    assert_eq!(d2.action, Action::Audit);
}
