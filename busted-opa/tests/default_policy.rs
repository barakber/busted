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
