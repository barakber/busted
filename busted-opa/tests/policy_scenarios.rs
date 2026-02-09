//! Concrete, real-world policy scenario tests.
//!
//! Each test represents a realistic deployment scenario that a user might
//! configure via Rego policies + data.json, demonstrating the kinds of
//! rules the engine supports.

use busted_opa::{Action, PolicyEngine};
use busted_types::processed::ProcessedEvent;
use std::io::Write;
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bare_event() -> ProcessedEvent {
    ProcessedEvent {
        event_type: "TCP_CONNECT".into(),
        timestamp: "12:00:00.000".into(),
        pid: 1000,
        uid: 1000,
        process_name: "python3".into(),
        src_ip: "10.0.0.5".into(),
        src_port: 45000,
        dst_ip: "104.18.1.1".into(),
        dst_port: 443,
        bytes: 1024,
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
    }
}

fn write_rego(dir: &Path, filename: &str, content: &str) {
    let path = dir.join(filename);
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

fn engine_with(rego: &str) -> (tempfile::TempDir, PolicyEngine) {
    let dir = tempfile::tempdir().unwrap();
    write_rego(dir.path(), "policy.rego", rego);
    let engine = PolicyEngine::new(dir.path()).unwrap();
    (dir, engine)
}

fn engine_with_data(rego: &str, data: &str) -> (tempfile::TempDir, PolicyEngine) {
    let dir = tempfile::tempdir().unwrap();
    write_rego(dir.path(), "policy.rego", rego);
    std::fs::write(dir.path().join("data.json"), data).unwrap();
    let engine = PolicyEngine::new(dir.path()).unwrap();
    (dir, engine)
}

// =====================================================================
// Scenario 1: Provider allowlist — only approved LLM providers
// =====================================================================

#[test]
fn scenario_provider_allowlist() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "deny"

decision = "allow" {
    input.provider == data.approved_providers[_]
}

decision = "allow" {
    input.provider == null
}

reasons[r] {
    input.provider != null
    not provider_approved
    r := concat("", ["Unapproved LLM provider: ", input.provider])
}

provider_approved {
    input.provider == data.approved_providers[_]
}
"#,
        r#"{"approved_providers": ["OpenAI", "Anthropic"]}"#,
    );

    // Approved providers pass
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    event.provider = Some("Anthropic".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Unapproved provider is denied
    event.provider = Some("DeepSeek".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("Unapproved")));

    // Non-LLM traffic (no provider) passes
    let d = engine.evaluate(&bare_event()).unwrap();
    assert_eq!(d.action, Action::Allow);
}

// =====================================================================
// Scenario 2: Namespace-gated — deny LLM access from production
// =====================================================================

#[test]
fn scenario_deny_llm_from_production() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.provider != null
    input.pod_namespace == "production"
}

decision = "audit" {
    input.provider != null
    input.pod_namespace != "production"
}

reasons[r] {
    input.provider != null
    input.pod_namespace == "production"
    r := "LLM access denied in production namespace"
}
"#,
    );

    // Production namespace + provider → deny
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.pod_namespace = Some("production".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("production")));

    // Staging namespace + provider → audit
    event.pod_namespace = Some("staging".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Audit);

    // No namespace + provider → audit
    event.pod_namespace = None;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Audit);

    // No provider at all → allow
    assert_eq!(
        engine.evaluate(&bare_event()).unwrap().action,
        Action::Allow
    );
}

// =====================================================================
// Scenario 3: Process name restrictions — only approved binaries
// =====================================================================

#[test]
fn scenario_process_allowlist() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.provider != null
    not approved_process
}

approved_process {
    input.process_name == data.allowed_processes[_]
}

reasons[r] {
    input.provider != null
    not approved_process
    r := concat("", ["Process '", input.process_name, "' is not authorized for LLM access"])
}
"#,
        r#"{"allowed_processes": ["llm-agent", "chatbot-svc", "python3"]}"#,
    );

    // Approved process + provider → allow
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.process_name = "llm-agent".into();
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    event.process_name = "python3".into();
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Unapproved process + provider → deny
    event.process_name = "curl".into();
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("curl")));

    // No provider → allow regardless
    let mut event2 = bare_event();
    event2.process_name = "curl".into();
    assert_eq!(engine.evaluate(&event2).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 4: MCP tool call restrictions
// =====================================================================

#[test]
fn scenario_mcp_tool_restrictions() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.mcp_method != null
    input.mcp_method == data.blocked_methods[_]
}

decision = "audit" {
    input.mcp_method != null
    not method_blocked
}

method_blocked {
    input.mcp_method == data.blocked_methods[_]
}

reasons[r] {
    input.mcp_method != null
    method_blocked
    r := concat("", ["Blocked MCP method: ", input.mcp_method])
}
"#,
        r#"{"blocked_methods": ["tools/call", "resources/write"]}"#,
    );

    // tools/call is blocked
    let mut event = bare_event();
    event.mcp_method = Some("tools/call".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("tools/call")));

    // resources/write is blocked
    event.mcp_method = Some("resources/write".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    // tools/list is allowed (just audited)
    event.mcp_method = Some("tools/list".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Audit);

    // No MCP method → allow
    assert_eq!(
        engine.evaluate(&bare_event()).unwrap().action,
        Action::Allow
    );
}

// =====================================================================
// Scenario 5: Rate limiting — high request rate audit
// =====================================================================

#[test]
fn scenario_rate_audit() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "audit" {
    input.request_rate > 100
}

reasons[r] {
    input.request_rate > 100
    r := "High request rate detected"
}
"#,
    );

    let mut event = bare_event();
    event.request_rate = Some(150.0);
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("rate")));

    event.request_rate = Some(50.0);
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    event.request_rate = None;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 6: Container-based restrictions
// =====================================================================

#[test]
fn scenario_container_allowlist() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.provider != null
    input.container_id != ""
    not container_approved
}

container_approved {
    startswith(input.container_id, data.approved_container_prefixes[_])
}
"#,
        r#"{"approved_container_prefixes": ["abc123", "def456"]}"#,
    );

    // Approved container
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.container_id = "abc123deadbeef".into();
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Unapproved container
    event.container_id = "xyz789badcafe".into();
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    // No container (bare metal) → allow (container_id is "")
    event.container_id = String::new();
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 7: Model restrictions — block specific models
// =====================================================================

#[test]
fn scenario_model_blocklist() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.llm_model == data.blocked_models[_]
}

reasons[r] {
    input.llm_model == data.blocked_models[_]
    r := concat("", ["Blocked model: ", input.llm_model])
}
"#,
        r#"{"blocked_models": ["gpt-4o", "claude-3-opus"]}"#,
    );

    let mut event = bare_event();
    event.llm_model = Some("gpt-4o".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("gpt-4o")));

    event.llm_model = Some("claude-3-opus".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    event.llm_model = Some("gpt-3.5-turbo".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    event.llm_model = None;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 8: Combined rule — deny PII + audit everything else
// =====================================================================

#[test]
fn scenario_pii_deny_else_audit() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.pii_detected == true
    input.provider != null
}

decision = "audit" {
    input.provider != null
    not input.pii_detected
}

reasons[r] {
    input.pii_detected == true
    input.provider != null
    r := "PII in LLM traffic"
}

reasons[r] {
    input.provider != null
    not input.pii_detected
    r := concat("", ["Auditing LLM traffic to ", input.provider])
}
"#,
    );

    // PII + provider → deny
    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.pii_detected = Some(true);
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("PII")));

    // Provider only → audit
    event.pii_detected = None;
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("Auditing")));

    // Nothing → allow
    assert_eq!(
        engine.evaluate(&bare_event()).unwrap().action,
        Action::Allow
    );
}

// =====================================================================
// Scenario 9: UID-based restrictions
// =====================================================================

#[test]
fn scenario_uid_restrictions() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

# Root processes should not be calling LLMs
decision = "deny" {
    input.uid == 0
    input.provider != null
}

# UID 65534 (nobody) should not access LLMs
decision = "deny" {
    input.uid == 65534
    input.provider != null
}

reasons[r] {
    input.uid == 0
    input.provider != null
    r := "Root process accessing LLM API"
}
"#,
    );

    // Root + provider → deny
    let mut event = bare_event();
    event.uid = 0;
    event.provider = Some("OpenAI".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("Root")));

    // nobody + provider → deny
    event.uid = 65534;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    // Normal user + provider → allow
    event.uid = 1000;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Root but no provider → allow
    event.uid = 0;
    event.provider = None;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 10: Bytes threshold — deny large payloads to LLMs
// =====================================================================

#[test]
fn scenario_bytes_threshold() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.provider != null
    input.bytes > 1048576
}

reasons[r] {
    input.provider != null
    input.bytes > 1048576
    r := "Payload exceeds 1MB limit for LLM traffic"
}
"#,
    );

    let mut event = bare_event();
    event.provider = Some("OpenAI".into());

    // Small payload → allow
    event.bytes = 1024;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Exactly 1MB → allow
    event.bytes = 1_048_576;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Over 1MB → deny
    event.bytes = 1_048_577;
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("1MB")));
}

// =====================================================================
// Scenario 11: SDK fingerprint restrictions
// =====================================================================

#[test]
fn scenario_sdk_restrictions() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.agent_sdk != null
    not sdk_approved
}

sdk_approved {
    input.agent_sdk == data.approved_sdks[_]
}

reasons[r] {
    input.agent_sdk != null
    not sdk_approved
    r := concat("", ["Unapproved SDK: ", input.agent_sdk])
}
"#,
        r#"{"approved_sdks": ["openai-python/1.12.0", "anthropic-python/0.25.0"]}"#,
    );

    let mut event = bare_event();
    event.agent_sdk = Some("openai-python/1.12.0".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    event.agent_sdk = Some("unknown-sdk/0.1.0".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("unknown-sdk")));

    // No SDK → allow
    event.agent_sdk = None;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 12: SNI-based routing
// =====================================================================

#[test]
fn scenario_sni_based_policy() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.sni != null
    input.sni == data.blocked_hosts[_]
}
"#,
        r#"{"blocked_hosts": ["api.deepseek.com", "api.together.xyz"]}"#,
    );

    let mut event = bare_event();
    event.sni = Some("api.deepseek.com".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    event.sni = Some("api.together.xyz".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    event.sni = Some("api.openai.com".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    event.sni = None;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 13: Port-based restrictions
// =====================================================================

#[test]
fn scenario_non_standard_port_audit() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "audit" {
    input.provider != null
    input.dst_port != 443
}

reasons[r] {
    input.provider != null
    input.dst_port != 443
    r := "LLM traffic on non-standard port"
}
"#,
    );

    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.dst_port = 8443;
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("non-standard")));

    event.dst_port = 443;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 14: ML confidence threshold for audit
// =====================================================================

#[test]
fn scenario_ml_confidence_threshold() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "audit" {
    input.ml_confidence > 0.8
    input.ml_provider != null
}

reasons[r] {
    input.ml_confidence > 0.8
    input.ml_provider != null
    r := concat("", ["ML detected LLM traffic to ", input.ml_provider, " with high confidence"])
}
"#,
    );

    let mut event = bare_event();
    event.ml_confidence = Some(0.95);
    event.ml_provider = Some("OpenAI".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("ML detected")));

    // Low confidence → allow
    event.ml_confidence = Some(0.5);
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 15: Service account restrictions in Kubernetes
// =====================================================================

#[test]
fn scenario_service_account_restrictions() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.provider != null
    input.service_account != null
    not sa_approved
}

sa_approved {
    input.service_account == data.approved_service_accounts[_]
}
"#,
        r#"{"approved_service_accounts": ["llm-gateway", "ai-proxy"]}"#,
    );

    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.service_account = Some("llm-gateway".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    event.service_account = Some("random-svc".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    // No service account → allow (not in k8s)
    event.service_account = None;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 16: Multiple .rego files working together
// =====================================================================

#[test]
fn scenario_split_policy_files() {
    let dir = tempfile::tempdir().unwrap();

    // File 1: base decision logic
    write_rego(
        dir.path(),
        "01_base.rego",
        r#"
package busted
default decision = "allow"
decision = "deny" {
    input.pii_detected == true
    input.provider != null
}
"#,
    );

    // File 2: reason annotations
    write_rego(
        dir.path(),
        "02_reasons.rego",
        r#"
package busted
reasons[r] {
    input.pii_detected == true
    input.provider != null
    r := "PII found — blocked by base policy"
}
reasons[r] {
    input.provider != null
    r := concat("", ["Provider: ", input.provider])
}
"#,
    );

    let mut engine = PolicyEngine::new(dir.path()).unwrap();

    let mut event = bare_event();
    event.provider = Some("OpenAI".into());
    event.pii_detected = Some(true);
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.len() >= 2);
    assert!(d.reasons.iter().any(|r| r.contains("PII")));
    assert!(d.reasons.iter().any(|r| r.contains("OpenAI")));
}

// =====================================================================
// Scenario 17: Complex data.json with nested structures
// =====================================================================

#[test]
fn scenario_complex_data_structure() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    rule := data.rules[_]
    rule.action == "deny"
    input.provider == rule.provider
    input.pod_namespace == rule.namespace
}

reasons[r] {
    rule := data.rules[_]
    rule.action == "deny"
    input.provider == rule.provider
    input.pod_namespace == rule.namespace
    r := concat("", ["Rule: deny ", rule.provider, " in ", rule.namespace])
}
"#,
        r#"{
    "rules": [
        {"action": "deny", "provider": "DeepSeek", "namespace": "production"},
        {"action": "deny", "provider": "OpenAI", "namespace": "restricted"}
    ]
}"#,
    );

    let mut event = bare_event();
    event.provider = Some("DeepSeek".into());
    event.pod_namespace = Some("production".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d
        .reasons
        .iter()
        .any(|r| r.contains("DeepSeek") && r.contains("production")));

    // Same provider, different namespace → allow
    event.pod_namespace = Some("staging".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Different provider, matching namespace → allow
    event.provider = Some("OpenAI".into());
    event.pod_namespace = Some("production".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // OpenAI in restricted → deny
    event.pod_namespace = Some("restricted".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);
}
