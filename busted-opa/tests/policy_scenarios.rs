//! Concrete, real-world policy scenario tests.
//!
//! Each test represents a realistic deployment scenario that a user might
//! configure via Rego policies + data.json, demonstrating the kinds of
//! rules the engine supports.

use busted_opa::{Action, PolicyEngine};
use busted_types::agentic::{
    AgenticAction, BustedEvent, IdentityInfo, NetworkEventKind, ProcessInfo,
};
use std::io::Write;
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal Network event: no provider, pure background traffic.
fn bare_event() -> BustedEvent {
    BustedEvent {
        timestamp: "12:00:00.000".into(),
        process: ProcessInfo {
            pid: 1000,
            uid: 1000,
            name: "python3".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1000:net".into(),
        identity: None,
        policy: None,
        action: AgenticAction::Network {
            kind: NetworkEventKind::Connect,
            src_ip: "10.0.0.5".into(),
            src_port: 45000,
            dst_ip: "104.18.1.1".into(),
            dst_port: 443,
            bytes: 1024,
            sni: None,
            provider: None,
        },
    }
}

/// Network event with a specific provider.
fn network_event(prov: &str) -> BustedEvent {
    let mut event = bare_event();
    if let AgenticAction::Network {
        ref mut provider, ..
    } = event.action
    {
        *provider = Some(prov.into());
    }
    event
}

/// Prompt event for PII/model/SDK tests.
fn prompt_event(provider: &str) -> BustedEvent {
    BustedEvent {
        timestamp: "12:00:00.000".into(),
        process: ProcessInfo {
            pid: 1000,
            uid: 1000,
            name: "python3".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1000:abc".into(),
        identity: None,
        policy: None,
        action: AgenticAction::Prompt {
            provider: provider.into(),
            model: None,
            user_message: None,
            system_prompt: None,
            stream: false,
            sdk: None,
            bytes: 1024,
            sni: None,
            endpoint: None,
            fingerprint: None,
            pii_detected: None,
            confidence: None,
            sdk_hash: None,
            model_hash: None,
        },
    }
}

/// McpRequest event.
fn mcp_event(method: &str) -> BustedEvent {
    BustedEvent {
        timestamp: "12:00:00.000".into(),
        process: ProcessInfo {
            pid: 1000,
            uid: 1000,
            name: "mcp-client".into(),
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
        },
        session_id: "1000:mcp".into(),
        identity: None,
        policy: None,
        action: AgenticAction::McpRequest {
            method: method.into(),
            category: None,
            params_preview: None,
        },
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
    input.action.provider == data.approved_providers[_]
}

decision = "allow" {
    not input.action.provider
}

reasons[r] {
    input.action.provider != null
    not provider_approved
    r := concat("", ["Unapproved LLM provider: ", input.action.provider])
}

provider_approved {
    input.action.provider == data.approved_providers[_]
}
"#,
        r#"{"approved_providers": ["OpenAI", "Anthropic"]}"#,
    );

    // Approved providers pass
    let event = network_event("OpenAI");
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    let event = network_event("Anthropic");
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Unapproved provider is denied
    let event = network_event("DeepSeek");
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
    input.action.provider
    is_production
}

decision = "audit" {
    input.action.provider
    not is_production
}

is_production {
    input.process.pod_namespace == "production"
}

reasons[r] {
    input.action.provider
    is_production
    r := "LLM access denied in production namespace"
}
"#,
    );

    // Production namespace + provider -> deny
    let mut event = network_event("OpenAI");
    event.process.pod_namespace = Some("production".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("production")));

    // Staging namespace + provider -> audit
    event.process.pod_namespace = Some("staging".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Audit);

    // No namespace + provider -> audit
    event.process.pod_namespace = None;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Audit);

    // No provider at all -> allow
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
    input.action.provider != null
    not approved_process
}

approved_process {
    input.process.name == data.allowed_processes[_]
}

reasons[r] {
    input.action.provider != null
    not approved_process
    r := concat("", ["Process '", input.process.name, "' is not authorized for LLM access"])
}
"#,
        r#"{"allowed_processes": ["llm-agent", "chatbot-svc", "python3"]}"#,
    );

    // Approved process + provider -> allow
    let mut event = network_event("OpenAI");
    event.process.name = "llm-agent".into();
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    event.process.name = "python3".into();
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Unapproved process + provider -> deny
    event.process.name = "curl".into();
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("curl")));

    // No provider -> allow regardless
    let mut event2 = bare_event();
    event2.process.name = "curl".into();
    assert_eq!(engine.evaluate(&event2).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 4: MCP method restrictions
// =====================================================================

#[test]
fn scenario_mcp_method_restrictions() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.action.method != null
    input.action.method == data.blocked_methods[_]
}

decision = "audit" {
    input.action.method != null
    not method_blocked
}

method_blocked {
    input.action.method == data.blocked_methods[_]
}

reasons[r] {
    input.action.method != null
    method_blocked
    r := concat("", ["Blocked MCP method: ", input.action.method])
}
"#,
        r#"{"blocked_methods": ["tools/call", "resources/write"]}"#,
    );

    // tools/call is blocked
    let event = mcp_event("tools/call");
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("tools/call")));

    // resources/write is blocked
    let event = mcp_event("resources/write");
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    // tools/list is allowed (just audited)
    let event = mcp_event("tools/list");
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Audit);

    // No MCP method (bare Network event) -> allow
    assert_eq!(
        engine.evaluate(&bare_event()).unwrap().action,
        Action::Allow
    );
}

// =====================================================================
// Scenario 5: Bytes threshold — deny large payloads to LLMs
// =====================================================================

#[test]
fn scenario_bytes_threshold() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.action.provider != null
    input.action.bytes > 1048576
}

reasons[r] {
    input.action.provider != null
    input.action.bytes > 1048576
    r := "Payload exceeds 1MB limit for LLM traffic"
}
"#,
    );

    let mut event = network_event("OpenAI");

    // Small payload -> allow
    if let AgenticAction::Network { ref mut bytes, .. } = event.action {
        *bytes = 1024;
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Exactly 1MB -> allow
    if let AgenticAction::Network { ref mut bytes, .. } = event.action {
        *bytes = 1_048_576;
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Over 1MB -> deny
    if let AgenticAction::Network { ref mut bytes, .. } = event.action {
        *bytes = 1_048_577;
    }
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("1MB")));
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
    input.action.provider != null
    input.process.container_id != ""
    not container_approved
}

container_approved {
    startswith(input.process.container_id, data.approved_container_prefixes[_])
}
"#,
        r#"{"approved_container_prefixes": ["abc123", "def456"]}"#,
    );

    // Approved container
    let mut event = network_event("OpenAI");
    event.process.container_id = "abc123deadbeef".into();
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Unapproved container
    event.process.container_id = "xyz789badcafe".into();
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    // No container (bare metal) -> allow (container_id is "" which is skipped by serde)
    // But the Rego checks input.process.container_id != "" which will be false since
    // the field is absent (skip_serializing_if = "String::is_empty").
    // Absent field in Rego is treated as undefined, not as "".
    // So the deny rule body fails at the second condition.
    event.process.container_id = String::new();
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 7: Model restrictions — block specific models (Prompt action)
// =====================================================================

#[test]
fn scenario_model_blocklist() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.action.model == data.blocked_models[_]
}

reasons[r] {
    input.action.model == data.blocked_models[_]
    r := concat("", ["Blocked model: ", input.action.model])
}
"#,
        r#"{"blocked_models": ["gpt-4o", "claude-3-opus"]}"#,
    );

    let mut event = prompt_event("OpenAI");
    if let AgenticAction::Prompt { ref mut model, .. } = event.action {
        *model = Some("gpt-4o".into());
    }
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("gpt-4o")));

    if let AgenticAction::Prompt { ref mut model, .. } = event.action {
        *model = Some("claude-3-opus".into());
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    if let AgenticAction::Prompt { ref mut model, .. } = event.action {
        *model = Some("gpt-3.5-turbo".into());
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    if let AgenticAction::Prompt { ref mut model, .. } = event.action {
        *model = None;
    }
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
    input.action.pii_detected == true
    input.action.provider != null
}

decision = "audit" {
    input.action.provider != null
    not input.action.pii_detected
}

reasons[r] {
    input.action.pii_detected == true
    input.action.provider != null
    r := "PII in LLM traffic"
}

reasons[r] {
    input.action.provider != null
    not input.action.pii_detected
    r := concat("", ["Auditing LLM traffic to ", input.action.provider])
}
"#,
    );

    // PII + provider -> deny
    let mut event = prompt_event("OpenAI");
    if let AgenticAction::Prompt {
        ref mut pii_detected,
        ..
    } = event.action
    {
        *pii_detected = Some(true);
    }
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("PII")));

    // Provider only (no PII) -> audit
    if let AgenticAction::Prompt {
        ref mut pii_detected,
        ..
    } = event.action
    {
        *pii_detected = None;
    }
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("Auditing")));

    // Nothing -> allow
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
    input.process.uid == 0
    input.action.provider != null
}

# UID 65534 (nobody) should not access LLMs
decision = "deny" {
    input.process.uid == 65534
    input.action.provider != null
}

reasons[r] {
    input.process.uid == 0
    input.action.provider != null
    r := "Root process accessing LLM API"
}
"#,
    );

    // Root + provider -> deny
    let mut event = network_event("OpenAI");
    event.process.uid = 0;
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("Root")));

    // nobody + provider -> deny
    event.process.uid = 65534;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    // Normal user + provider -> allow
    event.process.uid = 1000;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Root but no provider -> allow
    let mut event2 = bare_event();
    event2.process.uid = 0;
    assert_eq!(engine.evaluate(&event2).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 10: SDK restrictions (Prompt action)
// =====================================================================

#[test]
fn scenario_sdk_restrictions() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.action.sdk != null
    not sdk_approved
}

sdk_approved {
    input.action.sdk == data.approved_sdks[_]
}

reasons[r] {
    input.action.sdk != null
    not sdk_approved
    r := concat("", ["Unapproved SDK: ", input.action.sdk])
}
"#,
        r#"{"approved_sdks": ["openai-python/1.12.0", "anthropic-python/0.25.0"]}"#,
    );

    let mut event = prompt_event("OpenAI");
    if let AgenticAction::Prompt { ref mut sdk, .. } = event.action {
        *sdk = Some("openai-python/1.12.0".into());
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    if let AgenticAction::Prompt { ref mut sdk, .. } = event.action {
        *sdk = Some("unknown-sdk/0.1.0".into());
    }
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("unknown-sdk")));

    // No SDK -> allow
    if let AgenticAction::Prompt { ref mut sdk, .. } = event.action {
        *sdk = None;
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 11: SNI-based routing (Network action)
// =====================================================================

#[test]
fn scenario_sni_based_policy() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.action.sni != null
    input.action.sni == data.blocked_hosts[_]
}
"#,
        r#"{"blocked_hosts": ["api.deepseek.com", "api.together.xyz"]}"#,
    );

    let mut event = bare_event();
    if let AgenticAction::Network { ref mut sni, .. } = event.action {
        *sni = Some("api.deepseek.com".into());
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    if let AgenticAction::Network { ref mut sni, .. } = event.action {
        *sni = Some("api.together.xyz".into());
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    if let AgenticAction::Network { ref mut sni, .. } = event.action {
        *sni = Some("api.openai.com".into());
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    if let AgenticAction::Network { ref mut sni, .. } = event.action {
        *sni = None;
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 12: Port-based restrictions
// =====================================================================

#[test]
fn scenario_non_standard_port_audit() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "audit" {
    input.action.provider != null
    input.action.dst_port != 443
}

reasons[r] {
    input.action.provider != null
    input.action.dst_port != 443
    r := "LLM traffic on non-standard port"
}
"#,
    );

    let mut event = network_event("OpenAI");
    if let AgenticAction::Network {
        ref mut dst_port, ..
    } = event.action
    {
        *dst_port = 8443;
    }
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("non-standard")));

    if let AgenticAction::Network {
        ref mut dst_port, ..
    } = event.action
    {
        *dst_port = 443;
    }
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 13: Service account restrictions in Kubernetes
// =====================================================================

#[test]
fn scenario_service_account_restrictions() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.action.provider != null
    input.process.service_account != null
    not sa_approved
}

sa_approved {
    input.process.service_account == data.approved_service_accounts[_]
}
"#,
        r#"{"approved_service_accounts": ["llm-gateway", "ai-proxy"]}"#,
    );

    let mut event = network_event("OpenAI");
    event.process.service_account = Some("llm-gateway".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    event.process.service_account = Some("random-svc".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

    // No service account -> allow (not in k8s)
    event.process.service_account = None;
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
}

// =====================================================================
// Scenario 14: Multiple .rego files working together
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
    input.action.pii_detected == true
    input.action.provider != null
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
    input.action.pii_detected == true
    input.action.provider != null
    r := "PII found — blocked by base policy"
}
reasons[r] {
    input.action.provider != null
    r := concat("", ["Provider: ", input.action.provider])
}
"#,
    );

    let mut engine = PolicyEngine::new(dir.path()).unwrap();

    let mut event = prompt_event("OpenAI");
    if let AgenticAction::Prompt {
        ref mut pii_detected,
        ..
    } = event.action
    {
        *pii_detected = Some(true);
    }
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.len() >= 2);
    assert!(d.reasons.iter().any(|r| r.contains("PII")));
    assert!(d.reasons.iter().any(|r| r.contains("OpenAI")));
}

// =====================================================================
// Scenario 15: Complex data.json with nested structures
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
    input.action.provider == rule.provider
    input.process.pod_namespace == rule.namespace
}

reasons[r] {
    rule := data.rules[_]
    rule.action == "deny"
    input.action.provider == rule.provider
    input.process.pod_namespace == rule.namespace
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

    let mut event = network_event("DeepSeek");
    event.process.pod_namespace = Some("production".into());
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d
        .reasons
        .iter()
        .any(|r| r.contains("DeepSeek") && r.contains("production")));

    // Same provider, different namespace -> allow
    event.process.pod_namespace = Some("staging".into());
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // Different provider, matching namespace -> allow
    let mut event2 = network_event("OpenAI");
    event2.process.pod_namespace = Some("production".into());
    assert_eq!(engine.evaluate(&event2).unwrap().action, Action::Allow);

    // OpenAI in restricted -> deny
    event2.process.pod_namespace = Some("restricted".into());
    assert_eq!(engine.evaluate(&event2).unwrap().action, Action::Deny);
}

// =====================================================================
// Scenario 16: Array comprehension in Rego
// =====================================================================

#[test]
fn scenario_array_comprehension() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "audit" {
    arr := [x | x := input.action.provider; x != null]
    count(arr) > 0
}

reasons[r] {
    arr := [x | x := input.action.provider; x != null]
    count(arr) > 0
    r := "Provider found via array comprehension"
}
"#,
    );

    // Event with provider -> audit
    let event = network_event("OpenAI");
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Audit);
    assert!(d.reasons.iter().any(|r| r.contains("comprehension")));

    // No provider -> allow
    let d2 = engine.evaluate(&bare_event()).unwrap();
    assert_eq!(d2.action, Action::Allow);
}

// =====================================================================
// Scenario 17: Nested helper rules
// =====================================================================

#[test]
fn scenario_nested_helper_rules() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    _is_sensitive_traffic
}

reasons[r] {
    _is_sensitive_traffic
    r := "Sensitive traffic detected"
}

# Level 1 helper: traffic is sensitive if it has PII and is LLM-bound
_is_sensitive_traffic {
    _is_llm_bound
    _has_pii
}

# Level 2 helper: traffic is LLM-bound
_is_llm_bound {
    _has_provider
}

_is_llm_bound {
    input.action.type == "Prompt"
}

# Level 2 helper: has PII
_has_pii {
    input.action.pii_detected == true
}

# Level 3 helper: has any provider
_has_provider {
    input.action.provider != null
}
"#,
    );

    // PII + provider (Prompt) -> deny (traverses 3 levels of helpers)
    let mut event = prompt_event("OpenAI");
    if let AgenticAction::Prompt {
        ref mut pii_detected,
        ..
    } = event.action
    {
        *pii_detected = Some(true);
    }
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("Sensitive")));

    // PII in Prompt (type == "Prompt" path through _is_llm_bound) -> deny
    // This is the same as above since Prompt also has a provider.

    // Provider (Network) but no PII -> allow
    let event3 = network_event("OpenAI");
    assert_eq!(engine.evaluate(&event3).unwrap().action, Action::Allow);

    // No provider and no PII -> allow
    assert_eq!(
        engine.evaluate(&bare_event()).unwrap().action,
        Action::Allow
    );
}

// =====================================================================
// Scenario 18: Multiple packages — only package busted is evaluated
// =====================================================================

#[test]
fn scenario_multiple_packages_only_busted_evaluated() {
    let dir = tempfile::tempdir().unwrap();

    // File with package busted (this one matters)
    write_rego(
        dir.path(),
        "busted.rego",
        r#"
package busted
default decision = "allow"
decision = "audit" {
    input.action.provider != null
}
"#,
    );

    // File with a different package (should NOT affect data.busted.decision)
    write_rego(
        dir.path(),
        "other.rego",
        r#"
package other_system
default decision = "deny"
decision = "deny" {
    true
}
"#,
    );

    let mut engine = PolicyEngine::new(dir.path()).unwrap();

    // The "other_system" deny should NOT override busted's allow/audit
    let d = engine.evaluate(&bare_event()).unwrap();
    assert_eq!(
        d.action,
        Action::Allow,
        "non-busted package should not affect decision"
    );

    let event = network_event("OpenAI");
    let d2 = engine.evaluate(&event).unwrap();
    assert_eq!(d2.action, Action::Audit, "busted package audit should work");
}

// =====================================================================
// Scenario 19: Special JSON characters in event fields
// =====================================================================

#[test]
fn scenario_special_json_chars_in_fields() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted
default decision = "allow"
decision = "audit" { input.action.provider != null }
reasons[r] { input.action.provider != null; r := concat("", ["Provider: ", input.action.provider]) }
"#,
    );

    // Provider with quotes and backslashes
    let mut event = bare_event();
    if let AgenticAction::Network {
        ref mut provider, ..
    } = event.action
    {
        *provider = Some("Open\"AI\\Test\nLine".into());
    }
    let d = engine.evaluate(&event);
    assert!(d.is_ok(), "special chars should not cause evaluation error");
    assert_eq!(d.unwrap().action, Action::Audit);

    // Process name with special chars
    let mut event2 = network_event("Normal");
    event2.process.name = "my\"proc\\name".into();
    let d2 = engine.evaluate(&event2);
    assert!(d2.is_ok(), "special chars in process_name should not error");
}

// =====================================================================
// Scenario 20: All action variants populated with non-default values
// =====================================================================

#[test]
fn scenario_all_fields_populated() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted
default decision = "allow"
decision = "audit" { input.action.provider != null }
reasons[r] { input.action.provider != null; r := concat("", ["Provider: ", input.action.provider]) }
reasons[r] { input.action.method != null; r := concat("", ["MCP: ", input.action.method]) }
"#,
    );

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
        identity: Some(IdentityInfo {
            id: 42,
            instance: "test-instance".into(),
            confidence: 0.95,
            match_type: Some("exact".into()),
            narrative: Some("Test narrative".into()),
            timeline: None,
            timeline_len: Some(10),
            prompt_fingerprint: Some(0xdeadbeef),
            behavioral_digest: Some(0xcafebabe),
            capability_hash: Some(0x12345678),
            graph_node_count: Some(5),
            graph_edge_count: Some(8),
        }),
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
    assert_eq!(d.action, Action::Audit);
    assert!(
        !d.reasons.is_empty(),
        "should have reasons with all fields set"
    );
}

// =====================================================================
// Scenario 21: Many rapid sequential evaluations
// =====================================================================

#[test]
fn scenario_many_rapid_evaluations() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted
default decision = "allow"
decision = "deny" { input.action.pii_detected == true }
reasons[r] { input.action.pii_detected == true; r := "PII detected" }
"#,
    );

    for i in 0..1000u32 {
        let has_pii = i % 7 == 0;
        let event = if has_pii {
            let mut e = prompt_event("OpenAI");
            e.process.pid = i;
            if let AgenticAction::Prompt {
                ref mut pii_detected,
                ..
            } = e.action
            {
                *pii_detected = Some(true);
            }
            e
        } else {
            let mut e = bare_event();
            e.process.pid = i;
            e
        };
        let d = engine.evaluate(&event).unwrap();
        let expected = if has_pii { Action::Deny } else { Action::Allow };
        assert_eq!(
            d.action, expected,
            "iteration {i}: expected {:?}, got {:?}",
            expected, d.action
        );
    }
}

// =====================================================================
// Scenario 22: Large data.json with 1000 entries
// =====================================================================

#[test]
fn scenario_large_data_json() {
    // Build a data.json with 1000 entries in an array
    let entries: Vec<String> = (0..1000).map(|i| format!("\"provider_{i}\"")).collect();
    let data = format!("{{\"providers\": [{}]}}", entries.join(","));

    let (_dir, mut engine) = engine_with_data(
        r#"
package busted
default decision = "deny"
decision = "allow" {
    input.action.provider == data.providers[_]
}
"#,
        &data,
    );

    // Match a provider in the middle of the list
    let event = network_event("provider_500");
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Allow);

    // Match the last provider
    let event = network_event("provider_999");
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);

    // No match
    let event = network_event("provider_9999");
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);
}

// =====================================================================
// Scenario 23: Set operations in Rego
// =====================================================================

#[test]
fn scenario_set_operations() {
    let (_dir, mut engine) = engine_with_data(
        r#"
package busted

default decision = "allow"

# Collect the set of tags that apply to this event
tags[t] {
    input.action.provider != null
    t := "has_provider"
}
tags[t] {
    input.action.pii_detected == true
    t := "has_pii"
}
tags[t] {
    input.action.method != null
    t := "has_mcp"
}

# Deny if the event has both "has_provider" and "has_pii" in its tag set
decision = "deny" {
    tags["has_provider"]
    tags["has_pii"]
}

# Audit if any tag matches a "watched" tag from data
decision = "audit" {
    watched := data.watched_tags[_]
    tags[watched]
    not tags["has_pii"]
}

reasons[r] {
    tags["has_provider"]
    tags["has_pii"]
    r := "PII with provider detected via set membership"
}
"#,
        r#"{"watched_tags": ["has_provider", "has_mcp"]}"#,
    );

    // Provider + PII (Prompt) -> deny (set intersection: both tags present)
    let mut event = prompt_event("OpenAI");
    if let AgenticAction::Prompt {
        ref mut pii_detected,
        ..
    } = event.action
    {
        *pii_detected = Some(true);
    }
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("set membership")));

    // Provider only (Network) -> audit (watched tag matches)
    let event2 = network_event("OpenAI");
    assert_eq!(engine.evaluate(&event2).unwrap().action, Action::Audit);

    // MCP only -> audit (watched tag matches)
    let event3 = mcp_event("tools/call");
    assert_eq!(engine.evaluate(&event3).unwrap().action, Action::Audit);

    // Nothing -> allow
    assert_eq!(
        engine.evaluate(&bare_event()).unwrap().action,
        Action::Allow
    );
}

// =====================================================================
// Scenario 24: Identity-based restrictions
// =====================================================================

#[test]
fn scenario_identity_restrictions() {
    let (_dir, mut engine) = engine_with(
        r#"
package busted

default decision = "allow"

decision = "deny" {
    input.identity
    input.identity.timeline_len > 100
}

decision = "audit" {
    input.identity
    input.identity.confidence > 0.8
    not long_timeline
}

long_timeline {
    input.identity.timeline_len > 100
}

reasons[r] {
    input.identity
    input.identity.timeline_len > 100
    r := "Identity has suspiciously long timeline"
}
"#,
    );

    // Identity with high confidence -> audit
    let mut event = network_event("OpenAI");
    event.identity = Some(IdentityInfo {
        id: 42,
        instance: "test".into(),
        confidence: 0.95,
        match_type: None,
        narrative: None,
        timeline: None,
        timeline_len: Some(10),
        prompt_fingerprint: None,
        behavioral_digest: None,
        capability_hash: None,
        graph_node_count: None,
        graph_edge_count: None,
    });
    assert_eq!(engine.evaluate(&event).unwrap().action, Action::Audit);

    // Identity with long timeline -> deny
    event.identity.as_mut().unwrap().timeline_len = Some(150);
    let d = engine.evaluate(&event).unwrap();
    assert_eq!(d.action, Action::Deny);
    assert!(d.reasons.iter().any(|r| r.contains("timeline")));

    // No identity -> allow
    assert_eq!(
        engine.evaluate(&bare_event()).unwrap().action,
        Action::Allow
    );
}
