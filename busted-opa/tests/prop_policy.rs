//! Property-based tests for the OPA policy engine.
//!
//! These verify invariants that must hold regardless of input:
//! - `evaluate()` never panics on any valid `BustedEvent`
//! - The action is always one of Allow, Audit, Deny
//! - Evaluation is deterministic
//! - Sequential evaluations are independent

use busted_opa::{Action, PolicyEngine};
use busted_types::agentic::{AgenticAction, BustedEvent, NetworkEventKind, ProcessInfo};
use proptest::prelude::*;
use std::io::Write;
use std::path::Path;

// ---------------------------------------------------------------------------
// Proptest strategies
// ---------------------------------------------------------------------------

fn optional_provider() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some("OpenAI".to_string())),
        Just(Some("Anthropic".to_string())),
        Just(Some("Google".to_string())),
        Just(Some("Azure".to_string())),
        Just(Some("Cohere".to_string())),
        Just(Some("Mistral".to_string())),
        Just(Some("DeepSeek".to_string())),
        "[a-zA-Z]{3,20}".prop_map(Some),
    ]
}

fn provider_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("OpenAI".to_string()),
        Just("Anthropic".to_string()),
        Just("Google".to_string()),
        Just("Azure".to_string()),
        Just("Cohere".to_string()),
        Just("Mistral".to_string()),
        Just("DeepSeek".to_string()),
        "[a-zA-Z]{3,20}",
    ]
}

fn optional_bool() -> impl Strategy<Value = Option<bool>> {
    prop_oneof![Just(None), Just(Some(true)), Just(Some(false)),]
}

fn network_event_kind_strategy() -> impl Strategy<Value = NetworkEventKind> {
    prop_oneof![
        Just(NetworkEventKind::Connect),
        Just(NetworkEventKind::Close),
        Just(NetworkEventKind::DataSent),
        Just(NetworkEventKind::DataReceived),
        Just(NetworkEventKind::DnsQuery),
    ]
}

fn mcp_method_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("tools/call".to_string()),
        Just("tools/list".to_string()),
        Just("resources/read".to_string()),
        Just("initialize".to_string()),
    ]
}

fn process_info_strategy() -> impl Strategy<Value = ProcessInfo> {
    (
        any::<u32>(),                              // pid
        any::<u32>(),                              // uid
        "[a-z]{1,15}".prop_map(|s| s.to_string()), // name
        prop_oneof![
            Just(None),
            Just(Some("production".to_string())),
            Just(Some("staging".to_string())),
            "[a-z]{3,12}".prop_map(Some)
        ], // pod_namespace
    )
        .prop_map(|(pid, uid, name, pod_namespace)| ProcessInfo {
            pid,
            uid,
            name,
            container_id: String::new(),
            cgroup_id: 0,
            pod_name: None,
            pod_namespace,
            service_account: None,
        })
}

fn agentic_action_strategy() -> impl Strategy<Value = AgenticAction> {
    prop_oneof![
        // Network action (most common)
        (
            network_event_kind_strategy(),
            prop_oneof![Just(80u16), Just(443u16), Just(8080u16), any::<u16>()],
            0u64..1_000_000,
            optional_provider(),
        )
            .prop_map(|(kind, dst_port, bytes, provider)| AgenticAction::Network {
                kind,
                src_ip: "10.0.0.1".into(),
                src_port: 45000,
                dst_ip: "104.18.1.1".into(),
                dst_port,
                bytes,
                sni: None,
                provider,
            }),
        // Prompt action
        (provider_strategy(), optional_bool(), 0u64..1_000_000,).prop_map(
            |(provider, pii_detected, bytes)| AgenticAction::Prompt {
                provider,
                model: None,
                user_message: None,
                system_prompt: None,
                stream: false,
                sdk: None,
                bytes,
                sni: None,
                endpoint: None,
                fingerprint: None,
                pii_detected,
                confidence: None,
                sdk_hash: None,
                model_hash: None,
            }
        ),
        // McpRequest action
        mcp_method_strategy().prop_map(|method| AgenticAction::McpRequest {
            method,
            category: None,
            params_preview: None,
        }),
        // Response action
        provider_strategy().prop_map(|provider| AgenticAction::Response {
            provider,
            model: None,
            bytes: 512,
            sni: None,
            confidence: None,
        }),
    ]
}

/// Strategy that generates arbitrary BustedEvents with realistic field values.
fn busted_event_strategy() -> impl Strategy<Value = BustedEvent> {
    (process_info_strategy(), agentic_action_strategy()).prop_map(|(process, action)| {
        let session_id = format!("{}:test", process.pid);
        BustedEvent {
            timestamp: "12:34:56.789".into(),
            process,
            session_id,
            identity: None,
            policy: None,
            action,
        }
    })
}

/// Helper: extract provider from any action variant (returns Option).
fn event_provider(event: &BustedEvent) -> Option<&str> {
    event.provider()
}

/// Helper: extract pii_detected from Prompt action (returns Option<bool>).
fn event_pii(event: &BustedEvent) -> Option<bool> {
    match &event.action {
        AgenticAction::Prompt { pii_detected, .. } => *pii_detected,
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_rego(dir: &Path, filename: &str, content: &str) {
    let path = dir.join(filename);
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

// ---------------------------------------------------------------------------
// Property: evaluate() never panics with allow-all policy
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn never_panics_allow_all(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"package busted
default decision = "allow"
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let result = engine.evaluate(&event);
        prop_assert!(result.is_ok());
    }
}

// ---------------------------------------------------------------------------
// Property: evaluate() never panics with deny-all policy
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn never_panics_deny_all(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"package busted
default decision = "deny"
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let result = engine.evaluate(&event);
        prop_assert!(result.is_ok());
        prop_assert_eq!(result.unwrap().action, Action::Deny);
    }
}

// ---------------------------------------------------------------------------
// Property: evaluate() never panics with conditional policy
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn never_panics_conditional_policy(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
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
    input.action.provider != null
    r := concat("", ["Provider: ", input.action.provider])
}
reasons[r] {
    input.action.pii_detected == true
    r := "PII"
}
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let result = engine.evaluate(&event);
        prop_assert!(result.is_ok());
    }
}

// ---------------------------------------------------------------------------
// Property: action is always one of the three variants
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn action_always_valid(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "audit" { input.action.provider != null }
decision = "deny" { input.action.pii_detected == true; input.action.provider != null }
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d = engine.evaluate(&event).unwrap();
        let valid = matches!(d.action, Action::Allow | Action::Audit | Action::Deny);
        prop_assert!(valid, "unexpected action: {:?}", d.action);
    }
}

// ---------------------------------------------------------------------------
// Property: evaluation is deterministic
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn evaluation_is_deterministic(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "audit" { input.action.provider != null; not input.action.pii_detected }
decision = "deny" { input.action.pii_detected == true; input.action.provider != null }
reasons[r] { input.action.provider != null; r := "provider" }
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d1 = engine.evaluate(&event).unwrap();
        let d2 = engine.evaluate(&event).unwrap();
        prop_assert_eq!(d1.action, d2.action, "action not deterministic");
        // Reasons may be in different order (sets), so compare sorted
        let mut r1 = d1.reasons.clone();
        let mut r2 = d2.reasons.clone();
        r1.sort();
        r2.sort();
        prop_assert_eq!(r1, r2, "reasons not deterministic");
    }
}

// ---------------------------------------------------------------------------
// Property: sequential evaluations are independent
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn sequential_independence(
        events in proptest::collection::vec(busted_event_strategy(), 2..10)
    ) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "deny" { input.action.pii_detected == true }
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        for event in &events {
            let d = engine.evaluate(event).unwrap();
            let expected = if event_pii(event) == Some(true) {
                Action::Deny
            } else {
                Action::Allow
            };
            prop_assert_eq!(d.action, expected,
                "event with pii_detected={:?} should be {:?}",
                event_pii(event), expected);
        }
    }
}

// ---------------------------------------------------------------------------
// Property: empty policy dir always allows
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn empty_dir_always_allows(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d = engine.evaluate(&event).unwrap();
        prop_assert_eq!(d.action, Action::Allow);
        prop_assert!(d.reasons.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Property: reasons are always strings, never empty strings
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn reasons_are_non_empty_strings(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
reasons[r] { input.action.provider != null; r := concat("", ["P: ", input.action.provider]) }
reasons[r] { input.action.pii_detected == true; r := "PII detected" }
reasons[r] { input.action.method != null; r := concat("", ["MCP: ", input.action.method]) }
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d = engine.evaluate(&event).unwrap();
        for reason in &d.reasons {
            prop_assert!(!reason.is_empty(), "reason should not be empty");
        }
    }
}

// ---------------------------------------------------------------------------
// Property: data.json allowlist works for any provider string
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn data_allowlist_property(
        provider in "[a-zA-Z]{3,15}",
        in_list in any::<bool>(),
    ) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "deny"
decision = "allow" { input.action.provider == data.ok[_] }
"#);
        let data = if in_list {
            format!(r#"{{"ok": ["{provider}"]}}"#)
        } else {
            r#"{"ok": ["NOMATCH"]}"#.to_string()
        };
        std::fs::write(dir.path().join("data.json"), &data).unwrap();
        let mut engine = PolicyEngine::new(dir.path()).unwrap();

        let event = BustedEvent {
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
                dst_port: 443,
                bytes: 0,
                sni: None,
                provider: Some(provider),
            },
        };

        let d = engine.evaluate(&event).unwrap();
        if in_list {
            prop_assert_eq!(d.action, Action::Allow);
        } else {
            prop_assert_eq!(d.action, Action::Deny);
        }
    }
}

// ---------------------------------------------------------------------------
// Property: deny-on-PII is correctly applied for random events
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn pii_deny_correctness(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "deny" {
    input.action.pii_detected == true
    input.action.provider != null
}
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d = engine.evaluate(&event).unwrap();
        if event_pii(&event) == Some(true) && event_provider(&event).is_some() {
            prop_assert_eq!(d.action, Action::Deny);
        } else {
            prop_assert_eq!(d.action, Action::Allow);
        }
    }
}

// ---------------------------------------------------------------------------
// Property: audit-on-provider is correctly applied for random events
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn provider_audit_correctness(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "audit" {
    input.action.provider != null
}
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d = engine.evaluate(&event).unwrap();
        if event_provider(&event).is_some() {
            prop_assert_eq!(d.action, Action::Audit);
        } else {
            prop_assert_eq!(d.action, Action::Allow);
        }
    }
}

// ---------------------------------------------------------------------------
// Property: evaluation order does not affect per-event results
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn commutativity_evaluation_order(
        event_a in busted_event_strategy(),
        event_b in busted_event_strategy(),
    ) {
        let rego = r#"
package busted
default decision = "allow"
decision = "audit" { input.action.provider != null }
decision = "deny" { input.action.pii_detected == true; input.action.provider != null }
reasons[r] { input.action.provider != null; r := concat("", ["P: ", input.action.provider]) }
"#;
        // Evaluate A then B
        let dir1 = tempfile::tempdir().unwrap();
        write_rego(dir1.path(), "p.rego", rego);
        let mut engine1 = PolicyEngine::new(dir1.path()).unwrap();
        let da_first = engine1.evaluate(&event_a).unwrap();
        let db_second = engine1.evaluate(&event_b).unwrap();

        // Evaluate B then A
        let dir2 = tempfile::tempdir().unwrap();
        write_rego(dir2.path(), "p.rego", rego);
        let mut engine2 = PolicyEngine::new(dir2.path()).unwrap();
        let db_first = engine2.evaluate(&event_b).unwrap();
        let da_second = engine2.evaluate(&event_a).unwrap();

        // Per-event results should be the same regardless of order
        prop_assert_eq!(da_first.action, da_second.action,
            "event A action differs by evaluation order");
        prop_assert_eq!(db_first.action, db_second.action,
            "event B action differs by evaluation order");

        let mut ra1 = da_first.reasons.clone();
        let mut ra2 = da_second.reasons.clone();
        ra1.sort();
        ra2.sort();
        prop_assert_eq!(ra1, ra2, "event A reasons differ by evaluation order");

        let mut rb1 = db_first.reasons.clone();
        let mut rb2 = db_second.reasons.clone();
        rb1.sort();
        rb2.sort();
        prop_assert_eq!(rb1, rb2, "event B reasons differ by evaluation order");
    }
}

// ---------------------------------------------------------------------------
// Property: reload with unchanged directory yields same result
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn reload_stability_unchanged_dir(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "audit" { input.action.provider != null }
decision = "deny" { input.action.pii_detected == true; input.action.provider != null }
reasons[r] { input.action.provider != null; r := concat("", ["P: ", input.action.provider]) }
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d1 = engine.evaluate(&event).unwrap();
        engine.reload().unwrap();
        let d2 = engine.evaluate(&event).unwrap();

        prop_assert_eq!(d1.action, d2.action, "action changed after reload");
        let mut r1 = d1.reasons.clone();
        let mut r2 = d2.reasons.clone();
        r1.sort();
        r2.sort();
        prop_assert_eq!(r1, r2, "reasons changed after reload");
    }
}

// ---------------------------------------------------------------------------
// Property: from_rego and file-based engine produce same result
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn from_rego_equivalence(event in busted_event_strategy()) {
        let source = r#"
package busted
default decision = "allow"
decision = "audit" { input.action.provider != null }
decision = "deny" { input.action.pii_detected == true; input.action.provider != null }
reasons[r] { input.action.provider != null; r := concat("", ["P: ", input.action.provider]) }
"#;
        // File-based engine
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", source);
        let mut file_engine = PolicyEngine::new(dir.path()).unwrap();
        let d_file = file_engine.evaluate(&event).unwrap();

        // Inline from_rego engine
        let mut inline_engine = PolicyEngine::from_rego(source).unwrap();
        let d_inline = inline_engine.evaluate(&event).unwrap();

        prop_assert_eq!(d_file.action, d_inline.action,
            "file vs from_rego action mismatch");
        let mut rf = d_file.reasons.clone();
        let mut ri = d_inline.reasons.clone();
        rf.sort();
        ri.sort();
        prop_assert_eq!(rf, ri, "file vs from_rego reasons mismatch");
    }
}

// ---------------------------------------------------------------------------
// Property: special JSON characters in fields never cause errors
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn special_json_chars_in_fields(
        process_name in r#"[a-z]{1,5}["\\n]{1,3}[a-z]{1,5}"#,
        provider in r#"[A-Z]{1,5}["\\n]{1,3}[A-Z]{1,5}"#,
    ) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "audit" { input.action.provider != null }
reasons[r] { input.action.provider != null; r := "has provider" }
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let event = BustedEvent {
            timestamp: "00:00:00.000".into(),
            process: ProcessInfo {
                pid: 1,
                uid: 0,
                name: process_name,
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
                dst_port: 443,
                bytes: 0,
                sni: None,
                provider: Some(provider),
            },
        };
        let result = engine.evaluate(&event);
        prop_assert!(result.is_ok(), "evaluate errored on special chars: {:?}", result.err());
    }
}

// ---------------------------------------------------------------------------
// Property: deny-only policy (no audit) produces Deny for matching events
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn deny_always_overrides_audit(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        // Policy with ONLY deny rule, no audit rule at all
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "deny" {
    input.action.provider != null
}
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d = engine.evaluate(&event).unwrap();
        if event_provider(&event).is_some() {
            prop_assert_eq!(d.action, Action::Deny,
                "event with provider should be denied");
        } else {
            prop_assert_eq!(d.action, Action::Allow,
                "event without provider should be allowed");
        }
    }
}

// ---------------------------------------------------------------------------
// Property: removing all .rego files and reloading allows everything
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn empty_dir_after_reload(event in busted_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "deny"
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        // Confirm deny is active
        let d1 = engine.evaluate(&event).unwrap();
        prop_assert_eq!(d1.action, Action::Deny);

        // Remove all .rego files
        std::fs::remove_file(dir.path().join("p.rego")).unwrap();

        // Reload from now-empty directory
        engine.reload().unwrap();
        let d2 = engine.evaluate(&event).unwrap();
        prop_assert_eq!(d2.action, Action::Allow,
            "empty dir after reload should allow all");
        prop_assert!(d2.reasons.is_empty(),
            "empty dir after reload should have no reasons");
    }
}
