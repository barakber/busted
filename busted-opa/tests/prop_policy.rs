//! Property-based tests for the OPA policy engine.
//!
//! These verify invariants that must hold regardless of input:
//! - `evaluate()` never panics on any valid `ProcessedEvent`
//! - The action is always one of Allow, Audit, Deny
//! - Evaluation is deterministic
//! - Sequential evaluations are independent

use busted_opa::{Action, PolicyEngine};
use busted_types::processed::ProcessedEvent;
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

fn optional_bool() -> impl Strategy<Value = Option<bool>> {
    prop_oneof![Just(None), Just(Some(true)), Just(Some(false)),]
}

fn event_type_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("TCP_CONNECT".to_string()),
        Just("TCP_SENDMSG".to_string()),
        Just("TCP_RECVMSG".to_string()),
        Just("TCP_CLOSE".to_string()),
        Just("TLS_DATA_WRITE".to_string()),
        Just("TLS_DATA_READ".to_string()),
        Just("UDP_SENDMSG".to_string()),
    ]
}

fn content_class_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some("LlmApi".to_string())),
        Just(Some("Mcp".to_string())),
        Just(Some("GenericHttp".to_string())),
        Just(Some("LlmStream".to_string())),
    ]
}

fn mcp_method_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some("tools/call".to_string())),
        Just(Some("tools/list".to_string())),
        Just(Some("resources/read".to_string())),
        Just(Some("initialize".to_string())),
    ]
}

/// Strategy that generates arbitrary ProcessedEvents with realistic field values.
/// Uses nested tuples to stay within proptest's 12-element tuple limit.
fn processed_event_strategy() -> impl Strategy<Value = ProcessedEvent> {
    (
        // Group 1: core fields (10 elements)
        (
            event_type_strategy(),
            any::<u32>(),                                                        // pid
            any::<u32>(),                                                        // uid
            "[a-z]{1,15}".prop_map(|s| s.to_string()),                           // process_name
            prop_oneof![Just(80u16), Just(443u16), Just(8080u16), any::<u16>()], // dst_port
            0u64..1_000_000,                                                     // bytes
            optional_provider(),                                                 // provider
            optional_bool(),                                                     // pii_detected
            content_class_strategy(),                                            // content_class
            optional_provider(),                                                 // llm_provider
        ),
        // Group 2: optional fields (2 elements)
        (
            mcp_method_strategy(), // mcp_method
            prop_oneof![
                Just(None),
                Just(Some("production".to_string())),
                Just(Some("staging".to_string())),
                "[a-z]{3,12}".prop_map(Some)
            ], // pod_namespace
        ),
    )
        .prop_map(|(core, extra)| {
            let (
                event_type,
                pid,
                uid,
                process_name,
                dst_port,
                bytes,
                provider,
                pii_detected,
                content_class,
                llm_provider,
            ) = core;
            let (mcp_method, pod_namespace) = extra;
            ProcessedEvent {
                event_type,
                timestamp: "12:34:56.789".into(),
                pid,
                uid,
                process_name,
                src_ip: "10.0.0.1".into(),
                src_port: 45000,
                dst_ip: "104.18.1.1".into(),
                dst_port,
                bytes,
                provider,
                policy: None,
                container_id: String::new(),
                cgroup_id: 0,
                request_rate: None,
                session_bytes: None,
                pod_name: None,
                pod_namespace,
                service_account: None,
                ml_confidence: None,
                ml_provider: None,
                behavior_class: None,
                cluster_id: None,
                sni: None,
                tls_protocol: None,
                tls_details: None,
                tls_payload: None,
                content_class,
                llm_provider,
                llm_endpoint: None,
                llm_model: None,
                mcp_method,
                mcp_category: None,
                agent_sdk: None,
                agent_fingerprint: None,
                classifier_confidence: None,
                pii_detected,
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
        })
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
    fn never_panics_allow_all(event in processed_event_strategy()) {
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
    fn never_panics_deny_all(event in processed_event_strategy()) {
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
    fn never_panics_conditional_policy(event in processed_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
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
    input.provider != null
    r := concat("", ["Provider: ", input.provider])
}
reasons[r] {
    input.pii_detected == true
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
    fn action_always_valid(event in processed_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "audit" { input.provider != null }
decision = "deny" { input.pii_detected == true; input.provider != null }
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
    fn evaluation_is_deterministic(event in processed_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "audit" { input.provider != null; not input.pii_detected }
decision = "deny" { input.pii_detected == true; input.provider != null }
reasons[r] { input.provider != null; r := "provider" }
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
        events in proptest::collection::vec(processed_event_strategy(), 2..10)
    ) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "deny" { input.pii_detected == true }
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        for event in &events {
            let d = engine.evaluate(event).unwrap();
            let expected = if event.pii_detected == Some(true) {
                Action::Deny
            } else {
                Action::Allow
            };
            prop_assert_eq!(d.action, expected,
                "event with pii_detected={:?} should be {:?}",
                event.pii_detected, expected);
        }
    }
}

// ---------------------------------------------------------------------------
// Property: empty policy dir always allows
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn empty_dir_always_allows(event in processed_event_strategy()) {
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
    fn reasons_are_non_empty_strings(event in processed_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
reasons[r] { input.provider != null; r := concat("", ["P: ", input.provider]) }
reasons[r] { input.pii_detected == true; r := "PII detected" }
reasons[r] { input.mcp_method != null; r := concat("", ["MCP: ", input.mcp_method]) }
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
decision = "allow" { input.provider == data.ok[_] }
"#);
        let data = if in_list {
            format!(r#"{{"ok": ["{provider}"]}}"#)
        } else {
            r#"{"ok": ["NOMATCH"]}"#.to_string()
        };
        std::fs::write(dir.path().join("data.json"), &data).unwrap();
        let mut engine = PolicyEngine::new(dir.path()).unwrap();

        let event = ProcessedEvent {
            event_type: "TCP_CONNECT".into(),
            timestamp: "00:00:00.000".into(),
            pid: 1, uid: 0,
            process_name: "test".into(),
            src_ip: "0.0.0.0".into(), src_port: 0,
            dst_ip: "0.0.0.0".into(), dst_port: 443,
            bytes: 0,
            provider: Some(provider),
            policy: None,
            container_id: String::new(),
            cgroup_id: 0,
            request_rate: None, session_bytes: None,
            pod_name: None, pod_namespace: None, service_account: None,
            ml_confidence: None, ml_provider: None, behavior_class: None, cluster_id: None,
            sni: None, tls_protocol: None, tls_details: None, tls_payload: None,
            content_class: None, llm_provider: None, llm_endpoint: None, llm_model: None,
            mcp_method: None, mcp_category: None, agent_sdk: None, agent_fingerprint: None,
            classifier_confidence: None, pii_detected: None,
            llm_user_message: None, llm_system_prompt: None,
            llm_messages_json: None, llm_stream: None,
            identity_id: None, identity_instance: None,
            identity_confidence: None, identity_narrative: None,
            identity_timeline: None, identity_timeline_len: None,
            agent_sdk_hash: None, agent_model_hash: None,
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
    fn pii_deny_correctness(event in processed_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "deny" {
    input.pii_detected == true
    input.provider != null
}
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d = engine.evaluate(&event).unwrap();
        if event.pii_detected == Some(true) && event.provider.is_some() {
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
    fn provider_audit_correctness(event in processed_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "audit" {
    input.provider != null
}
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d = engine.evaluate(&event).unwrap();
        if event.provider.is_some() {
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
        event_a in processed_event_strategy(),
        event_b in processed_event_strategy(),
    ) {
        let rego = r#"
package busted
default decision = "allow"
decision = "audit" { input.provider != null }
decision = "deny" { input.pii_detected == true; input.provider != null }
reasons[r] { input.provider != null; r := concat("", ["P: ", input.provider]) }
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
    fn reload_stability_unchanged_dir(event in processed_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "audit" { input.provider != null }
decision = "deny" { input.pii_detected == true; input.provider != null }
reasons[r] { input.provider != null; r := concat("", ["P: ", input.provider]) }
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
    fn from_rego_equivalence(event in processed_event_strategy()) {
        let source = r#"
package busted
default decision = "allow"
decision = "audit" { input.provider != null }
decision = "deny" { input.pii_detected == true; input.provider != null }
reasons[r] { input.provider != null; r := concat("", ["P: ", input.provider]) }
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
decision = "audit" { input.provider != null }
reasons[r] { input.provider != null; r := "has provider" }
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let event = ProcessedEvent {
            event_type: "TCP_CONNECT".into(),
            timestamp: "00:00:00.000".into(),
            pid: 1, uid: 0,
            process_name,
            src_ip: "0.0.0.0".into(), src_port: 0,
            dst_ip: "0.0.0.0".into(), dst_port: 443,
            bytes: 0,
            provider: Some(provider),
            policy: None,
            container_id: String::new(),
            cgroup_id: 0,
            request_rate: None, session_bytes: None,
            pod_name: None, pod_namespace: None, service_account: None,
            ml_confidence: None, ml_provider: None, behavior_class: None, cluster_id: None,
            sni: None, tls_protocol: None, tls_details: None, tls_payload: None,
            content_class: None, llm_provider: None, llm_endpoint: None, llm_model: None,
            mcp_method: None, mcp_category: None, agent_sdk: None, agent_fingerprint: None,
            classifier_confidence: None, pii_detected: None,
            llm_user_message: None, llm_system_prompt: None,
            llm_messages_json: None, llm_stream: None,
            identity_id: None, identity_instance: None,
            identity_confidence: None, identity_narrative: None,
            identity_timeline: None, identity_timeline_len: None,
            agent_sdk_hash: None, agent_model_hash: None,
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
    fn deny_always_overrides_audit(event in processed_event_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        // Policy with ONLY deny rule, no audit rule at all
        write_rego(dir.path(), "p.rego", r#"
package busted
default decision = "allow"
decision = "deny" {
    input.provider != null
}
"#);
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d = engine.evaluate(&event).unwrap();
        if event.provider.is_some() {
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
    fn empty_dir_after_reload(event in processed_event_strategy()) {
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
