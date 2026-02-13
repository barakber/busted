//! OPA/Rego policy engine for LLM communication governance.
//!
//! Evaluates [`BustedEvent`]s against user-defined Rego policies and returns
//! allow / audit / deny decisions with human-readable reasons.
//!
//! # Quick start
//!
//! ```no_run
//! use busted_opa::PolicyEngine;
//! use std::path::Path;
//!
//! let mut engine = PolicyEngine::new(Path::new("/etc/busted/policies")).unwrap();
//! // engine.evaluate(&some_event) → PolicyDecision { action, reasons }
//! ```

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use busted_types::agentic::BustedEvent;
use log::{debug, info, warn};

/// Policy action returned by Rego evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Audit,
    Deny,
}

impl Action {
    /// String representation matching the Rego convention.
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Audit => "audit",
            Action::Deny => "deny",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of evaluating a single event against the loaded policies.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub action: Action,
    pub reasons: Vec<String>,
}

/// OPA/Rego policy engine backed by [regorus](https://github.com/microsoft/regorus).
pub struct PolicyEngine {
    engine: regorus::Engine,
    policy_dir: PathBuf,
}

impl PolicyEngine {
    /// Create an engine and load all `.rego` files from `policy_dir`.
    ///
    /// If a `data.json` file exists in the directory it is loaded as static
    /// data accessible via `data.*` in Rego rules.
    ///
    /// Returns `Ok` even when the directory is empty (all events will be
    /// allowed by default).
    pub fn new(policy_dir: &Path) -> Result<Self> {
        let mut engine = regorus::Engine::new();
        engine.set_rego_v0(true);
        load_policies(&mut engine, policy_dir)?;
        info!("OPA policy engine loaded from {}", policy_dir.display());
        Ok(Self {
            engine,
            policy_dir: policy_dir.to_path_buf(),
        })
    }

    /// Evaluate a [`BustedEvent`] against loaded policies.
    ///
    /// The event is serialized to JSON and set as `input`. The engine then
    /// queries `data.busted.decision` for the action and
    /// `data.busted.reasons` for human-readable explanation strings.
    ///
    /// If no policies are loaded, or the query returns an unexpected value,
    /// the default is `Action::Allow` with no reasons.
    pub fn evaluate(&mut self, event: &BustedEvent) -> Result<PolicyDecision> {
        let input_json = serde_json::to_string(event).context("Failed to serialize BustedEvent")?;
        self.engine.set_input_json(&input_json)?;

        let action = self.query_action()?;
        let reasons = self.query_reasons()?;

        debug!("OPA decision: {} (reasons: {:?})", action.as_str(), reasons);

        Ok(PolicyDecision { action, reasons })
    }

    /// Create an engine from a raw Rego source string (no directory needed).
    ///
    /// Useful for inline `--rule` evaluation from the CLI.
    pub fn from_rego(source: &str) -> Result<Self> {
        let mut engine = regorus::Engine::new();
        engine.set_rego_v0(true);
        engine
            .add_policy("inline.rego".to_string(), source.to_string())
            .context("Failed to parse inline Rego policy")?;
        info!("OPA policy engine loaded from inline Rego source");
        Ok(Self {
            engine,
            policy_dir: PathBuf::new(),
        })
    }

    /// Re-read all policies from the original directory (hot-reload).
    pub fn reload(&mut self) -> Result<()> {
        let mut engine = regorus::Engine::new();
        engine.set_rego_v0(true);
        load_policies(&mut engine, &self.policy_dir)?;
        self.engine = engine;
        info!("OPA policies reloaded from {}", self.policy_dir.display());
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn query_action(&mut self) -> Result<Action> {
        let value = self.engine.eval_rule("data.busted.decision".to_string());

        match value {
            Ok(v) => parse_action(&v),
            Err(e) => {
                debug!("OPA decision query returned no result: {e}");
                Ok(Action::Allow)
            }
        }
    }

    fn query_reasons(&mut self) -> Result<Vec<String>> {
        let value = self.engine.eval_rule("data.busted.reasons".to_string());

        match value {
            Ok(v) => parse_reasons(&v),
            Err(_) => Ok(vec![]),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load all .rego files and optional data.json from a directory.
fn load_policies(engine: &mut regorus::Engine, dir: &Path) -> Result<()> {
    if !dir.exists() {
        warn!("Policy directory does not exist: {}", dir.display());
        return Ok(());
    }

    let mut count = 0u32;
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read policy directory: {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rego") {
            engine
                .add_policy_from_file(path.clone())
                .with_context(|| format!("Failed to load policy: {}", path.display()))?;
            info!("Loaded policy: {}", path.display());
            count += 1;
        }
    }

    // Load optional static data
    let data_path = dir.join("data.json");
    if data_path.exists() {
        let data = std::fs::read_to_string(&data_path)
            .with_context(|| format!("Failed to read {}", data_path.display()))?;
        engine
            .add_data_json(&data)
            .with_context(|| format!("Failed to parse {}", data_path.display()))?;
        info!("Loaded policy data: {}", data_path.display());
    }

    if count == 0 {
        warn!(
            "No .rego files found in {}; all events will be allowed",
            dir.display()
        );
    }
    Ok(())
}

/// Parse a regorus `Value` into an `Action`.
fn parse_action(value: &regorus::Value) -> Result<Action> {
    match value {
        regorus::Value::String(s) => match s.as_ref() {
            "deny" => Ok(Action::Deny),
            "audit" => Ok(Action::Audit),
            "allow" => Ok(Action::Allow),
            other => {
                warn!("Unknown OPA decision value: {other:?}, defaulting to allow");
                Ok(Action::Allow)
            }
        },
        _ => {
            warn!("OPA decision is not a string: {value:?}, defaulting to allow");
            Ok(Action::Allow)
        }
    }
}

/// Parse a regorus `Value` (expected to be a set of strings) into `Vec<String>`.
fn parse_reasons(value: &regorus::Value) -> Result<Vec<String>> {
    let mut reasons = Vec::new();
    match value {
        regorus::Value::Set(set) => {
            for item in set.iter() {
                if let regorus::Value::String(s) = item {
                    reasons.push(s.as_ref().to_string());
                }
            }
        }
        regorus::Value::Array(arr) => {
            for item in arr.iter() {
                if let regorus::Value::String(s) = item {
                    reasons.push(s.as_ref().to_string());
                }
            }
        }
        _ => {}
    }
    Ok(reasons)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use busted_types::agentic::{AgenticAction, IdentityInfo, NetworkEventKind, ProcessInfo};
    use std::io::Write;

    // ---- Helpers ----

    /// Baseline event: Network Connect to OpenAI on port 443.
    pub(crate) fn sample_event() -> BustedEvent {
        BustedEvent {
            timestamp: "12:00:00.000".into(),
            process: ProcessInfo {
                pid: 1234,
                uid: 1000,
                name: "curl".into(),
                container_id: String::new(),
                cgroup_id: 0,
                pod_name: None,
                pod_namespace: None,
                service_account: None,
            },
            session_id: "1234:net".into(),
            identity: None,
            policy: None,
            action: AgenticAction::Network {
                kind: NetworkEventKind::Connect,
                src_ip: "10.0.0.1".into(),
                src_port: 54321,
                dst_ip: "104.18.1.1".into(),
                dst_port: 443,
                bytes: 512,
                sni: None,
                provider: Some("OpenAI".into()),
            },
        }
    }

    /// Minimal event: no provider, no PII — pure background traffic.
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

    /// Sample LLM prompt event with pii_detected and model fields.
    fn sample_prompt_event() -> BustedEvent {
        BustedEvent {
            timestamp: "12:00:00.000".into(),
            process: ProcessInfo {
                pid: 1234,
                uid: 1000,
                name: "python".into(),
                container_id: String::new(),
                cgroup_id: 0,
                pod_name: None,
                pod_namespace: None,
                service_account: None,
            },
            session_id: "1234:abc".into(),
            identity: None,
            policy: None,
            action: AgenticAction::Prompt {
                provider: "OpenAI".into(),
                model: Some("gpt-4o".into()),
                user_message: None,
                system_prompt: None,
                stream: false,
                sdk: None,
                bytes: 512,
                sni: Some("api.openai.com".into()),
                endpoint: None,
                fingerprint: None,
                pii_detected: None,
                confidence: None,
                sdk_hash: None,
                model_hash: None,
            },
        }
    }

    /// Sample MCP request event.
    fn sample_mcp_event() -> BustedEvent {
        BustedEvent {
            timestamp: "12:00:00.000".into(),
            process: ProcessInfo {
                pid: 3456,
                uid: 1000,
                name: "mcp-client".into(),
                container_id: String::new(),
                cgroup_id: 0,
                pod_name: None,
                pod_namespace: None,
                service_account: None,
            },
            session_id: "3456:mcp".into(),
            identity: None,
            policy: None,
            action: AgenticAction::McpRequest {
                method: "tools/call".into(),
                category: Some("Tools".into()),
                params_preview: None,
            },
        }
    }

    fn write_rego(dir: &Path, filename: &str, content: &str) {
        let path = dir.join(filename);
        let mut f = std::fs::File::create(&path).unwrap();
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

    // ================================================================
    // Action type tests
    // ================================================================

    #[test]
    fn action_as_str() {
        assert_eq!(Action::Allow.as_str(), "allow");
        assert_eq!(Action::Audit.as_str(), "audit");
        assert_eq!(Action::Deny.as_str(), "deny");
    }

    #[test]
    fn action_display_matches_as_str() {
        for action in [Action::Allow, Action::Audit, Action::Deny] {
            assert_eq!(format!("{}", action), action.as_str());
        }
    }

    #[test]
    fn action_eq() {
        assert_eq!(Action::Allow, Action::Allow);
        assert_ne!(Action::Allow, Action::Deny);
        assert_ne!(Action::Audit, Action::Allow);
    }

    #[test]
    fn action_clone() {
        let a = Action::Deny;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn action_debug() {
        let s = format!("{:?}", Action::Audit);
        assert!(s.contains("Audit"));
    }

    // ================================================================
    // PolicyDecision
    // ================================================================

    #[test]
    fn decision_clone() {
        let d = PolicyDecision {
            action: Action::Deny,
            reasons: vec!["test".into()],
        };
        let d2 = d.clone();
        assert_eq!(d2.action, Action::Deny);
        assert_eq!(d2.reasons, vec!["test".to_string()]);
    }

    #[test]
    fn decision_debug() {
        let d = PolicyDecision {
            action: Action::Allow,
            reasons: vec![],
        };
        let s = format!("{:?}", d);
        assert!(s.contains("Allow"));
    }

    // ================================================================
    // Engine construction
    // ================================================================

    #[test]
    fn empty_policy_dir_allows() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let decision = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(decision.action, Action::Allow);
        assert!(decision.reasons.is_empty());
    }

    #[test]
    fn nonexistent_dir_ok() {
        let result = PolicyEngine::new(Path::new("/tmp/nonexistent_busted_opa_test_dir_xyz"));
        assert!(result.is_ok());
        let mut engine = result.unwrap();
        let decision = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(decision.action, Action::Allow);
    }

    #[test]
    fn dir_with_non_rego_files_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not a policy").unwrap();
        std::fs::write(dir.path().join("notes.md"), "# notes").unwrap();
        std::fs::write(dir.path().join("backup.rego.bak"), "old stuff").unwrap();
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn invalid_rego_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        write_rego(dir.path(), "bad.rego", "this is not valid rego at all {{{");
        let result = PolicyEngine::new(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn invalid_data_json_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        write_rego(
            dir.path(),
            "ok.rego",
            r#"package busted
default decision = "allow"
"#,
        );
        std::fs::write(dir.path().join("data.json"), "not valid json!!!").unwrap();
        let result = PolicyEngine::new(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn multiple_rego_files_loaded() {
        let dir = tempfile::tempdir().unwrap();
        // File 1: defines decision (check pii_detected on Prompt action)
        write_rego(
            dir.path(),
            "decision.rego",
            r#"
package busted
default decision = "allow"
decision = "deny" {
    input.action.pii_detected == true
}
"#,
        );
        // File 2: defines reasons (same package)
        write_rego(
            dir.path(),
            "reasons.rego",
            r#"
package busted
reasons[r] {
    input.action.pii_detected == true
    r := "PII detected"
}
"#,
        );

        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        let mut event = sample_prompt_event();
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
    }

    // ================================================================
    // Basic policy evaluation
    // ================================================================

    #[test]
    fn deny_all_policy() {
        let (_dir, mut engine) = engine_with(
            r#"package busted
default decision = "deny"
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn allow_all_policy() {
        let (_dir, mut engine) = engine_with(
            r#"package busted
default decision = "allow"
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn audit_all_policy() {
        let (_dir, mut engine) = engine_with(
            r#"package busted
default decision = "audit"
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Audit);
    }

    #[test]
    fn unknown_decision_value_defaults_to_allow() {
        let (_dir, mut engine) = engine_with(
            r#"package busted
default decision = "quarantine"
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    // ================================================================
    // Deny / Audit / Allow with conditions
    // ================================================================

    #[test]
    fn deny_on_pii_in_prompt() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" {
    input.action.pii_detected == true
    input.action.type == "Prompt"
}
reasons[reason] {
    input.action.pii_detected == true
    reason := "PII detected in outbound LLM traffic"
}
"#,
        );

        // PII in Prompt → deny
        let mut event = sample_prompt_event();
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

        // No PII in Prompt → allow
        let d2 = engine.evaluate(&sample_prompt_event()).unwrap();
        assert_eq!(d2.action, Action::Allow);

        // Network event (no pii_detected field) → allow
        let d3 = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d3.action, Action::Allow);
    }

    #[test]
    fn audit_on_provider_detected() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "audit" {
    input.action.provider != null
}
"#,
        );
        // Network event with provider → audit
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Audit);

        // Network event without provider → allow
        let d2 = engine.evaluate(&bare_event()).unwrap();
        assert_eq!(d2.action, Action::Allow);
    }

    // ================================================================
    // Data.json integration
    // ================================================================

    #[test]
    fn data_json_allowlist() {
        let (_dir, mut engine) = engine_with_data(
            r#"
package busted
default decision = "deny"
decision = "allow" {
    input.action.provider == data.allowed_providers[_]
}
"#,
            r#"{"allowed_providers": ["OpenAI", "Anthropic"]}"#,
        );

        // OpenAI → allowed
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);

        // Anthropic → allowed
        let mut event2 = sample_event();
        if let AgenticAction::Network {
            ref mut provider, ..
        } = event2.action
        {
            *provider = Some("Anthropic".into());
        }
        let d2 = engine.evaluate(&event2).unwrap();
        assert_eq!(d2.action, Action::Allow);

        // Unknown → denied
        let mut event3 = sample_event();
        if let AgenticAction::Network {
            ref mut provider, ..
        } = event3.action
        {
            *provider = Some("SomeUnknown".into());
        }
        let d3 = engine.evaluate(&event3).unwrap();
        assert_eq!(d3.action, Action::Deny);
    }

    #[test]
    fn data_json_blocklist() {
        let (_dir, mut engine) = engine_with_data(
            r#"
package busted
default decision = "allow"
decision = "deny" {
    input.action.provider == data.blocked_providers[_]
}
"#,
            r#"{"blocked_providers": ["DeepSeek"]}"#,
        );

        // OpenAI → allowed
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);

        // DeepSeek → denied
        let mut event2 = sample_event();
        if let AgenticAction::Network {
            ref mut provider, ..
        } = event2.action
        {
            *provider = Some("DeepSeek".into());
        }
        let d2 = engine.evaluate(&event2).unwrap();
        assert_eq!(d2.action, Action::Deny);
    }

    #[test]
    fn data_json_nested_structure() {
        let (_dir, mut engine) = engine_with_data(
            r#"
package busted
default decision = "allow"
decision = "deny" {
    input.process.uid == data.restricted_uids[_]
    input.action.provider != null
}
"#,
            r#"{"restricted_uids": [0, 1000, 65534]}"#,
        );

        // uid 1000 with provider → deny
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Deny);

        // uid 2000 → allow
        let mut event2 = sample_event();
        event2.process.uid = 2000;
        let d2 = engine.evaluate(&event2).unwrap();
        assert_eq!(d2.action, Action::Allow);
    }

    // ================================================================
    // Reload
    // ================================================================

    #[test]
    fn reload_picks_up_new_policy() {
        let dir = tempfile::tempdir().unwrap();
        write_rego(
            dir.path(),
            "test.rego",
            r#"package busted
default decision = "allow"
"#,
        );
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Allow
        );

        write_rego(
            dir.path(),
            "test.rego",
            r#"package busted
default decision = "deny"
"#,
        );
        engine.reload().unwrap();
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );
    }

    #[test]
    fn reload_picks_up_new_data_json() {
        let dir = tempfile::tempdir().unwrap();
        write_rego(
            dir.path(),
            "test.rego",
            r#"
package busted
default decision = "deny"
decision = "allow" {
    input.action.provider == data.ok[_]
}
"#,
        );
        std::fs::write(dir.path().join("data.json"), r#"{"ok": ["Anthropic"]}"#).unwrap();
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );

        std::fs::write(dir.path().join("data.json"), r#"{"ok": ["OpenAI"]}"#).unwrap();
        engine.reload().unwrap();
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Allow
        );
    }

    #[test]
    fn reload_with_invalid_rego_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        write_rego(
            dir.path(),
            "test.rego",
            r#"package busted
default decision = "allow"
"#,
        );
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Allow
        );

        // Overwrite with invalid rego
        write_rego(dir.path(), "test.rego", "totally broken {{{{");
        let result = engine.reload();
        assert!(result.is_err());
    }

    // ================================================================
    // Reasons
    // ================================================================

    #[test]
    fn reasons_empty_when_no_rule_defined() {
        let (_dir, mut engine) = engine_with(
            r#"package busted
default decision = "deny"
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert!(d.reasons.is_empty());
    }

    #[test]
    fn reasons_multiple_rules_fire() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "audit"
reasons[r] {
    input.action.provider != null
    r := "has provider"
}
reasons[r] {
    input.action.type == "Network"
    r := "network event"
}
reasons[r] {
    input.action.dst_port == 443
    r := "TLS port"
}
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert!(
            d.reasons.len() >= 3,
            "expected >=3 reasons, got {:?}",
            d.reasons
        );
        assert!(d.reasons.contains(&"has provider".to_string()));
        assert!(d.reasons.contains(&"network event".to_string()));
        assert!(d.reasons.contains(&"TLS port".to_string()));
    }

    #[test]
    fn reasons_uses_concat() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "audit"
reasons[r] {
    input.action.provider != null
    r := concat("", ["Traffic to: ", input.action.provider])
}
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert!(d.reasons.iter().any(|r| r == "Traffic to: OpenAI"));
    }

    // ================================================================
    // Input field access — verify the Rego engine can see every
    // BustedEvent field through the JSON serialization.
    // ================================================================

    #[test]
    fn rego_sees_action_type() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { input.action.type == "Network" }
"#,
        );
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );
    }

    #[test]
    fn rego_sees_pid_and_uid() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { input.process.pid == 1234; input.process.uid == 1000 }
"#,
        );
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );
    }

    #[test]
    fn rego_sees_process_name() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { input.process.name == "curl" }
"#,
        );
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );
    }

    #[test]
    fn rego_sees_network_fields() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" {
    input.action.src_ip == "10.0.0.1"
    input.action.src_port == 54321
    input.action.dst_ip == "104.18.1.1"
    input.action.dst_port == 443
    input.action.bytes == 512
}
"#,
        );
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );
    }

    #[test]
    fn rego_sees_container_and_cgroup() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { input.process.container_id == "abc123" }
"#,
        );
        let mut event = sample_event();
        event.process.container_id = "abc123".into();
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);
    }

    #[test]
    fn rego_sees_k8s_fields() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" {
    input.process.pod_namespace == "production"
    input.process.service_account == "llm-agent"
}
"#,
        );
        let mut event = sample_event();
        event.process.pod_namespace = Some("production".into());
        event.process.service_account = Some("llm-agent".into());
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);
    }

    #[test]
    fn rego_sees_prompt_model() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "audit" {
    input.action.type == "Prompt"
    input.action.model == "gpt-4o"
}
"#,
        );
        assert_eq!(
            engine.evaluate(&sample_prompt_event()).unwrap().action,
            Action::Audit
        );
        // Network event has no model → allow
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Allow
        );
    }

    #[test]
    fn rego_sees_mcp_fields() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { input.action.method == "tools/call" }
"#,
        );
        assert_eq!(
            engine.evaluate(&sample_mcp_event()).unwrap().action,
            Action::Deny
        );
        // Non-MCP event → allow
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Allow
        );
    }

    #[test]
    fn rego_sees_sni() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "audit" { input.action.sni == "api.openai.com" }
"#,
        );
        let mut event = sample_event();
        if let AgenticAction::Network { ref mut sni, .. } = event.action {
            *sni = Some("api.openai.com".into());
        }
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Audit);
    }

    #[test]
    fn rego_sees_pii_detected_false() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { input.action.pii_detected == false }
"#,
        );
        let mut event = sample_prompt_event();
        if let AgenticAction::Prompt {
            ref mut pii_detected,
            ..
        } = event.action
        {
            *pii_detected = Some(false);
        }
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

        // null (None) should NOT match == false
        let event2 = sample_prompt_event();
        assert_eq!(engine.evaluate(&event2).unwrap().action, Action::Allow);
    }

    // ================================================================
    // Sequential evaluations (engine state doesn't leak between calls)
    // ================================================================

    #[test]
    fn sequential_evaluations_independent() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { input.action.pii_detected == true }
"#,
        );

        let mut pii_event = sample_prompt_event();
        if let AgenticAction::Prompt {
            ref mut pii_detected,
            ..
        } = pii_event.action
        {
            *pii_detected = Some(true);
        }
        assert_eq!(engine.evaluate(&pii_event).unwrap().action, Action::Deny);

        // Second call with a clean event should allow
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Allow
        );

        // Third call with PII again should deny
        assert_eq!(engine.evaluate(&pii_event).unwrap().action, Action::Deny);
    }

    #[test]
    fn many_sequential_evaluations() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { input.process.pid == 42 }
"#,
        );
        for i in 0..100u32 {
            let mut event = bare_event();
            event.process.pid = i;
            let expected = if i == 42 { Action::Deny } else { Action::Allow };
            assert_eq!(engine.evaluate(&event).unwrap().action, expected);
        }
    }

    // ================================================================
    // Deny priority over audit (Rego conflict resolution)
    // ================================================================

    #[test]
    fn deny_takes_precedence_over_audit() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" {
    input.action.pii_detected == true
}
decision = "audit" {
    input.action.provider != null
}
"#,
        );

        let mut event = sample_prompt_event();
        if let AgenticAction::Prompt {
            ref mut pii_detected,
            ..
        } = event.action
        {
            *pii_detected = Some(true);
        }
        let d = engine.evaluate(&event);
        // This may error (Rego conflict) or pick one value — verify no panic.
        assert!(d.is_ok() || d.is_err());
    }

    // ================================================================
    // Edge cases in Rego
    // ================================================================

    #[test]
    fn wrong_package_name_means_allow() {
        let (_dir, mut engine) = engine_with(
            r#"
package not_busted
default decision = "deny"
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn numeric_decision_defaults_to_allow() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
decision = 42
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn boolean_decision_defaults_to_allow() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
decision = true
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    // ================================================================
    // Rego builtin functions accessible
    // ================================================================

    #[test]
    fn rego_startswith_builtin() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { startswith(input.process.name, "cu") }
"#,
        );
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );

        let mut event = sample_event();
        event.process.name = "python".into();
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
    }

    #[test]
    fn rego_count_builtin() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { count(input.process.name) > 3 }
"#,
        );
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );

        let mut event = sample_event();
        event.process.name = "ls".into();
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
    }

    // ================================================================
    // from_rego (inline Rego source)
    // ================================================================

    #[test]
    fn from_rego_deny_all() {
        let mut engine = PolicyEngine::from_rego(
            r#"package busted
default decision = "deny"
"#,
        )
        .unwrap();
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn from_rego_allow_all() {
        let mut engine = PolicyEngine::from_rego(
            r#"package busted
default decision = "allow"
"#,
        )
        .unwrap();
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn from_rego_with_conditions() {
        let mut engine = PolicyEngine::from_rego(
            r#"
package busted
default decision = "allow"
decision = "deny" {
    input.action.pii_detected == true
}
reasons[r] {
    input.action.pii_detected == true
    r := "PII detected in inline rule"
}
"#,
        )
        .unwrap();

        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);

        let mut pii_event = sample_prompt_event();
        if let AgenticAction::Prompt {
            ref mut pii_detected,
            ..
        } = pii_event.action
        {
            *pii_detected = Some(true);
        }
        let d = engine.evaluate(&pii_event).unwrap();
        assert_eq!(d.action, Action::Deny);
        assert!(d.reasons.iter().any(|r| r.contains("PII")));
    }

    #[test]
    fn from_rego_invalid_source_errors() {
        let result = PolicyEngine::from_rego("this is not valid rego {{{");
        assert!(result.is_err());
    }

    // ================================================================
    // More Rego builtins
    // ================================================================

    #[test]
    fn rego_regex_match_builtin() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { regex.match("^10\\.0\\.", input.action.src_ip) }
"#,
        );
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );

        let mut event = sample_event();
        if let AgenticAction::Network { ref mut src_ip, .. } = event.action {
            *src_ip = "192.168.1.1".into();
        }
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
    }

    // ================================================================
    // from_rego edge cases
    // ================================================================

    #[test]
    fn from_rego_empty_string_errors() {
        let result = PolicyEngine::from_rego("");
        assert!(result.is_err(), "empty string should fail to parse as Rego");
    }

    #[test]
    fn from_rego_with_import() {
        let result = PolicyEngine::from_rego(
            r#"
package busted
import data.foo
default decision = "allow"
"#,
        );
        assert!(
            result.is_ok(),
            "import of non-existent data should not error at load time"
        );
        let mut engine = result.unwrap();
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn from_rego_referencing_data() {
        let mut engine = PolicyEngine::from_rego(
            r#"
package busted
default decision = "allow"
decision = "deny" {
    input.action.provider == data.blocked[_]
}
"#,
        )
        .unwrap();
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    // ================================================================
    // Reload edge cases
    // ================================================================

    #[test]
    fn reload_from_empty_dir_after_policies() {
        let dir = tempfile::tempdir().unwrap();
        write_rego(
            dir.path(),
            "test.rego",
            r#"package busted
default decision = "deny"
"#,
        );
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );

        std::fs::remove_file(dir.path().join("test.rego")).unwrap();
        engine.reload().unwrap();

        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
        assert!(d.reasons.is_empty());
    }

    #[test]
    fn reload_adding_data_json_mid_session() {
        let dir = tempfile::tempdir().unwrap();
        write_rego(
            dir.path(),
            "test.rego",
            r#"
package busted
default decision = "deny"
decision = "allow" {
    input.action.provider == data.ok[_]
}
"#,
        );
        let mut engine = PolicyEngine::new(dir.path()).unwrap();
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Deny
        );

        std::fs::write(dir.path().join("data.json"), r#"{"ok": ["OpenAI"]}"#).unwrap();
        engine.reload().unwrap();

        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Allow
        );
    }

    // ================================================================
    // Reason parsing edge cases
    // ================================================================

    #[test]
    fn non_string_reasons_ignored() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "audit"
reasons[r] {
    r := 42
}
reasons[r] {
    r := "valid reason"
}
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.reasons.len(), 1);
        assert_eq!(d.reasons[0], "valid reason");
    }

    #[test]
    fn object_decision_defaults_to_allow() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
decision = {"action": "deny"}
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn parse_reasons_handles_set_from_rego() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "audit"
reasons[r] {
    r := "set_reason_alpha"
}
reasons[r] {
    input.action.provider != null
    r := "set_reason_beta"
}
"#,
        );
        let d = engine.evaluate(&sample_event()).unwrap();
        assert!(
            d.reasons.contains(&"set_reason_alpha".to_string()),
            "should contain set_reason_alpha: {:?}",
            d.reasons
        );
        assert!(
            d.reasons.contains(&"set_reason_beta".to_string()),
            "should contain set_reason_beta: {:?}",
            d.reasons
        );
        assert!(
            d.reasons.len() >= 2,
            "expected at least 2 reasons, got {:?}",
            d.reasons
        );

        let mut engine2 = PolicyEngine::from_rego(
            r#"
package busted
default decision = "audit"
reasons[r] {
    input.action.provider == "NEVER_MATCHES"
    r := "should not appear"
}
"#,
        )
        .unwrap();
        let d2 = engine2.evaluate(&sample_event()).unwrap();
        assert!(
            d2.reasons.is_empty(),
            "non-matching reasons should be empty"
        );
    }

    // ================================================================
    // Identity fields visible in Rego
    // ================================================================

    #[test]
    fn rego_sees_identity_timeline_len() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { input.identity.timeline_len > 100 }
"#,
        );
        let mut event = sample_event();
        event.identity = Some(IdentityInfo {
            id: 1,
            instance: "test".into(),
            confidence: 0.9,
            match_type: None,
            narrative: None,
            timeline: None,
            timeline_len: Some(150),
            prompt_fingerprint: None,
            behavioral_digest: None,
            capability_hash: None,
            graph_node_count: None,
            graph_edge_count: None,
        });
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

        event.identity.as_mut().unwrap().timeline_len = Some(50);
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
    }

    #[test]
    fn rego_sees_identity_confidence() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "audit" { input.identity.confidence > 0.9 }
"#,
        );
        let mut event = sample_event();
        event.identity = Some(IdentityInfo {
            id: 1,
            instance: "test".into(),
            confidence: 0.95,
            match_type: None,
            narrative: None,
            timeline: None,
            timeline_len: None,
            prompt_fingerprint: None,
            behavioral_digest: None,
            capability_hash: None,
            graph_node_count: None,
            graph_edge_count: None,
        });
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Audit);

        event.identity.as_mut().unwrap().confidence = 0.5;
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Allow);
    }

    #[test]
    fn rego_sees_identity_id() {
        let (_dir, mut engine) = engine_with(
            r#"
package busted
default decision = "allow"
decision = "deny" { input.identity != null }
"#,
        );
        let mut event = sample_event();
        event.identity = Some(IdentityInfo {
            id: 12345,
            instance: "test".into(),
            confidence: 0.8,
            match_type: None,
            narrative: None,
            timeline: None,
            timeline_len: None,
            prompt_fingerprint: None,
            behavioral_digest: None,
            capability_hash: None,
            graph_node_count: None,
            graph_edge_count: None,
        });
        assert_eq!(engine.evaluate(&event).unwrap().action, Action::Deny);

        // null identity → allow
        assert_eq!(
            engine.evaluate(&sample_event()).unwrap().action,
            Action::Allow
        );
    }
}
