//! Integration tests for the Helm chart.
//!
//! These tests shell out to `helm template` and assert on the rendered YAML.
//! Skipped automatically if `helm` is not on PATH.

use serde::Deserialize;
use serde_yaml::Value;
use std::process::Command;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn has_helm() -> bool {
    Command::new("helm")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn chart_dir() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR"); // xtask/
    format!("{manifest}/../deploy/helm/busted")
}

/// Render the chart with optional `--set` overrides and return parsed YAML docs.
fn render(sets: &[&str]) -> Vec<Value> {
    let mut cmd = Command::new("helm");
    cmd.args(["template", "busted", &chart_dir()]);
    for s in sets {
        cmd.args(["--set", s]);
    }
    let output = cmd.output().expect("helm template failed to execute");
    assert!(
        output.status.success(),
        "helm template failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("non-UTF8 output");
    serde_yaml::Deserializer::from_str(&stdout)
        .map(|d| Value::deserialize(d).expect("invalid YAML document"))
        .collect()
}

/// Find the first document whose `kind` matches.
fn find_by_kind<'a>(docs: &'a [Value], kind: &str) -> Option<&'a Value> {
    docs.iter().find(|d| {
        d.get("kind")
            .and_then(Value::as_str)
            .map(|k| k == kind)
            .unwrap_or(false)
    })
}

/// Shorthand: assert a document of `kind` exists.
fn assert_has_kind(docs: &[Value], kind: &str) {
    assert!(
        find_by_kind(docs, kind).is_some(),
        "expected to find kind={kind}"
    );
}

/// Shorthand: assert a document of `kind` does NOT exist.
fn assert_no_kind(docs: &[Value], kind: &str) {
    assert!(
        find_by_kind(docs, kind).is_none(),
        "expected NOT to find kind={kind}"
    );
}

/// Dig into a Value by a dot-separated path (e.g. "spec.template.spec.hostPID").
fn dig(val: &Value, path: &str) -> Option<Value> {
    let mut cur = val.clone();
    for seg in path.split('.') {
        cur = cur.get(seg)?.clone();
    }
    Some(cur)
}

fn dig_str<'a>(val: &'a Value, path: &str) -> Option<String> {
    dig(val, path).and_then(|v| match v {
        Value::String(s) => Some(s),
        other => Some(format!("{other:?}")),
    })
}

fn dig_bool(val: &Value, path: &str) -> Option<bool> {
    dig(val, path).and_then(|v| v.as_bool())
}

/// Check that an array at `path` contains `needle` (substring match on rendered YAML).
fn array_contains_str(val: &Value, path: &str, needle: &str) -> bool {
    dig(val, path)
        .and_then(|v| v.as_sequence().cloned())
        .map(|seq| seq.iter().any(|item| format!("{item:?}").contains(needle)))
        .unwrap_or(false)
}

macro_rules! skip_no_helm {
    () => {
        if !has_helm() {
            eprintln!("SKIPPED: helm not found on PATH");
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests: default values
// ---------------------------------------------------------------------------

#[test]
fn default_renders_expected_kinds() {
    skip_no_helm!();
    let docs = render(&[]);

    assert_has_kind(&docs, "DaemonSet");
    assert_has_kind(&docs, "ServiceAccount");
    assert_has_kind(&docs, "ClusterRole");
    assert_has_kind(&docs, "ClusterRoleBinding");
    assert_has_kind(&docs, "Service");
    assert_no_kind(&docs, "ConfigMap");
    assert_no_kind(&docs, "ServiceMonitor");
}

// ---------------------------------------------------------------------------
// Tests: image
// ---------------------------------------------------------------------------

#[test]
fn default_image() {
    skip_no_helm!();
    let docs = render(&[]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    let image = dig_str(ds, "spec.template.spec.containers.0.image").unwrap();
    assert_eq!(image, "ghcr.io/barakber/busted:0.1.0");
}

#[test]
fn custom_image_tag() {
    skip_no_helm!();
    let docs = render(&["image.tag=2.0.0"]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    let image = dig_str(ds, "spec.template.spec.containers.0.image").unwrap();
    assert_eq!(image, "ghcr.io/barakber/busted:2.0.0");
}

#[test]
fn custom_image_repository() {
    skip_no_helm!();
    let docs = render(&["image.repository=myregistry.io/busted"]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    let image = dig_str(ds, "spec.template.spec.containers.0.image").unwrap();
    assert_eq!(image, "myregistry.io/busted:0.1.0");
}

// ---------------------------------------------------------------------------
// Tests: DaemonSet security
// ---------------------------------------------------------------------------

#[test]
fn daemonset_host_pid_and_network() {
    skip_no_helm!();
    let docs = render(&[]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();

    assert_eq!(dig_bool(ds, "spec.template.spec.hostPID"), Some(true));
    assert_eq!(dig_bool(ds, "spec.template.spec.hostNetwork"), Some(true));
}

#[test]
fn daemonset_privileged() {
    skip_no_helm!();
    let docs = render(&[]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();

    assert_eq!(
        dig_bool(
            ds,
            "spec.template.spec.containers.0.securityContext.privileged"
        ),
        Some(true)
    );
}

// ---------------------------------------------------------------------------
// Tests: DaemonSet volumes
// ---------------------------------------------------------------------------

#[test]
fn daemonset_mounts_host_paths() {
    skip_no_helm!();
    let docs = render(&[]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    let mounts = dig(ds, "spec.template.spec.containers.0.volumeMounts")
        .and_then(|v| v.as_sequence().cloned())
        .unwrap();

    let mount_paths: Vec<&str> = mounts
        .iter()
        .filter_map(|m| m.get("mountPath").and_then(Value::as_str))
        .collect();

    assert!(mount_paths.contains(&"/sys"), "missing /sys mount");
    assert!(mount_paths.contains(&"/proc"), "missing /proc mount");
    assert!(
        mount_paths.contains(&"/lib/modules"),
        "missing /lib/modules mount"
    );
    assert!(
        !mount_paths.contains(&"/etc/busted/policies"),
        "policies mount should not be present by default"
    );
}

// ---------------------------------------------------------------------------
// Tests: agent CLI args
// ---------------------------------------------------------------------------

#[test]
fn default_args_format_json() {
    skip_no_helm!();
    let docs = render(&[]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();

    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "json"
    ));
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--format"
    ));
}

#[test]
fn default_args_no_verbose_enforce_output() {
    skip_no_helm!();
    let docs = render(&[]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();

    assert!(!array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--verbose"
    ));
    assert!(!array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--enforce"
    ));
    assert!(!array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--output"
    ));
}

#[test]
fn format_text() {
    skip_no_helm!();
    let docs = render(&["agent.format=text"]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "text"
    ));
}

#[test]
fn verbose_flag() {
    skip_no_helm!();
    let docs = render(&["agent.verbose=true"]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--verbose"
    ));
}

#[test]
fn enforce_flag() {
    skip_no_helm!();
    let docs = render(&["agent.enforce=true"]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--enforce"
    ));
}

#[test]
fn custom_output() {
    skip_no_helm!();
    let docs = render(&["agent.output=webhook:https://example.com"]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--output"
    ));
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "webhook:https://example.com"
    ));
}

#[test]
fn metrics_port_in_args() {
    skip_no_helm!();
    let docs = render(&["metrics.enabled=true", "metrics.port=8080"]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--metrics-port"
    ));
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "8080"
    ));
}

#[test]
fn extra_args() {
    skip_no_helm!();
    let docs = render(&["agent.extraArgs[0]=--log-level", "agent.extraArgs[1]=debug"]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--log-level"
    ));
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "debug"
    ));
}

// ---------------------------------------------------------------------------
// Tests: metrics disabled
// ---------------------------------------------------------------------------

#[test]
fn metrics_disabled_no_service() {
    skip_no_helm!();
    let docs = render(&["metrics.enabled=false"]);
    assert_no_kind(&docs, "Service");
}

#[test]
fn metrics_disabled_no_port_args() {
    skip_no_helm!();
    let docs = render(&["metrics.enabled=false"]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();

    assert!(!array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--metrics-port"
    ));
    assert!(
        dig(ds, "spec.template.spec.containers.0.ports").is_none(),
        "no container ports when metrics disabled"
    );
}

// ---------------------------------------------------------------------------
// Tests: policies
// ---------------------------------------------------------------------------

#[test]
fn policies_enabled_creates_configmap() {
    skip_no_helm!();
    let docs = render(&[
        "policies.enabled=true",
        r"policies.rules.default\.rego=package busted",
    ]);

    assert_has_kind(&docs, "ConfigMap");
    let cm = find_by_kind(&docs, "ConfigMap").unwrap();
    assert!(
        dig(cm, "data").is_some(),
        "ConfigMap should have data section"
    );
}

#[test]
fn policies_enabled_mounts_volume() {
    skip_no_helm!();
    let docs = render(&[
        "policies.enabled=true",
        r"policies.rules.default\.rego=package busted",
    ]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    let mounts = dig(ds, "spec.template.spec.containers.0.volumeMounts")
        .and_then(|v| v.as_sequence().cloned())
        .unwrap();
    let mount_paths: Vec<&str> = mounts
        .iter()
        .filter_map(|m| m.get("mountPath").and_then(Value::as_str))
        .collect();

    assert!(mount_paths.contains(&"/etc/busted/policies"));
    assert!(array_contains_str(
        ds,
        "spec.template.spec.containers.0.args",
        "--policy-dir"
    ));
}

// ---------------------------------------------------------------------------
// Tests: RBAC
// ---------------------------------------------------------------------------

#[test]
fn rbac_disabled() {
    skip_no_helm!();
    let docs = render(&["rbac.create=false"]);
    assert_no_kind(&docs, "ClusterRole");
    assert_no_kind(&docs, "ClusterRoleBinding");
}

#[test]
fn rbac_default_permissions() {
    skip_no_helm!();
    let docs = render(&[]);
    let cr = find_by_kind(&docs, "ClusterRole").unwrap();
    let rules_yaml = serde_yaml::to_string(&dig(cr, "rules").unwrap()).unwrap();
    assert!(rules_yaml.contains("pods"), "should grant pod access");
    assert!(rules_yaml.contains("nodes"), "should grant node access");
    assert!(rules_yaml.contains("get"), "should allow get");
    assert!(rules_yaml.contains("list"), "should allow list");
    assert!(rules_yaml.contains("watch"), "should allow watch");
}

// ---------------------------------------------------------------------------
// Tests: ServiceMonitor
// ---------------------------------------------------------------------------

#[test]
fn servicemonitor_disabled_by_default() {
    skip_no_helm!();
    let docs = render(&[]);
    assert_no_kind(&docs, "ServiceMonitor");
}

#[test]
fn servicemonitor_enabled() {
    skip_no_helm!();
    let docs = render(&["metrics.serviceMonitor.enabled=true"]);
    assert_has_kind(&docs, "ServiceMonitor");
    let sm = find_by_kind(&docs, "ServiceMonitor").unwrap();
    assert_eq!(
        dig_str(sm, "apiVersion").unwrap(),
        "monitoring.coreos.com/v1"
    );
}

// ---------------------------------------------------------------------------
// Tests: resources
// ---------------------------------------------------------------------------

#[test]
fn default_resources() {
    skip_no_helm!();
    let docs = render(&[]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();

    let resources = dig(ds, "spec.template.spec.containers.0.resources").unwrap();
    let yaml = serde_yaml::to_string(&resources).unwrap();
    assert!(yaml.contains("50m"), "cpu request 50m");
    assert!(yaml.contains("64Mi"), "memory request 64Mi");
    assert!(yaml.contains("500m"), "cpu limit 500m");
    assert!(yaml.contains("256Mi"), "memory limit 256Mi");
}

// ---------------------------------------------------------------------------
// Tests: tolerations
// ---------------------------------------------------------------------------

#[test]
fn tolerations() {
    skip_no_helm!();
    let docs = render(&[
        "tolerations[0].key=node-role.kubernetes.io/control-plane",
        "tolerations[0].operator=Exists",
        "tolerations[0].effect=NoSchedule",
    ]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    let yaml = serde_yaml::to_string(&dig(ds, "spec.template.spec.tolerations").unwrap()).unwrap();
    assert!(yaml.contains("node-role.kubernetes.io/control-plane"));
}

// ---------------------------------------------------------------------------
// Tests: labels
// ---------------------------------------------------------------------------

#[test]
fn standard_labels() {
    skip_no_helm!();
    let docs = render(&[]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();
    let labels = dig(ds, "metadata.labels").unwrap();

    assert_eq!(
        labels.get("app.kubernetes.io/name").and_then(Value::as_str),
        Some("busted")
    );
    assert_eq!(
        labels
            .get("app.kubernetes.io/managed-by")
            .and_then(Value::as_str),
        Some("Helm")
    );
    assert_eq!(
        labels
            .get("app.kubernetes.io/version")
            .and_then(Value::as_str),
        Some("0.1.0")
    );
    assert_eq!(
        labels.get("helm.sh/chart").and_then(Value::as_str),
        Some("busted-0.1.0")
    );
}

#[test]
fn selector_labels_match_pod_labels() {
    skip_no_helm!();
    let docs = render(&[]);
    let ds = find_by_kind(&docs, "DaemonSet").unwrap();

    let selector = dig(ds, "spec.selector.matchLabels").unwrap();
    let pod_labels = dig(ds, "spec.template.metadata.labels").unwrap();

    // Every selector label must appear in pod labels
    for (k, v) in selector.as_mapping().unwrap() {
        assert_eq!(
            pod_labels.get(k),
            Some(v),
            "selector label {k:?}={v:?} missing from pod template"
        );
    }
}
