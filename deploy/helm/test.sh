#!/usr/bin/env bash
# Helm chart tests for busted.
# Uses plain `helm template` — no plugins required.
set -euo pipefail

CHART_DIR="$(cd "$(dirname "$0")/busted" && pwd)"
PASS=0
FAIL=0

assert() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS  $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $desc"
    FAIL=$((FAIL + 1))
  fi
}

assert_not() {
  local desc="$1"; shift
  if ! "$@" >/dev/null 2>&1; then
    echo "  PASS  $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $desc"
    FAIL=$((FAIL + 1))
  fi
}

render() {
  helm template busted "$CHART_DIR" "$@" 2>&1
}

# ── Lint ──────────────────────────────────────────────────────────────────────

echo "=== Lint ==="
assert "chart passes helm lint" helm lint "$CHART_DIR"

# ── Defaults ──────────────────────────────────────────────────────────────────

echo "=== Default values ==="
DEFAULT=$(render)

assert "renders a DaemonSet" \
  grep -q "kind: DaemonSet" <<< "$DEFAULT"

assert "renders a ServiceAccount" \
  grep -q "kind: ServiceAccount" <<< "$DEFAULT"

assert "renders a ClusterRole" \
  grep -q "kind: ClusterRole" <<< "$DEFAULT"

assert "renders a ClusterRoleBinding" \
  grep -q "kind: ClusterRoleBinding" <<< "$DEFAULT"

assert "renders a Service (metrics enabled by default)" \
  grep -q "kind: Service" <<< "$DEFAULT"

assert_not "does not render ConfigMap by default" \
  grep -q "kind: ConfigMap" <<< "$DEFAULT"

assert_not "does not render ServiceMonitor by default" \
  grep -q "kind: ServiceMonitor" <<< "$DEFAULT"

# ── Image ─────────────────────────────────────────────────────────────────────

echo "=== Image ==="

assert "uses default image ghcr.io/barakber/busted:0.1.0" \
  grep -q "image: ghcr.io/barakber/busted:0.1.0" <<< "$DEFAULT"

CUSTOM_TAG=$(render --set image.tag=2.0.0)
assert "respects custom image tag" \
  grep -q "image: ghcr.io/barakber/busted:2.0.0" <<< "$CUSTOM_TAG"

CUSTOM_REPO=$(render --set image.repository=myregistry.io/busted)
assert "respects custom image repository" \
  grep -q "image: myregistry.io/busted:0.1.0" <<< "$CUSTOM_REPO"

# ── DaemonSet security ───────────────────────────────────────────────────────

echo "=== DaemonSet security ==="

assert "sets hostPID: true" \
  grep -q "hostPID: true" <<< "$DEFAULT"

assert "sets hostNetwork: true" \
  grep -q "hostNetwork: true" <<< "$DEFAULT"

assert "runs privileged" \
  grep -q "privileged: true" <<< "$DEFAULT"

# ── DaemonSet volumes ────────────────────────────────────────────────────────

echo "=== DaemonSet volumes ==="

assert "mounts /sys" \
  grep -q "mountPath: /sys" <<< "$DEFAULT"

assert "mounts /proc" \
  grep -q "mountPath: /proc" <<< "$DEFAULT"

assert "mounts /lib/modules" \
  grep -q "mountPath: /lib/modules" <<< "$DEFAULT"

assert_not "does not mount policies volume by default" \
  grep -q "mountPath: /etc/busted/policies" <<< "$DEFAULT"

# ── Agent CLI args ────────────────────────────────────────────────────────────

echo "=== Agent CLI args ==="

assert "passes --format json by default" \
  grep -q '"json"' <<< "$DEFAULT"

assert_not "does not pass --verbose by default" \
  grep -q '"\-\-verbose"' <<< "$DEFAULT"

assert_not "does not pass --enforce by default" \
  grep -q '"\-\-enforce"' <<< "$DEFAULT"

assert_not "does not pass --output by default (stdout)" \
  grep -q '"\-\-output"' <<< "$DEFAULT"

assert "passes --metrics-port by default" \
  grep -q '"\-\-metrics\-port"' <<< "$DEFAULT"

TEXT_FMT=$(render --set agent.format=text)
assert "passes --format text when configured" \
  grep -q '"text"' <<< "$TEXT_FMT"

VERBOSE=$(render --set agent.verbose=true)
assert "passes --verbose when enabled" \
  grep -q '"\-\-verbose"' <<< "$VERBOSE"

ENFORCE=$(render --set agent.enforce=true)
assert "passes --enforce when enabled" \
  grep -q '"\-\-enforce"' <<< "$ENFORCE"

OUTPUT=$(render --set 'agent.output=webhook:https://example.com')
assert "passes --output when not stdout" \
  grep -q '"\-\-output"' <<< "$OUTPUT"

EXTRA=$(render --set 'agent.extraArgs[0]=--log-level' --set 'agent.extraArgs[1]=debug')
assert "passes extraArgs" \
  grep -q '"debug"' <<< "$EXTRA"

# ── Metrics disabled ─────────────────────────────────────────────────────────

echo "=== Metrics disabled ==="
NO_METRICS=$(render --set metrics.enabled=false)

assert_not "no Service when metrics disabled" \
  grep -qP "kind: Service$" <<< "$NO_METRICS"

assert_not "no --metrics-port when metrics disabled" \
  grep -q '"\-\-metrics\-port"' <<< "$NO_METRICS"

assert_not "no containerPort when metrics disabled" \
  grep -q "containerPort:" <<< "$NO_METRICS"

# ── Policies ──────────────────────────────────────────────────────────────────

echo "=== Policies ==="
POLICIES=$(render --set policies.enabled=true \
  --set 'policies.rules.default\.rego=package busted')

assert "renders ConfigMap when policies enabled" \
  grep -q "kind: ConfigMap" <<< "$POLICIES"

assert "ConfigMap has policy data" \
  grep -q "default.rego" <<< "$POLICIES"

assert "mounts policies volume" \
  grep -q "mountPath: /etc/busted/policies" <<< "$POLICIES"

assert "passes --policy-dir" \
  grep -q '"\-\-policy\-dir"' <<< "$POLICIES"

# ── RBAC disabled ─────────────────────────────────────────────────────────────

echo "=== RBAC disabled ==="
NO_RBAC=$(render --set rbac.create=false)

assert_not "no ClusterRole when rbac.create=false" \
  grep -q "kind: ClusterRole" <<< "$NO_RBAC"

assert_not "no ClusterRoleBinding when rbac.create=false" \
  grep -q "kind: ClusterRoleBinding" <<< "$NO_RBAC"

# ── RBAC permissions ─────────────────────────────────────────────────────────

echo "=== RBAC permissions ==="

assert "ClusterRole grants pod access" \
  grep -q '"pods"' <<< "$DEFAULT"

assert "ClusterRole grants node access" \
  grep -q '"nodes"' <<< "$DEFAULT"

assert "ClusterRole allows get/list/watch" \
  grep -q '"get"' <<< "$DEFAULT"

# ── ServiceMonitor ────────────────────────────────────────────────────────────

echo "=== ServiceMonitor ==="
SM=$(render --set metrics.serviceMonitor.enabled=true)

assert "renders ServiceMonitor when enabled" \
  grep -q "kind: ServiceMonitor" <<< "$SM"

assert "ServiceMonitor uses monitoring.coreos.com/v1" \
  grep -q "monitoring.coreos.com/v1" <<< "$SM"

assert "ServiceMonitor scrapes metrics port" \
  grep -q "port: metrics" <<< "$SM"

# ── Resources ─────────────────────────────────────────────────────────────────

echo "=== Resources ==="

assert "sets default CPU request" \
  grep -q "cpu: 50m" <<< "$DEFAULT"

assert "sets default memory request" \
  grep -q "memory: 64Mi" <<< "$DEFAULT"

assert "sets default CPU limit" \
  grep -q "cpu: 500m" <<< "$DEFAULT"

assert "sets default memory limit" \
  grep -q "memory: 256Mi" <<< "$DEFAULT"

# ── Tolerations ───────────────────────────────────────────────────────────────

echo "=== Tolerations ==="
TOLERATE=$(render \
  --set 'tolerations[0].key=node-role.kubernetes.io/control-plane' \
  --set 'tolerations[0].operator=Exists' \
  --set 'tolerations[0].effect=NoSchedule')

assert "renders tolerations when set" \
  grep -q "node-role.kubernetes.io/control-plane" <<< "$TOLERATE"

# ── Labels ────────────────────────────────────────────────────────────────────

echo "=== Labels ==="

assert "includes app.kubernetes.io/name" \
  grep -q "app.kubernetes.io/name: busted" <<< "$DEFAULT"

assert "includes app.kubernetes.io/managed-by: Helm" \
  grep -q "app.kubernetes.io/managed-by: Helm" <<< "$DEFAULT"

assert "includes app.kubernetes.io/version" \
  grep -q 'app.kubernetes.io/version: "0.1.0"' <<< "$DEFAULT"

assert "includes helm.sh/chart label" \
  grep -q "helm.sh/chart: busted-0.1.0" <<< "$DEFAULT"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "────────────────────────────────────"
echo "  $PASS passed, $FAIL failed"
echo "────────────────────────────────────"

[[ $FAIL -eq 0 ]]
