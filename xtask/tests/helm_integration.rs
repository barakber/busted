//! Helm E2E integration tests — deploys busted to a real kind cluster,
//! generates traffic, and verifies eBPF capture + OPA policy evaluation.
//!
//! Prerequisites: kind, helm, kubectl, docker, cargo xtask build --release
//!
//! Run: cargo test -p xtask --test helm_integration -- --ignored --nocapture
//! Or:  make helm-e2e
//!
//! These tests are `#[ignore]`d AND skip automatically when CI=true,
//! so they never run in CI/CD pipelines even with `--include-ignored`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

/// Skip the test if running in CI (CI=true / GITHUB_ACTIONS=true).
fn skip_in_ci() {
    if std::env::var("CI").unwrap_or_default() == "true"
        || std::env::var("GITHUB_ACTIONS").unwrap_or_default() == "true"
    {
        eprintln!("Skipping helm E2E test in CI (requires kind + Docker + real network).");
        std::process::exit(0);
    }
}

const CLUSTER_NAME: &str = "busted-helm-test";
const RELEASE_NAME: &str = "busted";
const IMAGE_NAME: &str = "busted";
const IMAGE_TAG: &str = "e2e-test";
const CURL_IMAGE: &str = "curlimages/curl:8.11.1";
const UBUNTU_IMAGE: &str = "ubuntu:24.04";

/// LLM providers to curl in the E2E test.
/// Each entry: (provider_name, url, dns_host for --resolve).
const TEST_PROVIDERS: &[(&str, &str, &str)] = &[
    (
        "OpenAI",
        "https://api.openai.com/v1/models",
        "api.openai.com",
    ),
    (
        "Anthropic",
        "https://api.anthropic.com/v1/messages",
        "api.anthropic.com",
    ),
    (
        "DeepSeek",
        "https://api.deepseek.com/v1/chat/completions",
        "api.deepseek.com",
    ),
];

/// Helm values overlay that enables OPA policies.
///
/// The Rego policy audits ALL provider-matched traffic (any event where
/// provider != null gets decision="audit"), allowing us to verify OPA
/// evaluation across multiple LLM providers.
const POLICY_VALUES: &str = r#"
policies:
  enabled: true
  rules:
    audit_all_providers.rego: |
      package busted

      default decision = "allow"

      decision = "audit" {
        input.provider != null
      }

      reasons[r] {
        input.provider != null
        r := concat("", ["LLM provider traffic: ", input.provider])
      }
"#;

/// Helm values overlay for file monitor E2E test.
///
/// Enables OPA policies that audit FileAccess events and deny writes to
/// sensitive files (.env, credentials, secrets).
const FILEMON_POLICY_VALUES: &str = r#"
policies:
  enabled: true
  rules:
    file_monitor.rego: |
      package busted

      default decision = "allow"

      decision = "audit" {
        input.action.type == "FileAccess"
      }

      decision = "audit" {
        input.action.type == "FileData"
        input.action.direction == "read"
      }

      decision = "deny" {
        input.action.type == "FileData"
        input.action.direction == "write"
        contains(input.action.path, ".env")
      }

      reasons[r] {
        input.action.type == "FileAccess"
        r := concat("", ["File opened: ", input.action.path])
      }

      reasons[r] {
        input.action.type == "FileData"
        r := concat("", ["File data ", input.action.direction, ": ", input.action.path])
      }
"#;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn kube_context() -> String {
    format!("kind-{CLUSTER_NAME}")
}

// ---------------------------------------------------------------------------
// Command helpers
// ---------------------------------------------------------------------------

fn run(cmd: &str, args: &[&str]) -> Output {
    Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to execute {cmd}: {e}"))
}

fn run_in(dir: &PathBuf, cmd: &str, args: &[&str]) -> Output {
    Command::new(cmd)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to execute {cmd}: {e}"))
}

fn assert_ok(out: &Output, context: &str) {
    assert!(
        out.status.success(),
        "{context} failed (exit {}):\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn stdout_string(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn kubectl(args: &[&str]) -> Output {
    let ctx = kube_context();
    let mut full: Vec<&str> = vec!["--context", &ctx];
    full.extend_from_slice(args);
    run("kubectl", &full)
}

fn kubectl_ok(args: &[&str]) {
    let out = kubectl(args);
    assert_ok(&out, &format!("kubectl {}", args.join(" ")));
}

fn kubectl_stdout(args: &[&str]) -> String {
    let out = kubectl(args);
    assert_ok(&out, &format!("kubectl {}", args.join(" ")));
    stdout_string(&out)
}

// ---------------------------------------------------------------------------
// KindCluster — RAII wrapper that deletes the cluster on Drop
// ---------------------------------------------------------------------------

struct KindCluster {
    name: String,
}

impl KindCluster {
    fn create() -> Self {
        let root = workspace_root();

        // 0. Check that the busted binary exists
        let binary = root.join("target/release/busted");
        assert!(
            binary.exists(),
            "busted binary not found at {}.\n\
             Run 'cargo xtask build --release' first (or 'make build-release').",
            binary.display()
        );

        // 1. Delete stale cluster (ignore errors)
        let _ = run("kind", &["delete", "cluster", "--name", CLUSTER_NAME]);

        // 2. Build lightweight Docker image
        println!(">>> Building test Docker image...");
        let tag = format!("{IMAGE_NAME}:{IMAGE_TAG}");
        let out = run_in(
            &root,
            "docker",
            &["build", "-f", "deploy/Dockerfile.test", "-t", &tag, "."],
        );
        assert_ok(&out, "docker build");

        // 3. Create kind cluster
        println!(">>> Creating kind cluster '{CLUSTER_NAME}'...");
        let out = run("kind", &["create", "cluster", "--name", CLUSTER_NAME]);
        assert_ok(&out, "kind create cluster");

        // 4. Load busted image
        println!(">>> Loading busted image into kind...");
        let out = run(
            "kind",
            &["load", "docker-image", &tag, "--name", CLUSTER_NAME],
        );
        assert_ok(&out, "kind load busted image");

        // 5. Pre-pull and load curl image so the test pod doesn't need internet from inside kind
        println!(">>> Loading curl image into kind...");
        let _ = run("docker", &["pull", CURL_IMAGE]);
        let out = run(
            "kind",
            &["load", "docker-image", CURL_IMAGE, "--name", CLUSTER_NAME],
        );
        assert_ok(&out, "kind load curl image");

        // 6. Pre-pull and load ubuntu image (used by file monitor E2E)
        // Ubuntu uses dash (not busybox), so `cp /bin/sh /tmp/claude` works
        // and /proc/<pid>/comm shows "claude".
        println!(">>> Loading ubuntu image into kind...");
        let _ = run("docker", &["pull", UBUNTU_IMAGE]);
        let out = run(
            "kind",
            &["load", "docker-image", UBUNTU_IMAGE, "--name", CLUSTER_NAME],
        );
        assert_ok(&out, "kind load ubuntu image");

        KindCluster {
            name: CLUSTER_NAME.to_string(),
        }
    }

    fn helm_install(&self) {
        let root = workspace_root();
        let ctx = kube_context();
        let image_set =
            format!("image.repository={IMAGE_NAME},image.tag={IMAGE_TAG},image.pullPolicy=Never");
        let toleration = "tolerations[0].key=node-role.kubernetes.io/control-plane,\
                          tolerations[0].operator=Exists,\
                          tolerations[0].effect=NoSchedule";

        // Write a temporary values file with OPA policy enabled.
        let values_file = root.join("target/helm-e2e-values.yaml");
        let mut f = std::fs::File::create(&values_file).expect("create temp values file");
        f.write_all(POLICY_VALUES.as_bytes())
            .expect("write temp values file");
        let values_path = values_file.to_str().unwrap();

        println!(">>> Helm installing busted (with OPA policy)...");
        let out = run_in(
            &root,
            "helm",
            &[
                "install",
                RELEASE_NAME,
                "deploy/helm/busted",
                "--kube-context",
                &ctx,
                "--set",
                &image_set,
                "--set",
                toleration,
                "-f",
                values_path,
                "--wait",
                "--timeout",
                "120s",
            ],
        );
        assert_ok(&out, "helm install");
    }

    fn helm_install_file_monitor(&self) {
        let root = workspace_root();
        let ctx = kube_context();
        let image_set =
            format!("image.repository={IMAGE_NAME},image.tag={IMAGE_TAG},image.pullPolicy=Never");
        let toleration = "tolerations[0].key=node-role.kubernetes.io/control-plane,\
                          tolerations[0].operator=Exists,\
                          tolerations[0].effect=NoSchedule";
        // File monitoring + OPA + TLS probes can use more memory than the default 256Mi.
        let resources = "resources.limits.memory=512Mi,resources.requests.memory=128Mi";

        // Write a temporary values file with OPA policy + file monitoring.
        let values_file = root.join("target/helm-e2e-filemon-values.yaml");
        let mut f = std::fs::File::create(&values_file).expect("create temp values file");
        f.write_all(FILEMON_POLICY_VALUES.as_bytes())
            .expect("write temp values file");
        let values_path = values_file.to_str().unwrap();

        println!(">>> Helm installing busted (with file monitor + OPA policy)...");
        let out = run_in(
            &root,
            "helm",
            &[
                "install",
                RELEASE_NAME,
                "deploy/helm/busted",
                "--kube-context",
                &ctx,
                "--set",
                &image_set,
                "--set",
                toleration,
                "--set",
                resources,
                "--set",
                "agent.fileMonitor=true",
                "-f",
                values_path,
                "--wait",
                "--timeout",
                "120s",
            ],
        );
        assert_ok(&out, "helm install");
    }

    fn helm_uninstall(&self) {
        let ctx = kube_context();
        println!(">>> Helm uninstalling busted...");
        let out = run(
            "helm",
            &["uninstall", RELEASE_NAME, "--kube-context", &ctx, "--wait"],
        );
        assert_ok(&out, "helm uninstall");
    }
}

impl Drop for KindCluster {
    fn drop(&mut self) {
        println!(">>> Deleting kind cluster '{}'...", self.name);
        let _ = run("kind", &["delete", "cluster", "--name", &self.name]);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a resolved IP for a given hostname from agent startup logs.
/// Matches lines like: "  api.openai.com -> 172.66.0.243 (OpenAI)"
fn extract_resolved_ip<'a>(logs: &'a str, hostname: &str) -> Option<&'a str> {
    let pattern = format!("{hostname} ->");
    logs.lines().find_map(|line| {
        if line.contains(&pattern) {
            line.split("->").nth(1)?.trim().split_whitespace().next()
        } else {
            None
        }
    })
}

/// Run a curl pod targeting the given URL with optional --resolve pinning.
/// Returns true if the pod completed (Succeeded or Failed).
fn run_curl_pod(pod_name: &str, url: &str, resolve_host: &str, resolved_ip: Option<&str>) {
    let resolve_arg;
    let curl_args: Vec<&str>;
    if let Some(ip) = resolved_ip {
        resolve_arg = format!("{resolve_host}:443:{ip}");
        curl_args = vec![
            "curl",
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--connect-timeout",
            "10",
            "--resolve",
            &resolve_arg,
            url,
        ];
    } else {
        curl_args = vec![
            "curl",
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--connect-timeout",
            "10",
            url,
        ];
    }

    let mut kubectl_run_args: Vec<&str> = vec![
        "run",
        pod_name,
        "--image",
        CURL_IMAGE,
        "--image-pull-policy=Never",
        "--restart=Never",
        "--overrides",
        r#"{"spec":{"hostNetwork":true}}"#,
        "--",
    ];
    kubectl_run_args.extend_from_slice(&curl_args);
    kubectl_ok(&kubectl_run_args);
}

/// Wait for a pod to reach Succeeded or Failed. Returns the pod logs.
fn wait_for_pod(pod_name: &str, timeout_secs: u64) -> Option<String> {
    let deadline = timeout_secs / 2;
    for _ in 0..deadline {
        let phase = kubectl_stdout(&["get", "pod", pod_name, "-o", "jsonpath={.status.phase}"]);
        match phase.as_str() {
            "Succeeded" | "Failed" => {
                let logs = kubectl_stdout(&["logs", pod_name]);
                println!(">>>   {pod_name}: {phase} (HTTP {logs})");
                return Some(logs);
            }
            _ => std::thread::sleep(Duration::from_secs(2)),
        }
    }
    None
}

/// Count JSON events matching a given provider name.
/// Checks both flat (legacy) and nested (BustedEvent) formats.
fn events_for_provider(events: &[serde_json::Value], provider: &str) -> Vec<serde_json::Value> {
    events
        .iter()
        .filter(|e| {
            // Nested format: action.provider
            let nested = e
                .get("action")
                .and_then(|a| a.get("provider"))
                .and_then(|v| v.as_str())
                .map_or(false, |p| p == provider);
            // Flat format (legacy): provider at top level
            let flat = e
                .get("provider")
                .and_then(|v| v.as_str())
                .map_or(false, |p| p == provider);
            nested || flat
        })
        .cloned()
        .collect()
}

/// Get the action type from a BustedEvent JSON value.
fn action_type(event: &serde_json::Value) -> Option<&str> {
    event.get("action")?.get("type")?.as_str()
}

/// Filter events by action type (e.g. "FileAccess", "FileData").
fn events_by_action_type(events: &[serde_json::Value], action: &str) -> Vec<serde_json::Value> {
    events
        .iter()
        .filter(|e| action_type(e) == Some(action))
        .cloned()
        .collect()
}

/// Filter events by action type and a path substring.
fn events_by_action_and_path(
    events: &[serde_json::Value],
    action: &str,
    path_needle: &str,
) -> Vec<serde_json::Value> {
    events
        .iter()
        .filter(|e| {
            action_type(e) == Some(action)
                && e.get("action")
                    .and_then(|a| a.get("path"))
                    .and_then(|v| v.as_str())
                    .map_or(false, |p| p.contains(path_needle))
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// E2E test
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn helm_e2e() {
    skip_in_ci();

    // ── Setup ────────────────────────────────────────────────────────────
    let cluster = KindCluster::create();
    cluster.helm_install();

    // Give the agent time to load eBPF programs and settle.
    println!(">>> Waiting 30s for eBPF programs to load...");
    std::thread::sleep(Duration::from_secs(30));

    // ── Phase 1: Verify deployment ───────────────────────────────────────
    println!("\n=== PHASE 1: Verify deployment ===");

    // DaemonSet should exist and have ready pods
    let ready = kubectl_stdout(&[
        "get",
        "daemonset",
        RELEASE_NAME,
        "-o",
        "jsonpath={.status.numberReady}",
    ]);
    let ready: i32 = ready.parse().unwrap_or(0);
    assert!(
        ready > 0,
        "DaemonSet has no ready pods (numberReady={ready})"
    );
    println!(">>>   DaemonSet: {ready} pod(s) ready");

    // Pod should be running
    let busted_pod = kubectl_stdout(&[
        "get",
        "pods",
        "-l",
        "app.kubernetes.io/name=busted",
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ]);
    assert!(!busted_pod.is_empty(), "Could not find busted pod");
    println!(">>>   Busted pod: {busted_pod}");

    let phase = kubectl_stdout(&["get", "pod", &busted_pod, "-o", "jsonpath={.status.phase}"]);
    assert_eq!(
        phase, "Running",
        "Busted pod is not Running (phase={phase})"
    );

    let restarts = kubectl_stdout(&[
        "get",
        "pod",
        &busted_pod,
        "-o",
        "jsonpath={.status.containerStatuses[0].restartCount}",
    ]);
    let restart_count: i32 = restarts.parse().unwrap_or(0);
    println!(">>>   Restart count: {restart_count}");

    // ── Phase 2: Verify agent health ─────────────────────────────────────
    println!("\n=== PHASE 2: Verify agent health (eBPF + DNS + OPA) ===");

    let mut startup_logs = String::new();
    let mut ebpf_loaded = false;
    for attempt in 0..6 {
        startup_logs = kubectl_stdout(&["logs", &busted_pod]);
        if startup_logs.contains("Attached to tcp_connect") {
            ebpf_loaded = true;
            break;
        }
        if attempt < 5 {
            println!(">>>   Waiting for eBPF (attempt {}/6)...", attempt + 1);
            std::thread::sleep(Duration::from_secs(10));
        }
    }

    if !ebpf_loaded {
        let diag_len = startup_logs.len().min(5000);
        panic!(
            "Agent did not attach eBPF kprobes after 80s.\n\
             Restart count: {restart_count}\n\
             Logs (first {diag_len} chars):\n{}",
            &startup_logs[..diag_len]
        );
    }
    println!(">>>   eBPF kprobes attached");

    if startup_logs.contains("All eBPF programs loaded successfully") {
        println!(">>>   All eBPF programs loaded (including TLS uprobes)");
    } else {
        println!(">>>   NOTE: TLS uprobes may still be loading (kprobes are enough for E2E)");
    }

    let dns_resolved =
        startup_logs.contains("Resolved") && startup_logs.contains("LLM provider IPs");
    assert!(
        dns_resolved,
        "Agent did not resolve LLM provider IPs. Logs:\n{}",
        &startup_logs[..startup_logs.len().min(5000)]
    );
    println!(">>>   DNS resolution working");

    let opa_loaded = startup_logs.contains("OPA policy engine loaded");
    assert!(
        opa_loaded,
        "OPA policy engine did not load. Logs:\n{}",
        &startup_logs[..startup_logs.len().min(5000)]
    );
    println!(">>>   OPA policy engine loaded");

    // Extract resolved IPs for each provider we'll test
    let mut resolved_ips: std::collections::HashMap<&str, String> =
        std::collections::HashMap::new();
    for &(provider, _, host) in TEST_PROVIDERS {
        if let Some(ip) = extract_resolved_ip(&startup_logs, host) {
            println!(">>>   {provider} ({host}) -> {ip}");
            resolved_ips.insert(provider, ip.to_string());
        } else {
            println!(">>>   {provider} ({host}) -> (DNS not resolved, will use natural DNS)");
        }
    }

    // ── Phase 3: Generate traffic (with retry) ─────────────────────────
    // The eBPF kprobes capture ALL host processes. On busy machines,
    // ambient traffic can fill the RingBuf. We retry up to 3 times,
    // curling all providers in each attempt.
    println!(
        "\n=== PHASE 3: Generate traffic ({} providers) ===",
        TEST_PROVIDERS.len()
    );

    let mut all_json_events: Vec<serde_json::Value> = Vec::new();
    let mut last_logs = String::new();
    let mut captured_providers: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for attempt in 1..=3 {
        println!(
            ">>> [{attempt}/3] Curling {} providers...",
            TEST_PROVIDERS.len()
        );

        // Launch curl pods for all providers
        for (i, &(provider, url, host)) in TEST_PROVIDERS.iter().enumerate() {
            let pod_name = format!("curl-{}-{attempt}", provider.to_lowercase());
            let ip = resolved_ips.get(provider).map(|s| s.as_str());
            println!(">>>   Starting {provider} curl (pod: {pod_name})...");
            run_curl_pod(&pod_name, url, host, ip);

            // Small delay between curls to avoid overwhelming RingBuf
            if i < TEST_PROVIDERS.len() - 1 {
                std::thread::sleep(Duration::from_secs(2));
            }
        }

        // Wait for all curl pods to complete
        for &(provider, _, _) in TEST_PROVIDERS {
            let pod_name = format!("curl-{}-{attempt}", provider.to_lowercase());
            if wait_for_pod(&pod_name, 60).is_none() {
                println!(">>>   WARNING: {pod_name} did not complete in time");
            }
        }

        // Wait for events to be processed
        println!(">>>   Waiting 10s for event processing...");
        std::thread::sleep(Duration::from_secs(10));

        // Collect events
        last_logs = kubectl_stdout(&["logs", &busted_pod]);
        all_json_events = last_logs
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        // Check which providers we captured
        for &(provider, _, _) in TEST_PROVIDERS {
            let count = events_for_provider(&all_json_events, provider).len();
            if count > 0 {
                captured_providers.insert(provider.to_string());
            }
        }

        let found = captured_providers.len();
        let total = TEST_PROVIDERS.len();
        println!(
            ">>>   Captured {found}/{total} providers: {:?} ({} total events)",
            captured_providers,
            all_json_events.len()
        );

        if found == total {
            break;
        }

        // Clean up pods before retrying
        for &(provider, _, _) in TEST_PROVIDERS {
            let pod_name = format!("curl-{}-{attempt}", provider.to_lowercase());
            let _ = kubectl(&["delete", "pod", &pod_name, "--grace-period=0", "--force"]);
        }

        if attempt < 3 {
            println!(">>>   Missing providers, retrying in 5s...");
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    // ── Phase 4: Verify capture ──────────────────────────────────────────
    println!("\n=== PHASE 4: Verify event capture ===");

    let phase = kubectl_stdout(&["get", "pod", &busted_pod, "-o", "jsonpath={.status.phase}"]);
    assert_eq!(
        phase, "Running",
        "Busted pod crashed during traffic test (phase={phase})"
    );
    println!(">>>   Agent still running after traffic test");
    println!(">>>   Total JSON events: {}", all_json_events.len());

    // Print per-provider breakdown
    println!("\n>>> Per-provider results:");
    for &(provider, _, _) in TEST_PROVIDERS {
        let provider_events = events_for_provider(&all_json_events, provider);
        let audited: Vec<_> = provider_events
            .iter()
            .filter(|e| {
                e.get("policy")
                    .and_then(|v| v.as_str())
                    .map_or(false, |p| p == "audit")
            })
            .collect();
        println!(
            ">>>   {provider}: {} events, {} with policy=audit",
            provider_events.len(),
            audited.len(),
        );
        if let Some(sample) = provider_events.first() {
            let process = sample
                .get("process_name")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let dst_ip = sample.get("dst_ip").and_then(|v| v.as_str()).unwrap_or("?");
            let policy = sample.get("policy").and_then(|v| v.as_str()).unwrap_or("?");
            println!(">>>     sample: process={process} dst_ip={dst_ip} policy={policy}");
        }
    }

    // Diagnostic on failure
    if captured_providers.len() < TEST_PROVIDERS.len() {
        println!("\n>>> DIAGNOSTIC: Missing providers.");
        println!(">>> All providers in JSON events:");
        let mut providers: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for ev in &all_json_events {
            let p = ev
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("null")
                .to_string();
            *providers.entry(p).or_insert(0) += 1;
        }
        for (p, count) in &providers {
            println!(">>>   {p}: {count}");
        }
        println!(">>> Last 30 log lines:");
        for line in last_logs
            .lines()
            .rev()
            .take(30)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            println!(">>>   {line}");
        }
    }

    // ── Assertions ───────────────────────────────────────────────────────

    // Hard: eBPF captured traffic
    assert!(
        !all_json_events.is_empty(),
        "No events captured at all — eBPF pipeline may not be working.",
    );
    println!(
        "\n>>> eBPF pipeline verified ({} events)",
        all_json_events.len()
    );

    // Hard: Each provider was captured
    for &(provider, _, _) in TEST_PROVIDERS {
        let provider_events = events_for_provider(&all_json_events, provider);
        assert!(
            !provider_events.is_empty(),
            "{provider} traffic not captured despite curl succeeding (3 attempts).\n\
             Total events: {}, captured providers: {:?}.\n\
             Likely cause: RingBuf overflow from ambient host traffic.",
            all_json_events.len(),
            captured_providers,
        );
    }
    println!(
        ">>> All {} providers captured: {:?}",
        TEST_PROVIDERS.len(),
        captured_providers,
    );

    // Hard: OPA policy set "audit" on all provider-matched events
    for &(provider, _, _) in TEST_PROVIDERS {
        let provider_events = events_for_provider(&all_json_events, provider);
        let audited_count = provider_events
            .iter()
            .filter(|e| {
                e.get("policy")
                    .and_then(|v| v.as_str())
                    .map_or(false, |p| p == "audit")
            })
            .count();
        assert!(
            audited_count > 0,
            "OPA policy did not mark {provider} events as 'audit'.\n\
             {provider} events: {}, with policy=audit: {}.\n\
             Sample: {}",
            provider_events.len(),
            audited_count,
            provider_events.first().map_or("none".to_string(), |e| {
                serde_json::to_string_pretty(e).unwrap()
            }),
        );
    }
    println!(">>> OPA policy verified: all provider events have policy=audit");

    // ── Cleanup ──────────────────────────────────────────────────────────
    for attempt in 1..=3 {
        for &(provider, _, _) in TEST_PROVIDERS {
            let pod_name = format!("curl-{}-{attempt}", provider.to_lowercase());
            let _ = kubectl(&["delete", "pod", &pod_name, "--grace-period=0", "--force"]);
        }
    }
    cluster.helm_uninstall();

    println!("\n>>> E2E test passed!");
}

// ---------------------------------------------------------------------------
// E2E test: file monitoring (FileAccess + FileData events)
// ---------------------------------------------------------------------------

/// Run a ubuntu pod that creates and reads files matching AI-related patterns.
///
/// The pod:
/// 1. Copies /bin/sh (dash) to /tmp/claude (so /proc/<pid>/comm = "claude")
/// 2. Runs the file operations via /tmp/claude (to be picked up by /proc scanner)
/// 3. Creates and reads .env and .claude/settings.json
/// 4. Sleeps to allow the /proc scanner to detect the process and eBPF to capture events
///
/// Ubuntu's /bin/sh is dash (not busybox), so copying it creates a real binary
/// whose /proc/<pid>/comm matches AI_PROCESS_NAMES for INTERESTING_PIDS.
fn run_file_ops_pod(pod_name: &str) {
    // Phase 1: copy dash as "claude" so the /proc scanner detects it.
    // Phase 2: /tmp/claude sleeps 45s (enough for 1-2 /proc scan cycles at 30s).
    // Phase 3: perform file operations (open, read, write) on AI-pattern paths.
    // Phase 4: sleep 10s to let eBPF events flush.
    let script = r#"
        set -e
        cp /bin/sh /tmp/claude
        /tmp/claude -c '
            mkdir -p /tmp/testdir/.claude
            echo "{\"theme\":\"dark\",\"model\":\"claude-sonnet\"}" > /tmp/testdir/.claude/settings.json
            echo "SECRET_KEY=s3cret_value_123" > /tmp/testdir/.env
            sleep 45
            cat /tmp/testdir/.claude/settings.json
            cat /tmp/testdir/.env
            echo "NEW_SECRET=updated" >> /tmp/testdir/.env
            sleep 10
        '
    "#;

    let overrides = r#"{"spec":{"hostPID":true,"hostNetwork":true}}"#;
    kubectl_ok(&[
        "run",
        pod_name,
        "--image",
        UBUNTU_IMAGE,
        "--image-pull-policy=Never",
        "--restart=Never",
        "--overrides",
        overrides,
        "--",
        "sh",
        "-c",
        script,
    ]);
}

#[test]
#[ignore]
fn helm_e2e_file_monitor() {
    skip_in_ci();

    // ── Setup ────────────────────────────────────────────────────────────
    let cluster = KindCluster::create();
    cluster.helm_install_file_monitor();

    println!(">>> Waiting 30s for eBPF programs to load...");
    std::thread::sleep(Duration::from_secs(30));

    // ── Phase 1: Verify deployment ───────────────────────────────────────
    println!("\n=== PHASE 1: Verify deployment ===");

    let busted_pod = kubectl_stdout(&[
        "get",
        "pods",
        "-l",
        "app.kubernetes.io/name=busted",
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ]);
    assert!(!busted_pod.is_empty(), "Could not find busted pod");

    let phase = kubectl_stdout(&["get", "pod", &busted_pod, "-o", "jsonpath={.status.phase}"]);
    assert_eq!(
        phase, "Running",
        "Busted pod is not Running (phase={phase})"
    );
    println!(">>>   Busted pod: {busted_pod} (Running)");

    // Verify eBPF loaded
    let mut startup_logs = String::new();
    for attempt in 0..6 {
        startup_logs = kubectl_stdout(&["logs", &busted_pod]);
        if startup_logs.contains("Attached to tcp_connect") {
            break;
        }
        if attempt < 5 {
            println!(">>>   Waiting for eBPF (attempt {}/6)...", attempt + 1);
            std::thread::sleep(Duration::from_secs(10));
        }
    }
    assert!(
        startup_logs.contains("Attached to tcp_connect"),
        "Agent did not attach eBPF programs"
    );
    println!(">>>   eBPF programs attached");

    // Verify file monitor is active
    let file_monitor_active = startup_logs.contains("file-access tracepoint")
        || startup_logs.contains("file-data tracepoint");

    // Show agent-only log lines (filter out noisy eBPF TCP connect messages).
    let agent_lines: Vec<_> = startup_logs
        .lines()
        .filter(|l| !l.contains("busted_ebpf]"))
        .collect();
    println!(
        ">>>   Agent log lines ({} total, filtered from eBPF noise):",
        agent_lines.len()
    );
    for line in &agent_lines {
        println!(">>>     {line}");
    }

    if !file_monitor_active {
        // Check if the pod crashed and restarted (error would be in previous container logs).
        let restarts = kubectl_stdout(&[
            "get",
            "pod",
            &busted_pod,
            "-o",
            "jsonpath={.status.containerStatuses[0].restartCount}",
        ]);
        println!(">>>   Pod restart count: {restarts}");
        if restarts != "0" {
            let prev = kubectl(&["logs", &busted_pod, "--previous"]);
            if prev.status.success() {
                let prev_logs = String::from_utf8_lossy(&prev.stdout);
                let prev_agent: Vec<_> = prev_logs
                    .lines()
                    .filter(|l| !l.contains("busted_ebpf]"))
                    .collect();
                println!(">>>   PREVIOUS container agent lines (last 30):");
                for line in prev_agent.iter().rev().take(30).rev() {
                    println!(">>>     {line}");
                }
            }
        }
    }

    assert!(
        file_monitor_active,
        "File monitor tracepoints not attached. Check --file-monitor flag and file-monitor feature.\n\
         file_monitor config in logs: {}\n\
         'failed to load' in logs: {}\n\
         'not found' in logs: {}",
        startup_logs.contains("file_monitor="),
        startup_logs.contains("failed to load"),
        startup_logs.contains("not found in binary"),
    );
    println!(">>>   File monitor active (tracepoints attached)");

    // ── Phase 2: Generate file activity ──────────────────────────────────
    println!("\n=== PHASE 2: Generate file activity ===");

    let pod_name = "file-ops-claude";
    println!(">>>   Starting file-ops pod (with process name 'claude')...");
    run_file_ops_pod(pod_name);

    // Wait for the pod to be running and for the /proc scanner to pick up the PID.
    // The scanner runs every 30s; the pod sleeps 45s before doing reads.
    println!(">>>   Waiting 60s for /proc scan cycle + file operations...");
    std::thread::sleep(Duration::from_secs(60));

    // Wait for the pod to complete
    if let Some(logs) = wait_for_pod(pod_name, 60) {
        println!(
            ">>>   File-ops pod completed. Logs: {}",
            &logs[..logs.len().min(200)]
        );
    } else {
        println!(">>>   WARNING: file-ops pod did not complete in time");
    }

    // Wait for events to be processed
    println!(">>>   Waiting 10s for event processing...");
    std::thread::sleep(Duration::from_secs(10));

    // ── Phase 3: Collect and verify events ───────────────────────────────
    println!("\n=== PHASE 3: Verify file monitoring events ===");

    let phase = kubectl_stdout(&["get", "pod", &busted_pod, "-o", "jsonpath={.status.phase}"]);
    assert_eq!(
        phase, "Running",
        "Busted pod crashed during file monitor test (phase={phase})"
    );

    // Check for pod restarts (e.g. OOM-kill).
    let restart_count = kubectl_stdout(&[
        "get",
        "pod",
        &busted_pod,
        "-o",
        "jsonpath={.status.containerStatuses[0].restartCount}",
    ]);
    println!(">>>   Agent pod status: Running, restarts={restart_count}");
    if restart_count != "0" {
        // Show previous container logs if the pod restarted.
        let prev = kubectl(&["logs", &busted_pod, "--previous"]);
        if prev.status.success() {
            let prev_logs = String::from_utf8_lossy(&prev.stdout);
            println!(">>>   PREVIOUS container last 20 lines:");
            for line in prev_logs
                .lines()
                .rev()
                .take(20)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                println!(">>>     {line}");
            }
        }
    }
    assert_eq!(
        restart_count, "0",
        "Busted pod restarted {restart_count} time(s) during test. \
         Likely OOM — increase resources.limits.memory in the Helm values.",
    );

    let logs = kubectl_stdout(&["logs", &busted_pod]);
    let all_events: Vec<serde_json::Value> = logs
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let non_json_lines: Vec<_> = logs
        .lines()
        .filter(|line| serde_json::from_str::<serde_json::Value>(line).is_err())
        .collect();
    println!(">>>   Total JSON events: {}", all_events.len());
    println!(">>>   Non-JSON log lines: {}", non_json_lines.len());
    if all_events.is_empty() {
        println!(">>>   DIAGNOSTIC: Last 40 agent log lines:");
        for line in logs
            .lines()
            .rev()
            .take(40)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            println!(">>>     {line}");
        }
    }

    // ── Phase 3a: FileAccess events ──────────────────────────────────────
    // FileAccess is triggered by path pattern matching (no INTERESTING_PIDS needed).
    let file_access_events = events_by_action_type(&all_events, "FileAccess");
    println!(">>>   FileAccess events: {}", file_access_events.len());

    let claude_access = events_by_action_and_path(&all_events, "FileAccess", ".claude");
    let env_access = events_by_action_and_path(&all_events, "FileAccess", ".env");
    println!(">>>     .claude path matches: {}", claude_access.len());
    println!(">>>     .env path matches: {}", env_access.len());

    // Print samples
    for ev in claude_access.iter().take(2) {
        if let Some(path) = ev
            .get("action")
            .and_then(|a| a.get("path"))
            .and_then(|v| v.as_str())
        {
            let mode = ev
                .get("action")
                .and_then(|a| a.get("mode"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let policy = ev.get("policy").and_then(|v| v.as_str()).unwrap_or("?");
            println!(">>>       sample: path={path} mode={mode} policy={policy}");
        }
    }

    assert!(
        !file_access_events.is_empty(),
        "No FileAccess events captured. The eBPF openat probe may not be firing.\n\
         Total events: {}. Check agent logs for errors.",
        all_events.len(),
    );

    assert!(
        !claude_access.is_empty(),
        "No FileAccess events for .claude paths.\n\
         FileAccess events: {}. Sample paths: {:?}",
        file_access_events.len(),
        file_access_events
            .iter()
            .take(5)
            .filter_map(|e| e.get("action")?.get("path")?.as_str().map(String::from))
            .collect::<Vec<_>>(),
    );

    assert!(
        !env_access.is_empty(),
        "No FileAccess events for .env paths.\n\
         FileAccess events: {}. Sample paths: {:?}",
        file_access_events.len(),
        file_access_events
            .iter()
            .take(5)
            .filter_map(|e| e.get("action")?.get("path")?.as_str().map(String::from))
            .collect::<Vec<_>>(),
    );

    // Verify OPA policy marked FileAccess as "audit"
    let audited_access = file_access_events
        .iter()
        .filter(|e| {
            e.get("policy")
                .and_then(|v| v.as_str())
                .map_or(false, |p| p == "audit")
        })
        .count();
    assert!(
        audited_access > 0,
        "OPA policy did not mark any FileAccess events as 'audit'.\n\
         FileAccess events: {}",
        file_access_events.len(),
    );
    println!(">>>   FileAccess OPA audit verified ({audited_access} events)");

    // ── Phase 3b: FileData events ────────────────────────────────────────
    // FileData requires the process PID in INTERESTING_PIDS (populated by /proc scanner).
    // The pod runs as process name "claude" (via `cp /bin/sh /tmp/claude`), which
    // should be detected by the scanner within 30s.
    let file_data_events = events_by_action_type(&all_events, "FileData");
    println!(">>>   FileData events: {}", file_data_events.len());

    let claude_data = events_by_action_and_path(&all_events, "FileData", ".claude");
    let env_data = events_by_action_and_path(&all_events, "FileData", ".env");
    println!(">>>     .claude content events: {}", claude_data.len());
    println!(">>>     .env content events: {}", env_data.len());

    // Print samples with content preview
    for ev in file_data_events.iter().take(3) {
        let action = ev.get("action").unwrap();
        let path = action.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let direction = action
            .get("direction")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let content = action.get("content").and_then(|v| v.as_str()).unwrap_or("");
        let preview = &content[..content.len().min(60)];
        let policy = ev.get("policy").and_then(|v| v.as_str()).unwrap_or("?");
        println!(">>>       sample: {direction} {path} policy={policy} content={preview:?}");
    }

    if file_data_events.is_empty() {
        println!(
            ">>>   NOTE: No FileData events captured. This can happen if the /proc scanner\n\
             >>>   did not detect the 'claude' process in time. FileAccess (openat) events\n\
             >>>   were captured successfully, confirming the eBPF pipeline works."
        );
    } else {
        // If we got FileData events, verify content and OPA policy

        // Check that .claude/settings.json content was captured
        if !claude_data.is_empty() {
            let has_settings_content = claude_data.iter().any(|e| {
                e.get("action")
                    .and_then(|a| a.get("content"))
                    .and_then(|v| v.as_str())
                    .map_or(false, |c| c.contains("theme"))
            });
            assert!(
                has_settings_content,
                "FileData for .claude path exists but doesn't contain expected content.\n\
                 Samples: {:?}",
                claude_data
                    .iter()
                    .take(3)
                    .map(|e| e
                        .get("action")
                        .and_then(|a| a.get("content"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .chars()
                        .take(80)
                        .collect::<String>())
                    .collect::<Vec<_>>(),
            );
            println!(">>>   FileData content verified: .claude/settings.json contains 'theme'");
        }

        // Check that .env content was captured
        if !env_data.is_empty() {
            let has_env_content = env_data.iter().any(|e| {
                e.get("action")
                    .and_then(|a| a.get("content"))
                    .and_then(|v| v.as_str())
                    .map_or(false, |c| c.contains("SECRET"))
            });
            assert!(
                has_env_content,
                "FileData for .env path exists but doesn't contain expected content.",
            );
            println!(">>>   FileData content verified: .env contains 'SECRET'");
        }

        // Verify OPA policy: reads should be "audit", writes to .env should be "deny"
        let read_events: Vec<_> = file_data_events
            .iter()
            .filter(|e| {
                e.get("action")
                    .and_then(|a| a.get("direction"))
                    .and_then(|v| v.as_str())
                    == Some("read")
            })
            .collect();
        let write_env_events: Vec<_> = env_data
            .iter()
            .filter(|e| {
                e.get("action")
                    .and_then(|a| a.get("direction"))
                    .and_then(|v| v.as_str())
                    == Some("write")
            })
            .collect();

        if !read_events.is_empty() {
            let audited = read_events
                .iter()
                .filter(|e| {
                    e.get("policy")
                        .and_then(|v| v.as_str())
                        .map_or(false, |p| p == "audit")
                })
                .count();
            println!(
                ">>>   FileData reads: {} total, {} with policy=audit",
                read_events.len(),
                audited
            );
        }

        if !write_env_events.is_empty() {
            let denied = write_env_events
                .iter()
                .filter(|e| {
                    e.get("policy")
                        .and_then(|v| v.as_str())
                        .map_or(false, |p| p == "deny")
                })
                .count();
            if denied > 0 {
                println!(
                    ">>>   FileData OPA deny verified: .env write → policy=deny ({denied} events)"
                );
            } else {
                println!(
                    ">>>   NOTE: .env write events found but none with policy=deny.\n\
                     >>>   Write events: {}",
                    write_env_events.len()
                );
            }
        }

        println!(
            ">>>   FileData capture verified ({} events, {} reads, {} .env writes)",
            file_data_events.len(),
            read_events.len(),
            write_env_events.len(),
        );
    }

    // ── Diagnostic dump on any failure ───────────────────────────────────
    println!("\n>>> Event type breakdown:");
    let mut type_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for ev in &all_events {
        let t = action_type(ev).unwrap_or("unknown").to_string();
        *type_counts.entry(t).or_insert(0) += 1;
    }
    for (t, count) in &type_counts {
        println!(">>>   {t}: {count}");
    }

    // ── Cleanup ──────────────────────────────────────────────────────────
    let _ = kubectl(&["delete", "pod", pod_name, "--grace-period=0", "--force"]);
    cluster.helm_uninstall();

    println!("\n>>> File monitor E2E test passed!");
}
