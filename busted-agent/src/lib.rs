//! Userspace eBPF monitoring agent for LLM/AI communication tracking.
//!
//! This crate loads eBPF programs into the kernel (kprobes, uprobes, LSM hooks),
//! consumes events via a RingBuf, classifies traffic against known LLM providers,
//! and broadcasts [`BustedEvent`]s to CLI output, a Unix socket server (for the
//! dashboard UI), and optional SIEM sinks.
//!
//! # Feature flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `tls` | SSL_write/SSL_read plaintext capture and SNI extraction |
//! | `ml` | Behavioral traffic classification via `busted_ml` |
//! | `identity` | Cross-event agent identity tracking via `busted_identity` |
//! | `opa` | OPA/Rego policy evaluation via `busted_opa` |
//! | `k8s` | Kubernetes pod metadata enrichment |
//! | `prometheus` | Prometheus metrics exporter |
//!
//! # Usage
//!
//! ```no_run
//! use busted_agent::{AgentConfig, run_agent};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = AgentConfig {
//!     verbose: false,
//!     format: "text".into(),
//!     enforce: false,
//!     output: "stdout".into(),
//!     policy_dir: None,
//!     policy_rule: None,
//!     metrics_port: 9184,
//!     identity_store_path: None,
//!     file_monitor: false,
//! };
//! run_agent(config).await
//! # }
//! ```

#[cfg(feature = "tls")]
pub mod actions;
pub mod events;
#[cfg(feature = "file-monitor")]
pub mod file_monitor;
#[cfg(feature = "k8s")]
pub mod k8s;
#[cfg(feature = "prometheus")]
pub mod metrics;
pub mod server;
pub mod siem;
#[cfg(feature = "tls")]
pub mod tls;

use anyhow::{Context, Result};
#[cfg(feature = "file-monitor")]
use aya::programs::TracePoint;
#[cfg(feature = "tls")]
use aya::programs::UProbe;
use aya::{
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, MapData, RingBuf},
    programs::{KProbe, Lsm},
    Btf, Ebpf,
};
use aya_log::EbpfLogger;
#[cfg(feature = "identity")]
use busted_identity as identity;
#[cfg(feature = "ml")]
use busted_ml as ml;
use busted_types::agentic::{AgenticAction, BustedEvent};
use busted_types::{AgentIdentity, NetworkEvent};
#[cfg(feature = "file-monitor")]
use busted_types::{FileAccessEvent, FileDataEvent};
#[cfg(feature = "tls")]
use busted_types::{TlsConnKey, TlsDataEvent, TlsHandshakeEvent};
use log::{debug, info, warn};
use regex::Regex;
#[cfg(feature = "prometheus")]
use std::collections::HashSet;
use std::{
    collections::HashMap,
    net::{IpAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};
use tokio::{
    io::unix::AsyncFd,
    signal,
    sync::{broadcast, Mutex, RwLock},
    task,
    time::Duration,
};

// ---------------------------------------------------------------------------
// AgentConfig
// ---------------------------------------------------------------------------

/// Configuration for the monitoring agent.
pub struct AgentConfig {
    pub verbose: bool,
    pub format: String,
    pub enforce: bool,
    pub output: String,
    pub policy_dir: Option<PathBuf>,
    pub policy_rule: Option<String>,
    pub metrics_port: u16,
    pub identity_store_path: Option<PathBuf>,
    pub file_monitor: bool,
}

// ---------------------------------------------------------------------------
// LLM provider classification
// ---------------------------------------------------------------------------

const LLM_ENDPOINTS: &[(&str, &str)] = &[
    ("api.openai.com", "OpenAI"),
    ("api.anthropic.com", "Anthropic"),
    ("generativelanguage.googleapis.com", "Google"),
    ("aiplatform.googleapis.com", "Google"),
    ("openai.azure.com", "Azure"),
    ("cognitiveservices.azure.com", "Azure"),
    ("bedrock-runtime.us-east-1.amazonaws.com", "AWS Bedrock"),
    ("bedrock-runtime.us-west-2.amazonaws.com", "AWS Bedrock"),
    ("api.cohere.ai", "Cohere"),
    ("api-inference.huggingface.co", "HuggingFace"),
    ("api.mistral.ai", "Mistral"),
    ("api.groq.com", "Groq"),
    ("api.together.xyz", "Together"),
    ("api.deepseek.com", "DeepSeek"),
    ("api.perplexity.ai", "Perplexity"),
];

/// Known subnet prefixes for LLM providers (covers CDN/anycast rotation).
const LLM_SUBNETS: &[([u8; 2], &str)] = &[
    // Anthropic (160.79.x.x)
    ([160, 79], "Anthropic"),
    // Cloudflare ranges used by OpenAI (104.18.x.x, 172.66.x.x, 162.159.x.x)
    ([104, 18], "OpenAI"),
    ([172, 66], "OpenAI"),
    ([162, 159], "OpenAI"),
];

/// Known /32 IPv6 prefixes for LLM providers.
const LLM_SUBNETS_V6: &[([u8; 4], &str)] = &[
    // Anthropic 2607:6bc0::/32
    ([0x26, 0x07, 0x6b, 0xc0], "Anthropic"),
    // Google Cloud 2600:1901::/32 (used by Anthropic infrastructure)
    ([0x26, 0x00, 0x19, 0x01], "Anthropic"),
];

/// Resolve all LLM endpoints to IPs and return the map.
fn resolve_provider_ips() -> HashMap<IpAddr, &'static str> {
    let mut m = HashMap::new();
    for &(hostname, provider) in LLM_ENDPOINTS {
        let addr = format!("{}:443", hostname);
        match addr.to_socket_addrs() {
            Ok(addrs) => {
                for a in addrs {
                    info!("  {} -> {} ({})", hostname, a.ip(), provider);
                    m.insert(a.ip(), provider);
                }
            }
            Err(e) => {
                warn!("Failed to resolve {}: {}", hostname, e);
            }
        }
    }
    info!("Resolved {} LLM provider IPs", m.len());
    m
}

fn classify_llm_provider(
    ip: &IpAddr,
    dport: u16,
    provider_map: &HashMap<IpAddr, &'static str>,
) -> Option<&'static str> {
    if dport != 443 {
        return None;
    }

    // 1. Exact IP match from DNS resolution
    if let Some(provider) = provider_map.get(ip).copied() {
        return Some(provider);
    }

    // 2. Subnet prefix match for CDN/anycast ranges
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            for &(prefix, provider) in LLM_SUBNETS {
                if octets[0] == prefix[0] && octets[1] == prefix[1] {
                    return Some(provider);
                }
            }
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            for &(prefix, provider) in LLM_SUBNETS_V6 {
                if octets[0] == prefix[0]
                    && octets[1] == prefix[1]
                    && octets[2] == prefix[2]
                    && octets[3] == prefix[3]
                {
                    return Some(provider);
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Container resolver (Kubernetes / Docker)
// ---------------------------------------------------------------------------

fn resolve_container_id(pid: u32, cache: &mut HashMap<u32, String>) -> String {
    if let Some(cached) = cache.get(&pid) {
        return cached.clone();
    }

    let container_id = resolve_container_id_from_proc(pid);

    // LRU-style: clear cache if too large
    if cache.len() > 10_000 {
        cache.clear();
    }
    cache.insert(pid, container_id.clone());
    container_id
}

fn resolve_container_id_from_proc(pid: u32) -> String {
    let path = format!("/proc/{}/cgroup", pid);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    // Match Docker or containerd container IDs
    let re = Regex::new(r"(?:docker-|cri-containerd-)([a-f0-9]{64})\.scope").unwrap();
    if let Some(caps) = re.captures(&content) {
        if let Some(m) = caps.get(1) {
            return m.as_str()[..12].to_string(); // Short container ID
        }
    }

    // Also try bare hex IDs in cgroup path (common in k8s)
    let re2 = Regex::new(r"/([a-f0-9]{64})$").unwrap();
    for line in content.lines() {
        if let Some(caps) = re2.captures(line) {
            if let Some(m) = caps.get(1) {
                return m.as_str()[..12].to_string();
            }
        }
    }

    String::new()
}

// ---------------------------------------------------------------------------
// Traffic pattern heuristics
// ---------------------------------------------------------------------------

struct PidStats {
    first_seen: Instant,
    event_count: u64,
    bytes_total: u64,
}

impl PidStats {
    fn new() -> Self {
        Self {
            first_seen: Instant::now(),
            event_count: 0,
            bytes_total: 0,
        }
    }

    fn request_rate(&self) -> f64 {
        let elapsed = self.first_seen.elapsed().as_secs_f64();
        if elapsed < 0.001 {
            0.0
        } else {
            self.event_count as f64 / elapsed
        }
    }
}

// ---------------------------------------------------------------------------
// Event handling
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn handle_event(
    event: NetworkEvent,
    tx: &broadcast::Sender<BustedEvent>,
    identity_map: &Arc<Mutex<AyaHashMap<MapData, u32, AgentIdentity>>>,
    policy_map: &Arc<Mutex<AyaHashMap<MapData, u32, u8>>>,
    provider_map: &Arc<RwLock<HashMap<IpAddr, &'static str>>>,
    enforce: bool,
    container_cache: &mut HashMap<u32, String>,
    pid_stats: &mut HashMap<u32, PidStats>,
    #[cfg(feature = "k8s")] k8s_cache: &Arc<RwLock<HashMap<String, k8s::PodMetadata>>>,
    #[cfg(feature = "identity")] identity_tracker: &mut identity::IdentityTracker,
    #[cfg(feature = "ml")] _ml_classifier: &mut ml::MlClassifier,
    #[cfg(feature = "tls")] sni_cache: &tls::SniCache,
    #[cfg(feature = "opa")] opa_engine: &mut Option<busted_opa::PolicyEngine>,
    #[cfg(feature = "prometheus")] llm_pids: &mut HashSet<u32>,
    #[cfg(feature = "prometheus")] unique_providers: &mut HashSet<String>,
) {
    let dst_ip = event.dest_ip();

    // Try SNI-based classification first (more reliable than IP)
    #[cfg(feature = "tls")]
    let sni_hostname: Option<&str> = sni_cache.get(event.pid);

    let pmap = provider_map.read().await;
    #[cfg(feature = "tls")]
    let provider = {
        if event.dport == 443 {
            if let Some(sni) = sni_hostname {
                tls::classify_by_sni(sni)
                    .or_else(|| classify_llm_provider(&dst_ip, event.dport, &pmap))
            } else {
                classify_llm_provider(&dst_ip, event.dport, &pmap)
            }
        } else {
            classify_llm_provider(&dst_ip, event.dport, &pmap)
        }
    };
    #[cfg(not(feature = "tls"))]
    let provider = classify_llm_provider(&dst_ip, event.dport, &pmap);
    drop(pmap);

    // Log TLS-port connections at debug level for diagnostics
    if event.dport == 443 {
        debug!(
            "TLS conn: PID {} ({}) -> {}:{} provider={:?}",
            event.pid,
            event.process_name(),
            dst_ip,
            event.dport,
            provider,
        );
    }

    let policy_str = if provider.is_some() && enforce {
        if let Ok(mut pmap) = policy_map.try_lock() {
            // With LSM: write Deny (1) to block; without LSM: Audit (2)
            let _ = pmap.insert(event.pid, 1, 0);
        }
        Some("deny")
    } else if provider.is_some() {
        if let Ok(mut pmap) = policy_map.try_lock() {
            let _ = pmap.insert(event.pid, 2, 0);
        }
        Some("audit")
    } else {
        None
    };

    // Record policy decision metric
    #[cfg(feature = "prometheus")]
    if let Some(decision) = policy_str {
        metrics::record_policy_decision(decision);
    }

    // Store identity for processes communicating with LLM providers
    if provider.is_some() {
        if let Ok(mut imap) = identity_map.try_lock() {
            let mut identity = AgentIdentity::new();
            identity.pid = event.pid;
            identity.uid = event.uid;
            identity.comm = event.comm;
            identity.container_id = event.container_id;
            identity.created_at_ns = event.timestamp_ns;
            let _ = imap.insert(event.pid, identity, 0);
        }
    }

    // Resolve container ID from /proc
    let container_id = resolve_container_id(event.pid, container_cache);

    // Update per-PID traffic stats
    let stats = pid_stats.entry(event.pid).or_insert_with(PidStats::new);
    stats.event_count += 1;
    stats.bytes_total += event.bytes;
    let request_rate = stats.request_rate();
    let _session_bytes = stats.bytes_total;

    // Flag high-rate port-443 traffic as possible LLM even without IP match
    if provider.is_none() && event.dport == 443 && request_rate > 10.0 {
        debug!(
            "High-rate TLS traffic from PID {} ({}): {:.1} events/sec",
            event.pid,
            event.process_name(),
            request_rate
        );
    }

    let mut processed = events::from_network_event(&event, provider, policy_str);
    // Override container_id with the one resolved from /proc (more reliable)
    if !container_id.is_empty() {
        processed.process.container_id = container_id;
    }

    // Attach SNI hostname if available
    #[cfg(feature = "tls")]
    if let AgenticAction::Network { ref mut sni, .. } = processed.action {
        *sni = sni_hostname.map(|s| s.to_string());
    }

    // Enrich with Kubernetes pod metadata if available
    #[cfg(feature = "k8s")]
    {
        let k8s_map = k8s_cache.read().await;
        if let Some(meta) = k8s::resolve_pod_metadata(&processed.process.container_id, &k8s_map) {
            processed.process.pod_name = Some(meta.pod_name);
            processed.process.pod_namespace = Some(meta.namespace);
            processed.process.service_account = Some(meta.service_account);
        }
    }

    // Identity tracking
    #[cfg(feature = "identity")]
    enrich_with_identity(&mut processed, identity_tracker);

    // OPA policy evaluation (overrides hardcoded policy if enabled)
    #[cfg(feature = "opa")]
    if let Some(ref mut engine) = opa_engine {
        let opa_start = Instant::now();
        let opa_result = engine.evaluate(&processed);
        let opa_elapsed = opa_start.elapsed();
        match opa_result {
            Ok(decision) => {
                #[cfg(feature = "prometheus")]
                metrics::record_opa_eval_duration(opa_elapsed, decision.action.as_str());
                processed.policy = Some(decision.action.as_str().to_string());
                match decision.action {
                    busted_opa::Action::Deny => {
                        if let Ok(mut pmap) = policy_map.try_lock() {
                            let _ = pmap.insert(event.pid, 1, 0);
                        }
                    }
                    busted_opa::Action::Audit => {
                        if let Ok(mut pmap) = policy_map.try_lock() {
                            let _ = pmap.insert(event.pid, 2, 0);
                        }
                    }
                    busted_opa::Action::Allow => {}
                }
            }
            Err(e) => {
                #[cfg(feature = "prometheus")]
                metrics::record_opa_eval_duration(opa_elapsed, "error");
                warn!("OPA evaluation failed: {e}");
            }
        }
    }

    // Record event metrics (all events, not just interesting ones)
    #[cfg(feature = "prometheus")]
    metrics::record_event(
        processed.event_type(),
        processed.provider(),
        processed.bytes(),
    );

    // Only broadcast interesting events (LLM/AI-related)
    if processed.provider().is_some() {
        #[cfg(feature = "prometheus")]
        {
            llm_pids.insert(processed.process.pid);
            metrics::set_active_pids(llm_pids.len());
            if let Some(p) = processed.provider() {
                if unique_providers.insert(p.to_string()) {
                    metrics::set_providers_detected(unique_providers.len());
                }
            }
        }
        let _ = tx.send(processed);
    } else {
        debug!(
            "[{}] PID: {} ({}) | {} bytes",
            processed.event_type(),
            processed.process.pid,
            processed.process.name,
            processed.bytes(),
        );
    }
}

/// Enrich a BustedEvent with identity tracking fields.
#[cfg(feature = "identity")]
fn enrich_with_identity(processed: &mut BustedEvent, tracker: &mut identity::IdentityTracker) {
    use busted_types::agentic::IdentityInfo;
    if let Some(id_match) = tracker.observe(processed) {
        processed.identity = Some(IdentityInfo {
            id: id_match.identity_id,
            instance: id_match.instance_id.to_string(),
            confidence: id_match.confidence,
            match_type: Some(id_match.match_type),
            narrative: Some(id_match.narrative),
            timeline: Some(id_match.timeline_summary),
            timeline_len: Some(id_match.timeline_len),
            prompt_fingerprint: id_match.prompt_fingerprint,
            behavioral_digest: id_match.behavioral_digest,
            capability_hash: id_match.capability_hash,
            graph_node_count: Some(tracker.graph_node_count()),
            graph_edge_count: Some(tracker.graph_edge_count()),
        });
    }
}

// ---------------------------------------------------------------------------
// CLI output consumer
// ---------------------------------------------------------------------------

async fn cli_output_consumer(
    mut rx: broadcast::Receiver<BustedEvent>,
    format: String,
    verbose: bool,
) {
    loop {
        match rx.recv().await {
            Ok(event) => match format.as_str() {
                "json" => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        println!("{}", json);
                    }
                }
                "verbose" => {
                    info!(
                        "[{}] {} | PID: {} ({}) | {} bytes | {:?}",
                        event.event_type(),
                        event.timestamp,
                        event.process.pid,
                        event.process.name,
                        event.bytes(),
                        event.action,
                    );
                }
                _ => {
                    // Default "text" format — action-focused output
                    let ts = if event.timestamp.len() > 8 {
                        &event.timestamp[..8]
                    } else {
                        &event.timestamp
                    };
                    let pid = event.process.pid;
                    let name = &event.process.name;

                    match &event.action {
                        AgenticAction::Prompt {
                            provider,
                            model,
                            user_message,
                            system_prompt,
                            stream,
                            sdk,
                            pii_detected,
                            ..
                        } => {
                            let mut indicators = Vec::new();
                            if let Some(ref s) = sdk {
                                indicators.push(format!("sdk:{}", s));
                            }
                            if *stream {
                                indicators.push("stream".to_string());
                            }
                            if pii_detected == &Some(true) {
                                indicators.push("PII!".to_string());
                            }
                            if let Some(ref p) = event.policy {
                                if p != "allow" {
                                    indicators.push(format!("policy:{}", p));
                                }
                            }
                            let ind = if indicators.is_empty() {
                                String::new()
                            } else {
                                format!(" [{}]", indicators.join(" | "))
                            };
                            let model_str = model.as_deref().unwrap_or("");
                            println!(
                                "{} {} ({}) >>> {} {}{}",
                                ts, name, pid, provider, model_str, ind,
                            );
                            if let Some(ref msg) = user_message {
                                let display = if verbose {
                                    msg.clone()
                                } else {
                                    truncate_at_char(msg, 120)
                                };
                                println!("  user: {}", display);
                            }
                            if let Some(ref prompt) = system_prompt {
                                let display = if verbose {
                                    prompt.clone()
                                } else {
                                    truncate_at_char(prompt, 120)
                                };
                                println!("  system: {}", display);
                            }
                        }
                        AgenticAction::Response {
                            provider,
                            model,
                            bytes,
                            ..
                        } => {
                            let model_str = model.as_deref().unwrap_or("");
                            println!(
                                "{} {} ({}) <<< {} {} ({})",
                                ts,
                                name,
                                pid,
                                provider,
                                model_str,
                                format_human_bytes(*bytes),
                            );
                        }
                        AgenticAction::ToolCall {
                            tool_name,
                            provider,
                            ..
                        } => {
                            println!(
                                "{} {} ({}) <~> tool: {} ({})",
                                ts, name, pid, tool_name, provider,
                            );
                        }
                        AgenticAction::ToolResult {
                            tool_name,
                            output_preview,
                        } => {
                            let preview = output_preview
                                .as_deref()
                                .map(|s| truncate_at_char(s, 80))
                                .unwrap_or_default();
                            println!(
                                "{} {} ({}) ~>  result: {} {}",
                                ts, name, pid, tool_name, preview,
                            );
                        }
                        AgenticAction::McpRequest {
                            method, category, ..
                        } => {
                            let cat = category
                                .as_deref()
                                .map(|c| format!(" ({})", c))
                                .unwrap_or_default();
                            println!("{} {} ({}) >>> MCP {}{}", ts, name, pid, method, cat,);
                        }
                        AgenticAction::McpResponse { method, .. } => {
                            println!("{} {} ({}) <<< MCP {}", ts, name, pid, method,);
                        }
                        AgenticAction::PiiDetected {
                            direction,
                            pii_types,
                        } => {
                            let types =
                                pii_types.as_ref().map(|t| t.join(", ")).unwrap_or_default();
                            println!(
                                "{} {} ({}) !! PII detected ({}) [{}]",
                                ts, name, pid, direction, types,
                            );
                        }
                        AgenticAction::Network {
                            kind,
                            dst_ip,
                            dst_port,
                            bytes,
                            ..
                        } => {
                            if verbose {
                                println!(
                                    "{} {} ({}) [{:?}] {}:{} {} bytes",
                                    ts, name, pid, kind, dst_ip, dst_port, bytes,
                                );
                            }
                        }
                        AgenticAction::FileAccess { path, mode, reason } => {
                            let reason_str = reason
                                .as_deref()
                                .map(|r| format!(" [{}]", r))
                                .unwrap_or_default();
                            println!(
                                "{} {} ({}) [o] {} ({}){}",
                                ts, name, pid, path, mode, reason_str,
                            );
                        }
                        AgenticAction::FileData {
                            path,
                            direction,
                            content,
                            bytes,
                            truncated,
                        } => {
                            let arrow = if direction == "read" { "<-" } else { "->" };
                            let trunc = if truncated == &Some(true) {
                                " [truncated]"
                            } else {
                                ""
                            };
                            println!(
                                "{} {} ({}) {} {} ({} B){}",
                                ts, name, pid, arrow, path, bytes, trunc,
                            );
                            if verbose {
                                let preview = if content.len() > 200 {
                                    format!("{}...", &content[..200])
                                } else {
                                    content.clone()
                                };
                                println!("  content: {}", preview);
                            }
                        }
                    }

                    // Identity narrative (verbose only)
                    if verbose {
                        if let Some(ref ident) = event.identity {
                            if let Some(ref narrative) = ident.narrative {
                                println!("  identity: {}", narrative);
                            }
                        }
                    }
                }
            },
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("CLI consumer lagged, dropped {} events", n);
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Truncate a string at a UTF-8 character boundary.
fn truncate_at_char(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => format!("{}...", &s[..idx]),
        None => s.to_string(),
    }
}

/// Format bytes in human-readable form.
fn format_human_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{} B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    }
}

// ---------------------------------------------------------------------------
// Main agent entry point
// ---------------------------------------------------------------------------

/// Run the eBPF monitoring agent with the given configuration.
pub async fn run_agent(config: AgentConfig) -> Result<()> {
    // Install rustls CryptoProvider before any TLS operations (needed by kube-rs)
    #[cfg(feature = "k8s")]
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Initialize Prometheus metrics exporter
    #[cfg(feature = "prometheus")]
    metrics::init(config.metrics_port)?;

    // Resolve LLM provider IPs into shared map
    let provider_map = Arc::new(RwLock::new(resolve_provider_ips()));

    #[cfg(feature = "prometheus")]
    metrics::set_dns_resolutions(provider_map.read().await.len());

    // Spawn periodic DNS re-resolution task
    {
        let pm = provider_map.clone();
        task::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let new_map = tokio::task::spawn_blocking(resolve_provider_ips)
                    .await
                    .unwrap_or_default();
                let count = new_map.len();
                *pm.write().await = new_map;
                #[cfg(feature = "prometheus")]
                metrics::set_dns_resolutions(count);
                info!("Re-resolved {} LLM provider IPs", count);
            }
        });
    }

    // Bump memlock rlimit for older kernels
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("Failed to increase rlimit");
    }

    // Load eBPF program (compiled by build.rs via aya-build)
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/busted-ebpf"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    info!("Loading eBPF programs...");

    // Attach kprobes
    let program: &mut KProbe = bpf.program_mut("tcp_connect").unwrap().try_into()?;
    program.load()?;
    program
        .attach("tcp_connect", 0)
        .context("Failed to attach tcp_connect")?;
    info!("Attached to tcp_connect");

    let program: &mut KProbe = bpf.program_mut("tcp_sendmsg").unwrap().try_into()?;
    program.load()?;
    program
        .attach("tcp_sendmsg", 0)
        .context("Failed to attach tcp_sendmsg")?;
    info!("Attached to tcp_sendmsg");

    let program: &mut KProbe = bpf.program_mut("tcp_recvmsg").unwrap().try_into()?;
    program.load()?;
    program
        .attach("tcp_recvmsg", 0)
        .context("Failed to attach tcp_recvmsg")?;
    info!("Attached to tcp_recvmsg");

    let program: &mut KProbe = bpf.program_mut("tcp_close").unwrap().try_into()?;
    program.load()?;
    program
        .attach("tcp_close", 0)
        .context("Failed to attach tcp_close")?;
    info!("Attached to tcp_close");

    let program: &mut KProbe = bpf.program_mut("udp_sendmsg").unwrap().try_into()?;
    program.load()?;
    program
        .attach("udp_sendmsg", 0)
        .context("Failed to attach udp_sendmsg")?;
    info!("Attached to udp_sendmsg (DNS probe)");

    // Try to attach LSM hook (optional — requires CONFIG_BPF_LSM and lsm=bpf boot param)
    match Btf::from_sys_fs() {
        Ok(btf) => {
            if let Some(prog) = bpf.program_mut("lsm_socket_connect") {
                match TryInto::<&mut Lsm>::try_into(prog) {
                    Ok(lsm) => match lsm.load("socket_connect", &btf) {
                        Ok(()) => match lsm.attach() {
                            Ok(_) => info!("LSM socket_connect enforcement attached"),
                            Err(e) => warn!("LSM attach failed (BPF not in LSM list?): {}", e),
                        },
                        Err(e) => warn!("LSM load failed: {}", e),
                    },
                    Err(e) => warn!("LSM program type mismatch: {}", e),
                }
            }
        }
        Err(e) => {
            warn!("BTF not available, LSM hooks disabled: {}", e);
        }
    }

    // Attach TLS uprobes (behind tls feature flag)
    #[cfg(feature = "tls")]
    {
        // Collect all SSL targets: system libssl + binaries with statically-linked OpenSSL
        let mut ssl_targets: Vec<PathBuf> = Vec::new();
        if let Some(libssl_path) = tls::detect_libssl_path() {
            ssl_targets.push(libssl_path);
        }
        for target in tls::detect_additional_ssl_targets() {
            if !ssl_targets.contains(&target) {
                ssl_targets.push(target);
            }
        }

        if ssl_targets.is_empty() {
            warn!("No SSL libraries found, TLS probes disabled");
        } else {
            info!(
                "Found {} SSL target(s) for uprobe attachment",
                ssl_targets.len()
            );

            // Load each eBPF program once, then attach to all targets
            let prog: &mut UProbe = bpf.program_mut("ssl_ctrl_sni").unwrap().try_into()?;
            prog.load()?;
            for target in &ssl_targets {
                match prog.attach(Some("SSL_ctrl"), 0, target, None) {
                    Ok(_) => info!("TLS uprobe: SSL_ctrl at {}", target.display()),
                    Err(e) => warn!("Failed to attach SSL_ctrl at {}: {}", target.display(), e),
                }
            }

            let prog: &mut UProbe = bpf.program_mut("ssl_write_entry").unwrap().try_into()?;
            prog.load()?;
            for target in &ssl_targets {
                match prog.attach(Some("SSL_write"), 0, target, None) {
                    Ok(_) => info!("TLS uprobe: SSL_write at {}", target.display()),
                    Err(e) => warn!("Failed to attach SSL_write at {}: {}", target.display(), e),
                }
                // SSL_write_ex has compatible first 3 args — reuse same eBPF program
                match prog.attach(Some("SSL_write_ex"), 0, target, None) {
                    Ok(_) => info!("TLS uprobe: SSL_write_ex at {}", target.display()),
                    Err(e) => warn!(
                        "Failed to attach SSL_write_ex at {}: {}",
                        target.display(),
                        e
                    ),
                }
            }

            let prog: &mut UProbe = bpf.program_mut("ssl_read_entry").unwrap().try_into()?;
            prog.load()?;
            for target in &ssl_targets {
                match prog.attach(Some("SSL_read"), 0, target, None) {
                    Ok(_) => info!("TLS uprobe: SSL_read at {}", target.display()),
                    Err(e) => warn!("Failed to attach SSL_read at {}: {}", target.display(), e),
                }
            }

            // SSL_read_ex has a 4th arg (size_t *readbytes) — separate entry probe stashes it
            let prog: &mut UProbe = bpf.program_mut("ssl_read_ex_entry").unwrap().try_into()?;
            prog.load()?;
            for target in &ssl_targets {
                match prog.attach(Some("SSL_read_ex"), 0, target, None) {
                    Ok(_) => info!("TLS uprobe: SSL_read_ex at {}", target.display()),
                    Err(e) => warn!(
                        "Failed to attach SSL_read_ex at {}: {}",
                        target.display(),
                        e
                    ),
                }
            }

            // ssl_read_ret handles both SSL_read and SSL_read_ex (checks readbytes_ptr)
            let prog: &mut UProbe = bpf.program_mut("ssl_read_ret").unwrap().try_into()?;
            prog.load()?;
            for target in &ssl_targets {
                match prog.attach(Some("SSL_read"), 0, target, None) {
                    Ok(_) => info!("TLS uretprobe: SSL_read at {}", target.display()),
                    Err(e) => {
                        warn!(
                            "Failed to attach SSL_read ret at {}: {}",
                            target.display(),
                            e
                        )
                    }
                }
                match prog.attach(Some("SSL_read_ex"), 0, target, None) {
                    Ok(_) => info!("TLS uretprobe: SSL_read_ex at {}", target.display()),
                    Err(e) => {
                        warn!(
                            "Failed to attach SSL_read_ex ret at {}: {}",
                            target.display(),
                            e
                        )
                    }
                }
            }

            let prog: &mut UProbe = bpf.program_mut("ssl_free_cleanup").unwrap().try_into()?;
            prog.load()?;
            for target in &ssl_targets {
                match prog.attach(Some("SSL_free"), 0, target, None) {
                    Ok(_) => info!("TLS uprobe: SSL_free at {}", target.display()),
                    Err(e) => warn!("Failed to attach SSL_free at {}: {}", target.display(), e),
                }
            }
        }
    }

    // Attach file-access tracepoints (behind file-monitor feature flag)
    #[cfg(feature = "file-monitor")]
    if config.file_monitor {
        let file_tp_names = [
            (
                "sys_enter_openat",
                "syscalls",
                "sys_enter_openat",
                "file-access",
            ),
            (
                "sys_exit_openat",
                "syscalls",
                "sys_exit_openat",
                "file-data",
            ),
            (
                "sys_enter_write",
                "syscalls",
                "sys_enter_write",
                "file-data",
            ),
            ("sys_enter_read", "syscalls", "sys_enter_read", "file-data"),
            ("sys_exit_read", "syscalls", "sys_exit_read", "file-data"),
            (
                "sys_enter_close",
                "syscalls",
                "sys_enter_close",
                "file-data",
            ),
        ];
        for (prog_name, category, tp_name, label) in file_tp_names {
            match bpf.program_mut(prog_name) {
                Some(prog) => {
                    let tp: &mut TracePoint = prog.try_into()?;
                    tp.load()
                        .context(format!("Failed to load {prog_name} into kernel"))?;
                    tp.attach(category, tp_name)
                        .context(format!("Failed to attach {tp_name} tracepoint"))?;
                    info!("Attached {label} tracepoint: {tp_name}");
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "File monitor: eBPF program '{prog_name}' not found"
                    ));
                }
            }
        }
    }

    info!("All eBPF programs loaded successfully");

    // Take BPF maps for identity and policy
    let identity_map: AyaHashMap<_, u32, AgentIdentity> =
        AyaHashMap::try_from(bpf.take_map("AGENT_IDENTITIES").unwrap())?;
    let identity_map = Arc::new(Mutex::new(identity_map));

    let policy_map: AyaHashMap<_, u32, u8> =
        AyaHashMap::try_from(bpf.take_map("POLICY_MAP").unwrap())?;
    let policy_map = Arc::new(Mutex::new(policy_map));

    // TLS connection verdict map — shared between event loop and tracker
    #[cfg(feature = "tls")]
    let tls_verdict_map: AyaHashMap<_, TlsConnKey, u8> =
        AyaHashMap::try_from(bpf.take_map("TLS_CONN_VERDICT").unwrap())?;

    // File-monitor: take INTERESTING_PIDS map and spawn periodic /proc scanner
    #[cfg(feature = "file-monitor")]
    let interesting_pids_map: Option<Arc<Mutex<AyaHashMap<MapData, u32, u8>>>> =
        if config.file_monitor {
            let map: AyaHashMap<_, u32, u8> =
                AyaHashMap::try_from(bpf.take_map("INTERESTING_PIDS").unwrap())?;
            let map = Arc::new(Mutex::new(map));

            // Initial scan
            {
                let initial = tokio::task::spawn_blocking(file_monitor::scan_ai_processes)
                    .await
                    .unwrap_or_default();
                if let Ok(mut m) = map.try_lock() {
                    for pid in &initial {
                        let _ = m.insert(*pid, 1u8, 0);
                    }
                }
                if !initial.is_empty() {
                    info!(
                        "File monitor: found {} AI processes via /proc scan",
                        initial.len()
                    );
                }
            }

            // Periodic re-scan
            {
                let map_clone = map.clone();
                task::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        let pids = tokio::task::spawn_blocking(file_monitor::scan_ai_processes)
                            .await
                            .unwrap_or_default();
                        if let Ok(mut m) = map_clone.try_lock() {
                            for pid in &pids {
                                let _ = m.insert(*pid, 1u8, 0);
                            }
                        }
                    }
                });
            }

            Some(map)
        } else {
            None
        };

    // Kubernetes pod metadata cache (behind feature flag)
    #[cfg(feature = "k8s")]
    let k8s_cache = {
        let cache = Arc::new(RwLock::new(HashMap::<String, k8s::PodMetadata>::new()));
        let cache_clone = cache.clone();
        task::spawn(k8s::start_pod_watcher(cache_clone));
        cache
    };

    // Event broadcast channel
    let (tx, _) = broadcast::channel::<BustedEvent>(4096);

    // Start CLI output consumer
    let cli_rx = tx.subscribe();
    let format = config.format.clone();
    let verbose = config.verbose;
    task::spawn(cli_output_consumer(cli_rx, format, verbose));

    // Start Unix socket server for UI
    let server_rx = tx.subscribe();
    task::spawn(server::run_socket_server(server_rx));

    // Start SIEM output consumer if configured
    if config.output != "stdout" {
        if let Some(sink) = siem::OutputSink::parse(&config.output) {
            let siem_rx = tx.subscribe();
            task::spawn(siem::run_siem_consumer(siem_rx, sink));
        } else {
            warn!("Unknown output sink format: {}", config.output);
        }
    }

    // Set up RingBuf consumer
    let ring_buf = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let async_fd = AsyncFd::new(ring_buf)?;
    let enforce = config.enforce;

    // Initialize OPA policy engine (if configured via --policy-dir or --rule)
    #[cfg(feature = "opa")]
    let opa_engine: Option<busted_opa::PolicyEngine> = if let Some(ref dir) = config.policy_dir {
        Some(busted_opa::PolicyEngine::new(dir).expect("Failed to initialize OPA policy engine"))
    } else if let Some(ref rule) = config.policy_rule {
        Some(busted_opa::PolicyEngine::from_rego(rule).expect("Failed to parse inline Rego rule"))
    } else {
        None
    };

    #[cfg(feature = "k8s")]
    let k8s_cache_clone = k8s_cache.clone();

    #[cfg(feature = "identity")]
    let identity_store_path = config.identity_store_path;
    // Suppress unused warning when identity feature is off
    #[cfg(not(feature = "identity"))]
    let _ = config.identity_store_path;

    task::spawn(async move {
        let mut container_cache: HashMap<u32, String> = HashMap::new();
        let mut pid_stats: HashMap<u32, PidStats> = HashMap::new();
        let mut async_fd = async_fd;
        #[cfg(feature = "opa")]
        let mut opa_engine = opa_engine;
        #[cfg(feature = "identity")]
        let mut identity_tracker = {
            let mut tracker_config = identity::TrackerConfig::default();
            tracker_config.store_path = identity_store_path;
            identity::IdentityTracker::with_config(tracker_config)
        };
        #[cfg(feature = "identity")]
        let mut identity_last_gc = Instant::now();
        #[cfg(feature = "identity")]
        info!("Identity tracker initialized");
        #[cfg(feature = "ml")]
        let mut ml_classifier = ml::MlClassifier::new();
        #[cfg(feature = "ml")]
        let mut ml_last_gc = Instant::now();
        #[cfg(feature = "ml")]
        info!("ML behavioral classifier initialized");
        #[cfg(feature = "prometheus")]
        let mut llm_pids: HashSet<u32> = HashSet::new();
        #[cfg(feature = "prometheus")]
        let mut unique_providers: HashSet<String> = HashSet::new();
        #[cfg(feature = "tls")]
        let mut sni_cache = tls::SniCache::new();
        #[cfg(feature = "tls")]
        let mut tls_conn_tracker = tls::TlsConnTracker::new();
        #[cfg(feature = "tls")]
        let mut tls_verdict_map = tls_verdict_map;
        #[cfg(feature = "tls")]
        let mut tls_last_gc = Instant::now();

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    warn!("RingBuf async fd error: {}", e);
                    break;
                }
            };
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                let item_len = item.len();

                // Dispatch by event type byte (first byte) and item size
                // TlsDataEvent: event_type 7 or 8
                #[cfg(feature = "tls")]
                if item_len >= std::mem::size_of::<TlsDataEvent>()
                    && !item.is_empty()
                    && (item[0] == 7 || item[0] == 8)
                {
                    let tls_data =
                        unsafe { (item.as_ptr() as *const TlsDataEvent).read_unaligned() };
                    drop(item);

                    let direction_str = if tls_data.direction == 0 {
                        "write"
                    } else {
                        "read"
                    };
                    let key = TlsConnKey {
                        pid: tls_data.pid,
                        _pad: 0,
                        ssl_ptr: tls_data.ssl_ptr,
                    };

                    // Track chunk count
                    let chunk_num = tls_conn_tracker.record_chunk(tls_data.pid, tls_data.ssl_ptr);

                    // Get SNI hint for this PID
                    let sni_hint = sni_cache.get(tls_data.pid);

                    // SNI fast path: if SNI matches a known LLM provider, mark
                    // interesting immediately. This handles HTTP/2 connections
                    // where the classifier can't parse binary framing.
                    if !tls_conn_tracker.is_decided(tls_data.pid, tls_data.ssl_ptr) {
                        if let Some(sni) = sni_hint {
                            if tls::classify_by_sni(sni).is_some() {
                                tls_conn_tracker.set_verdict(tls_data.pid, tls_data.ssl_ptr, true);
                                let _ = tls_verdict_map.insert(key, 1u8, 0);
                                #[cfg(feature = "prometheus")]
                                metrics::record_tls_verdict("interesting");
                                info!(
                                    "TLS: PID {} ({}) -> SNI {} matches LLM provider, tracking",
                                    tls_data.pid,
                                    tls_data.process_name(),
                                    sni,
                                );
                            }
                        }
                    }

                    if tls_conn_tracker.is_decided(tls_data.pid, tls_data.ssl_ptr) {
                        // Already decided interesting — accumulate payload
                        tls_conn_tracker.append_payload(
                            tls_data.pid,
                            tls_data.ssl_ptr,
                            tls_data.direction,
                            tls_data.payload_bytes(),
                        );
                        debug!(
                            "TLS data {}: PID {} ({}) {} bytes",
                            direction_str,
                            tls_data.pid,
                            tls_data.process_name(),
                            tls_data.payload_len,
                        );

                        // Session completion: emit actions on direction transitions
                        // When read arrives and write not yet emitted → emit request actions
                        if tls_data.direction == 1
                            && tls_conn_tracker.should_emit_request(tls_data.pid, tls_data.ssl_ptr)
                        {
                            if let Some(write_buf) =
                                tls_conn_tracker.take_write_buf(tls_data.pid, tls_data.ssl_ptr)
                            {
                                let session_id =
                                    tls::TlsConnTracker::session_id(tls_data.pid, tls_data.ssl_ptr);
                                let write_actions =
                                    actions::parse_write_actions(&write_buf, sni_hint);
                                for action in write_actions {
                                    #[allow(unused_mut)]
                                    let mut evt = events::from_tls_session(
                                        tls_data.pid,
                                        tls_data.process_name(),
                                        &session_id,
                                        sni_hint,
                                        action,
                                    );
                                    #[cfg(feature = "identity")]
                                    enrich_with_identity(&mut evt, &mut identity_tracker);
                                    #[cfg(feature = "opa")]
                                    if let Some(ref mut engine) = opa_engine {
                                        if let Ok(decision) = engine.evaluate(&evt) {
                                            evt.policy = Some(decision.action.as_str().to_string());
                                            if enforce
                                                && matches!(
                                                    decision.action,
                                                    busted_opa::Action::Deny
                                                )
                                            {
                                                let _ = tls_verdict_map.insert(key, 3u8, 0);
                                                unsafe {
                                                    libc::kill(tls_data.pid as i32, libc::SIGKILL);
                                                }
                                            }
                                        }
                                    }
                                    let _ = tx.send(evt);
                                }
                            }
                        }
                        // When write arrives and read not yet emitted → emit response actions
                        if tls_data.direction == 0
                            && tls_conn_tracker.should_emit_response(tls_data.pid, tls_data.ssl_ptr)
                        {
                            if let Some(read_buf) =
                                tls_conn_tracker.take_read_buf(tls_data.pid, tls_data.ssl_ptr)
                            {
                                let session_id =
                                    tls::TlsConnTracker::session_id(tls_data.pid, tls_data.ssl_ptr);
                                let read_actions = actions::parse_read_actions(&read_buf, sni_hint);
                                for action in read_actions {
                                    #[allow(unused_mut)]
                                    let mut evt = events::from_tls_session(
                                        tls_data.pid,
                                        tls_data.process_name(),
                                        &session_id,
                                        sni_hint,
                                        action,
                                    );
                                    #[cfg(feature = "identity")]
                                    enrich_with_identity(&mut evt, &mut identity_tracker);
                                    let _ = tx.send(evt);
                                }
                                tls_conn_tracker.reset_emission(tls_data.pid, tls_data.ssl_ptr);
                            }
                        }
                    } else {
                        // Still undecided — classify this chunk
                        let classification = tls::classify_payload(
                            tls_data.payload_bytes(),
                            tls_data.direction,
                            sni_hint,
                        );

                        if classification.is_interesting {
                            // Found LLM/MCP traffic!
                            tls_conn_tracker.set_verdict(tls_data.pid, tls_data.ssl_ptr, true);
                            tls_conn_tracker.append_payload(
                                tls_data.pid,
                                tls_data.ssl_ptr,
                                tls_data.direction,
                                tls_data.payload_bytes(),
                            );
                            let _ = tls_verdict_map.insert(key, 1u8, 0); // INTERESTING

                            #[cfg(feature = "prometheus")]
                            {
                                metrics::record_tls_verdict("interesting");
                                metrics::record_classifier_confidence(classification.confidence);
                            }

                            info!(
                                "TLS: PID {} ({}) -> {} {} [chunk #{}]",
                                tls_data.pid,
                                tls_data.process_name(),
                                classification.content_class_str().unwrap_or("unknown"),
                                classification.provider().unwrap_or(""),
                                chunk_num,
                            );
                        } else if tls_conn_tracker
                            .should_mark_boring(tls_data.pid, tls_data.ssl_ptr)
                        {
                            tls_conn_tracker.set_verdict(tls_data.pid, tls_data.ssl_ptr, false);
                            let _ = tls_verdict_map.insert(key, 2u8, 0); // BORING

                            #[cfg(feature = "prometheus")]
                            metrics::record_tls_verdict("boring");

                            debug!(
                                "TLS: PID {} ({}) -> boring after {} chunks",
                                tls_data.pid,
                                tls_data.process_name(),
                                chunk_num,
                            );
                        } else {
                            debug!(
                                "TLS {} (undecided #{}) PID {} ({}) {} bytes",
                                direction_str,
                                chunk_num,
                                tls_data.pid,
                                tls_data.process_name(),
                                tls_data.payload_len,
                            );
                        }
                    }

                    continue;
                }

                // TlsHandshakeEvent: event_type 6
                // Use exact size match to avoid confusion with NetworkEvent
                // (whose first byte is PID's low byte, which could be 6).
                #[cfg(feature = "tls")]
                if item_len == std::mem::size_of::<TlsHandshakeEvent>()
                    && !item.is_empty()
                    && item[0] == 6
                {
                    let tls_event =
                        unsafe { (item.as_ptr() as *const TlsHandshakeEvent).read_unaligned() };
                    let sni = tls_event.sni_str().to_string();
                    if !sni.is_empty() {
                        info!(
                            "TLS SNI: PID {} ({}) -> {}",
                            tls_event.pid,
                            tls_event.process_name(),
                            sni,
                        );
                        sni_cache.insert(tls_event.pid, sni);
                    }
                    drop(item);
                    continue;
                }

                // FileDataEvent: event_type 10 (large — uses PerCpuArray scratch)
                #[cfg(feature = "file-monitor")]
                if item_len >= std::mem::size_of::<FileDataEvent>()
                    && !item.is_empty()
                    && item[0] == 10
                {
                    let fd_event =
                        unsafe { (item.as_ptr() as *const FileDataEvent).read_unaligned() };
                    drop(item);

                    let mut processed = events::from_file_data_event(&fd_event);
                    #[cfg(feature = "opa")]
                    if let Some(ref mut engine) = opa_engine {
                        match engine.evaluate(&processed) {
                            Ok(decision) => {
                                processed.policy = Some(decision.action.as_str().to_string());
                            }
                            Err(e) => {
                                debug!("OPA eval failed for FileData: {e}");
                            }
                        }
                    }
                    let _ = tx.send(processed);
                    continue;
                }

                // FileAccessEvent: event_type 9, size 240
                #[cfg(feature = "file-monitor")]
                if item_len == std::mem::size_of::<FileAccessEvent>()
                    && !item.is_empty()
                    && item[0] == 9
                {
                    let fa_event =
                        unsafe { (item.as_ptr() as *const FileAccessEvent).read_unaligned() };
                    drop(item);

                    let path = fa_event.path_str().to_string();
                    let pid_tracked = if let Some(ref pids_map) = interesting_pids_map {
                        pids_map
                            .try_lock()
                            .ok()
                            .and_then(|m| m.get(&fa_event.pid, 0).ok())
                            .is_some()
                    } else {
                        false
                    };
                    let reason = file_monitor::classify_reason(&path, pid_tracked);
                    let mut processed = events::from_file_access_event(&fa_event, reason);
                    #[cfg(feature = "opa")]
                    if let Some(ref mut engine) = opa_engine {
                        match engine.evaluate(&processed) {
                            Ok(decision) => {
                                processed.policy = Some(decision.action.as_str().to_string());
                            }
                            Err(e) => {
                                debug!("OPA eval failed for FileAccess: {e}");
                            }
                        }
                    }
                    let _ = tx.send(processed);
                    continue;
                }

                if item_len >= std::mem::size_of::<NetworkEvent>() {
                    let event = unsafe { (item.as_ptr() as *const NetworkEvent).read_unaligned() };
                    drop(item); // consume the ring buf entry before async work
                    handle_event(
                        event,
                        &tx,
                        &identity_map,
                        &policy_map,
                        &provider_map,
                        enforce,
                        &mut container_cache,
                        &mut pid_stats,
                        #[cfg(feature = "k8s")]
                        &k8s_cache_clone,
                        #[cfg(feature = "identity")]
                        &mut identity_tracker,
                        #[cfg(feature = "ml")]
                        &mut ml_classifier,
                        #[cfg(feature = "tls")]
                        &sni_cache,
                        #[cfg(feature = "opa")]
                        &mut opa_engine,
                        #[cfg(feature = "prometheus")]
                        &mut llm_pids,
                        #[cfg(feature = "prometheus")]
                        &mut unique_providers,
                    )
                    .await;
                }
            }
            guard.clear_ready();

            // Periodic identity tracker garbage collection
            #[cfg(feature = "identity")]
            if identity_last_gc.elapsed() >= Duration::from_secs(60) {
                identity_tracker.gc();
                identity_last_gc = Instant::now();
            }

            // Periodic ML idle PID garbage collection
            #[cfg(feature = "ml")]
            if ml_last_gc.elapsed() >= Duration::from_secs(60) {
                ml_classifier.gc_idle_pids(Duration::from_secs(300));
                ml_last_gc = Instant::now();
            }

            // Periodic SNI cache + TLS connection tracker garbage collection
            #[cfg(feature = "tls")]
            if tls_last_gc.elapsed() >= Duration::from_secs(60) {
                sni_cache.gc();
                tls_conn_tracker.gc();
                #[cfg(feature = "prometheus")]
                metrics::set_tls_connections_tracked(tls_conn_tracker.len());
                tls_last_gc = Instant::now();
            }
        }
    });

    info!("Monitoring LLM/AI communications... Press Ctrl-C to exit");

    signal::ctrl_c().await?;
    info!("Exiting...");

    // Clean up socket file
    let _ = std::fs::remove_file("/tmp/busted.sock");

    Ok(())
}
