mod events;
#[cfg(feature = "k8s")]
mod k8s;
#[cfg(feature = "ml")]
use busted_ml as ml;
#[cfg(feature = "prometheus")]
mod metrics;
mod server;
mod siem;
#[cfg(feature = "tls")]
mod tls;

use anyhow::{Context, Result};
#[cfg(feature = "tls")]
use aya::programs::UProbe;
use aya::{
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, MapData, RingBuf},
    programs::{KProbe, Lsm},
    Btf, Ebpf,
};
use aya_log::EbpfLogger;
use busted_types::processed::ProcessedEvent;
use busted_types::{AgentIdentity, NetworkEvent};
#[cfg(feature = "tls")]
use busted_types::{TlsConnKey, TlsDataEvent, TlsHandshakeEvent};
use clap::Parser;
use log::{debug, info, warn};
use regex::Regex;
use serde::Serialize;
#[cfg(feature = "prometheus")]
use std::collections::HashSet;
use std::{
    collections::HashMap,
    net::{IpAddr, ToSocketAddrs},
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
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(name = "busted")]
#[command(about = "eBPF-based LLM/AI communication monitoring and identity management")]
struct Cli {
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output format (json, text)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Enable policy enforcement (audit mode, or deny with LSM)
    #[arg(short, long)]
    enforce: bool,

    /// Output sink: "stdout" (default), "webhook:URL", "file:PATH", "syslog:HOST"
    #[arg(short, long, default_value = "stdout")]
    output: String,

    /// Directory containing OPA/Rego policy files
    #[cfg(feature = "opa")]
    #[arg(long)]
    policy_dir: Option<std::path::PathBuf>,

    /// Prometheus metrics HTTP port
    #[cfg(feature = "prometheus")]
    #[arg(long, default_value_t = 9090)]
    metrics_port: u16,
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
// Structured output
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct EventOutput {
    event_type: String,
    timestamp: String,
    pid: u32,
    uid: u32,
    process_name: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    bytes: u64,
    provider: Option<String>,
    policy: Option<String>,
    container_id: String,
    cgroup_id: u64,
    request_rate: Option<f64>,
    session_bytes: Option<u64>,
    pod_name: Option<String>,
    pod_namespace: Option<String>,
    service_account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ml_confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ml_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    behavior_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    llm_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    llm_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    llm_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_sdk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_fingerprint: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classifier_confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pii_detected: Option<bool>,
}

impl From<&ProcessedEvent> for EventOutput {
    fn from(e: &ProcessedEvent) -> Self {
        EventOutput {
            event_type: e.event_type.clone(),
            timestamp: e.timestamp.clone(),
            pid: e.pid,
            uid: e.uid,
            process_name: e.process_name.clone(),
            src_ip: e.src_ip.clone(),
            src_port: e.src_port,
            dst_ip: e.dst_ip.clone(),
            dst_port: e.dst_port,
            bytes: e.bytes,
            provider: e.provider.clone(),
            policy: e.policy.clone(),
            container_id: e.container_id.clone(),
            cgroup_id: e.cgroup_id,
            request_rate: e.request_rate,
            session_bytes: e.session_bytes,
            pod_name: e.pod_name.clone(),
            pod_namespace: e.pod_namespace.clone(),
            service_account: e.service_account.clone(),
            ml_confidence: e.ml_confidence,
            ml_provider: e.ml_provider.clone(),
            behavior_class: e.behavior_class.clone(),
            cluster_id: e.cluster_id,
            sni: e.sni.clone(),
            tls_protocol: e.tls_protocol.clone(),
            tls_details: e.tls_details.clone(),
            tls_payload: e.tls_payload.clone(),
            content_class: e.content_class.clone(),
            llm_provider: e.llm_provider.clone(),
            llm_endpoint: e.llm_endpoint.clone(),
            llm_model: e.llm_model.clone(),
            mcp_method: e.mcp_method.clone(),
            mcp_category: e.mcp_category.clone(),
            agent_sdk: e.agent_sdk.clone(),
            agent_fingerprint: e.agent_fingerprint,
            classifier_confidence: e.classifier_confidence,
            pii_detected: e.pii_detected,
        }
    }
}

// ---------------------------------------------------------------------------
// Event handling
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn handle_event(
    event: NetworkEvent,
    tx: &broadcast::Sender<ProcessedEvent>,
    identity_map: &Arc<Mutex<AyaHashMap<MapData, u32, AgentIdentity>>>,
    policy_map: &Arc<Mutex<AyaHashMap<MapData, u32, u8>>>,
    provider_map: &Arc<RwLock<HashMap<IpAddr, &'static str>>>,
    enforce: bool,
    container_cache: &mut HashMap<u32, String>,
    pid_stats: &mut HashMap<u32, PidStats>,
    #[cfg(feature = "k8s")] k8s_cache: &Arc<RwLock<HashMap<String, k8s::PodMetadata>>>,
    #[cfg(feature = "ml")] ml_classifier: &mut ml::MlClassifier,
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
    let session_bytes = stats.bytes_total;

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
        processed.container_id = container_id;
    }
    processed.request_rate = Some(request_rate);
    processed.session_bytes = Some(session_bytes);

    // Attach SNI hostname if available
    #[cfg(feature = "tls")]
    {
        processed.sni = sni_hostname.map(|s| s.to_string());
    }

    // Enrich with Kubernetes pod metadata if available
    #[cfg(feature = "k8s")]
    {
        let k8s_map = k8s_cache.read().await;
        if let Some(meta) = k8s::resolve_pod_metadata(&processed.container_id, &k8s_map) {
            processed.pod_name = Some(meta.pod_name);
            processed.pod_namespace = Some(meta.namespace);
            processed.service_account = Some(meta.service_account);
        }
    }

    // ML behavioral classification
    #[cfg(feature = "ml")]
    {
        let behavior = ml_classifier.process_event(&event, provider);
        if let Some(ref b) = behavior {
            // If ML detects LLM traffic with high confidence but IP match missed it,
            // promote the ML prediction to the provider field.
            if b.is_novel && b.confidence > 0.85 && processed.provider.is_none() {
                if let ml::BehaviorClass::LlmApi(ref p) = b.class {
                    processed.provider = Some(format!("{} (ML)", p));
                }
            }
            processed.ml_confidence = Some(b.confidence);
            processed.behavior_class = Some(b.class.to_string());
            processed.cluster_id = Some(b.cluster_id);
            if let ml::BehaviorClass::LlmApi(ref p) = b.class {
                processed.ml_provider = Some(p.clone());
            }

            #[cfg(feature = "prometheus")]
            metrics::record_ml_classification(&b.class.to_string());
        }
    }

    // OPA policy evaluation (overrides hardcoded policy if enabled)
    #[cfg(feature = "opa")]
    if let Some(ref mut engine) = opa_engine {
        match engine.evaluate(&processed) {
            Ok(decision) => {
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
            Err(e) => warn!("OPA evaluation failed: {e}"),
        }
    }

    // Record event metrics (all events, not just interesting ones)
    #[cfg(feature = "prometheus")]
    metrics::record_event(
        &processed.event_type,
        processed.provider.as_deref(),
        processed.bytes,
    );

    // Only broadcast interesting events (LLM/AI-related)
    // Non-interesting traffic is only visible at debug log level
    if processed.provider.is_some() {
        // Track unique PIDs and providers for metrics
        #[cfg(feature = "prometheus")]
        {
            llm_pids.insert(processed.pid);
            metrics::set_active_pids(llm_pids.len());
            if let Some(ref p) = processed.provider {
                if unique_providers.insert(p.clone()) {
                    metrics::set_providers_detected(unique_providers.len());
                }
            }
        }
        let _ = tx.send(processed);
    } else {
        debug!(
            "[{}] PID: {} ({}) | {}:{} -> {}:{} | {} bytes",
            processed.event_type,
            processed.pid,
            processed.process_name,
            processed.src_ip,
            processed.src_port,
            processed.dst_ip,
            processed.dst_port,
            processed.bytes,
        );
    }
}

// ---------------------------------------------------------------------------
// CLI output consumer
// ---------------------------------------------------------------------------

async fn cli_output_consumer(mut rx: broadcast::Receiver<ProcessedEvent>, format: String) {
    loop {
        match rx.recv().await {
            Ok(event) => match format.as_str() {
                "json" => {
                    let output = EventOutput::from(&event);
                    if let Ok(json) = serde_json::to_string(&output) {
                        println!("{}", json);
                    }
                }
                _ => {
                    // TLS data events: show decrypted payload
                    if event.event_type.starts_with("TLS_DATA_") {
                        if let Some(ref payload) = event.tls_payload {
                            info!(
                                "[{}] {} | PID: {} ({}) | {} bytes | {}{}\n---\n{}\n---",
                                event.event_type,
                                event.timestamp,
                                event.pid,
                                event.process_name,
                                event.bytes,
                                event.tls_protocol.as_deref().unwrap_or(""),
                                event
                                    .tls_details
                                    .as_ref()
                                    .map(|d| format!(" ({})", d))
                                    .unwrap_or_default(),
                                payload,
                            );
                        }
                    } else {
                        info!(
                            "[{}] {} | PID: {} ({}) | UID: {} | {}:{} -> {}:{} | {} bytes | Provider: {}{}{}",
                            event.event_type,
                            event.timestamp,
                            event.pid,
                            event.process_name,
                            event.uid,
                            event.src_ip,
                            event.src_port,
                            event.dst_ip,
                            event.dst_port,
                            event.bytes,
                            event.provider.as_deref().unwrap_or("unknown"),
                            event.policy.as_ref().map(|p| format!(" | Policy: {}", p)).unwrap_or_default(),
                            if !event.container_id.is_empty() {
                                format!(" | Container: {}", event.container_id)
                            } else {
                                String::new()
                            },
                        );
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if cli.verbose { "debug" } else { "info" }),
    )
    .init();

    // Initialize Prometheus metrics exporter
    #[cfg(feature = "prometheus")]
    metrics::init(cli.metrics_port)?;

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

    // Load eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/busted-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/busted-ebpf"
    ))?;

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
        if let Some(libssl_path) = tls::detect_libssl_path() {
            // SNI extraction (existing)
            let prog: &mut UProbe = bpf.program_mut("ssl_ctrl_sni").unwrap().try_into()?;
            prog.load()?;
            match prog.attach(Some("SSL_ctrl"), 0, &libssl_path, None) {
                Ok(_) => info!(
                    "TLS uprobe attached to SSL_ctrl at {}",
                    libssl_path.display()
                ),
                Err(e) => warn!("Failed to attach TLS uprobe: {}", e),
            }

            // SSL_write plaintext capture
            let prog: &mut UProbe = bpf.program_mut("ssl_write_entry").unwrap().try_into()?;
            prog.load()?;
            match prog.attach(Some("SSL_write"), 0, &libssl_path, None) {
                Ok(_) => info!("TLS uprobe attached to SSL_write"),
                Err(e) => warn!("Failed to attach SSL_write uprobe: {}", e),
            }

            // SSL_read entry (stash args)
            let prog: &mut UProbe = bpf.program_mut("ssl_read_entry").unwrap().try_into()?;
            prog.load()?;
            match prog.attach(Some("SSL_read"), 0, &libssl_path, None) {
                Ok(_) => info!("TLS uprobe attached to SSL_read"),
                Err(e) => warn!("Failed to attach SSL_read uprobe: {}", e),
            }

            // SSL_read return (read buffer)
            let prog: &mut UProbe = bpf.program_mut("ssl_read_ret").unwrap().try_into()?;
            prog.load()?;
            match prog.attach(Some("SSL_read"), 0, &libssl_path, None) {
                Ok(_) => info!("TLS uretprobe attached to SSL_read"),
                Err(e) => warn!("Failed to attach SSL_read uretprobe: {}", e),
            }

            // SSL_free cleanup
            let prog: &mut UProbe = bpf.program_mut("ssl_free_cleanup").unwrap().try_into()?;
            prog.load()?;
            match prog.attach(Some("SSL_free"), 0, &libssl_path, None) {
                Ok(_) => info!("TLS uprobe attached to SSL_free"),
                Err(e) => warn!("Failed to attach SSL_free uprobe: {}", e),
            }
        } else {
            warn!("libssl.so not found, TLS probes disabled");
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

    // Kubernetes pod metadata cache (behind feature flag)
    #[cfg(feature = "k8s")]
    let k8s_cache = {
        let cache = Arc::new(RwLock::new(HashMap::<String, k8s::PodMetadata>::new()));
        let cache_clone = cache.clone();
        task::spawn(k8s::start_pod_watcher(cache_clone));
        cache
    };

    // Event broadcast channel
    let (tx, _) = broadcast::channel::<ProcessedEvent>(4096);

    // Start CLI output consumer
    let cli_rx = tx.subscribe();
    let format = cli.format.clone();
    task::spawn(cli_output_consumer(cli_rx, format));

    // Start Unix socket server for UI
    let server_rx = tx.subscribe();
    task::spawn(server::run_socket_server(server_rx));

    // Start SIEM output consumer if configured
    if cli.output != "stdout" {
        if let Some(sink) = siem::OutputSink::parse(&cli.output) {
            let siem_rx = tx.subscribe();
            task::spawn(siem::run_siem_consumer(siem_rx, sink));
        } else {
            warn!("Unknown output sink format: {}", cli.output);
        }
    }

    // Set up RingBuf consumer
    let ring_buf = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let async_fd = AsyncFd::new(ring_buf)?;
    let enforce = cli.enforce;

    // Initialize OPA policy engine (if configured)
    #[cfg(feature = "opa")]
    let opa_engine: Option<busted_opa::PolicyEngine> = cli.policy_dir.as_ref().map(|dir| {
        busted_opa::PolicyEngine::new(dir).expect("Failed to initialize OPA policy engine")
    });

    #[cfg(feature = "k8s")]
    let k8s_cache_clone = k8s_cache.clone();

    task::spawn(async move {
        let mut container_cache: HashMap<u32, String> = HashMap::new();
        let mut pid_stats: HashMap<u32, PidStats> = HashMap::new();
        let mut async_fd = async_fd;
        #[cfg(feature = "opa")]
        let mut opa_engine = opa_engine;
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

                    if tls_conn_tracker.is_decided(tls_data.pid, tls_data.ssl_ptr) {
                        // Already decided interesting — classify and forward
                        let classification = tls::classify_payload(
                            tls_data.payload_bytes(),
                            tls_data.direction,
                            sni_hint,
                        );
                        debug!(
                            "TLS data {}: PID {} ({}) {} bytes",
                            direction_str,
                            tls_data.pid,
                            tls_data.process_name(),
                            tls_data.payload_len,
                        );

                        #[cfg(feature = "opa")]
                        let mut processed = events::from_tls_data_event(&tls_data, &classification);
                        #[cfg(not(feature = "opa"))]
                        let processed = events::from_tls_data_event(&tls_data, &classification);
                        #[cfg(feature = "opa")]
                        if let Some(ref mut engine) = opa_engine {
                            match engine.evaluate(&processed) {
                                Ok(decision) => {
                                    processed.policy = Some(decision.action.as_str().to_string());
                                }
                                Err(e) => warn!("OPA evaluation failed: {e}"),
                            }
                        }
                        let _ = tx.send(processed);
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

                            #[cfg(feature = "opa")]
                            let mut processed =
                                events::from_tls_data_event(&tls_data, &classification);
                            #[cfg(not(feature = "opa"))]
                            let processed = events::from_tls_data_event(&tls_data, &classification);
                            #[cfg(feature = "opa")]
                            if let Some(ref mut engine) = opa_engine {
                                match engine.evaluate(&processed) {
                                    Ok(decision) => {
                                        processed.policy =
                                            Some(decision.action.as_str().to_string());
                                    }
                                    Err(e) => warn!("OPA evaluation failed: {e}"),
                                }
                            }
                            let _ = tx.send(processed);
                        } else if tls_conn_tracker
                            .should_mark_boring(tls_data.pid, tls_data.ssl_ptr)
                        {
                            // Hit the limit — mark as boring
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
                #[cfg(feature = "tls")]
                if item_len >= std::mem::size_of::<TlsHandshakeEvent>()
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
