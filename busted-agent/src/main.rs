mod events;
mod server;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, perf::AsyncPerfEventArray},
    programs::KProbe,
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use busted_types::{AgentIdentity, NetworkEvent};
use bytes::BytesMut;
use clap::Parser;
use events::ProcessedEvent;
use log::{info, warn};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::{IpAddr, ToSocketAddrs},
    sync::{Arc, OnceLock},
};
use tokio::{
    signal,
    sync::{broadcast, Mutex},
    task,
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

    /// Enable policy enforcement (audit mode)
    #[arg(short, long)]
    enforce: bool,
}

// ---------------------------------------------------------------------------
// LLM provider classification (Phase 2)
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
];

/// Known subnet prefixes for LLM providers (covers CDN/anycast rotation).
/// Format: (first 2 octets as u16, provider name)
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

static PROVIDER_MAP: OnceLock<HashMap<IpAddr, &'static str>> = OnceLock::new();

fn init_provider_map() {
    let map = PROVIDER_MAP.get_or_init(|| {
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
    });
    let _ = map;
}

fn classify_llm_provider(ip: &IpAddr, dport: u16) -> Option<&'static str> {
    if dport != 443 {
        return None;
    }

    // 1. Exact IP match from DNS resolution
    if let Some(provider) = PROVIDER_MAP.get().and_then(|m| m.get(ip).copied()) {
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
// Structured output (Phase 4)
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
        }
    }
}

// ---------------------------------------------------------------------------
// Event handling (Phase 3 + 4 + 5)
// ---------------------------------------------------------------------------

async fn handle_event(
    event: NetworkEvent,
    tx: &broadcast::Sender<ProcessedEvent>,
    identity_map: &Arc<Mutex<AyaHashMap<aya::maps::MapData, u32, AgentIdentity>>>,
    policy_map: &Arc<Mutex<AyaHashMap<aya::maps::MapData, u32, u8>>>,
    enforce: bool,
) {
    let dst_ip = event.dest_ip();

    let provider = classify_llm_provider(&dst_ip, event.dport);

    let policy_str = if provider.is_some() && enforce {
        // Audit mode: log but allow (kprobes can't block traffic)
        if let Ok(mut pmap) = policy_map.try_lock() {
            // Write audit decision (2 = Audit)
            let _ = pmap.insert(event.pid, 2, 0);
        }
        Some("audit")
    } else {
        None
    };

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

    let processed = ProcessedEvent::from_network_event(&event, provider, policy_str);

    // Send to broadcast channel (for UI and other consumers)
    let _ = tx.send(processed);
}

// ---------------------------------------------------------------------------
// CLI output consumer (Phase 4 + 5)
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
                    // text format
                    if let Some(ref provider) = event.provider {
                        info!(
                            "[{}] {} | PID: {} ({}) | UID: {} | {}:{} -> {}:{} | {} bytes | Provider: {}{}",
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
                            provider,
                            event.policy.as_ref().map(|p| format!(" | Policy: {}", p)).unwrap_or_default(),
                        );
                    } else {
                        log::debug!(
                            "[{}] PID: {} ({}) | {}:{} -> {}:{} | {} bytes",
                            event.event_type,
                            event.pid,
                            event.process_name,
                            event.src_ip,
                            event.src_port,
                            event.dst_ip,
                            event.dst_port,
                            event.bytes,
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

    // Resolve LLM provider IPs
    init_provider_map();

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

    // Attach probes
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

    info!("All eBPF programs loaded successfully");

    // Take BPF maps for identity and policy (Phase 3)
    let identity_map: AyaHashMap<_, u32, AgentIdentity> =
        AyaHashMap::try_from(bpf.take_map("AGENT_IDENTITIES").unwrap())?;
    let identity_map = Arc::new(Mutex::new(identity_map));

    let policy_map: AyaHashMap<_, u32, u8> =
        AyaHashMap::try_from(bpf.take_map("POLICY_MAP").unwrap())?;
    let policy_map = Arc::new(Mutex::new(policy_map));

    // Event broadcast channel (Phase 5)
    let (tx, _) = broadcast::channel::<ProcessedEvent>(4096);

    // Start CLI output consumer
    let cli_rx = tx.subscribe();
    let format = cli.format.clone();
    task::spawn(cli_output_consumer(cli_rx, format));

    // Start Unix socket server for UI (Phase 5b)
    let server_rx = tx.subscribe();
    task::spawn(server::run_socket_server(server_rx));

    // Get the events perf array
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    let enforce = cli.enforce;

    // Process events from all CPUs
    for cpu_id in online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();
        let identity_map = identity_map.clone();
        let policy_map = policy_map.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<NetworkEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const NetworkEvent;
                    let event = unsafe { ptr.read_unaligned() };
                    handle_event(event, &tx, &identity_map, &policy_map, enforce).await;
                }
            }
        });
    }

    info!("Monitoring LLM/AI communications... Press Ctrl-C to exit");

    signal::ctrl_c().await?;
    info!("Exiting...");

    // Clean up socket file
    let _ = std::fs::remove_file("/tmp/busted.sock");

    Ok(())
}
