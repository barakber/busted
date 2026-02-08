use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::KProbe,
    util::online_cpus,
    Bpf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use busted_types::NetworkEvent;
use clap::Parser;
use log::{info, warn};
use std::net::IpAddr;
use tokio::{signal, task};

#[derive(Debug, Parser)]
#[command(name = "busted")]
#[command(about = "eBPF-based LLM/AI communication monitoring and identity management", long_about = None)]
struct Cli {
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output format (json, text)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Enable policy enforcement (blocking)
    #[arg(short, long)]
    enforce: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(
        if cli.verbose { "debug" } else { "info" },
    ))
    .init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("Failed to increase rlimit");
    }

    // Load the eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/busted-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/busted-ebpf"
    ))?;

    // Initialize BPF logger
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    info!("Loading eBPF programs...");

    // Attach tcp_connect probe
    let program: &mut KProbe = bpf.program_mut("tcp_connect").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)
        .context("Failed to attach tcp_connect")?;
    info!("Attached to tcp_connect");

    // Attach tcp_sendmsg probe
    let program: &mut KProbe = bpf.program_mut("tcp_sendmsg").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_sendmsg", 0)
        .context("Failed to attach tcp_sendmsg")?;
    info!("Attached to tcp_sendmsg");

    // Attach tcp_recvmsg probe
    let program: &mut KProbe = bpf.program_mut("tcp_recvmsg").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_recvmsg", 0)
        .context("Failed to attach tcp_recvmsg")?;
    info!("Attached to tcp_recvmsg");

    info!("All eBPF programs loaded successfully");

    // Get the events perf array
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // Process events from all CPUs
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<NetworkEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const NetworkEvent;
                    let event = unsafe { ptr.read_unaligned() };
                    handle_event(event);
                }
            }
        });
    }

    info!("Monitoring LLM/AI communications... Press Ctrl-C to exit");

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

/// Handle a network event from eBPF
fn handle_event(event: NetworkEvent) {
    let event_type = match event.event_type {
        1 => "TCP_CONNECT",
        2 => "DATA_SENT",
        3 => "DATA_RECEIVED",
        4 => "CONNECTION_CLOSED",
        _ => "UNKNOWN",
    };

    let process_name = event.process_name();
    let src_ip = event.source_ip();
    let dst_ip = event.dest_ip();

    // Classify if this looks like LLM traffic
    let provider = classify_llm_provider(&dst_ip);

    if let Some(provider_name) = provider {
        info!(
            "[{}] {} | PID: {} ({}) | UID: {} | {}:{} -> {}:{} | Provider: {}",
            event_type,
            format_timestamp(event.timestamp_ns),
            event.pid,
            process_name,
            event.uid,
            src_ip,
            event.sport,
            dst_ip,
            event.dport,
            provider_name
        );

        // TODO: Apply policy enforcement here
        // TODO: Store identity mapping
        // TODO: Emit structured logs/metrics
    } else {
        // Non-LLM traffic - can be filtered or logged at debug level
        log::debug!(
            "[{}] PID: {} ({}) | {}:{} -> {}:{}",
            event_type,
            event.pid,
            process_name,
            src_ip,
            event.sport,
            dst_ip,
            event.dport
        );
    }
}

/// Classify LLM provider based on destination IP
fn classify_llm_provider(ip: &IpAddr) -> Option<&'static str> {
    // TODO: Implement proper IP range matching
    // For now, this is a placeholder
    // In production, you'd maintain maps of known LLM provider IP ranges
    // and update them periodically

    // This would typically involve:
    // 1. DNS resolution of known LLM endpoints
    // 2. ASN lookups
    // 3. Periodic updates from cloud provider IP ranges
    // 4. Machine learning classification based on traffic patterns

    None
}

/// Format timestamp from nanoseconds
fn format_timestamp(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let subsec_ns = (ns % 1_000_000_000) as u32;

    use std::time::{SystemTime, UNIX_EPOCH, Duration};
    let duration = Duration::new(secs, subsec_ns);
    let datetime = UNIX_EPOCH + duration;

    // Simple formatting - in production you'd use chrono
    format!("{:?}", datetime)
}
