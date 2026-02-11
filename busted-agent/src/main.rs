use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "busted-agent")]
#[command(about = "eBPF-based LLM/AI communication monitoring agent")]
struct Cli {
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output format: "text" (default, high-level actions), "verbose" (raw network logs), "json" (full structured JSON)
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if cli.verbose { "debug" } else { "info" }),
    )
    .init();

    let config = busted_agent::AgentConfig {
        verbose: cli.verbose,
        format: cli.format,
        enforce: cli.enforce,
        output: cli.output,
        #[cfg(feature = "opa")]
        policy_dir: cli.policy_dir,
        #[cfg(not(feature = "opa"))]
        policy_dir: None,
        policy_rule: None,
        #[cfg(feature = "prometheus")]
        metrics_port: cli.metrics_port,
        #[cfg(not(feature = "prometheus"))]
        metrics_port: 9090,
    };

    busted_agent::run_agent(config).await
}
