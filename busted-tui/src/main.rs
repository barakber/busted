use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "busted-tui")]
#[command(about = "Terminal dashboard for Busted LLM/AI monitoring")]
#[command(version)]
struct Args {
    /// Run in demo mode with synthetic events
    #[arg(long)]
    demo: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let args = Args::parse();
    busted_tui::run_tui(busted_tui::TuiConfig {
        demo_mode: args.demo,
    })
    .await
}
