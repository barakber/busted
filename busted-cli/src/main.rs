mod cli;
mod monitor;
mod policy;
#[cfg(feature = "tui")]
mod tui;
mod ui;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = cli::Cli::parse();

    match args.command {
        cli::Command::Monitor(monitor_args) => monitor::run(monitor_args),
        cli::Command::Policy(policy_args) => policy::run(policy_args.command),
        #[cfg(feature = "ui")]
        cli::Command::Ui(ui_args) => ui::run(ui_args),
        #[cfg(feature = "tui")]
        cli::Command::Tui(tui_args) => tui::run(tui_args),
    }
}
