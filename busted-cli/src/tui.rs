#[cfg(feature = "tui")]
use crate::cli::TuiArgs;

#[cfg(feature = "tui")]
pub fn run(args: TuiArgs) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(busted_tui::run_tui(busted_tui::TuiConfig {
        demo_mode: args.demo,
    }))
}
