#[cfg(feature = "ui")]
use crate::cli::UiArgs;

#[cfg(feature = "ui")]
pub fn run(args: UiArgs) -> anyhow::Result<()> {
    busted_ui::run_ui(busted_ui::UiConfig {
        demo_mode: args.demo,
    })
}
