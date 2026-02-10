use anyhow::Result;

use crate::cli::MonitorArgs;

pub fn run(args: MonitorArgs) -> Result<()> {
    #[cfg(not(feature = "monitor"))]
    {
        let _ = args;
        anyhow::bail!(
            "The 'monitor' feature is not enabled. \
             Rebuild with: cargo install busted --features monitor"
        );
    }

    #[cfg(feature = "monitor")]
    {
        let config = busted_agent::AgentConfig {
            verbose: args.verbose,
            format: args.format,
            enforce: args.enforce,
            output: args.output,
            policy_dir: args.policy_dir,
            policy_rule: args.rule,
            metrics_port: args.metrics_port,
        };

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(busted_agent::run_agent(config))
    }
}
