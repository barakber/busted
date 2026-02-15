use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "busted")]
#[command(about = "eBPF-based LLM/AI communication monitoring and governance")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the eBPF monitoring agent
    Monitor(MonitorArgs),

    /// OPA/Rego policy management
    Policy(PolicyArgs),

    /// Launch the web dashboard
    #[cfg(feature = "ui")]
    Ui(UiArgs),

    /// Launch the terminal dashboard
    #[cfg(feature = "tui")]
    Tui(TuiArgs),
}

#[derive(Debug, Parser)]
pub struct MonitorArgs {
    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Output format: "text" (default, high-level actions), "verbose" (raw network logs), "json" (full structured JSON)
    #[arg(short, long, default_value = "text")]
    pub format: String,

    /// Enable policy enforcement (audit mode, or deny with LSM)
    #[arg(short, long)]
    pub enforce: bool,

    /// Output sink: "stdout" (default), "webhook:URL", "file:PATH", "syslog:HOST"
    #[arg(short, long, default_value = "stdout")]
    pub output: String,

    /// Directory containing OPA/Rego policy files
    #[arg(long, group = "policy_source")]
    pub policy_dir: Option<PathBuf>,

    /// Inline Rego rule for policy evaluation
    #[arg(long, group = "policy_source")]
    pub rule: Option<String>,

    /// Prometheus metrics HTTP port
    #[arg(long, default_value_t = 9090)]
    pub metrics_port: u16,

    /// Path for persistent identity store (enables cross-session identity tracking)
    #[arg(long)]
    pub identity_store_path: Option<PathBuf>,

    /// Enable file access monitoring (track which files AI agents open)
    #[arg(long)]
    pub file_monitor: bool,
}

#[derive(Debug, Parser)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Validate .rego policy files
    Check {
        /// Directory containing .rego policy files
        #[arg(long)]
        dir: PathBuf,
    },

    /// Evaluate events against policies (stdin NDJSON -> stdout decisions)
    Eval {
        /// Directory containing .rego policy files
        #[arg(long, group = "source")]
        dir: Option<PathBuf>,

        /// Inline Rego rule to evaluate
        #[arg(long, group = "source")]
        rule: Option<String>,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Test policies against sample events and report pass/fail
    Test {
        /// Directory containing .rego policy files
        #[arg(long)]
        dir: PathBuf,

        /// File with NDJSON events to test (reads stdin if omitted)
        #[arg(long)]
        events: Option<PathBuf>,
    },
}

#[cfg(feature = "ui")]
#[derive(Debug, Parser)]
pub struct UiArgs {
    /// Run in demo mode with synthetic events
    #[arg(long)]
    pub demo: bool,
}

#[cfg(feature = "tui")]
#[derive(Debug, Parser)]
pub struct TuiArgs {
    /// Run in demo mode with synthetic events
    #[arg(long)]
    pub demo: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_monitor() {
        let cli = Cli::try_parse_from(["busted", "monitor"]).unwrap();
        assert!(matches!(cli.command, Command::Monitor(_)));
    }

    #[test]
    fn cli_parses_monitor_with_flags() {
        let cli =
            Cli::try_parse_from(["busted", "monitor", "-v", "-f", "json", "--enforce"]).unwrap();
        if let Command::Monitor(args) = cli.command {
            assert!(args.verbose);
            assert_eq!(args.format, "json");
            assert!(args.enforce);
            assert!(!args.file_monitor);
        } else {
            panic!("Expected Monitor command");
        }
    }

    #[test]
    fn cli_parses_monitor_with_file_monitor() {
        let cli = Cli::try_parse_from(["busted", "monitor", "--file-monitor"]).unwrap();
        if let Command::Monitor(args) = cli.command {
            assert!(args.file_monitor);
        } else {
            panic!("Expected Monitor command");
        }
    }

    #[test]
    fn cli_parses_monitor_with_rule() {
        let cli = Cli::try_parse_from([
            "busted",
            "monitor",
            "--enforce",
            "--rule",
            "package busted\ndefault decision = \"deny\"",
        ])
        .unwrap();
        if let Command::Monitor(args) = cli.command {
            assert!(args.enforce);
            assert!(args.rule.is_some());
            assert!(args.policy_dir.is_none());
        } else {
            panic!("Expected Monitor command");
        }
    }

    #[test]
    fn cli_monitor_rule_and_policy_dir_conflict() {
        let result = Cli::try_parse_from([
            "busted",
            "monitor",
            "--rule",
            "package busted",
            "--policy-dir",
            "/tmp/policies",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_parses_policy_check() {
        let cli =
            Cli::try_parse_from(["busted", "policy", "check", "--dir", "/tmp/policies"]).unwrap();
        if let Command::Policy(args) = cli.command {
            assert!(matches!(args.command, PolicyCommand::Check { .. }));
        } else {
            panic!("Expected Policy command");
        }
    }

    #[test]
    fn cli_parses_policy_eval_with_dir() {
        let cli = Cli::try_parse_from([
            "busted",
            "policy",
            "eval",
            "--dir",
            "/tmp/policies",
            "-f",
            "json",
        ])
        .unwrap();
        if let Command::Policy(PolicyArgs {
            command: PolicyCommand::Eval { dir, rule, format },
        }) = cli.command
        {
            assert!(dir.is_some());
            assert!(rule.is_none());
            assert_eq!(format, "json");
        } else {
            panic!("Expected Policy Eval command");
        }
    }

    #[test]
    fn cli_parses_policy_eval_with_rule() {
        let cli = Cli::try_parse_from([
            "busted",
            "policy",
            "eval",
            "--rule",
            "package busted\ndefault decision = \"deny\"",
        ])
        .unwrap();
        if let Command::Policy(PolicyArgs {
            command: PolicyCommand::Eval { dir, rule, .. },
        }) = cli.command
        {
            assert!(dir.is_none());
            assert!(rule.is_some());
        } else {
            panic!("Expected Policy Eval command");
        }
    }

    #[test]
    fn cli_parses_policy_test() {
        let cli =
            Cli::try_parse_from(["busted", "policy", "test", "--dir", "/tmp/policies"]).unwrap();
        if let Command::Policy(PolicyArgs {
            command: PolicyCommand::Test { dir, events },
        }) = cli.command
        {
            assert_eq!(dir, std::path::PathBuf::from("/tmp/policies"));
            assert!(events.is_none());
        } else {
            panic!("Expected Policy Test command");
        }
    }

    #[cfg(feature = "ui")]
    #[test]
    fn cli_parses_ui() {
        let cli = Cli::try_parse_from(["busted", "ui"]).unwrap();
        assert!(matches!(cli.command, Command::Ui(_)));
    }

    #[cfg(feature = "ui")]
    #[test]
    fn cli_parses_ui_demo() {
        let cli = Cli::try_parse_from(["busted", "ui", "--demo"]).unwrap();
        if let Command::Ui(args) = cli.command {
            assert!(args.demo);
        } else {
            panic!("Expected Ui command");
        }
    }

    #[cfg(feature = "tui")]
    #[test]
    fn cli_parses_tui() {
        let cli = Cli::try_parse_from(["busted", "tui"]).unwrap();
        assert!(matches!(cli.command, Command::Tui(_)));
    }

    #[cfg(feature = "tui")]
    #[test]
    fn cli_parses_tui_demo() {
        let cli = Cli::try_parse_from(["busted", "tui", "--demo"]).unwrap();
        if let Command::Tui(args) = cli.command {
            assert!(args.demo);
        } else {
            panic!("Expected Tui command");
        }
    }
}
