use anyhow::{Context, Result};
use clap::Parser;
use std::{
    path::PathBuf,
    process::Command,
};

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Subcommand,
}

#[derive(Debug, Parser)]
enum Subcommand {
    /// Build the eBPF programs
    BuildEbpf(BuildEbpfOptions),
    /// Build the entire project (eBPF + userspace)
    Build(BuildOptions),
    /// Run the agent (builds everything first)
    Run(RunOptions),
}

#[derive(Debug, Parser)]
pub struct BuildEbpfOptions {
    /// Build in release mode
    #[clap(long)]
    release: bool,
    /// Target architecture
    #[clap(long, default_value = "bpfel-unknown-none")]
    target: String,
}

#[derive(Debug, Parser)]
pub struct BuildOptions {
    /// Build in release mode
    #[clap(long)]
    release: bool,
}

#[derive(Debug, Parser)]
pub struct RunOptions {
    /// Build in release mode
    #[clap(long)]
    release: bool,
    /// Arguments to pass to the agent
    #[clap(last = true)]
    run_args: Vec<String>,
}

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{:#}", e);
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let opts = Options::parse();

    match opts.command {
        Subcommand::BuildEbpf(opts) => build_ebpf(opts),
        Subcommand::Build(opts) => {
            build_ebpf(BuildEbpfOptions {
                release: opts.release,
                target: "bpfel-unknown-none".to_string(),
            })?;
            build_userspace(opts.release)
        }
        Subcommand::Run(opts) => {
            build_ebpf(BuildEbpfOptions {
                release: opts.release,
                target: "bpfel-unknown-none".to_string(),
            })?;
            build_userspace(opts.release)?;
            run(opts)
        }
    }
}

fn build_ebpf(opts: BuildEbpfOptions) -> Result<()> {
    let mut args = vec![
        "build",
        "--package",
        "busted-ebpf",
        "--target",
        &opts.target,
        "-Z",
        "build-std=core",
    ];

    if opts.release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("Failed to build eBPF programs")?;

    if !status.success() {
        anyhow::bail!("Failed to build eBPF programs");
    }

    println!("✓ eBPF programs built successfully");

    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    let mut args = vec!["build", "--package", "busted-agent"];

    if release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("Failed to build userspace agent")?;

    if !status.success() {
        anyhow::bail!("Failed to build userspace agent");
    }

    println!("✓ Userspace agent built successfully");

    Ok(())
}

fn run(opts: RunOptions) -> Result<()> {
    let profile = if opts.release { "release" } else { "debug" };
    let bin_path = PathBuf::from(format!("target/{}/busted", profile));

    let mut cmd = Command::new(bin_path);
    cmd.args(&opts.run_args);

    let status = cmd.status().context("Failed to run agent")?;

    if !status.success() {
        anyhow::bail!("Agent exited with error");
    }

    Ok(())
}
