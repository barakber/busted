use anyhow::{Context, Result};
use clap::Parser;
use std::{fs, path::PathBuf, process::Command};

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
    /// Bump version across the entire workspace
    VersionBump(VersionBumpOptions),
    /// Check that all workspace versions are consistent
    VersionCheck,
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
    /// Comma-separated list of features to enable (e.g. tls,ml,k8s)
    #[clap(long)]
    features: Option<String>,
}

#[derive(Debug, Parser)]
pub struct RunOptions {
    /// Build in release mode
    #[clap(long)]
    release: bool,
    /// Comma-separated list of features to enable (e.g. tls,ml,k8s)
    #[clap(long)]
    features: Option<String>,
    /// Arguments to pass to the agent
    #[clap(last = true)]
    run_args: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct VersionBumpOptions {
    /// The new version (e.g. 0.2.0)
    version: String,
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
            build_userspace(opts.release, opts.features.as_deref())
        }
        Subcommand::Run(opts) => {
            build_ebpf(BuildEbpfOptions {
                release: opts.release,
                target: "bpfel-unknown-none".to_string(),
            })?;
            build_userspace(opts.release, opts.features.as_deref())?;
            run(opts)
        }
        Subcommand::VersionBump(opts) => version_bump(&opts.version),
        Subcommand::VersionCheck => version_check(),
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be inside workspace")
        .to_path_buf()
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

fn build_userspace(release: bool, features: Option<&str>) -> Result<()> {
    // Build the `busted` CLI crate with full features
    let mut args = vec!["build", "--package", "busted", "--features", "full"];

    if release {
        args.push("--release");
    }

    // If extra features requested, they're already covered by "full"
    let features_owned;
    if let Some(f) = features {
        // Merge with "full" — comma-separated
        features_owned = format!("full,{}", f);
        args[4] = &features_owned;
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("Failed to build busted CLI")?;

    if !status.success() {
        anyhow::bail!("Failed to build busted CLI");
    }

    println!("✓ Busted CLI built successfully (with full features)");

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

/// Publishable crate directories (order doesn't matter for version bumping).
const CRATE_DIRS: &[&str] = &[
    "busted-types",
    "busted-classifier",
    "busted-ebpf",
    "busted-ml",
    "busted-opa",
    "busted-ui",
    "busted-agent",
    "busted-cli",
];

fn version_bump(new_version: &str) -> Result<()> {
    // Validate version format (basic semver check)
    let parts: Vec<&str> = new_version.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.parse::<u64>().is_err()) {
        anyhow::bail!(
            "Invalid version '{}': expected semver format X.Y.Z",
            new_version
        );
    }

    let root = workspace_root();

    // 1. Update workspace.package.version in root Cargo.toml
    let root_toml_path = root.join("Cargo.toml");
    let contents = fs::read_to_string(&root_toml_path)
        .with_context(|| format!("Failed to read {}", root_toml_path.display()))?;
    let mut doc = contents
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("Failed to parse {}", root_toml_path.display()))?;

    doc["workspace"]["package"]["version"] = toml_edit::value(new_version);
    fs::write(&root_toml_path, doc.to_string())
        .with_context(|| format!("Failed to write {}", root_toml_path.display()))?;
    println!("  Updated workspace.package.version in Cargo.toml");

    // 2. Update path dependency versions in each crate
    for dir in CRATE_DIRS {
        let toml_path = root.join(dir).join("Cargo.toml");
        if !toml_path.exists() {
            continue;
        }

        let contents = fs::read_to_string(&toml_path)
            .with_context(|| format!("Failed to read {}", toml_path.display()))?;
        let mut doc = contents
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("Failed to parse {}", toml_path.display()))?;

        let mut updated = false;
        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(deps) = doc.get_mut(section).and_then(|d| d.as_table_mut()) {
                for (dep_name, dep_value) in deps.iter_mut() {
                    if let Some(tbl) = dep_value.as_inline_table_mut() {
                        if tbl.contains_key("path") && tbl.contains_key("version") {
                            tbl["version"] =
                                toml_edit::value(new_version).as_value().unwrap().clone();
                            updated = true;
                            println!("  Updated {}/{} -> {}", dir, dep_name, new_version);
                        }
                    } else if let Some(tbl) = dep_value.as_table_mut() {
                        if tbl.contains_key("path") && tbl.contains_key("version") {
                            tbl["version"] = toml_edit::value(new_version);
                            updated = true;
                            println!("  Updated {}/{} -> {}", dir, dep_name, new_version);
                        }
                    }
                }
            }
        }

        if updated {
            fs::write(&toml_path, doc.to_string())
                .with_context(|| format!("Failed to write {}", toml_path.display()))?;
        }
    }

    println!("\nVersion bumped to {}", new_version);
    Ok(())
}

fn version_check() -> Result<()> {
    let root = workspace_root();

    // Read expected version from workspace
    let root_toml_path = root.join("Cargo.toml");
    let contents = fs::read_to_string(&root_toml_path)
        .with_context(|| format!("Failed to read {}", root_toml_path.display()))?;
    let doc = contents
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("Failed to parse {}", root_toml_path.display()))?;

    let expected = doc["workspace"]["package"]["version"]
        .as_str()
        .context("workspace.package.version not found in root Cargo.toml")?;

    println!("Workspace version: {}", expected);

    let mut errors = Vec::new();

    for dir in CRATE_DIRS {
        let toml_path = root.join(dir).join("Cargo.toml");
        if !toml_path.exists() {
            continue;
        }

        let contents = fs::read_to_string(&toml_path)
            .with_context(|| format!("Failed to read {}", toml_path.display()))?;
        let doc = contents
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("Failed to parse {}", toml_path.display()))?;

        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(deps) = doc.get(section).and_then(|d| d.as_table()) {
                for (dep_name, dep_value) in deps.iter() {
                    let (has_path, version) = if let Some(tbl) = dep_value.as_inline_table() {
                        (
                            tbl.contains_key("path"),
                            tbl.get("version").and_then(|v| v.as_str()),
                        )
                    } else if let Some(tbl) = dep_value.as_table() {
                        (
                            tbl.contains_key("path"),
                            tbl.get("version").and_then(|v| v.as_str()),
                        )
                    } else {
                        (false, None)
                    };

                    if has_path {
                        if let Some(ver) = version {
                            if ver != expected {
                                errors.push(format!(
                                    "  {}/Cargo.toml: {}.{} has version \"{}\" (expected \"{}\")",
                                    dir, section, dep_name, ver, expected
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    if errors.is_empty() {
        println!("All path dependency versions are consistent.");
        Ok(())
    } else {
        eprintln!("Version mismatches found:");
        for e in &errors {
            eprintln!("{}", e);
        }
        anyhow::bail!("{} version mismatch(es) found", errors.len());
    }
}
