use std::io::{self, BufRead, Write};
use std::path::Path;

use anyhow::{Context, Result};
use log::info;

use crate::cli::PolicyCommand;

pub fn run(command: PolicyCommand) -> Result<()> {
    #[cfg(not(feature = "policy"))]
    {
        let _ = command;
        anyhow::bail!(
            "The 'policy' feature is not enabled. \
             Rebuild with: cargo install busted --features policy"
        );
    }

    #[cfg(feature = "policy")]
    match command {
        PolicyCommand::Check { dir } => check(&dir),
        PolicyCommand::Eval { dir, rule, format } => eval(dir.as_deref(), rule.as_deref(), &format),
        PolicyCommand::Test { dir, events } => test(&dir, events.as_deref()),
    }
}

#[cfg(feature = "policy")]
fn check(dir: &Path) -> Result<()> {
    let count = count_rego_files(dir)?;
    // Try to load — this validates all .rego files and data.json
    let _engine = busted_opa::PolicyEngine::new(dir)
        .with_context(|| format!("Policy validation failed for {}", dir.display()))?;

    println!("OK: {} .rego file(s) loaded from {}", count, dir.display());
    Ok(())
}

#[cfg(feature = "policy")]
fn eval(dir: Option<&Path>, rule: Option<&str>, format: &str) -> Result<()> {
    let mut engine = match (dir, rule) {
        (Some(d), _) => busted_opa::PolicyEngine::new(d)
            .with_context(|| format!("Failed to load policies from {}", d.display()))?,
        (_, Some(r)) => {
            busted_opa::PolicyEngine::from_rego(r).context("Failed to parse inline Rego rule")?
        }
        (None, None) => anyhow::bail!("Either --dir or --rule must be provided"),
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line.context("Failed to read stdin")?;
        if line.trim().is_empty() {
            continue;
        }

        let event: busted_types::agentic::BustedEvent =
            serde_json::from_str(&line).with_context(|| "Failed to parse NDJSON event")?;

        let decision = engine
            .evaluate(&event)
            .with_context(|| "Policy evaluation failed")?;

        match format {
            "json" => {
                let output = serde_json::json!({
                    "action": decision.action.as_str(),
                    "reasons": decision.reasons,
                    "pid": event.process.pid,
                    "process_name": event.process.name,
                });
                writeln!(out, "{}", output)?;
            }
            _ => {
                let reasons_str = if decision.reasons.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", decision.reasons.join("; "))
                };
                writeln!(
                    out,
                    "{}: PID {} ({}){}",
                    decision.action, event.process.pid, event.process.name, reasons_str
                )?;
            }
        }
    }

    Ok(())
}

#[cfg(feature = "policy")]
fn test(dir: &Path, events_file: Option<&Path>) -> Result<()> {
    let mut engine = busted_opa::PolicyEngine::new(dir)
        .with_context(|| format!("Failed to load policies from {}", dir.display()))?;

    let reader: Box<dyn BufRead> = match events_file {
        Some(path) => {
            let file = std::fs::File::open(path)
                .with_context(|| format!("Failed to open events file: {}", path.display()))?;
            Box::new(io::BufReader::new(file))
        }
        None => {
            info!("Reading events from stdin...");
            Box::new(io::stdin().lock())
        }
    };

    let mut total = 0u32;
    let mut allow_count = 0u32;
    let mut audit_count = 0u32;
    let mut deny_count = 0u32;
    let mut errors = 0u32;

    for line in reader.lines() {
        let line = line.context("Failed to read line")?;
        if line.trim().is_empty() {
            continue;
        }

        total += 1;

        let event: busted_types::agentic::BustedEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("  PARSE ERROR (line {}): {}", total, e);
                errors += 1;
                continue;
            }
        };

        match engine.evaluate(&event) {
            Ok(decision) => {
                match decision.action {
                    busted_opa::Action::Allow => allow_count += 1,
                    busted_opa::Action::Audit => audit_count += 1,
                    busted_opa::Action::Deny => deny_count += 1,
                }
                let reasons_str = if decision.reasons.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", decision.reasons.join("; "))
                };
                println!(
                    "  [{}] PID {} ({}){}",
                    decision.action.as_str().to_uppercase(),
                    event.process.pid,
                    event.process.name,
                    reasons_str,
                );
            }
            Err(e) => {
                eprintln!("  EVAL ERROR (line {}): {}", total, e);
                errors += 1;
            }
        }
    }

    println!();
    println!("Results: {} events tested", total);
    println!(
        "  ALLOW: {}  AUDIT: {}  DENY: {}  ERRORS: {}",
        allow_count, audit_count, deny_count, errors
    );

    if errors > 0 {
        anyhow::bail!("{} error(s) during policy testing", errors);
    }

    Ok(())
}

#[cfg(feature = "policy")]
fn count_rego_files(dir: &Path) -> Result<usize> {
    if !dir.exists() {
        anyhow::bail!("Policy directory does not exist: {}", dir.display());
    }
    let count = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "rego"))
        .count();
    Ok(count)
}
