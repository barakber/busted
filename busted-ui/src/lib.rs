//! Native egui dashboard for real-time LLM communication monitoring.
//!
//! Connects to the `busted-agent` over a Unix socket (`/tmp/busted.sock`) and
//! displays a live table of classified events with provider statistics, process
//! views, and identity tracking columns.
//!
//! # Modes
//!
//! - **Live mode** (default): Reads NDJSON events from the agent's Unix socket.
//!   Requires the agent to be running.
//! - **Demo mode** (`--demo`): Generates synthetic events for quick evaluation
//!   without requiring root or a running agent.
//!
//! # Usage
//!
//! ```no_run
//! use busted_ui::{UiConfig, run_ui};
//!
//! let config = UiConfig { demo_mode: true };
//! run_ui(config).unwrap();
//! ```

pub mod app;
pub mod demo;
pub mod views;

use app::BustedApp;
use std::io::BufRead;
use std::sync::mpsc;

const SOCKET_PATH: &str = "/tmp/busted.sock";

/// Configuration for the UI.
pub struct UiConfig {
    pub demo_mode: bool,
}

/// Launch the egui dashboard.
pub fn run_ui(config: UiConfig) -> eframe::Result<()> {
    let (tx, rx) = mpsc::channel();

    if config.demo_mode {
        demo::start(tx);
    } else {
        // Background thread: connect to agent's Unix socket and forward events
        std::thread::spawn(move || {
            loop {
                match std::os::unix::net::UnixStream::connect(SOCKET_PATH) {
                    Ok(stream) => {
                        let reader = std::io::BufReader::new(stream);
                        for line in reader.lines() {
                            match line {
                                Ok(line) if !line.is_empty() => {
                                    if let Ok(event) = serde_json::from_str(&line) {
                                        if tx.send(event).is_err() {
                                            return; // UI closed
                                        }
                                    }
                                }
                                Err(_) => break, // Connection lost, retry
                                _ => {}
                            }
                        }
                    }
                    Err(_) => {
                        // Agent not running, retry after delay
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        });
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 700.0])
            .with_title("Busted - LLM Communication Monitor"),
        ..Default::default()
    };

    eframe::run_native(
        "Busted",
        options,
        Box::new(move |_cc| Ok(Box::new(BustedApp::new(rx, config.demo_mode)))),
    )
}
