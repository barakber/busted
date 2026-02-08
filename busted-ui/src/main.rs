mod app;
mod demo;
mod views;

use app::BustedApp;
use std::io::BufRead;
use std::sync::mpsc;

const SOCKET_PATH: &str = "/tmp/busted.sock";

fn main() -> eframe::Result<()> {
    let demo_mode = std::env::args().any(|a| a == "--demo");

    let (tx, rx) = mpsc::channel();

    if demo_mode {
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
        Box::new(move |_cc| Ok(Box::new(BustedApp::new(rx, demo_mode)))),
    )
}
