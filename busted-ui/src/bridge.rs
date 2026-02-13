use busted_types::agentic::BustedEvent;
use std::sync::mpsc;

const SOCKET_PATH: &str = "/tmp/busted.sock";

/// Spawn a background thread that runs a tokio runtime to connect to the agent
/// socket (or generate demo events) and forward them via an mpsc channel.
/// Returns the receiving end of the channel.
pub fn spawn_bridge(ctx: eframe::egui::Context, demo_mode: bool) -> mpsc::Receiver<BustedEvent> {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        rt.block_on(async move {
            if demo_mode {
                run_demo(tx, ctx).await;
            } else {
                run_socket(tx, ctx).await;
            }
        });
    });

    rx
}

async fn run_demo(tx: mpsc::Sender<BustedEvent>, ctx: eframe::egui::Context) {
    use crate::demo;

    let mut cycle = 0usize;
    loop {
        let batch = demo::generate_batch(cycle);
        for (event, delay_ms) in batch {
            if tx.send(event).is_err() {
                return;
            }
            ctx.request_repaint();
            if delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
        cycle += 1;
        let delay = 300 + (cycle * 29) % 200;
        tokio::time::sleep(std::time::Duration::from_millis(delay as u64)).await;
    }
}

async fn run_socket(tx: mpsc::Sender<BustedEvent>, ctx: eframe::egui::Context) {
    use tokio::io::AsyncBufReadExt;

    loop {
        match tokio::net::UnixStream::connect(SOCKET_PATH).await {
            Ok(stream) => {
                log::info!("Connected to agent at {SOCKET_PATH}");
                let reader = tokio::io::BufReader::new(stream);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if line.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<BustedEvent>(&line) {
                        Ok(event) => {
                            if tx.send(event).is_err() {
                                return;
                            }
                            ctx.request_repaint();
                        }
                        Err(e) => {
                            log::warn!("Failed to parse event: {e}");
                        }
                    }
                }
                log::info!("Agent connection closed, reconnecting...");
            }
            Err(_) => {
                log::debug!("Agent not available at {SOCKET_PATH}, retrying...");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
