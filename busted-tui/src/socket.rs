use busted_types::agentic::BustedEvent;
use log::{debug, warn};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::event::AppEvent;

const SOCKET_PATH: &str = "/tmp/busted.sock";

/// Connect to the agent's Unix socket and forward NDJSON events.
/// Reconnects automatically on disconnection.
pub async fn unix_socket_bridge(tx: mpsc::UnboundedSender<AppEvent>) {
    loop {
        match UnixStream::connect(SOCKET_PATH).await {
            Ok(stream) => {
                log::info!("Connected to agent at {SOCKET_PATH}");
                let reader = BufReader::new(stream);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if line.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<BustedEvent>(&line) {
                        Ok(event) => {
                            if tx.send(AppEvent::Busted(Box::new(event))).is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse event: {e}");
                        }
                    }
                }
                log::info!("Agent connection closed, reconnecting...");
            }
            Err(_) => {
                debug!("Agent not available at {SOCKET_PATH}, retrying...");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
