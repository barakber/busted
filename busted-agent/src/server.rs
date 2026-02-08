use busted_types::processed::ProcessedEvent;
use log::{info, warn};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::sync::broadcast;

const SOCKET_PATH: &str = "/tmp/busted.sock";

pub async fn run_socket_server(mut rx: broadcast::Receiver<ProcessedEvent>) {
    // Remove stale socket file
    if Path::new(SOCKET_PATH).exists() {
        let _ = std::fs::remove_file(SOCKET_PATH);
    }

    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            warn!("Failed to bind Unix socket at {}: {}", SOCKET_PATH, e);
            return;
        }
    };

    // Allow non-root users to connect (agent runs as root, UI runs as user)
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o777)) {
        warn!("Failed to set socket permissions: {}", e);
    }

    info!("UI socket server listening on {}", SOCKET_PATH);

    // Track connected clients via their own broadcast receivers
    let (client_tx, _) = broadcast::channel::<ProcessedEvent>(1024);
    let client_tx_clone = client_tx.clone();

    // Forward events from the main broadcast to the client broadcast
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    // Ignore send errors (no clients connected)
                    let _ = client_tx_clone.send(event);
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Socket server lagged, dropped {} events", n);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                info!("UI client connected");
                let mut client_rx = client_tx.subscribe();

                tokio::spawn(async move {
                    let mut stream = stream;
                    loop {
                        match client_rx.recv().await {
                            Ok(event) => {
                                let mut line =
                                    match serde_json::to_string(&event) {
                                        Ok(s) => s,
                                        Err(_) => continue,
                                    };
                                line.push('\n');
                                if stream.write_all(line.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("Client lagged, dropped {} events", n);
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    info!("UI client disconnected");
                });
            }
            Err(e) => {
                warn!("Failed to accept UI connection: {}", e);
            }
        }
    }
}
