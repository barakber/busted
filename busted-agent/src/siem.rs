use crate::events::ProcessedEvent;
use log::{info, warn};
use std::path::PathBuf;
use tokio::sync::broadcast;

/// Output sink for SIEM integration
pub enum OutputSink {
    /// POST NDJSON batches to a webhook URL
    Webhook { url: String },
    /// Append NDJSON lines to a file
    File { path: PathBuf },
    /// Send JSON via UDP to a syslog host (port 514)
    Syslog { host: String },
}

impl OutputSink {
    /// Parse a sink specification string.
    /// Formats: "webhook:URL", "file:PATH", "syslog:HOST"
    pub fn parse(spec: &str) -> Option<Self> {
        if let Some(url) = spec.strip_prefix("webhook:") {
            Some(OutputSink::Webhook {
                url: url.to_string(),
            })
        } else if let Some(path) = spec.strip_prefix("file:") {
            Some(OutputSink::File {
                path: PathBuf::from(path),
            })
        } else if let Some(host) = spec.strip_prefix("syslog:") {
            Some(OutputSink::Syslog {
                host: host.to_string(),
            })
        } else {
            None
        }
    }
}

/// Run a SIEM consumer that reads events from broadcast and writes to the given sink.
pub async fn run_siem_consumer(rx: broadcast::Receiver<ProcessedEvent>, sink: OutputSink) {
    match sink {
        OutputSink::Webhook { url } => run_webhook_consumer(rx, url).await,
        OutputSink::File { path } => run_file_consumer(rx, path).await,
        OutputSink::Syslog { host } => run_syslog_consumer(rx, host).await,
    }
}

async fn run_webhook_consumer(mut rx: broadcast::Receiver<ProcessedEvent>, url: String) {
    info!("SIEM webhook consumer started -> {}", url);
    let client = reqwest::Client::new();
    let mut batch: Vec<String> = Vec::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        if let Ok(json) = serde_json::to_string(&event) {
                            batch.push(json);
                        }
                        if batch.len() >= 10 {
                            flush_webhook_batch(&client, &url, &mut batch).await;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("SIEM webhook consumer lagged, dropped {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = interval.tick() => {
                if !batch.is_empty() {
                    flush_webhook_batch(&client, &url, &mut batch).await;
                }
            }
        }
    }
}

async fn flush_webhook_batch(client: &reqwest::Client, url: &str, batch: &mut Vec<String>) {
    let body = batch.join("\n");
    batch.clear();
    match client
        .post(url)
        .header("Content-Type", "application/x-ndjson")
        .body(body)
        .send()
        .await
    {
        Ok(resp) => {
            if !resp.status().is_success() {
                warn!("SIEM webhook returned status {}", resp.status());
            }
        }
        Err(e) => {
            warn!("SIEM webhook POST failed: {}", e);
        }
    }
}

async fn run_file_consumer(mut rx: broadcast::Receiver<ProcessedEvent>, path: PathBuf) {
    use tokio::io::AsyncWriteExt;

    info!("SIEM file consumer started -> {}", path.display());
    let file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to open SIEM output file {}: {}", path.display(), e);
            return;
        }
    };
    let mut writer = tokio::io::BufWriter::new(file);

    loop {
        match rx.recv().await {
            Ok(event) => {
                if let Ok(json) = serde_json::to_string(&event) {
                    let line = format!("{}\n", json);
                    if writer.write_all(line.as_bytes()).await.is_err() {
                        warn!("Failed to write to SIEM file");
                        break;
                    }
                    // Flush periodically for timely output
                    let _ = writer.flush().await;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("SIEM file consumer lagged, dropped {} events", n);
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn run_syslog_consumer(mut rx: broadcast::Receiver<ProcessedEvent>, host: String) {
    info!("SIEM syslog consumer started -> {}:514", host);
    let addr = format!("{}:514", host);
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to bind UDP socket for syslog: {}", e);
            return;
        }
    };
    if let Err(e) = socket.connect(&addr).await {
        warn!("Failed to connect to syslog at {}: {}", addr, e);
        return;
    }

    loop {
        match rx.recv().await {
            Ok(event) => {
                if let Ok(json) = serde_json::to_string(&event) {
                    // RFC 5424 structured syslog with JSON payload
                    let msg = format!("<14>1 - busted - - - - {}", json);
                    if let Err(e) = socket.send(msg.as_bytes()).await {
                        warn!("Failed to send syslog message: {}", e);
                    }
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("SIEM syslog consumer lagged, dropped {} events", n);
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}
