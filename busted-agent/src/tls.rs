use log::{debug, warn};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::LLM_ENDPOINTS;

/// Entry in the SNI cache: hostname + insertion timestamp.
struct SniEntry {
    hostname: String,
    inserted_at: Instant,
}

/// Cache mapping PID → SNI hostname extracted from SSL_ctrl uprobes.
pub struct SniCache {
    map: HashMap<u32, SniEntry>,
}

/// TTL for SNI cache entries (5 minutes).
const SNI_TTL_SECS: u64 = 300;

/// Maximum entries before forced GC.
const SNI_MAX_ENTRIES: usize = 10_000;

impl SniCache {
    pub fn new() -> Self {
        SniCache {
            map: HashMap::new(),
        }
    }

    /// Record an SNI hostname for a given PID.
    pub fn insert(&mut self, pid: u32, hostname: String) {
        if self.map.len() >= SNI_MAX_ENTRIES {
            self.gc();
        }
        self.map.insert(
            pid,
            SniEntry {
                hostname,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Look up the SNI hostname for a PID, returning None if expired.
    pub fn get(&self, pid: u32) -> Option<&str> {
        self.map.get(&pid).and_then(|entry| {
            if entry.inserted_at.elapsed().as_secs() < SNI_TTL_SECS {
                Some(entry.hostname.as_str())
            } else {
                None
            }
        })
    }

    /// Evict entries older than TTL.
    pub fn gc(&mut self) {
        self.map
            .retain(|_, entry| entry.inserted_at.elapsed().as_secs() < SNI_TTL_SECS);
    }
}

/// Attempt to detect the path to libssl.so on this system.
pub fn detect_libssl_path() -> Option<PathBuf> {
    // Common paths by distro and OpenSSL version
    let candidates = [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/aarch64-linux-gnu/libssl.so.3",
        "/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        "/usr/lib/libssl.so.3",
        "/usr/lib/libssl.so.1.1",
    ];

    for path in &candidates {
        if Path::new(path).exists() {
            debug!("Found libssl at {}", path);
            return Some(PathBuf::from(path));
        }
    }

    // Fallback: parse ldconfig -p
    match std::process::Command::new("ldconfig")
        .arg("-p")
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("libssl.so") && line.contains("x86-64") || line.contains("libssl.so.3") {
                    // Format: "    libssl.so.3 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libssl.so.3"
                    if let Some(path) = line.split("=> ").nth(1) {
                        let path = path.trim();
                        if Path::new(path).exists() {
                            debug!("Found libssl via ldconfig: {}", path);
                            return Some(PathBuf::from(path));
                        }
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to run ldconfig: {}", e);
        }
    }

    None
}

/// Classify an SNI hostname to an LLM provider name.
/// Uses substring matching against the same endpoint list as IP classification.
pub fn classify_by_sni(sni: &str) -> Option<&'static str> {
    let sni_lower = sni.to_lowercase();
    for &(hostname, provider) in LLM_ENDPOINTS {
        if sni_lower.contains(hostname) {
            return Some(provider);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// TLS connection tracker and content classification
// ---------------------------------------------------------------------------

/// Classify a decrypted TLS payload using busted-classifier.
pub fn classify_payload(
    payload: &[u8],
    direction: u8,
    sni: Option<&str>,
) -> busted_classifier::Classification {
    let dir = if direction == 0 {
        busted_classifier::Direction::Write
    } else {
        busted_classifier::Direction::Read
    };
    busted_classifier::classify(payload, dir, sni)
}

struct ConnState {
    decided: bool,
    interesting: bool,
    chunks_seen: u32,
    first_seen: Instant,
}

/// Tracks per-connection state in userspace, keyed by (pid, ssl_ptr).
pub struct TlsConnTracker {
    conns: HashMap<(u32, u64), ConnState>,
}

/// TTL for connection tracker entries (5 minutes).
const CONN_TTL_SECS: u64 = 300;

/// Number of chunks to analyze before giving up and marking BORING.
/// HTTP/2 typically needs 3-5 SSL_write calls before the actual request body.
const MAX_UNDECIDED_CHUNKS: u32 = 10;

impl TlsConnTracker {
    pub fn new() -> Self {
        TlsConnTracker {
            conns: HashMap::new(),
        }
    }

    /// Record a chunk for this connection. Returns the chunk count.
    pub fn record_chunk(&mut self, pid: u32, ssl_ptr: u64) -> u32 {
        let state = self.conns.entry((pid, ssl_ptr)).or_insert(ConnState {
            decided: false,
            interesting: false,
            chunks_seen: 0,
            first_seen: Instant::now(),
        });
        state.chunks_seen += 1;
        state.chunks_seen
    }

    /// Check if this connection has a final verdict.
    pub fn is_decided(&self, pid: u32, ssl_ptr: u64) -> bool {
        self.conns
            .get(&(pid, ssl_ptr))
            .map(|s| s.decided)
            .unwrap_or(false)
    }

    /// Mark a connection with a final verdict (interesting or boring).
    pub fn set_verdict(&mut self, pid: u32, ssl_ptr: u64, interesting: bool) {
        let state = self.conns.entry((pid, ssl_ptr)).or_insert(ConnState {
            decided: false,
            interesting: false,
            chunks_seen: 0,
            first_seen: Instant::now(),
        });
        state.decided = true;
        state.interesting = interesting;
    }

    /// Returns true if we've seen enough chunks to give up.
    pub fn should_mark_boring(&self, pid: u32, ssl_ptr: u64) -> bool {
        self.conns
            .get(&(pid, ssl_ptr))
            .map(|s| !s.decided && s.chunks_seen >= MAX_UNDECIDED_CHUNKS)
            .unwrap_or(false)
    }

    /// Number of tracked connections.
    pub fn len(&self) -> usize {
        self.conns.len()
    }

    /// Evict entries older than TTL.
    pub fn gc(&mut self) {
        self.conns
            .retain(|_, state| state.first_seen.elapsed().as_secs() < CONN_TTL_SECS);
    }
}

