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

impl Default for SniCache {
    fn default() -> Self {
        Self::new()
    }
}

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
    match std::process::Command::new("ldconfig").arg("-p").output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("libssl.so") && line.contains("x86-64")
                    || line.contains("libssl.so.3")
                {
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

/// Detect additional binaries that statically link OpenSSL (e.g., Node.js).
/// These need separate uprobe attachments since they don't use the system libssl.so.
/// We don't verify symbols here — aya will resolve them during attach() and we
/// log a warning if attachment fails.
pub fn detect_additional_ssl_targets() -> Vec<PathBuf> {
    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Try `which node` first
    if let Ok(output) = std::process::Command::new("which").arg("node").output() {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path_str.is_empty() {
                // Resolve symlinks to get the real binary
                if let Ok(real) = std::fs::canonicalize(&path_str) {
                    if seen.insert(real.clone()) {
                        debug!("Found Node.js binary at {}", real.display());
                        targets.push(real);
                    }
                }
            }
        }
    }

    // Also scan running node processes via /proc for nvm/snap/other installs
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().parse::<u32>().is_ok() {
                let exe_link = entry.path().join("exe");
                if let Ok(real_path) = std::fs::read_link(&exe_link) {
                    let name = real_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if name == "node" && seen.insert(real_path.clone()) {
                        debug!("Found running Node.js process at {}", real_path.display());
                        targets.push(real_path);
                    }
                }
            }
        }
    }

    targets
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
// HTTP/2 frame extraction
// ---------------------------------------------------------------------------

/// HTTP/2 connection preface sent by the client.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 frame types we care about.
const H2_FRAME_DATA: u8 = 0x00;

/// HTTP/2 frame header size.
const H2_FRAME_HEADER_LEN: usize = 9;

/// Extract body content from HTTP/2 binary frames.
///
/// Scans through the buffer, parses 9-byte frame headers, and concatenates
/// DATA frame (type 0x00) payloads. This recovers the plain-text JSON body
/// from the binary HTTP/2 framing that wraps it.
///
/// Returns `None` if the data doesn't look like HTTP/2 or contains no DATA frames.
pub fn extract_http2_body(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }

    // Skip the HTTP/2 connection preface if present
    let mut pos = if data.starts_with(H2_PREFACE) {
        H2_PREFACE.len()
    } else {
        0
    };

    // Quick check: does this look like HTTP/2 frames?
    // A valid frame header has length (3 bytes) + type (1 byte) + flags (1 byte) + stream_id (4 bytes)
    if data.len() < pos + H2_FRAME_HEADER_LEN {
        return None;
    }

    let mut body = Vec::new();
    let mut found_frames = false;

    while pos + H2_FRAME_HEADER_LEN <= data.len() {
        // Parse frame header
        let frame_len = ((data[pos] as usize) << 16)
            | ((data[pos + 1] as usize) << 8)
            | (data[pos + 2] as usize);
        let frame_type = data[pos + 3];
        let _flags = data[pos + 4];
        // stream_id bytes: pos+5..pos+9 (clear reserved bit)

        // Sanity check: frame_len shouldn't be absurdly large
        if frame_len > 16 * 1024 * 1024 {
            break;
        }

        let payload_start = pos + H2_FRAME_HEADER_LEN;
        let payload_end = payload_start + frame_len;

        found_frames = true;

        if frame_type == H2_FRAME_DATA && payload_end <= data.len() {
            // Handle PADDED flag (bit 3): first byte of payload is pad length
            let (actual_start, pad_len) = if _flags & 0x08 != 0 && frame_len > 0 {
                let pad = data[payload_start] as usize;
                (payload_start + 1, pad)
            } else {
                (payload_start, 0)
            };
            let actual_end = if pad_len < payload_end - actual_start {
                payload_end - pad_len
            } else {
                payload_end
            };
            if actual_start < actual_end && actual_end <= data.len() {
                body.extend_from_slice(&data[actual_start..actual_end]);
            }
        }

        // Advance to next frame
        if payload_end > data.len() {
            break; // Truncated frame
        }
        pos = payload_end;
    }

    if found_frames && !body.is_empty() {
        Some(body)
    } else {
        None
    }
}

/// Convert raw bytes to a string, extracting HTTP/2 DATA frame bodies if detected.
/// Falls back to from_utf8_lossy for HTTP/1.1 or non-HTTP data.
pub fn payload_to_string(data: &[u8]) -> String {
    if let Some(body) = extract_http2_body(data) {
        String::from_utf8_lossy(&body).to_string()
    } else {
        String::from_utf8_lossy(data).to_string()
    }
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
    /// Accumulated outbound payload (SSL_write data).
    write_buf: Vec<u8>,
    /// Accumulated inbound payload (SSL_read data).
    read_buf: Vec<u8>,
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

/// Maximum accumulated payload per direction before we stop appending.
const FLOW_MAX_BYTES: usize = 128 * 1024; // 128 KB

impl Default for TlsConnTracker {
    fn default() -> Self {
        Self::new()
    }
}

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
            write_buf: Vec::new(),
            read_buf: Vec::new(),
        });
        state.chunks_seen += 1;
        state.chunks_seen
    }

    /// Append payload bytes to the flow buffer for this connection.
    /// `direction`: 0 = write (outbound), 1 = read (inbound).
    pub fn append_payload(&mut self, pid: u32, ssl_ptr: u64, direction: u8, data: &[u8]) {
        if let Some(state) = self.conns.get_mut(&(pid, ssl_ptr)) {
            let buf = if direction == 0 {
                &mut state.write_buf
            } else {
                &mut state.read_buf
            };
            let remaining = FLOW_MAX_BYTES.saturating_sub(buf.len());
            if remaining > 0 {
                let to_copy = data.len().min(remaining);
                buf.extend_from_slice(&data[..to_copy]);
            }
        }
    }

    /// Get the accumulated flow payload for this connection as a string.
    /// Returns the write (outbound) flow — this contains the user's request.
    /// Extracts HTTP/2 DATA frame bodies if the data looks like HTTP/2 framing.
    pub fn flow_payload(&self, pid: u32, ssl_ptr: u64) -> Option<String> {
        self.conns
            .get(&(pid, ssl_ptr))
            .map(|state| payload_to_string(&state.write_buf))
    }

    /// Get the accumulated read (inbound) flow payload for this connection.
    /// Extracts HTTP/2 DATA frame bodies if the data looks like HTTP/2 framing.
    pub fn read_flow_payload(&self, pid: u32, ssl_ptr: u64) -> Option<String> {
        self.conns
            .get(&(pid, ssl_ptr))
            .map(|state| payload_to_string(&state.read_buf))
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
            write_buf: Vec::new(),
            read_buf: Vec::new(),
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

    /// Returns true if there are no tracked connections.
    pub fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    /// Evict entries older than TTL.
    pub fn gc(&mut self) {
        self.conns
            .retain(|_, state| state.first_seen.elapsed().as_secs() < CONN_TTL_SECS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_http2_data_frame() {
        // Build a minimal HTTP/2 DATA frame:
        // Frame header: length=13, type=DATA(0x00), flags=0, stream_id=1
        // Payload: "hello, berko!"
        let payload = b"hello, berko!";
        let frame_len = payload.len();
        let mut data = Vec::new();
        data.push((frame_len >> 16) as u8);
        data.push((frame_len >> 8) as u8);
        data.push(frame_len as u8);
        data.push(0x00); // DATA frame
        data.push(0x00); // no flags
        data.extend_from_slice(&1u32.to_be_bytes()); // stream id = 1
        data.extend_from_slice(payload);

        let body = extract_http2_body(&data).unwrap();
        assert_eq!(body, b"hello, berko!");
    }

    #[test]
    fn test_extract_http2_skips_non_data_frames() {
        // SETTINGS frame (type=0x04) followed by DATA frame
        let mut data = Vec::new();
        // SETTINGS frame: length=6, type=0x04, flags=0, stream=0
        data.extend_from_slice(&[0, 0, 6, 0x04, 0, 0, 0, 0, 0]);
        data.extend_from_slice(&[0; 6]); // 6 bytes settings payload
                                         // DATA frame: length=5, type=0x00, flags=0, stream=1
        data.extend_from_slice(&[0, 0, 5, 0x00, 0, 0, 0, 0, 1]);
        data.extend_from_slice(b"berko");

        let body = extract_http2_body(&data).unwrap();
        assert_eq!(body, b"berko");
    }

    #[test]
    fn test_extract_http2_with_preface() {
        let mut data = Vec::new();
        data.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        // SETTINGS frame
        data.extend_from_slice(&[0, 0, 0, 0x04, 0, 0, 0, 0, 0]);
        // DATA frame with "test"
        data.extend_from_slice(&[0, 0, 4, 0x00, 0, 0, 0, 0, 1]);
        data.extend_from_slice(b"test");

        let body = extract_http2_body(&data).unwrap();
        assert_eq!(body, b"test");
    }

    #[test]
    fn test_extract_http2_returns_none_for_http1() {
        let data =
            b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n{\"model\":\"claude\"}";
        assert!(extract_http2_body(data).is_none());
    }

    #[test]
    fn test_payload_to_string_http1() {
        let data = b"POST /v1/messages HTTP/1.1\r\n\r\n{\"query\":\"berko\"}";
        let s = payload_to_string(data);
        assert!(s.contains("berko"));
    }

    #[test]
    fn test_payload_to_string_http2() {
        // Build HTTP/2 DATA frame containing JSON with "berko"
        let json = b"{\"messages\":[{\"content\":\"berko\"}]}";
        let mut data = Vec::new();
        let len = json.len();
        data.push((len >> 16) as u8);
        data.push((len >> 8) as u8);
        data.push(len as u8);
        data.push(0x00); // DATA
        data.push(0x01); // END_STREAM flag
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(json);

        let s = payload_to_string(&data);
        assert!(
            s.contains("berko"),
            "HTTP/2 body extraction should find 'berko', got: {}",
            s
        );
    }

    #[test]
    fn test_sni_cache_basic() {
        let mut cache = SniCache::new();
        cache.insert(123, "api.anthropic.com".to_string());
        assert_eq!(cache.get(123), Some("api.anthropic.com"));
        assert_eq!(cache.get(456), None);
    }

    #[test]
    fn test_classify_by_sni() {
        assert_eq!(classify_by_sni("api.anthropic.com"), Some("Anthropic"));
        assert_eq!(classify_by_sni("api.openai.com"), Some("OpenAI"));
        assert_eq!(classify_by_sni("example.com"), None);
    }
}
