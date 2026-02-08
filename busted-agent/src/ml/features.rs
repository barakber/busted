use std::collections::HashSet;

use ndarray::Array1;

use super::symbol::SYMBOL_SPACE;
use super::window::EventWindow;

/// Total feature vector dimensionality.
///
/// | Range     | Count | Feature Group                                          |
/// |-----------|-------|--------------------------------------------------------|
/// | 0..180    |  180  | Unigram histogram (normalized symbol frequencies)      |
/// | 180..280  |  100  | Bigram histogram (hashed consecutive pairs)             |
/// | 280..330  |   50  | Trigram histogram (hashed triples)                      |
/// | 330..336  |    6  | Timing: inter-arrival mean/std/min/max/p50/p90          |
/// | 336..342  |    6  | Bytes: send/recv ratio, mean send/recv, var, zero frac  |
/// | 342..346  |    4  | Connection: IP diversity, port div, unique dst, reuse   |
/// | 346..350  |    4  | Burst: count, mean len, max gap, burst byte fraction    |
/// | 350..352  |    2  | Entropy: symbol entropy, bigram entropy                 |
pub const FEATURE_DIM: usize = 352;

const BIGRAM_BINS: usize = 100;
const TRIGRAM_BINS: usize = 50;

pub struct FeatureExtractor {
    scratch: Vec<f64>,
}

impl FeatureExtractor {
    pub fn new() -> Self {
        FeatureExtractor {
            scratch: vec![0.0; FEATURE_DIM],
        }
    }

    pub fn extract(&mut self, window: &EventWindow) -> Array1<f64> {
        self.scratch.fill(0.0);

        let syms: Vec<_> = window.symbols().collect();
        let n = syms.len() as f64;
        if n < 1.0 {
            return Array1::zeros(FEATURE_DIM);
        }

        // ---- Unigrams (0..180) ----
        for ts in &syms {
            let idx = ts.symbol.encode() as usize;
            if idx < SYMBOL_SPACE {
                self.scratch[idx] += 1.0 / n;
            }
        }

        // ---- Bigrams (180..280) ----
        for pair in syms.windows(2) {
            let a = pair[0].symbol.encode() as u64;
            let b = pair[1].symbol.encode() as u64;
            let hash = fnv1a_u64(a.wrapping_mul(181).wrapping_add(b));
            let bin = (hash as usize) % BIGRAM_BINS;
            self.scratch[SYMBOL_SPACE + bin] += 1.0 / (n - 1.0).max(1.0);
        }

        // ---- Trigrams (280..330) ----
        for triple in syms.windows(3) {
            let a = triple[0].symbol.encode() as u64;
            let b = triple[1].symbol.encode() as u64;
            let c = triple[2].symbol.encode() as u64;
            let hash = fnv1a_u64(a.wrapping_mul(32761).wrapping_add(b.wrapping_mul(181)).wrapping_add(c));
            let bin = (hash as usize) % TRIGRAM_BINS;
            self.scratch[SYMBOL_SPACE + BIGRAM_BINS + bin] += 1.0 / (n - 2.0).max(1.0);
        }

        // ---- Timing features (330..336) ----
        let timing_offset = SYMBOL_SPACE + BIGRAM_BINS + TRIGRAM_BINS;
        let mut deltas = Vec::new();
        for pair in syms.windows(2) {
            let dt = pair[1].timestamp_ns.saturating_sub(pair[0].timestamp_ns) as f64;
            deltas.push(dt);
        }
        if !deltas.is_empty() {
            deltas.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
            let variance = deltas.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / deltas.len() as f64;
            let std_dev = variance.sqrt();
            let min = deltas[0];
            let max = deltas[deltas.len() - 1];
            let p50 = percentile(&deltas, 0.5);
            let p90 = percentile(&deltas, 0.9);

            // Normalize to milliseconds for more reasonable feature scales
            self.scratch[timing_offset] = mean / 1_000_000.0;
            self.scratch[timing_offset + 1] = std_dev / 1_000_000.0;
            self.scratch[timing_offset + 2] = min / 1_000_000.0;
            self.scratch[timing_offset + 3] = max / 1_000_000.0;
            self.scratch[timing_offset + 4] = p50 / 1_000_000.0;
            self.scratch[timing_offset + 5] = p90 / 1_000_000.0;
        }

        // ---- Bytes features (336..342) ----
        let bytes_offset = timing_offset + 6;
        let mut send_bytes = Vec::new();
        let mut recv_bytes = Vec::new();
        let mut zero_count = 0u64;
        for ts in &syms {
            match ts.symbol.kind {
                1 => send_bytes.push(ts.bytes as f64), // DATA_SENT
                2 => recv_bytes.push(ts.bytes as f64), // DATA_RECEIVED
                _ => {}
            }
            if ts.bytes == 0 {
                zero_count += 1;
            }
        }
        let total_send: f64 = send_bytes.iter().sum();
        let total_recv: f64 = recv_bytes.iter().sum();
        // Send/recv ratio
        self.scratch[bytes_offset] = if total_recv > 0.0 {
            total_send / total_recv
        } else if total_send > 0.0 {
            10.0 // cap
        } else {
            0.0
        };
        // Mean send size
        self.scratch[bytes_offset + 1] = if !send_bytes.is_empty() {
            total_send / send_bytes.len() as f64 / 1024.0
        } else {
            0.0
        };
        // Mean recv size
        self.scratch[bytes_offset + 2] = if !recv_bytes.is_empty() {
            total_recv / recv_bytes.len() as f64 / 1024.0
        } else {
            0.0
        };
        // Byte variance (all events)
        let all_bytes: Vec<f64> = syms.iter().map(|ts| ts.bytes as f64).collect();
        let byte_mean = all_bytes.iter().sum::<f64>() / n;
        self.scratch[bytes_offset + 3] = all_bytes
            .iter()
            .map(|b| (b - byte_mean).powi(2))
            .sum::<f64>()
            / n
            / 1_000_000.0; // normalize
        // Zero-byte fraction
        self.scratch[bytes_offset + 4] = zero_count as f64 / n;
        // Total bytes (normalized to KB)
        self.scratch[bytes_offset + 5] = (total_send + total_recv) / 1024.0;

        // ---- Connection features (342..346) ----
        let conn_offset = bytes_offset + 6;
        let unique_ips: HashSet<u32> = syms.iter().map(|ts| ts.dst_ip_hash).collect();
        let unique_ports: HashSet<u16> = syms.iter().map(|ts| ts.dst_port).collect();
        self.scratch[conn_offset] = unique_ips.len() as f64 / n.max(1.0); // IP diversity
        self.scratch[conn_offset + 1] = unique_ports.len() as f64 / n.max(1.0); // Port diversity
        self.scratch[conn_offset + 2] = unique_ips.len() as f64; // Unique dst count
        // Connection reuse ratio: events / unique destinations
        self.scratch[conn_offset + 3] = if unique_ips.is_empty() {
            0.0
        } else {
            n / unique_ips.len() as f64
        };

        // ---- Burst features (346..350) ----
        let burst_offset = conn_offset + 4;
        let burst_gap_ms = 500.0; // events within 500ms are a burst
        let mut bursts: Vec<(usize, u64)> = Vec::new(); // (length, bytes)
        let mut burst_len = 1usize;
        let mut burst_bytes = syms.first().map_or(0, |ts| ts.bytes);
        let mut max_gap_ms: f64 = 0.0;
        for pair in syms.windows(2) {
            let dt_ms = pair[1].timestamp_ns.saturating_sub(pair[0].timestamp_ns) as f64 / 1_000_000.0;
            max_gap_ms = max_gap_ms.max(dt_ms);
            if dt_ms < burst_gap_ms {
                burst_len += 1;
                burst_bytes += pair[1].bytes;
            } else {
                if burst_len > 1 {
                    bursts.push((burst_len, burst_bytes));
                }
                burst_len = 1;
                burst_bytes = pair[1].bytes;
            }
        }
        if burst_len > 1 {
            bursts.push((burst_len, burst_bytes));
        }
        self.scratch[burst_offset] = bursts.len() as f64; // burst count
        self.scratch[burst_offset + 1] = if bursts.is_empty() {
            0.0
        } else {
            bursts.iter().map(|(l, _)| *l as f64).sum::<f64>() / bursts.len() as f64
        }; // mean burst length
        self.scratch[burst_offset + 2] = max_gap_ms / 1000.0; // max gap in seconds
        let total_burst_bytes: u64 = bursts.iter().map(|(_, b)| b).sum();
        let total_all_bytes: u64 = syms.iter().map(|ts| ts.bytes).sum();
        self.scratch[burst_offset + 3] = if total_all_bytes > 0 {
            total_burst_bytes as f64 / total_all_bytes as f64
        } else {
            0.0
        }; // burst byte fraction

        // ---- Entropy features (350..352) ----
        let entropy_offset = burst_offset + 4;
        // Symbol entropy
        self.scratch[entropy_offset] = shannon_entropy(&self.scratch[0..SYMBOL_SPACE]);
        // Bigram entropy
        self.scratch[entropy_offset + 1] =
            shannon_entropy(&self.scratch[SYMBOL_SPACE..SYMBOL_SPACE + BIGRAM_BINS]);

        Array1::from_vec(self.scratch.clone())
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p * (sorted.len() - 1) as f64) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn shannon_entropy(probs: &[f64]) -> f64 {
    let mut ent = 0.0;
    for &p in probs {
        if p > 0.0 {
            ent -= p * p.log2();
        }
    }
    ent
}

/// Simple FNV-1a hash for u64 values.
fn fnv1a_u64(val: u64) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &byte in &val.to_le_bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
