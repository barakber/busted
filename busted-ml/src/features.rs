use std::collections::HashSet;

use ndarray::Array1;

use crate::symbol::SYMBOL_SPACE;
use crate::window::EventWindow;

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
            let hash = fnv1a_u64(
                a.wrapping_mul(32761)
                    .wrapping_add(b.wrapping_mul(181))
                    .wrapping_add(c),
            );
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
            let variance =
                deltas.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / deltas.len() as f64;
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
            let dt_ms =
                pair[1].timestamp_ns.saturating_sub(pair[0].timestamp_ns) as f64 / 1_000_000.0;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbol::Symbol;
    use crate::window::{EventWindow, TimedSymbol, WindowConfig};
    use std::time::Instant;

    fn make_ts(
        kind: u8,
        size_bucket: u8,
        port_class: u8,
        timestamp_ns: u64,
        bytes: u64,
    ) -> TimedSymbol {
        TimedSymbol {
            symbol: Symbol {
                kind,
                size_bucket,
                port_class,
            },
            timestamp_ns,
            bytes,
            arrived_at: Instant::now(),
            dst_ip_hash: kind as u32 * 1000 + port_class as u32,
            dst_port: match port_class {
                0 => 443,
                1 => 80,
                2 => 53,
                _ => 8080,
            },
        }
    }

    fn make_window_with_events(events: Vec<TimedSymbol>) -> EventWindow {
        let config = WindowConfig {
            window_size: 100,
            min_events: 1,
            stride: 1,
        };
        let mut w = EventWindow::new(1);
        for ts in events {
            w.push(ts, &config);
        }
        w
    }

    #[test]
    fn feature_dim_is_352() {
        assert_eq!(FEATURE_DIM, 352);
    }

    #[test]
    fn empty_window_all_zeros() {
        let w = EventWindow::new(1);
        let mut ext = FeatureExtractor::new();
        let features = ext.extract(&w);
        assert_eq!(features.len(), FEATURE_DIM);
        assert!(features.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn unigram_normalization_single_symbol() {
        let events = vec![make_ts(0, 0, 0, 0, 100)];
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        // Symbol (0,0,0) encodes to index 0. With 1 event, its frequency is 1.0
        assert_eq!(f[0], 1.0);
        // Sum of unigrams should be 1.0
        let sum: f64 = f.iter().take(SYMBOL_SPACE).sum();
        assert!((sum - 1.0).abs() < 1e-9);
    }

    #[test]
    fn unigram_normalization_identical_symbols() {
        let events: Vec<_> = (0..10).map(|i| make_ts(1, 2, 0, i * 1000, 500)).collect();
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        // Symbol (1,2,0) encodes to 1*30 + 2*5 + 0 = 40
        assert!((f[40] - 1.0).abs() < 1e-9);
        let sum: f64 = f.iter().take(SYMBOL_SPACE).sum();
        assert!((sum - 1.0).abs() < 1e-9);
    }

    #[test]
    fn bigram_bins_populated_for_pair() {
        let events = vec![make_ts(0, 0, 0, 0, 100), make_ts(1, 1, 1, 1000, 200)];
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        let bigram_sum: f64 = f.iter().skip(SYMBOL_SPACE).take(BIGRAM_BINS).sum();
        assert!(bigram_sum > 0.0);
    }

    #[test]
    fn trigram_bins_populated_for_triple() {
        let events = vec![
            make_ts(0, 0, 0, 0, 100),
            make_ts(1, 1, 1, 1000, 200),
            make_ts(2, 2, 2, 2000, 300),
        ];
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        let trigram_sum: f64 = f
            .iter()
            .skip(SYMBOL_SPACE + BIGRAM_BINS)
            .take(TRIGRAM_BINS)
            .sum();
        assert!(trigram_sum > 0.0);
    }

    #[test]
    fn timing_features_same_timestamps_zero() {
        let events = vec![
            make_ts(0, 0, 0, 1000, 100),
            make_ts(1, 1, 1, 1000, 200),
            make_ts(2, 2, 2, 1000, 300),
        ];
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        let timing_offset = SYMBOL_SPACE + BIGRAM_BINS + TRIGRAM_BINS;
        // All timestamps equal → deltas are 0 → mean, std, min, max all 0
        assert_eq!(f[timing_offset], 0.0); // mean
        assert_eq!(f[timing_offset + 1], 0.0); // std
    }

    #[test]
    fn timing_features_linear_spacing() {
        // 3 events at 0, 1_000_000, 2_000_000 ns → deltas = [1ms, 1ms]
        let events = vec![
            make_ts(0, 0, 0, 0, 100),
            make_ts(0, 0, 0, 1_000_000, 100),
            make_ts(0, 0, 0, 2_000_000, 100),
        ];
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        let timing_offset = SYMBOL_SPACE + BIGRAM_BINS + TRIGRAM_BINS;
        // mean = 1ms, stored in ms → 1.0
        assert!((f[timing_offset] - 1.0).abs() < 1e-6);
        // std = 0 (all deltas equal)
        assert!(f[timing_offset + 1].abs() < 1e-6);
    }

    #[test]
    fn bytes_send_recv_ratio() {
        // 2 send events (kind=1), 1 recv event (kind=2)
        let events = vec![
            make_ts(1, 3, 0, 0, 1000),   // send 1000
            make_ts(1, 3, 0, 100, 1000), // send 1000
            make_ts(2, 3, 0, 200, 500),  // recv 500
        ];
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        let bytes_offset = SYMBOL_SPACE + BIGRAM_BINS + TRIGRAM_BINS + 6;
        // send/recv ratio = 2000/500 = 4.0
        assert!((f[bytes_offset] - 4.0).abs() < 1e-6);
    }

    #[test]
    fn bytes_no_recv_cap() {
        // Only send, no recv → ratio capped at 10.0
        let events = vec![make_ts(1, 3, 0, 0, 1000)];
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        let bytes_offset = SYMBOL_SPACE + BIGRAM_BINS + TRIGRAM_BINS + 6;
        assert!((f[bytes_offset] - 10.0).abs() < 1e-6);
    }

    #[test]
    fn bytes_no_send_no_recv() {
        // Only connect events (kind=0) → ratio = 0.0
        let events = vec![make_ts(0, 0, 0, 0, 0), make_ts(0, 0, 0, 100, 0)];
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        let bytes_offset = SYMBOL_SPACE + BIGRAM_BINS + TRIGRAM_BINS + 6;
        assert_eq!(f[bytes_offset], 0.0);
    }

    #[test]
    fn connection_diversity_single_dest() {
        let events: Vec<_> = (0..5).map(|i| make_ts(0, 0, 0, i * 1000, 100)).collect();
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        let conn_offset = SYMBOL_SPACE + BIGRAM_BINS + TRIGRAM_BINS + 12;
        // All same dst_ip_hash → unique=1
        assert_eq!(f[conn_offset + 2], 1.0); // unique dst count
    }

    #[test]
    fn connection_diversity_multiple_dests() {
        // Different kinds → different dst_ip_hash values
        let events = vec![
            make_ts(0, 0, 0, 0, 100),
            make_ts(1, 0, 0, 100, 100),
            make_ts(2, 0, 0, 200, 100),
        ];
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        let conn_offset = SYMBOL_SPACE + BIGRAM_BINS + TRIGRAM_BINS + 12;
        assert!(f[conn_offset + 2] >= 3.0); // at least 3 unique dsts
    }

    #[test]
    fn entropy_single_symbol_is_zero() {
        let events: Vec<_> = (0..5).map(|i| make_ts(0, 0, 0, i * 1000, 100)).collect();
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        // entropy_offset = 180 + 100 + 50 + 6(timing) + 6(bytes) + 4(conn) + 4(burst) = 350
        let entropy_offset = SYMBOL_SPACE + BIGRAM_BINS + TRIGRAM_BINS + 20;
        // Only one symbol type → entropy should be exactly -1.0*log2(1.0) = 0
        assert!(f[entropy_offset].abs() < 1e-9);
    }

    #[test]
    fn entropy_uniform_distribution() {
        // 5 events with 5 different symbol types → higher entropy
        let events = vec![
            make_ts(0, 0, 0, 0, 100),
            make_ts(1, 0, 0, 100, 100),
            make_ts(2, 0, 0, 200, 100),
            make_ts(3, 0, 0, 300, 100),
            make_ts(4, 0, 0, 400, 100),
        ];
        let w = make_window_with_events(events);
        let mut ext = FeatureExtractor::new();
        let f = ext.extract(&w);
        let entropy_offset = SYMBOL_SPACE + BIGRAM_BINS + TRIGRAM_BINS + 20;
        // 5 symbols with equal probability → entropy = log2(5) ≈ 2.32
        assert!(f[entropy_offset] > 2.0);
    }

    // -- Private helper tests --

    #[test]
    fn percentile_empty() {
        assert_eq!(percentile(&[], 0.5), 0.0);
    }

    #[test]
    fn percentile_single_element() {
        assert_eq!(percentile(&[42.0], 0.5), 42.0);
    }

    #[test]
    fn percentile_known_values() {
        let sorted = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(percentile(&sorted, 0.0), 1.0);
        assert_eq!(percentile(&sorted, 0.5), 3.0);
        assert_eq!(percentile(&sorted, 1.0), 5.0);
    }

    #[test]
    fn shannon_entropy_all_zero() {
        assert_eq!(shannon_entropy(&[0.0, 0.0, 0.0]), 0.0);
    }

    #[test]
    fn shannon_entropy_single_prob() {
        // p=1.0 → -1.0*log2(1.0) = 0
        assert_eq!(shannon_entropy(&[1.0, 0.0, 0.0]), 0.0);
    }

    #[test]
    fn shannon_entropy_uniform() {
        // Two equal probabilities of 0.5: entropy = -2*(0.5*log2(0.5)) = 1.0
        let ent = shannon_entropy(&[0.5, 0.5]);
        assert!((ent - 1.0).abs() < 1e-9);
    }
}
