use std::collections::VecDeque;
use std::time::Instant;

use crate::symbol::Symbol;

/// A symbol with timing and metadata for feature extraction.
pub struct TimedSymbol {
    pub symbol: Symbol,
    pub timestamp_ns: u64,
    pub bytes: u64,
    pub arrived_at: Instant,
    /// FNV-1a hash of destination IP for diversity tracking.
    pub dst_ip_hash: u32,
    pub dst_port: u16,
}

pub struct WindowConfig {
    /// Maximum events in the window.
    pub window_size: usize,
    /// Minimum events before first classification.
    pub min_events: usize,
    /// Re-classify every `stride` new events.
    pub stride: usize,
}

impl Default for WindowConfig {
    fn default() -> Self {
        WindowConfig {
            window_size: 50,
            min_events: 20,
            stride: 10,
        }
    }
}

/// Per-PID sliding event window using a ring buffer.
pub struct EventWindow {
    #[allow(dead_code)]
    pub pid: u32,
    buf: VecDeque<TimedSymbol>,
    /// Events received since last classification.
    events_since_classify: usize,
}

impl EventWindow {
    pub fn new(pid: u32) -> Self {
        EventWindow {
            pid,
            buf: VecDeque::with_capacity(64),
            events_since_classify: 0,
        }
    }

    /// Push a new event. Returns `true` when the window is ready for classification
    /// (has enough events and stride threshold is met).
    pub fn push(&mut self, ts: TimedSymbol, config: &WindowConfig) -> bool {
        if self.buf.len() >= config.window_size {
            self.buf.pop_front();
        }
        self.buf.push_back(ts);
        self.events_since_classify += 1;

        self.buf.len() >= config.min_events && self.events_since_classify >= config.stride
    }

    /// Mark that classification was performed; reset stride counter.
    pub fn mark_classified(&mut self) {
        self.events_since_classify = 0;
    }

    /// Iterator over all symbols in the window.
    pub fn symbols(&self) -> impl Iterator<Item = &TimedSymbol> {
        self.buf.iter()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Timestamp of the most recent event (for idle GC).
    pub fn last_arrival(&self) -> Option<Instant> {
        self.buf.back().map(|ts| ts.arrived_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_timed_symbol(kind: u8, timestamp_ns: u64) -> TimedSymbol {
        TimedSymbol {
            symbol: Symbol {
                kind,
                size_bucket: 0,
                port_class: 0,
            },
            timestamp_ns,
            bytes: 100,
            arrived_at: Instant::now(),
            dst_ip_hash: 0,
            dst_port: 443,
        }
    }

    #[test]
    fn new_window_is_empty() {
        let w = EventWindow::new(42);
        assert_eq!(w.len(), 0);
        assert_eq!(w.pid, 42);
    }

    #[test]
    fn new_window_last_arrival_none() {
        let w = EventWindow::new(1);
        assert!(w.last_arrival().is_none());
    }

    #[test]
    fn push_not_ready_until_min_events() {
        let config = WindowConfig {
            window_size: 50,
            min_events: 5,
            stride: 3,
        };
        let mut w = EventWindow::new(1);
        for i in 0..4 {
            assert!(!w.push(make_timed_symbol(0, i), &config));
        }
        assert_eq!(w.len(), 4);
    }

    #[test]
    fn push_ready_when_min_events_and_stride_met() {
        let config = WindowConfig {
            window_size: 50,
            min_events: 3,
            stride: 3,
        };
        let mut w = EventWindow::new(1);
        assert!(!w.push(make_timed_symbol(0, 0), &config));
        assert!(!w.push(make_timed_symbol(0, 1), &config));
        assert!(w.push(make_timed_symbol(0, 2), &config)); // 3 events, stride=3
    }

    #[test]
    fn mark_classified_resets_stride_counter() {
        let config = WindowConfig {
            window_size: 50,
            min_events: 3,
            stride: 2,
        };
        let mut w = EventWindow::new(1);
        // Fill to min_events
        for i in 0..3 {
            w.push(make_timed_symbol(0, i), &config);
        }
        w.mark_classified();
        // Now need stride=2 more events
        assert!(!w.push(make_timed_symbol(0, 10), &config));
        assert!(w.push(make_timed_symbol(0, 11), &config));
    }

    #[test]
    fn eviction_enforces_window_size() {
        let config = WindowConfig {
            window_size: 5,
            min_events: 2,
            stride: 1,
        };
        let mut w = EventWindow::new(1);
        for i in 0..10 {
            w.push(make_timed_symbol(0, i), &config);
        }
        assert_eq!(w.len(), 5); // capped at window_size
    }

    #[test]
    fn symbols_iterator() {
        let config = WindowConfig {
            window_size: 50,
            min_events: 1,
            stride: 1,
        };
        let mut w = EventWindow::new(1);
        w.push(make_timed_symbol(0, 100), &config);
        w.push(make_timed_symbol(1, 200), &config);
        w.push(make_timed_symbol(2, 300), &config);

        let kinds: Vec<u8> = w.symbols().map(|ts| ts.symbol.kind).collect();
        assert_eq!(kinds, vec![0, 1, 2]);
    }

    #[test]
    fn last_arrival_correctness() {
        let config = WindowConfig {
            window_size: 50,
            min_events: 1,
            stride: 1,
        };
        let mut w = EventWindow::new(1);
        let before = Instant::now();
        w.push(make_timed_symbol(0, 0), &config);
        let after = Instant::now();
        let arrival = w.last_arrival().unwrap();
        assert!(arrival >= before && arrival <= after);
    }

    #[test]
    fn default_window_config() {
        let c = WindowConfig::default();
        assert_eq!(c.window_size, 50);
        assert_eq!(c.min_events, 20);
        assert_eq!(c.stride, 10);
    }
}
