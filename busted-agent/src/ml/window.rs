use std::collections::VecDeque;
use std::time::Instant;

use super::symbol::Symbol;

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
