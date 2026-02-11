use crate::action::Action;

/// A single entry in the identity timeline.
#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub action: Action,
}

/// Bounded ring buffer of timeline entries for one identity.
///
/// Pre-allocated with `Option<TimelineEntry>` slots. When full,
/// `push()` overwrites the oldest entry.
#[derive(Debug)]
pub struct Timeline {
    entries: Vec<Option<TimelineEntry>>,
    /// Points to the next slot to write.
    head: usize,
    /// Total entries ever pushed (may exceed capacity).
    total: usize,
    capacity: usize,
}

impl Timeline {
    /// Create a new timeline with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let mut entries = Vec::with_capacity(capacity);
        entries.resize_with(capacity, || None);
        Self {
            entries,
            head: 0,
            total: 0,
            capacity,
        }
    }

    /// Push a new entry, overwriting the oldest if full.
    pub fn push(&mut self, timestamp: String, action: Action) {
        self.entries[self.head] = Some(TimelineEntry { timestamp, action });
        self.head = (self.head + 1) % self.capacity;
        self.total += 1;
    }

    /// Number of entries currently stored (up to capacity).
    pub fn len(&self) -> usize {
        self.total.min(self.capacity)
    }

    /// Whether the timeline is empty.
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Total entries ever pushed (may exceed capacity).
    pub fn total_pushed(&self) -> usize {
        self.total
    }

    /// Iterate entries in chronological order.
    pub fn iter(&self) -> impl Iterator<Item = &TimelineEntry> {
        let len = self.len();
        let cap = self.capacity;
        // If we've wrapped, oldest is at `head`; otherwise oldest is at 0
        let start = if self.total > cap { self.head } else { 0 };
        (0..len).filter_map(move |i| {
            let idx = (start + i) % cap;
            self.entries[idx].as_ref()
        })
    }

    /// Last N entries in chronological order.
    pub fn last_n(&self, n: usize) -> Vec<&TimelineEntry> {
        let entries: Vec<_> = self.iter().collect();
        let skip = entries.len().saturating_sub(n);
        entries[skip..].to_vec()
    }

    /// Compact summary of timeline contents.
    pub fn summary(&self) -> String {
        if self.is_empty() {
            return String::new();
        }

        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for entry in self.iter() {
            *counts.entry(entry.action.label()).or_insert(0) += 1;
        }

        let mut parts: Vec<_> = counts.into_iter().collect();
        parts.sort_by_key(|b| std::cmp::Reverse(b.1)); // Most frequent first

        parts
            .iter()
            .map(|(label, count)| format!("{} x{}", label, count))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ProviderTag;

    fn make_action() -> Action {
        Action::LlmCall {
            provider: ProviderTag::OpenAI,
            model_hash: 42,
            streaming: false,
        }
    }

    #[test]
    fn push_and_iterate() {
        let mut tl = Timeline::new(4);
        tl.push("t1".into(), make_action());
        tl.push("t2".into(), make_action());
        let entries: Vec<_> = tl.iter().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].timestamp, "t1");
        assert_eq!(entries[1].timestamp, "t2");
    }

    #[test]
    fn ring_buffer_overflow() {
        let mut tl = Timeline::new(3);
        tl.push("t1".into(), make_action());
        tl.push("t2".into(), make_action());
        tl.push("t3".into(), make_action());
        tl.push("t4".into(), make_action()); // overwrites t1

        assert_eq!(tl.len(), 3);
        assert_eq!(tl.total_pushed(), 4);
        let entries: Vec<_> = tl.iter().collect();
        assert_eq!(entries[0].timestamp, "t2");
        assert_eq!(entries[1].timestamp, "t3");
        assert_eq!(entries[2].timestamp, "t4");
    }

    #[test]
    fn summary_output() {
        let mut tl = Timeline::new(10);
        for _ in 0..3 {
            tl.push("t".into(), make_action());
        }
        tl.push(
            "t".into(),
            Action::McpCall {
                category: crate::action::McpCategoryTag::Tools,
                method_hash: 0,
            },
        );
        let s = tl.summary();
        assert!(s.contains("LlmCall x3"), "got: {s}");
        assert!(s.contains("McpCall x1"), "got: {s}");
    }

    #[test]
    fn last_n() {
        let mut tl = Timeline::new(10);
        for i in 0..5 {
            tl.push(format!("t{}", i), make_action());
        }
        let last2 = tl.last_n(2);
        assert_eq!(last2.len(), 2);
        assert_eq!(last2[0].timestamp, "t3");
        assert_eq!(last2[1].timestamp, "t4");
    }

    #[test]
    fn empty_timeline() {
        let tl = Timeline::new(4);
        assert!(tl.is_empty());
        assert_eq!(tl.len(), 0);
        assert_eq!(tl.summary(), "");
        assert_eq!(tl.last_n(5).len(), 0);
    }
}
