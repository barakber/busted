//! Behavioral sequence n-gram analysis.
//!
//! Extracts action bigrams from identity timelines and computes a
//! deterministic FNV-1a digest over the top-8 most frequent pairs.
//! This captures an agent's behavioral "rhythm" — the sequence of
//! actions it typically performs.

use crate::action::Action;
use crate::timeline::Timeline;

/// FNV-1a 64-bit hash.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let prime: u64 = 0x00000100000001B3;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(prime);
    }
    h
}

/// Compact bigram key: pair of action labels.
type BigramKey = (&'static str, &'static str);

/// Compute the behavioral digest from a timeline.
///
/// Extracts all consecutive action pairs (bigrams), counts them,
/// takes the top 8 by frequency, and hashes the sorted result
/// into a stable u64 digest.
///
/// Returns `None` if the timeline has fewer than 2 entries.
pub fn compute_behavioral_digest(timeline: &Timeline) -> Option<u64> {
    let entries: Vec<_> = timeline.iter().collect();
    if entries.len() < 2 {
        return None;
    }

    // Count bigrams
    let mut counts: std::collections::HashMap<BigramKey, u32> = std::collections::HashMap::new();
    for window in entries.windows(2) {
        let key = (window[0].action.label(), window[1].action.label());
        *counts.entry(key).or_insert(0) += 1;
    }

    // Sort by count descending, then alphabetically for determinism
    let mut bigrams: Vec<_> = counts.into_iter().collect();
    bigrams.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0 .0.cmp(b.0 .0))
            .then_with(|| a.0 .1.cmp(b.0 .1))
    });
    bigrams.truncate(8);

    // Build a deterministic byte representation for hashing
    let mut bytes = Vec::new();
    for ((a, b), count) in &bigrams {
        bytes.extend_from_slice(a.as_bytes());
        bytes.push(b'|');
        bytes.extend_from_slice(b.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.push(b'\n');
    }

    Some(fnv1a_64(&bytes))
}

/// Whether the digest should be recomputed.
///
/// Returns true every 10 events once the timeline has at least 4 entries.
pub fn should_recompute(event_count: u64, timeline_len: usize) -> bool {
    timeline_len >= 4 && event_count % 10 == 0
}

/// Extract a compact action tag for bigram analysis.
///
/// This is the same as `Action::label()` but provided here for clarity.
#[inline]
pub fn action_tag(action: &Action) -> &'static str {
    action.label()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{McpCategoryTag, ProviderTag};

    fn make_llm_action() -> Action {
        Action::LlmCall {
            provider: ProviderTag::OpenAI,
            model_hash: 42,
            streaming: false,
        }
    }

    fn make_mcp_action() -> Action {
        Action::McpCall {
            category: McpCategoryTag::Tools,
            method_hash: 99,
        }
    }

    #[test]
    fn empty_timeline_returns_none() {
        let tl = Timeline::new(8);
        assert!(compute_behavioral_digest(&tl).is_none());
    }

    #[test]
    fn single_entry_returns_none() {
        let mut tl = Timeline::new(8);
        tl.push("t1".into(), make_llm_action());
        assert!(compute_behavioral_digest(&tl).is_none());
    }

    #[test]
    fn two_entries_produce_digest() {
        let mut tl = Timeline::new(8);
        tl.push("t1".into(), make_llm_action());
        tl.push("t2".into(), make_mcp_action());
        let digest = compute_behavioral_digest(&tl);
        assert!(digest.is_some());
    }

    #[test]
    fn deterministic_digest() {
        let mut tl = Timeline::new(16);
        for _ in 0..5 {
            tl.push("t".into(), make_llm_action());
            tl.push("t".into(), make_mcp_action());
        }
        let d1 = compute_behavioral_digest(&tl).unwrap();
        let d2 = compute_behavioral_digest(&tl).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn different_sequences_different_digests() {
        let mut tl1 = Timeline::new(16);
        for _ in 0..5 {
            tl1.push("t".into(), make_llm_action());
            tl1.push("t".into(), make_mcp_action());
        }

        let mut tl2 = Timeline::new(16);
        for _ in 0..10 {
            tl2.push("t".into(), make_llm_action());
        }

        let d1 = compute_behavioral_digest(&tl1).unwrap();
        let d2 = compute_behavioral_digest(&tl2).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn should_recompute_logic() {
        assert!(!should_recompute(5, 3)); // too few entries
        assert!(!should_recompute(7, 10)); // not on 10th event
        assert!(should_recompute(10, 4)); // exactly right
        assert!(should_recompute(20, 100)); // multiple of 10
        assert!(should_recompute(0, 4)); // 0 % 10 == 0
    }
}
