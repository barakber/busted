use crate::action::ProviderTag;
use serde::{Deserialize, Serialize};

/// Instance key — identifies a specific running process (changes on restart).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstanceKey {
    pub pid: u32,
    pub container_id_hash: u32,
    pub cgroup_id: u64,
}

impl InstanceKey {
    pub fn new(pid: u32, container_id_hash: u32, cgroup_id: u64) -> Self {
        Self {
            pid,
            container_id_hash,
            cgroup_id,
        }
    }
}

impl std::fmt::Display for InstanceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pid={} cgroup={} container={:#x}",
            self.pid, self.cgroup_id, self.container_id_hash
        )
    }
}

/// Type key — identifies a *kind* of agent (persists across restarts).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypeKey {
    pub signature_hash: u64,
    pub sdk_hash: u32,
    pub model_hash: u32,
}

/// Stable identity ID — FNV-1a 64-bit hash of the TypeKey.
pub type IdentityId = u64;

/// Compute a stable identity ID from a TypeKey.
pub fn compute_identity_id(key: &TypeKey) -> IdentityId {
    let mut h: u64 = 0xcbf29ce484222325;
    let prime: u64 = 0x00000100000001B3;

    // Hash signature_hash bytes
    for &b in &key.signature_hash.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(prime);
    }
    // Hash sdk_hash bytes
    for &b in &key.sdk_hash.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(prime);
    }
    // Hash model_hash bytes
    for &b in &key.model_hash.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(prime);
    }

    h
}

/// A resolved identity — accumulated state for one agent type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedIdentity {
    pub identity_id: IdentityId,
    pub type_key: TypeKey,
    pub first_seen: String,
    pub last_seen: String,
    pub event_count: u64,
    /// Human-readable label (e.g. "openai-python (gpt-4)").
    pub label: String,
    /// Currently active instances of this agent type.
    pub active_instances: Vec<InstanceKey>,
    /// Providers this agent has communicated with.
    pub providers: Vec<ProviderTag>,
    /// FNV-1a digest of top-8 action bigrams (behavioral fingerprint).
    #[serde(default)]
    pub behavioral_digest: Option<u64>,
    /// FNV-1a hash of sorted MCP tool names (capability fingerprint).
    #[serde(default)]
    pub capability_hash: Option<u64>,
    /// SimHash of the system prompt embedding (or FNV-1a fallback).
    #[serde(default)]
    pub prompt_fingerprint: Option<u64>,
}

/// Result of matching an event to an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMatch {
    pub identity_id: IdentityId,
    pub instance_id: InstanceKey,
    pub confidence: f32,
    pub narrative: String,
    pub timeline_summary: String,
    pub timeline_len: usize,
    /// How the identity was matched (e.g. "ExactInstance", "CompositeMatch(0.78)").
    pub match_type: String,
    /// Behavioral digest from n-gram analysis.
    pub behavioral_digest: Option<u64>,
    /// MCP capability hash.
    pub capability_hash: Option<u64>,
    /// Prompt fingerprint (SimHash or FNV-1a).
    pub prompt_fingerprint: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_identity_id_deterministic() {
        let key = TypeKey {
            signature_hash: 0xdeadbeef,
            sdk_hash: 42,
            model_hash: 99,
        };
        let id1 = compute_identity_id(&key);
        let id2 = compute_identity_id(&key);
        assert_eq!(id1, id2);
    }

    #[test]
    fn distinct_keys_produce_distinct_ids() {
        let k1 = TypeKey {
            signature_hash: 1,
            sdk_hash: 2,
            model_hash: 3,
        };
        let k2 = TypeKey {
            signature_hash: 4,
            sdk_hash: 5,
            model_hash: 6,
        };
        assert_ne!(compute_identity_id(&k1), compute_identity_id(&k2));
    }

    #[test]
    fn instance_key_display() {
        let k = InstanceKey::new(1234, 0xabcd, 9999);
        let s = format!("{}", k);
        assert!(s.contains("1234"));
        assert!(s.contains("9999"));
    }
}
