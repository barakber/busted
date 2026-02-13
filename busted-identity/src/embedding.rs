//! System prompt embedding and fingerprinting.
//!
//! Without the `semantic` feature: FNV-1a hash of prompt text → used as
//! `prompt_fingerprint`. Similarity is binary (0.0 or 1.0).
//!
//! With the `semantic` feature: lazy-init fastembed TextEmbedding, embed
//! prompt → 384-dim Vec<f32> → SimHash → `prompt_fingerprint`. Similarity
//! is Hamming-based (0.0–1.0, fuzzy matching).

use crate::identity::IdentityId;
#[cfg(feature = "semantic")]
use crate::simhash::SimHasher;
use std::collections::HashMap;

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

/// Cached embedding for an identity.
struct CachedEmbedding {
    /// FNV-1a hash of the raw prompt text (for dedup).
    text_hash: u64,
    /// SimHash fingerprint of the embedding.
    fingerprint: u64,
    /// Full embedding vector (only stored with `semantic` feature).
    #[cfg(feature = "semantic")]
    _vector: Vec<f32>,
}

/// Manages prompt embeddings and fingerprints for identities.
pub struct EmbeddingCache {
    cache: HashMap<IdentityId, CachedEmbedding>,
    /// SimHasher (only needed with semantic feature, but kept for non-semantic
    /// to allow scoring code to call similarity without feature gates).
    #[cfg(feature = "semantic")]
    hasher: Option<SimHasher>,
    #[cfg(feature = "semantic")]
    model: Option<busted_embed::Embedder>,
}

impl EmbeddingCache {
    /// Create a new empty embedding cache.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            #[cfg(feature = "semantic")]
            hasher: None,
            #[cfg(feature = "semantic")]
            model: None,
        }
    }

    /// Compute or retrieve the prompt fingerprint for an identity.
    ///
    /// Returns the SimHash (semantic) or FNV-1a (fallback) fingerprint.
    /// Skips re-embedding if the text hash matches a cached entry.
    pub fn fingerprint(&mut self, identity_id: IdentityId, prompt: &str) -> u64 {
        let text_hash = fnv1a_64(prompt.as_bytes());

        // Check dedup — skip if same text already cached
        if let Some(cached) = self.cache.get(&identity_id) {
            if cached.text_hash == text_hash {
                return cached.fingerprint;
            }
        }

        let fingerprint = self.compute_fingerprint(prompt, text_hash);

        self.cache.insert(
            identity_id,
            CachedEmbedding {
                text_hash,
                fingerprint,
                #[cfg(feature = "semantic")]
                _vector: Vec::new(), // Populated below in semantic path
            },
        );

        fingerprint
    }

    /// Compute similarity between two fingerprints.
    ///
    /// With `semantic`: Hamming-based similarity (0.0–1.0, fuzzy).
    /// Without `semantic`: exact match (0.0 or 1.0).
    pub fn similarity(a: u64, b: u64) -> f32 {
        #[cfg(feature = "semantic")]
        {
            SimHasher::similarity(a, b)
        }
        #[cfg(not(feature = "semantic"))]
        {
            if a == b {
                1.0
            } else {
                0.0
            }
        }
    }

    /// Get a cached fingerprint for an identity, if any.
    pub fn get_fingerprint(&self, identity_id: IdentityId) -> Option<u64> {
        self.cache.get(&identity_id).map(|c| c.fingerprint)
    }

    /// Remove an identity's cached embedding (e.g. on GC eviction).
    pub fn remove(&mut self, identity_id: IdentityId) {
        self.cache.remove(&identity_id);
    }

    /// Number of cached embeddings.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    #[cfg(not(feature = "semantic"))]
    fn compute_fingerprint(&mut self, prompt: &str, _text_hash: u64) -> u64 {
        // Fallback: FNV-1a of the prompt text
        fnv1a_64(prompt.as_bytes())
    }

    #[cfg(feature = "semantic")]
    fn compute_fingerprint(&mut self, prompt: &str, _text_hash: u64) -> u64 {
        // Lazy-init model and hasher
        if self.model.is_none() {
            match busted_embed::Embedder::new() {
                Ok(embedder) => {
                    self.hasher = Some(SimHasher::new(embedder.dim()));
                    self.model = Some(embedder);
                }
                Err(e) => {
                    log::warn!("Failed to init embedder: {e}, falling back to FNV-1a");
                    return fnv1a_64(prompt.as_bytes());
                }
            }
        }

        let model = self.model.as_mut().unwrap();
        let hasher = self.hasher.as_ref().unwrap();

        match model.embed(prompt) {
            Ok(embedding) => hasher.hash(&embedding),
            Err(e) => {
                log::warn!("Embedding failed: {e}, falling back to FNV-1a");
                fnv1a_64(prompt.as_bytes())
            }
        }
    }
}

impl Default for EmbeddingCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_deterministic() {
        let mut cache = EmbeddingCache::new();
        let f1 = cache.fingerprint(1, "You are a helpful assistant");
        let f2 = cache.fingerprint(1, "You are a helpful assistant");
        assert_eq!(f1, f2);
    }

    #[test]
    fn different_prompts_different_fingerprints() {
        let mut cache = EmbeddingCache::new();
        let f1 = cache.fingerprint(1, "You are a helpful assistant");
        let f2 = cache.fingerprint(2, "You are a malicious agent");
        assert_ne!(f1, f2);
    }

    #[test]
    fn cache_dedup() {
        let mut cache = EmbeddingCache::new();
        cache.fingerprint(1, "prompt A");
        cache.fingerprint(1, "prompt A"); // same text → cached
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_updates_on_new_prompt() {
        let mut cache = EmbeddingCache::new();
        let f1 = cache.fingerprint(1, "prompt A");
        let f2 = cache.fingerprint(1, "prompt B");
        assert_ne!(f1, f2);
        assert_eq!(cache.len(), 1); // same identity, updated in place
    }

    #[test]
    fn similarity_exact_match() {
        let sim = EmbeddingCache::similarity(12345, 12345);
        assert_eq!(sim, 1.0);
    }

    #[test]
    fn similarity_no_match() {
        // Without semantic, different hashes → 0.0
        #[cfg(not(feature = "semantic"))]
        assert_eq!(EmbeddingCache::similarity(111, 222), 0.0);
    }

    #[test]
    fn remove_entry() {
        let mut cache = EmbeddingCache::new();
        cache.fingerprint(1, "test");
        assert_eq!(cache.len(), 1);
        cache.remove(1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn get_fingerprint_cached() {
        let mut cache = EmbeddingCache::new();
        let fp = cache.fingerprint(42, "hello");
        assert_eq!(cache.get_fingerprint(42), Some(fp));
        assert_eq!(cache.get_fingerprint(99), None);
    }
}
