//! Composite multi-signal identity scoring.
//!
//! Replaces simple hash-equality matching in the resolver fallback path
//! with a weighted combination of:
//! - Prompt fingerprint similarity (SimHash or exact-match)
//! - TypeKey component overlap
//! - Behavioral digest match
//! - Network locality (same destination IP/port)

use crate::embedding::EmbeddingCache;
use crate::identity::{IdentityId, ResolvedIdentity};
use busted_types::agentic::BustedEvent;

/// Context for scoring a candidate identity against an event.
pub struct ResolveContext<'a> {
    pub event: &'a BustedEvent,
    /// Prompt fingerprint computed for this event (if any).
    pub prompt_fingerprint: Option<u64>,
    /// Behavioral digest from event's identity (if previously resolved).
    pub behavioral_digest: Option<u64>,
}

/// Signal weights when semantic embeddings are available.
struct SemanticWeights;

impl SemanticWeights {
    const PROMPT: f32 = 0.40;
    const TYPE_KEY: f32 = 0.25;
    const BEHAVIORAL: f32 = 0.20;
    const NETWORK: f32 = 0.15;
}

/// Signal weights when using FNV-1a fallback (no semantic feature).
struct FallbackWeights;

impl FallbackWeights {
    const PROMPT: f32 = 0.15;
    const TYPE_KEY: f32 = 0.40;
    const BEHAVIORAL: f32 = 0.25;
    const NETWORK: f32 = 0.20;
}

/// Minimum composite score to consider a match.
pub const COMPOSITE_THRESHOLD: f32 = 0.60;

/// Score threshold for "semantic match" level.
pub const SEMANTIC_THRESHOLD: f32 = 0.85;

/// Score a candidate identity against the current event.
///
/// Returns a score in [0.0, 1.0]. Higher = better match.
pub fn score_candidate(
    candidate: &ResolvedIdentity,
    ctx: &ResolveContext<'_>,
    embedding_cache: &EmbeddingCache,
) -> f32 {
    let has_semantic = cfg!(feature = "semantic");

    let (w_prompt, w_type, w_behavioral, w_network) = if has_semantic {
        (
            SemanticWeights::PROMPT,
            SemanticWeights::TYPE_KEY,
            SemanticWeights::BEHAVIORAL,
            SemanticWeights::NETWORK,
        )
    } else {
        (
            FallbackWeights::PROMPT,
            FallbackWeights::TYPE_KEY,
            FallbackWeights::BEHAVIORAL,
            FallbackWeights::NETWORK,
        )
    };

    let prompt_score = compute_prompt_score(candidate, ctx, embedding_cache);
    let type_score = compute_type_key_score(candidate, ctx.event);
    let behavioral_score = compute_behavioral_score(candidate, ctx);
    let network_score = compute_network_score(candidate, ctx.event);

    w_prompt * prompt_score
        + w_type * type_score
        + w_behavioral * behavioral_score
        + w_network * network_score
}

/// Prompt fingerprint similarity.
fn compute_prompt_score(
    candidate: &ResolvedIdentity,
    ctx: &ResolveContext<'_>,
    embedding_cache: &EmbeddingCache,
) -> f32 {
    match (ctx.prompt_fingerprint, candidate.prompt_fingerprint) {
        (Some(event_fp), Some(cand_fp)) => EmbeddingCache::similarity(event_fp, cand_fp),
        // If either side has no prompt, try the embedding cache
        (Some(event_fp), None) => {
            if let Some(cached_fp) = embedding_cache.get_fingerprint(candidate.identity_id) {
                EmbeddingCache::similarity(event_fp, cached_fp)
            } else {
                0.0
            }
        }
        _ => 0.0,
    }
}

/// TypeKey component overlap score.
///
/// Scores each component independently (signature, sdk, model),
/// giving partial credit for partial matches.
fn compute_type_key_score(candidate: &ResolvedIdentity, event: &BustedEvent) -> f32 {
    let sig = event.fingerprint().unwrap_or(0);
    let sdk = event.sdk_hash().unwrap_or(0);
    let model = event.model_hash().unwrap_or(0);

    let mut score = 0.0;
    let mut weight = 0.0;

    // Signature match (highest signal)
    if sig != 0 && candidate.type_key.signature_hash != 0 {
        weight += 0.4;
        if sig == candidate.type_key.signature_hash {
            score += 0.4;
        }
    }

    // SDK match
    if sdk != 0 && candidate.type_key.sdk_hash != 0 {
        weight += 0.3;
        if sdk == candidate.type_key.sdk_hash {
            score += 0.3;
        }
    }

    // Model match
    if model != 0 && candidate.type_key.model_hash != 0 {
        weight += 0.3;
        if model == candidate.type_key.model_hash {
            score += 0.3;
        }
    }

    if weight > 0.0 {
        score / weight
    } else {
        0.0
    }
}

/// Behavioral digest similarity (exact match for now).
fn compute_behavioral_score(candidate: &ResolvedIdentity, ctx: &ResolveContext<'_>) -> f32 {
    match (ctx.behavioral_digest, candidate.behavioral_digest) {
        (Some(a), Some(b)) if a == b => 1.0,
        (Some(_), Some(_)) => 0.0,
        _ => 0.0,
    }
}

/// Network locality score.
///
/// Same destination IP+port suggests same service endpoint.
fn compute_network_score(candidate: &ResolvedIdentity, event: &BustedEvent) -> f32 {
    // Check provider overlap as a proxy for network locality
    let event_provider = event.provider();

    if let Some(provider_str) = event_provider {
        let tag = crate::action::ProviderTag::parse(provider_str);
        if candidate.providers.contains(&tag) {
            return 1.0;
        }
    }

    0.0
}

/// Find the best matching identity above the composite threshold.
///
/// Returns `(identity_id, score)` if a match is found.
pub fn find_best_composite_match<'a>(
    identities: impl Iterator<Item = &'a ResolvedIdentity>,
    ctx: &ResolveContext<'_>,
    embedding_cache: &EmbeddingCache,
) -> Option<(IdentityId, f32)> {
    let mut best_id = None;
    let mut best_score = 0.0f32;

    for candidate in identities {
        let score = score_candidate(candidate, ctx, embedding_cache);
        if score > best_score {
            best_score = score;
            best_id = Some(candidate.identity_id);
        }
    }

    if best_score >= COMPOSITE_THRESHOLD {
        best_id.map(|id| (id, best_score))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TypeKey;

    fn test_identity(id: u64) -> ResolvedIdentity {
        ResolvedIdentity {
            identity_id: id,
            type_key: TypeKey {
                signature_hash: 0xdeadbeef,
                sdk_hash: 100,
                model_hash: 200,
            },
            first_seen: "12:00:00".into(),
            last_seen: "12:01:00".into(),
            event_count: 10,
            label: "test-agent".into(),
            active_instances: vec![],
            providers: vec![crate::action::ProviderTag::OpenAI],
            behavioral_digest: Some(0xABCD),
            capability_hash: None,
            prompt_fingerprint: Some(0x1234),
        }
    }

    fn test_event() -> BustedEvent {
        use busted_types::agentic::{AgenticAction, ProcessInfo};
        BustedEvent {
            timestamp: "12:00:00.000".into(),
            process: ProcessInfo {
                pid: 1234,
                uid: 1000,
                name: "python3".into(),
                container_id: String::new(),
                cgroup_id: 42,
                pod_name: None,
                pod_namespace: None,
                service_account: None,
            },
            session_id: "1234:abc".into(),
            identity: None,
            policy: None,
            action: AgenticAction::Prompt {
                provider: "OpenAI".into(),
                model: Some("gpt-4".into()),
                user_message: None,
                system_prompt: None,
                stream: false,
                sdk: Some("openai-python/1.12.0".into()),
                bytes: 512,
                sni: None,
                endpoint: None,
                fingerprint: Some(0xdeadbeef),
                pii_detected: Some(false),
                confidence: Some(0.9),
                sdk_hash: Some(100),
                model_hash: Some(200),
            },
        }
    }

    #[test]
    fn full_match_scores_high() {
        let identity = test_identity(1);
        let event = test_event();
        let ctx = ResolveContext {
            event: &event,
            prompt_fingerprint: Some(0x1234),
            behavioral_digest: Some(0xABCD),
        };
        let cache = EmbeddingCache::new();
        let score = score_candidate(&identity, &ctx, &cache);
        assert!(score > 0.8, "full match should score high, got {score}");
    }

    #[test]
    fn no_signals_scores_zero() {
        let mut identity = test_identity(1);
        identity.type_key = TypeKey {
            signature_hash: 999,
            sdk_hash: 999,
            model_hash: 999,
        };
        identity.providers = vec![];
        identity.behavioral_digest = None;
        identity.prompt_fingerprint = None;

        let event = test_event();
        let ctx = ResolveContext {
            event: &event,
            prompt_fingerprint: None,
            behavioral_digest: None,
        };
        let cache = EmbeddingCache::new();
        let score = score_candidate(&identity, &ctx, &cache);
        // Should be low — type keys don't match, no prompt, no behavioral
        assert!(
            score < COMPOSITE_THRESHOLD,
            "mismatched should score low, got {score}"
        );
    }

    #[test]
    fn type_key_only_match() {
        let mut identity = test_identity(1);
        identity.prompt_fingerprint = None;
        identity.behavioral_digest = None;
        identity.providers = vec![];

        let event = test_event();
        let ctx = ResolveContext {
            event: &event,
            prompt_fingerprint: None,
            behavioral_digest: None,
        };
        let cache = EmbeddingCache::new();
        let score = score_candidate(&identity, &ctx, &cache);
        // TypeKey matches fully → type_key_score = 1.0, weighted
        assert!(
            score > 0.0,
            "type key match alone should give some score, got {score}"
        );
    }

    #[test]
    fn find_best_match_above_threshold() {
        let identity = test_identity(42);
        let event = test_event();
        let ctx = ResolveContext {
            event: &event,
            prompt_fingerprint: Some(0x1234),
            behavioral_digest: Some(0xABCD),
        };
        let cache = EmbeddingCache::new();
        let result = find_best_composite_match(std::iter::once(&identity), &ctx, &cache);
        assert!(result.is_some());
        let (id, score) = result.unwrap();
        assert_eq!(id, 42);
        assert!(score >= COMPOSITE_THRESHOLD);
    }

    #[test]
    fn find_best_match_below_threshold() {
        let mut identity = test_identity(42);
        identity.type_key = TypeKey {
            signature_hash: 999,
            sdk_hash: 999,
            model_hash: 999,
        };
        identity.providers = vec![];
        identity.behavioral_digest = None;
        identity.prompt_fingerprint = None;

        let event = test_event();
        let ctx = ResolveContext {
            event: &event,
            prompt_fingerprint: None,
            behavioral_digest: None,
        };
        let cache = EmbeddingCache::new();
        let result = find_best_composite_match(std::iter::once(&identity), &ctx, &cache);
        assert!(result.is_none());
    }

    #[test]
    fn network_score_provider_overlap() {
        let identity = test_identity(1);
        let event = test_event();
        let score = compute_network_score(&identity, &event);
        assert_eq!(score, 1.0, "same provider should give full network score");
    }
}
