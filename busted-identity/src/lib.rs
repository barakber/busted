//! Cross-event AI agent identity resolution and timeline tracking.
//!
//! `busted-classifier` analyzes each TLS payload in isolation. This crate
//! correlates events over time: it resolves stable identities from weak
//! signals (PID, SDK, model, container, signature hash) and records
//! action sequences per identity.
//!
//! # Architecture
//!
//! - **Stateless classifier** (`busted-classifier`) = per-event, hot path
//! - **Stateful identity tracker** (`busted-identity`) = cross-event accumulator
//!
//! The tracker is synchronous (`&mut self`), called from the agent's async
//! event loop just like `MlClassifier`.
//!
//! # Usage
//!
//! ```no_run
//! use busted_identity::IdentityTracker;
//!
//! let mut tracker = IdentityTracker::new();
//! // In the event loop:
//! // if let Some(identity_match) = tracker.observe(&processed_event) {
//! //     processed_event.identity_id = Some(identity_match.identity_id);
//! //     // ... fill other identity fields
//! // }
//! ```

pub mod action;
pub mod capability;
pub mod embedding;
#[cfg(feature = "graph")]
pub mod graph;
pub mod identity;
pub mod narrative;
pub mod ngrams;
pub mod resolver;
pub mod scoring;
pub mod simhash;
#[cfg(feature = "persist")]
pub mod store;
pub mod timeline;

use busted_types::agentic::BustedEvent;
use std::collections::HashMap;

use action::Action;
use identity::{IdentityId, IdentityMatch, InstanceKey, ResolvedIdentity, TypeKey};
use timeline::Timeline;

/// Configuration for the identity tracker.
#[derive(Debug, Clone)]
pub struct TrackerConfig {
    /// Maximum number of distinct identities to track.
    pub max_identities: usize,
    /// Ring buffer capacity per identity timeline.
    pub timeline_capacity: usize,
    /// Maximum number of instance-to-identity mappings.
    pub max_instances: usize,
    /// Path for persistent identity store (requires `persist` feature).
    pub store_path: Option<std::path::PathBuf>,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            max_identities: 256,
            timeline_capacity: 256,
            max_instances: 4096,
            store_path: None,
        }
    }
}

/// Cross-event identity tracker.
///
/// Call `observe()` for each `BustedEvent` to resolve its identity
/// and record the action in the timeline. Returns `Some(IdentityMatch)`
/// for interesting events (LLM/MCP), `None` for background traffic.
pub struct IdentityTracker {
    config: TrackerConfig,
    /// Resolved identities by ID.
    identities: HashMap<IdentityId, ResolvedIdentity>,
    /// Timelines by identity ID.
    timelines: HashMap<IdentityId, Timeline>,
    /// Instance key → identity ID mapping (fast path).
    instance_map: HashMap<InstanceKey, IdentityId>,
    /// Type key → identity ID mapping (strong match).
    type_map: HashMap<TypeKey, IdentityId>,
    /// Prompt embedding cache for system prompt fingerprinting.
    embedding_cache: embedding::EmbeddingCache,
    /// Persistent identity store (requires `persist` feature).
    #[cfg(feature = "persist")]
    store: Option<store::IdentityStore>,
    /// Agent relationship graph (requires `graph` feature).
    #[cfg(feature = "graph")]
    agent_graph: graph::AgentGraph,
}

impl IdentityTracker {
    /// Create a tracker with default configuration.
    pub fn new() -> Self {
        Self::with_config(TrackerConfig::default())
    }

    /// Create a tracker with custom configuration.
    pub fn with_config(config: TrackerConfig) -> Self {
        // Try to open persistent store if configured
        #[cfg(feature = "persist")]
        let store =
            config
                .store_path
                .as_ref()
                .and_then(|path| match store::IdentityStore::open(path) {
                    Ok(s) => {
                        log::info!("Opened identity store at {}", path.display());
                        Some(s)
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to open identity store: {e}, running without persistence"
                        );
                        None
                    }
                });

        #[allow(unused_mut)]
        let mut tracker = Self {
            identities: HashMap::with_capacity(config.max_identities),
            timelines: HashMap::with_capacity(config.max_identities),
            instance_map: HashMap::with_capacity(config.max_instances),
            type_map: HashMap::with_capacity(config.max_identities),
            embedding_cache: embedding::EmbeddingCache::new(),
            #[cfg(feature = "persist")]
            store,
            #[cfg(feature = "graph")]
            agent_graph: graph::AgentGraph::new(),
            config,
        };

        // Load persisted identities and type mappings
        #[cfg(feature = "persist")]
        tracker.load_from_store();

        tracker
    }

    /// Load identities and type mappings from the persistent store.
    #[cfg(feature = "persist")]
    fn load_from_store(&mut self) {
        let store = match self.store.as_ref() {
            Some(s) => s,
            None => return,
        };

        match store.load_identities() {
            Ok(identities) => {
                let count = identities.len();
                for identity in identities {
                    let id = identity.identity_id;
                    self.identities.insert(id, identity);
                    self.timelines
                        .insert(id, Timeline::new(self.config.timeline_capacity));
                }
                if count > 0 {
                    log::info!("Loaded {count} identities from store");
                }
            }
            Err(e) => log::warn!("Failed to load identities: {e}"),
        }

        match store.load_type_mappings() {
            Ok(mappings) => {
                for (type_key, identity_id) in mappings {
                    self.type_map.insert(type_key, identity_id);
                }
            }
            Err(e) => log::warn!("Failed to load type mappings: {e}"),
        }
    }

    /// Observe a processed event and resolve its identity.
    ///
    /// Returns `Some(IdentityMatch)` for interesting events that have
    /// identity signals (LLM calls, MCP calls, PII events, etc.).
    /// Returns `None` for uninteresting background traffic.
    pub fn observe(&mut self, event: &BustedEvent) -> Option<IdentityMatch> {
        // Extract action — if not interesting, skip
        let action = Action::from_busted_event(event)?;

        // Compute prompt fingerprint before resolution (for future scoring)
        let prompt_fingerprint = event
            .system_prompt()
            .filter(|s| !s.is_empty())
            .map(|prompt| {
                // Use identity_id=0 as temp key; will be re-keyed after resolution
                self.embedding_cache.fingerprint(0, prompt)
            });

        let (mut identity_id, instance_key, mut match_level, mut is_new) =
            resolver::resolve(event, &self.instance_map, &self.type_map, &self.identities);

        // If resolver found no match (New), try composite scoring
        if is_new && !self.identities.is_empty() {
            let ctx = scoring::ResolveContext {
                event,
                prompt_fingerprint,
                behavioral_digest: None,
            };
            if let Some((matched_id, score)) = scoring::find_best_composite_match(
                self.identities.values(),
                &ctx,
                &self.embedding_cache,
            ) {
                identity_id = matched_id;
                is_new = false;
                match_level = if score >= scoring::SEMANTIC_THRESHOLD {
                    resolver::MatchLevel::SemanticMatch(score)
                } else {
                    resolver::MatchLevel::CompositeMatch(score)
                };
            }
        }

        if is_new {
            // GC if at capacity
            if self.identities.len() >= self.config.max_identities {
                self.gc();
            }

            let type_key = resolver::extract_type_key(event);
            let label = resolver::build_label(event);
            let provider = event.provider().map(action::ProviderTag::parse);

            let identity = ResolvedIdentity {
                identity_id,
                type_key: type_key.clone(),
                first_seen: event.timestamp.clone(),
                last_seen: event.timestamp.clone(),
                event_count: 0,
                label,
                active_instances: vec![instance_key.clone()],
                providers: provider.into_iter().collect(),
                behavioral_digest: None,
                capability_hash: None,
                prompt_fingerprint: None,
            };

            self.identities.insert(identity_id, identity);
            self.timelines
                .insert(identity_id, Timeline::new(self.config.timeline_capacity));
            self.type_map.insert(type_key, identity_id);
        }

        // Register instance mapping
        if self.instance_map.len() < self.config.max_instances {
            self.instance_map.insert(instance_key.clone(), identity_id);
        }

        // Update identity state
        if let Some(identity) = self.identities.get_mut(&identity_id) {
            identity.last_seen = event.timestamp.clone();
            identity.event_count += 1;

            // Add instance if not already tracked
            if !identity.active_instances.contains(&instance_key) {
                identity.active_instances.push(instance_key.clone());
            }

            // Add provider if new
            if let Some(provider_str) = event.provider() {
                let tag = action::ProviderTag::parse(provider_str);
                if !identity.providers.contains(&tag) {
                    identity.providers.push(tag);
                }
            }
        }

        // Record in timeline
        if let Some(tl) = self.timelines.get_mut(&identity_id) {
            tl.push(event.timestamp.clone(), action);
        }

        // Extract MCP capability hash if available
        if let Some(cap_hash) = capability::extract_capability_hash(event) {
            if let Some(identity) = self.identities.get_mut(&identity_id) {
                identity.capability_hash = Some(cap_hash);
            }
        }

        // Store prompt fingerprint on the identity
        if let Some(fp) = prompt_fingerprint {
            // Re-key the embedding cache entry with the actual identity_id
            if let Some(identity) = self.identities.get_mut(&identity_id) {
                identity.prompt_fingerprint = Some(fp);
            }
            // Cache under the real identity_id for future lookups
            if let Some(prompt) = event.system_prompt() {
                self.embedding_cache.fingerprint(identity_id, prompt);
            }
        }

        // Recompute behavioral digest periodically
        if let (Some(identity), Some(tl)) = (
            self.identities.get(&identity_id),
            self.timelines.get(&identity_id),
        ) {
            if ngrams::should_recompute(identity.event_count, tl.len()) {
                if let Some(digest) = ngrams::compute_behavioral_digest(tl) {
                    if let Some(identity) = self.identities.get_mut(&identity_id) {
                        identity.behavioral_digest = Some(digest);
                    }
                }
            }
        }

        // Persist updated identity to store
        #[cfg(feature = "persist")]
        if let (Some(store), Some(identity)) =
            (self.store.as_ref(), self.identities.get(&identity_id))
        {
            if let Err(e) = store.save_identity(identity) {
                log::debug!("Failed to persist identity {identity_id}: {e}");
            }
            if is_new {
                if let Err(e) = store.save_type_mapping(&identity.type_key, identity_id) {
                    log::debug!("Failed to persist type mapping: {e}");
                }
            }
        }

        // Update agent relationship graph
        #[cfg(feature = "graph")]
        {
            let label = self
                .identities
                .get(&identity_id)
                .map(|i| i.label.as_str())
                .unwrap_or("unknown");
            self.agent_graph
                .ensure_node(identity_id, label, &event.timestamp);

            // Record outbound calls for relay detection
            let is_outbound = matches!(event.action_type(), "Prompt" | "ToolResult" | "McpRequest");
            if is_outbound {
                let container_hash = if event.process.container_id.is_empty() {
                    0
                } else {
                    // Simple FNV hash of container_id
                    let mut h: u32 = 0x811c9dc5;
                    for &b in event.process.container_id.as_bytes() {
                        h ^= b as u32;
                        h = h.wrapping_mul(0x01000193);
                    }
                    h
                };
                let ts_ms = graph::parse_timestamp_ms(&event.timestamp);
                self.agent_graph
                    .record_outbound(identity_id, container_hash, ts_ms);
            }

            // Check for relay patterns on inbound LLM responses
            let is_inbound = matches!(event.action_type(), "Response" | "ToolCall" | "McpResponse");
            if is_inbound && !event.process.container_id.is_empty() {
                let container_hash = {
                    let mut h: u32 = 0x811c9dc5;
                    for &b in event.process.container_id.as_bytes() {
                        h ^= b as u32;
                        h = h.wrapping_mul(0x01000193);
                    }
                    h
                };
                let ts_ms = graph::parse_timestamp_ms(&event.timestamp);
                self.agent_graph
                    .check_relay(identity_id, container_hash, ts_ms, &event.timestamp);
            }
        }

        // Build match result
        let timeline = self.timelines.get(&identity_id)?;
        let identity = self.identities.get(&identity_id)?;
        let narrative_str = narrative::generate(identity, timeline);
        let summary = timeline.summary();
        let tl_len = timeline.len();

        Some(IdentityMatch {
            identity_id,
            instance_id: instance_key,
            confidence: match_level.confidence(),
            narrative: narrative_str,
            timeline_summary: summary,
            timeline_len: tl_len,
            match_type: format!("{:?}", match_level),
            behavioral_digest: identity.behavioral_digest,
            capability_hash: identity.capability_hash,
            prompt_fingerprint: identity.prompt_fingerprint,
        })
    }

    /// Look up a resolved identity by ID.
    pub fn get_identity(&self, id: IdentityId) -> Option<&ResolvedIdentity> {
        self.identities.get(&id)
    }

    /// Look up a timeline by identity ID.
    pub fn get_timeline(&self, id: IdentityId) -> Option<&Timeline> {
        self.timelines.get(&id)
    }

    /// Number of distinct identities currently tracked.
    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    /// Number of nodes in the agent relationship graph (0 without `graph` feature).
    pub fn graph_node_count(&self) -> usize {
        #[cfg(feature = "graph")]
        {
            self.agent_graph.node_count()
        }
        #[cfg(not(feature = "graph"))]
        {
            0
        }
    }

    /// Number of edges in the agent relationship graph (0 without `graph` feature).
    pub fn graph_edge_count(&self) -> usize {
        #[cfg(feature = "graph")]
        {
            self.agent_graph.edge_count()
        }
        #[cfg(not(feature = "graph"))]
        {
            0
        }
    }

    /// LRU eviction: remove the identity with the oldest `last_seen`.
    pub fn gc(&mut self) {
        if self.identities.is_empty() {
            return;
        }

        // Find the identity with the oldest last_seen
        let oldest_id = self
            .identities
            .iter()
            .min_by(|a, b| a.1.last_seen.cmp(&b.1.last_seen))
            .map(|(&id, _)| id);

        if let Some(id) = oldest_id {
            if let Some(identity) = self.identities.remove(&id) {
                self.timelines.remove(&id);
                self.type_map.remove(&identity.type_key);
                self.embedding_cache.remove(id);
                // Remove all instance mappings pointing to this identity
                self.instance_map.retain(|_, v| *v != id);

                #[cfg(feature = "persist")]
                if let Some(store) = self.store.as_ref() {
                    if let Err(e) = store.remove_identity(id) {
                        log::debug!("Failed to remove identity {id} from store: {e}");
                    }
                }

                #[cfg(feature = "graph")]
                self.agent_graph.remove_node(id);

                log::debug!("GC evicted identity {} ({})", id, identity.label);
            }
        }
    }
}

impl Default for IdentityTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busted_types::agentic::{AgenticAction, NetworkEventKind, ProcessInfo};

    fn llm_event(pid: u32) -> BustedEvent {
        BustedEvent {
            timestamp: "12:00:00.000".into(),
            process: ProcessInfo {
                pid,
                uid: 1000,
                name: "python3".into(),
                container_id: String::new(),
                cgroup_id: 42,
                pod_name: None,
                pod_namespace: None,
                service_account: None,
            },
            session_id: format!("{}:abc", pid),
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
                sdk_hash: Some(123),
                model_hash: Some(456),
            },
        }
    }

    fn bare_event() -> BustedEvent {
        BustedEvent {
            timestamp: "00:00:00.000".into(),
            process: ProcessInfo {
                pid: 9999,
                uid: 0,
                name: "nginx".into(),
                container_id: String::new(),
                cgroup_id: 0,
                pod_name: None,
                pod_namespace: None,
                service_account: None,
            },
            session_id: "9999:net".into(),
            identity: None,
            policy: None,
            action: AgenticAction::Network {
                kind: NetworkEventKind::DataSent,
                src_ip: "10.0.0.1".into(),
                src_port: 80,
                dst_ip: "10.0.0.2".into(),
                dst_port: 8080,
                bytes: 64,
                sni: None,
                provider: None,
            },
        }
    }

    fn llm_event_with_hashes(pid: u32, fp: u64, sdk: u32, model: u32) -> BustedEvent {
        let mut event = llm_event(pid);
        event.action = AgenticAction::Prompt {
            provider: "OpenAI".into(),
            model: Some("gpt-4".into()),
            user_message: None,
            system_prompt: None,
            stream: false,
            sdk: Some("openai-python/1.12.0".into()),
            bytes: 512,
            sni: None,
            endpoint: None,
            fingerprint: Some(fp),
            pii_detected: None,
            confidence: None,
            sdk_hash: Some(sdk),
            model_hash: Some(model),
        };
        event
    }

    #[test]
    fn uninteresting_event_returns_none() {
        let mut tracker = IdentityTracker::new();
        assert!(tracker.observe(&bare_event()).is_none());
        assert_eq!(tracker.identity_count(), 0);
    }

    #[test]
    fn first_observation_creates_identity() {
        let mut tracker = IdentityTracker::new();
        let m = tracker.observe(&llm_event(1234)).unwrap();
        assert_eq!(tracker.identity_count(), 1);
        assert!(m.confidence > 0.0);
        assert!(!m.narrative.is_empty());
    }

    #[test]
    fn same_pid_resolves_same_identity() {
        let mut tracker = IdentityTracker::new();
        let m1 = tracker.observe(&llm_event(1234)).unwrap();
        let m2 = tracker.observe(&llm_event(1234)).unwrap();
        assert_eq!(m1.identity_id, m2.identity_id);
        assert_eq!(tracker.identity_count(), 1);
        assert_eq!(m2.confidence, 1.0); // Exact instance match
    }

    #[test]
    fn same_sdk_model_across_pids_resolves_same_type() {
        let mut tracker = IdentityTracker::new();
        let m1 = tracker.observe(&llm_event(1234)).unwrap();
        let m2 = tracker.observe(&llm_event(5678)).unwrap();
        // Same SDK hash + model hash + signature → same type key → same identity
        assert_eq!(m1.identity_id, m2.identity_id);
        assert_eq!(tracker.identity_count(), 1);
    }

    #[test]
    fn different_sdk_creates_different_identity() {
        let mut tracker = IdentityTracker::new();
        let event1 = llm_event_with_hashes(1234, 300, 100, 200);
        let event2 = llm_event_with_hashes(5678, 600, 400, 500);

        let m1 = tracker.observe(&event1).unwrap();
        let m2 = tracker.observe(&event2).unwrap();
        assert_ne!(m1.identity_id, m2.identity_id);
        assert_eq!(tracker.identity_count(), 2);
    }

    #[test]
    fn gc_evicts_oldest() {
        let config = TrackerConfig {
            max_identities: 2,
            timeline_capacity: 4,
            max_instances: 100,
            store_path: None,
        };
        let mut tracker = IdentityTracker::with_config(config);

        // Create identity 1
        let mut e1 = llm_event_with_hashes(100, 1, 1, 1);
        e1.timestamp = "01:00:00".into();
        tracker.observe(&e1);

        // Create identity 2
        let mut e2 = llm_event_with_hashes(200, 2, 2, 2);
        e2.timestamp = "02:00:00".into();
        tracker.observe(&e2);

        assert_eq!(tracker.identity_count(), 2);

        // Create identity 3 — should trigger GC of identity 1 (oldest)
        let mut e3 = llm_event_with_hashes(300, 3, 3, 3);
        e3.timestamp = "03:00:00".into();
        tracker.observe(&e3);

        assert_eq!(tracker.identity_count(), 2);
    }

    #[test]
    fn timeline_accumulates() {
        let mut tracker = IdentityTracker::new();
        for i in 0..5 {
            let mut event = llm_event(1234);
            event.timestamp = format!("12:00:0{}.000", i);
            tracker.observe(&event);
        }
        let m = tracker.observe(&llm_event(1234)).unwrap();
        assert_eq!(m.timeline_len, 6);
    }

    #[test]
    fn get_identity_and_timeline() {
        let mut tracker = IdentityTracker::new();
        let m = tracker.observe(&llm_event(1234)).unwrap();
        let id = m.identity_id;

        assert!(tracker.get_identity(id).is_some());
        assert!(tracker.get_timeline(id).is_some());
        assert!(tracker.get_identity(0).is_none());
    }
}
