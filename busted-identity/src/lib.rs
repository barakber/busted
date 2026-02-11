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
pub mod identity;
pub mod narrative;
pub mod resolver;
pub mod timeline;

use busted_types::processed::ProcessedEvent;
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
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            max_identities: 256,
            timeline_capacity: 256,
            max_instances: 4096,
        }
    }
}

/// Cross-event identity tracker.
///
/// Call `observe()` for each `ProcessedEvent` to resolve its identity
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
}

impl IdentityTracker {
    /// Create a tracker with default configuration.
    pub fn new() -> Self {
        Self::with_config(TrackerConfig::default())
    }

    /// Create a tracker with custom configuration.
    pub fn with_config(config: TrackerConfig) -> Self {
        Self {
            identities: HashMap::with_capacity(config.max_identities),
            timelines: HashMap::with_capacity(config.max_identities),
            instance_map: HashMap::with_capacity(config.max_instances),
            type_map: HashMap::with_capacity(config.max_identities),
            config,
        }
    }

    /// Observe a processed event and resolve its identity.
    ///
    /// Returns `Some(IdentityMatch)` for interesting events that have
    /// identity signals (LLM calls, MCP calls, PII events, etc.).
    /// Returns `None` for uninteresting background traffic.
    pub fn observe(&mut self, event: &ProcessedEvent) -> Option<IdentityMatch> {
        // Extract action — if not interesting, skip
        let action = Action::from_processed_event(event)?;

        let (identity_id, instance_key, match_level, is_new) =
            resolver::resolve(event, &self.instance_map, &self.type_map, &self.identities);

        if is_new {
            // GC if at capacity
            if self.identities.len() >= self.config.max_identities {
                self.gc();
            }

            let type_key = resolver::extract_type_key(event);
            let label = resolver::build_label(event);
            let provider = event
                .llm_provider
                .as_deref()
                .or(event.provider.as_deref())
                .map(action::ProviderTag::parse);

            let identity = ResolvedIdentity {
                identity_id,
                type_key: type_key.clone(),
                first_seen: event.timestamp.clone(),
                last_seen: event.timestamp.clone(),
                event_count: 0,
                label,
                active_instances: vec![instance_key.clone()],
                providers: provider.into_iter().collect(),
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
            if let Some(provider_str) = event.llm_provider.as_deref().or(event.provider.as_deref())
            {
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
                // Remove all instance mappings pointing to this identity
                self.instance_map.retain(|_, v| *v != id);
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

    fn llm_event(pid: u32) -> ProcessedEvent {
        ProcessedEvent {
            event_type: "TLS_DATA_WRITE".into(),
            timestamp: "12:00:00.000".into(),
            pid,
            uid: 1000,
            process_name: "python3".into(),
            src_ip: "10.0.0.1".into(),
            src_port: 54321,
            dst_ip: "104.18.1.1".into(),
            dst_port: 443,
            bytes: 512,
            provider: Some("OpenAI".into()),
            policy: None,
            container_id: String::new(),
            cgroup_id: 42,
            request_rate: None,
            session_bytes: None,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
            ml_confidence: None,
            ml_provider: None,
            behavior_class: None,
            cluster_id: None,
            sni: None,
            tls_protocol: None,
            tls_details: None,
            tls_payload: None,
            content_class: Some("LlmApi".into()),
            llm_provider: Some("OpenAI".into()),
            llm_endpoint: None,
            llm_model: Some("gpt-4".into()),
            mcp_method: None,
            mcp_category: None,
            agent_sdk: Some("openai-python/1.12.0".into()),
            agent_fingerprint: Some(0xdeadbeef),
            classifier_confidence: Some(0.9),
            pii_detected: Some(false),
            llm_user_message: None,
            llm_system_prompt: None,
            llm_messages_json: None,
            llm_stream: None,
            identity_id: None,
            identity_instance: None,
            identity_confidence: None,
            identity_narrative: None,
            identity_timeline: None,
            identity_timeline_len: None,
            agent_sdk_hash: Some(123),
            agent_model_hash: Some(456),
        }
    }

    fn bare_event() -> ProcessedEvent {
        ProcessedEvent {
            event_type: "TCP_SENDMSG".into(),
            timestamp: "00:00:00.000".into(),
            pid: 9999,
            uid: 0,
            process_name: "nginx".into(),
            src_ip: "10.0.0.1".into(),
            src_port: 80,
            dst_ip: "10.0.0.2".into(),
            dst_port: 8080,
            bytes: 64,
            provider: None,
            policy: None,
            container_id: String::new(),
            cgroup_id: 0,
            request_rate: None,
            session_bytes: None,
            pod_name: None,
            pod_namespace: None,
            service_account: None,
            ml_confidence: None,
            ml_provider: None,
            behavior_class: None,
            cluster_id: None,
            sni: None,
            tls_protocol: None,
            tls_details: None,
            tls_payload: None,
            content_class: None,
            llm_provider: None,
            llm_endpoint: None,
            llm_model: None,
            mcp_method: None,
            mcp_category: None,
            agent_sdk: None,
            agent_fingerprint: None,
            classifier_confidence: None,
            pii_detected: None,
            llm_user_message: None,
            llm_system_prompt: None,
            llm_messages_json: None,
            llm_stream: None,
            identity_id: None,
            identity_instance: None,
            identity_confidence: None,
            identity_narrative: None,
            identity_timeline: None,
            identity_timeline_len: None,
            agent_sdk_hash: None,
            agent_model_hash: None,
        }
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
        let mut event1 = llm_event(1234);
        event1.agent_sdk_hash = Some(100);
        event1.agent_model_hash = Some(200);
        event1.agent_fingerprint = Some(300);

        let mut event2 = llm_event(5678);
        event2.agent_sdk_hash = Some(400);
        event2.agent_model_hash = Some(500);
        event2.agent_fingerprint = Some(600);

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
        };
        let mut tracker = IdentityTracker::with_config(config);

        // Create identity 1
        let mut e1 = llm_event(100);
        e1.agent_fingerprint = Some(1);
        e1.agent_sdk_hash = Some(1);
        e1.agent_model_hash = Some(1);
        e1.timestamp = "01:00:00".into();
        tracker.observe(&e1);

        // Create identity 2
        let mut e2 = llm_event(200);
        e2.agent_fingerprint = Some(2);
        e2.agent_sdk_hash = Some(2);
        e2.agent_model_hash = Some(2);
        e2.timestamp = "02:00:00".into();
        tracker.observe(&e2);

        assert_eq!(tracker.identity_count(), 2);

        // Create identity 3 — should trigger GC of identity 1 (oldest)
        let mut e3 = llm_event(300);
        e3.agent_fingerprint = Some(3);
        e3.agent_sdk_hash = Some(3);
        e3.agent_model_hash = Some(3);
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
