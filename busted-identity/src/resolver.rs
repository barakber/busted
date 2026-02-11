use busted_types::processed::ProcessedEvent;

use crate::action::ProviderTag;
use crate::identity::{compute_identity_id, IdentityId, InstanceKey, ResolvedIdentity, TypeKey};
use std::collections::HashMap;

/// FNV-1a 32-bit hash (local copy).
fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

/// Extract an InstanceKey from a ProcessedEvent.
pub fn extract_instance_key(event: &ProcessedEvent) -> InstanceKey {
    let container_id_hash = if event.container_id.is_empty() {
        0
    } else {
        fnv1a_32(event.container_id.as_bytes())
    };
    InstanceKey::new(event.pid, container_id_hash, event.cgroup_id)
}

/// Extract a TypeKey from a ProcessedEvent (may be partial).
pub fn extract_type_key(event: &ProcessedEvent) -> TypeKey {
    TypeKey {
        signature_hash: event.agent_fingerprint.unwrap_or(0),
        sdk_hash: event.agent_sdk_hash.unwrap_or(0),
        model_hash: event.agent_model_hash.unwrap_or(0),
    }
}

/// Build a human-readable label from event fields.
pub fn build_label(event: &ProcessedEvent) -> String {
    let sdk = event.agent_sdk.as_deref().unwrap_or("");
    let model = event.llm_model.as_deref().unwrap_or("");
    let provider = event
        .llm_provider
        .as_deref()
        .or(event.provider.as_deref())
        .unwrap_or("");

    if !sdk.is_empty() && !model.is_empty() {
        format!("{} ({})", sdk, model)
    } else if !sdk.is_empty() {
        sdk.to_string()
    } else if !model.is_empty() && !provider.is_empty() {
        format!("{} {}", provider, model)
    } else if !provider.is_empty() {
        provider.to_string()
    } else {
        format!("pid:{}", event.pid)
    }
}

/// Match confidence level.
#[derive(Debug)]
pub enum MatchLevel {
    /// Exact instance key lookup.
    ExactInstance,
    /// Full TypeKey match (signature + sdk + model).
    StrongType,
    /// Partial: signature_hash + model_hash.
    MediumType,
    /// Weak: same provider + ML cluster.
    Weak,
    /// No match — new identity.
    New,
}

impl MatchLevel {
    pub fn confidence(&self) -> f32 {
        match self {
            Self::ExactInstance => 1.0,
            Self::StrongType => 0.95,
            Self::MediumType => 0.75,
            Self::Weak => 0.45,
            Self::New => 0.3,
        }
    }
}

/// Resolve an event to an identity ID.
///
/// Returns `(identity_id, instance_key, match_level, is_new)`.
pub fn resolve(
    event: &ProcessedEvent,
    instance_map: &HashMap<InstanceKey, IdentityId>,
    type_map: &HashMap<TypeKey, IdentityId>,
    identities: &HashMap<IdentityId, ResolvedIdentity>,
) -> (IdentityId, InstanceKey, MatchLevel, bool) {
    let instance_key = extract_instance_key(event);
    let type_key = extract_type_key(event);

    // 1. Fast path: exact instance key lookup
    if let Some(&id) = instance_map.get(&instance_key) {
        return (id, instance_key, MatchLevel::ExactInstance, false);
    }

    // 2. Strong match: full TypeKey
    if type_key.signature_hash != 0 && type_key.sdk_hash != 0 && type_key.model_hash != 0 {
        if let Some(&id) = type_map.get(&type_key) {
            return (id, instance_key, MatchLevel::StrongType, false);
        }
    }

    // 3. Medium match: signature_hash + model_hash (ignoring sdk_hash)
    if type_key.signature_hash != 0 && type_key.model_hash != 0 {
        for (tk, &id) in type_map {
            if tk.signature_hash == type_key.signature_hash && tk.model_hash == type_key.model_hash
            {
                return (id, instance_key, MatchLevel::MediumType, false);
            }
        }
    }

    // 4. Weak match: same provider + ML cluster_id
    if let (Some(provider_str), Some(cluster)) = (event.provider.as_deref(), event.cluster_id) {
        let provider = ProviderTag::parse(provider_str);
        for identity in identities.values() {
            if identity.providers.contains(&provider) {
                // Check if any active instance has the same cluster
                // This is a weak heuristic — cluster_id isn't stored per-identity,
                // so just match on provider overlap for now
                if cluster >= 0 {
                    return (identity.identity_id, instance_key, MatchLevel::Weak, false);
                }
            }
        }
    }

    // 5. New identity
    let id = if type_key.signature_hash != 0 || type_key.sdk_hash != 0 || type_key.model_hash != 0 {
        compute_identity_id(&type_key)
    } else {
        // Fallback: hash from PID + container + cgroup
        let mut h: u64 = 0xcbf29ce484222325;
        let prime: u64 = 0x00000100000001B3;
        for &b in &instance_key.pid.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(prime);
        }
        for &b in &instance_key.cgroup_id.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(prime);
        }
        for &b in &instance_key.container_id_hash.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(prime);
        }
        h
    };

    (id, instance_key, MatchLevel::New, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_event() -> ProcessedEvent {
        ProcessedEvent {
            event_type: "TLS_DATA_WRITE".into(),
            timestamp: "12:00:00.000".into(),
            pid: 1234,
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
            agent_sdk_hash: Some(fnv1a_32(b"openai-python")),
            agent_model_hash: Some(fnv1a_32(b"gpt-4")),
        }
    }

    #[test]
    fn instance_key_exact_match() {
        let event = base_event();
        let ik = extract_instance_key(&event);
        let mut instance_map = HashMap::new();
        instance_map.insert(ik.clone(), 999);

        let (id, _, level, is_new) =
            resolve(&event, &instance_map, &HashMap::new(), &HashMap::new());
        assert_eq!(id, 999);
        assert!(matches!(level, MatchLevel::ExactInstance));
        assert!(!is_new);
    }

    #[test]
    fn type_key_match() {
        let event = base_event();
        let tk = extract_type_key(&event);
        let id = compute_identity_id(&tk);
        let mut type_map = HashMap::new();
        type_map.insert(tk, id);

        let (resolved_id, _, level, is_new) =
            resolve(&event, &HashMap::new(), &type_map, &HashMap::new());
        assert_eq!(resolved_id, id);
        assert!(matches!(level, MatchLevel::StrongType));
        assert!(!is_new);
    }

    #[test]
    fn new_identity_created() {
        let event = base_event();
        let (_, _, level, is_new) =
            resolve(&event, &HashMap::new(), &HashMap::new(), &HashMap::new());
        assert!(matches!(level, MatchLevel::New));
        assert!(is_new);
    }

    #[test]
    fn deterministic_id_for_same_event() {
        let event = base_event();
        let (id1, _, _, _) = resolve(&event, &HashMap::new(), &HashMap::new(), &HashMap::new());
        let (id2, _, _, _) = resolve(&event, &HashMap::new(), &HashMap::new(), &HashMap::new());
        assert_eq!(id1, id2);
    }

    #[test]
    fn build_label_sdk_and_model() {
        let event = base_event();
        let label = build_label(&event);
        assert_eq!(label, "openai-python/1.12.0 (gpt-4)");
    }

    #[test]
    fn build_label_no_sdk() {
        let mut event = base_event();
        event.agent_sdk = None;
        let label = build_label(&event);
        assert_eq!(label, "OpenAI gpt-4");
    }
}
