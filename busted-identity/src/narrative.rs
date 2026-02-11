use crate::action::{Action, ProviderTag};
use crate::identity::ResolvedIdentity;
use crate::timeline::Timeline;

/// Generate a rule-based narrative from identity state and timeline.
pub fn generate(identity: &ResolvedIdentity, timeline: &Timeline) -> String {
    if timeline.is_empty() {
        return format!("{}: no activity recorded", identity.label);
    }

    let mut llm_calls = 0u32;
    let mut mcp_calls = 0u32;
    let mut streaming = 0u32;
    let mut pii_events = 0u32;
    let mut primary_provider = ProviderTag::Other;

    for entry in timeline.iter() {
        match &entry.action {
            Action::LlmCall {
                provider,
                streaming: s,
                ..
            } => {
                llm_calls += 1;
                if *s {
                    streaming += 1;
                }
                if *provider != ProviderTag::Other {
                    primary_provider = *provider;
                }
            }
            Action::McpCall { .. } => {
                mcp_calls += 1;
            }
            Action::LlmStreamRecv { provider } => {
                streaming += 1;
                if *provider != ProviderTag::Other {
                    primary_provider = *provider;
                }
            }
            Action::PiiDetected => {
                pii_events += 1;
            }
            Action::Connect { provider } => {
                if *provider != ProviderTag::Other {
                    primary_provider = *provider;
                }
            }
            Action::Disconnect => {}
        }
    }

    let mut parts = Vec::new();

    if llm_calls > 0 {
        let mut s = format!(
            "{} {} call{}",
            llm_calls,
            primary_provider,
            plural(llm_calls)
        );
        if streaming > 0 {
            s.push_str(&format!(" ({} streaming)", streaming));
        }
        parts.push(s);
    }

    if mcp_calls > 0 {
        parts.push(format!("{} MCP tool{}", mcp_calls, plural(mcp_calls)));
    }

    if pii_events > 0 {
        parts.push(format!("{} PII event{}", pii_events, plural(pii_events)));
    }

    if parts.is_empty() {
        return format!(
            "{}: {} event{}",
            identity.label,
            timeline.len(),
            plural(timeline.len() as u32)
        );
    }

    format!("{} agent: {}", identity.label, parts.join(", "))
}

fn plural(n: u32) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{McpCategoryTag, ProviderTag};
    use crate::identity::TypeKey;

    fn test_identity() -> ResolvedIdentity {
        ResolvedIdentity {
            identity_id: 1,
            type_key: TypeKey {
                signature_hash: 0,
                sdk_hash: 0,
                model_hash: 0,
            },
            first_seen: "12:00:00".into(),
            last_seen: "12:01:00".into(),
            event_count: 0,
            label: "openai-python (gpt-4)".into(),
            active_instances: vec![],
            providers: vec![],
        }
    }

    #[test]
    fn empty_timeline() {
        let id = test_identity();
        let tl = Timeline::new(4);
        let n = generate(&id, &tl);
        assert!(n.contains("no activity"));
    }

    #[test]
    fn llm_only() {
        let id = test_identity();
        let mut tl = Timeline::new(10);
        for _ in 0..5 {
            tl.push(
                "t".into(),
                Action::LlmCall {
                    provider: ProviderTag::OpenAI,
                    model_hash: 42,
                    streaming: false,
                },
            );
        }
        let n = generate(&id, &tl);
        assert!(n.contains("5 OpenAI calls"), "got: {n}");
    }

    #[test]
    fn mixed_timeline() {
        let id = test_identity();
        let mut tl = Timeline::new(10);
        tl.push(
            "t".into(),
            Action::LlmCall {
                provider: ProviderTag::Anthropic,
                model_hash: 0,
                streaming: true,
            },
        );
        tl.push(
            "t".into(),
            Action::McpCall {
                category: McpCategoryTag::Tools,
                method_hash: 0,
            },
        );
        tl.push("t".into(), Action::PiiDetected);
        let n = generate(&id, &tl);
        assert!(n.contains("1 Anthropic call"), "got: {n}");
        assert!(n.contains("1 streaming"), "got: {n}");
        assert!(n.contains("1 MCP tool"), "got: {n}");
        assert!(n.contains("1 PII event"), "got: {n}");
    }

    #[test]
    fn streaming_count() {
        let id = test_identity();
        let mut tl = Timeline::new(10);
        for i in 0..3 {
            tl.push(
                "t".into(),
                Action::LlmCall {
                    provider: ProviderTag::OpenAI,
                    model_hash: 0,
                    streaming: i < 2,
                },
            );
        }
        let n = generate(&id, &tl);
        assert!(n.contains("3 OpenAI calls"), "got: {n}");
        assert!(n.contains("2 streaming"), "got: {n}");
    }
}
