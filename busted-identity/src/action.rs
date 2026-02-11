use busted_types::processed::ProcessedEvent;

/// Compact provider tag — no heap allocation.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderTag {
    OpenAI,
    Anthropic,
    Google,
    Azure,
    AwsBedrock,
    Cohere,
    Mistral,
    Groq,
    Together,
    DeepSeek,
    Perplexity,
    Ollama,
    Other,
}

impl ProviderTag {
    /// Parse a provider string into a tag.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "openai" => Self::OpenAI,
            "anthropic" => Self::Anthropic,
            "google" => Self::Google,
            "azure" => Self::Azure,
            "aws bedrock" | "aws" | "bedrock" => Self::AwsBedrock,
            "cohere" => Self::Cohere,
            "mistral" => Self::Mistral,
            "groq" => Self::Groq,
            "together" => Self::Together,
            "deepseek" => Self::DeepSeek,
            "perplexity" => Self::Perplexity,
            "ollama" => Self::Ollama,
            _ => Self::Other,
        }
    }

    /// Convert back to a display string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpenAI => "OpenAI",
            Self::Anthropic => "Anthropic",
            Self::Google => "Google",
            Self::Azure => "Azure",
            Self::AwsBedrock => "AWS Bedrock",
            Self::Cohere => "Cohere",
            Self::Mistral => "Mistral",
            Self::Groq => "Groq",
            Self::Together => "Together",
            Self::DeepSeek => "DeepSeek",
            Self::Perplexity => "Perplexity",
            Self::Ollama => "Ollama",
            Self::Other => "Other",
        }
    }
}

impl std::fmt::Display for ProviderTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Compact MCP category tag.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpCategoryTag {
    Tools,
    Resources,
    Prompts,
    Lifecycle,
    Completion,
    Logging,
    Other,
}

impl McpCategoryTag {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "tools" | "tool_use" => Self::Tools,
            "resources" => Self::Resources,
            "prompts" => Self::Prompts,
            "lifecycle" => Self::Lifecycle,
            "completion" => Self::Completion,
            "logging" => Self::Logging,
            _ => Self::Other,
        }
    }
}

/// Compact, stack-allocated action extracted from a ProcessedEvent.
#[derive(Debug, Clone)]
pub enum Action {
    LlmCall {
        provider: ProviderTag,
        model_hash: u32,
        streaming: bool,
    },
    McpCall {
        category: McpCategoryTag,
        method_hash: u32,
    },
    LlmStreamRecv {
        provider: ProviderTag,
    },
    PiiDetected,
    Connect {
        provider: ProviderTag,
    },
    Disconnect,
}

impl Action {
    /// Extract an action from a ProcessedEvent, if interesting.
    pub fn from_processed_event(event: &ProcessedEvent) -> Option<Self> {
        // PII detected takes priority
        if event.pii_detected == Some(true) {
            return Some(Action::PiiDetected);
        }

        // MCP call
        if event.mcp_method.is_some() {
            let category = event
                .mcp_category
                .as_deref()
                .map(McpCategoryTag::parse)
                .unwrap_or(McpCategoryTag::Other);
            let method_hash = event
                .mcp_method
                .as_deref()
                .map(|m| fnv1a_32(m.as_bytes()))
                .unwrap_or(0);
            return Some(Action::McpCall {
                category,
                method_hash,
            });
        }

        // LLM stream receive
        if event.content_class.as_deref() == Some("LlmStream") {
            let provider = event
                .llm_provider
                .as_deref()
                .or(event.provider.as_deref())
                .map(ProviderTag::parse)
                .unwrap_or(ProviderTag::Other);
            return Some(Action::LlmStreamRecv { provider });
        }

        // LLM API call (TLS data write = outbound request)
        if event.content_class.as_deref() == Some("LlmApi")
            || event.llm_provider.is_some()
            || event.llm_model.is_some()
        {
            let provider = event
                .llm_provider
                .as_deref()
                .or(event.provider.as_deref())
                .map(ProviderTag::parse)
                .unwrap_or(ProviderTag::Other);
            let model_hash = event.agent_model_hash.unwrap_or(0);
            let streaming = event.llm_stream.unwrap_or(false);
            return Some(Action::LlmCall {
                provider,
                model_hash,
                streaming,
            });
        }

        // TCP connect to a known provider
        if event.event_type == "TCP_CONNECT" {
            if let Some(ref prov) = event.provider {
                return Some(Action::Connect {
                    provider: ProviderTag::parse(prov),
                });
            }
        }

        // Connection closed
        if event.event_type == "CONNECTION_CLOSED" && event.provider.is_some() {
            return Some(Action::Disconnect);
        }

        None
    }

    /// Short label for display.
    pub fn label(&self) -> &'static str {
        match self {
            Action::LlmCall { .. } => "LlmCall",
            Action::McpCall { .. } => "McpCall",
            Action::LlmStreamRecv { .. } => "LlmStreamRecv",
            Action::PiiDetected => "PiiDetected",
            Action::Connect { .. } => "Connect",
            Action::Disconnect => "Disconnect",
        }
    }
}

/// FNV-1a 32-bit hash (local copy to avoid classifier dependency).
fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_event() -> ProcessedEvent {
        ProcessedEvent {
            event_type: "TCP_CONNECT".into(),
            timestamp: "12:00:00.000".into(),
            pid: 1234,
            uid: 1000,
            process_name: "python3".into(),
            src_ip: "10.0.0.1".into(),
            src_port: 54321,
            dst_ip: "104.18.1.1".into(),
            dst_port: 443,
            bytes: 512,
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
    fn bare_event_returns_none() {
        let event = base_event();
        assert!(Action::from_processed_event(&event).is_none());
    }

    #[test]
    fn llm_call_extracted() {
        let mut event = base_event();
        event.llm_provider = Some("OpenAI".into());
        event.llm_model = Some("gpt-4".into());
        event.agent_model_hash = Some(12345);
        event.llm_stream = Some(true);
        let action = Action::from_processed_event(&event).unwrap();
        match action {
            Action::LlmCall {
                provider,
                model_hash,
                streaming,
            } => {
                assert_eq!(provider, ProviderTag::OpenAI);
                assert_eq!(model_hash, 12345);
                assert!(streaming);
            }
            _ => panic!("expected LlmCall"),
        }
    }

    #[test]
    fn mcp_call_extracted() {
        let mut event = base_event();
        event.mcp_method = Some("tools/call".into());
        event.mcp_category = Some("Tools".into());
        let action = Action::from_processed_event(&event).unwrap();
        match action {
            Action::McpCall { category, .. } => {
                assert_eq!(category, McpCategoryTag::Tools);
            }
            _ => panic!("expected McpCall"),
        }
    }

    #[test]
    fn pii_takes_priority() {
        let mut event = base_event();
        event.pii_detected = Some(true);
        event.llm_provider = Some("OpenAI".into());
        let action = Action::from_processed_event(&event).unwrap();
        assert!(matches!(action, Action::PiiDetected));
    }

    #[test]
    fn connect_with_provider() {
        let mut event = base_event();
        event.event_type = "TCP_CONNECT".into();
        event.provider = Some("Anthropic".into());
        let action = Action::from_processed_event(&event).unwrap();
        match action {
            Action::Connect { provider } => {
                assert_eq!(provider, ProviderTag::Anthropic);
            }
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn provider_tag_roundtrip() {
        for tag in [
            ProviderTag::OpenAI,
            ProviderTag::Anthropic,
            ProviderTag::Google,
            ProviderTag::Azure,
            ProviderTag::AwsBedrock,
            ProviderTag::Groq,
            ProviderTag::Other,
        ] {
            let s = tag.as_str();
            let back = ProviderTag::parse(s);
            assert_eq!(tag, back, "roundtrip failed for {s}");
        }
    }

    #[test]
    fn llm_stream_recv_extracted() {
        let mut event = base_event();
        event.content_class = Some("LlmStream".into());
        event.provider = Some("OpenAI".into());
        let action = Action::from_processed_event(&event).unwrap();
        assert!(matches!(action, Action::LlmStreamRecv { .. }));
    }
}
