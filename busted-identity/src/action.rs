use busted_types::agentic::{AgenticAction, BustedEvent, NetworkEventKind};
use serde::{Deserialize, Serialize};

/// Compact provider tag — no heap allocation.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Compact, stack-allocated action extracted from a BustedEvent.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Extract an action from a BustedEvent, if interesting.
    pub fn from_busted_event(event: &BustedEvent) -> Option<Self> {
        match &event.action {
            AgenticAction::PiiDetected { .. } => Some(Action::PiiDetected),

            AgenticAction::McpRequest {
                method, category, ..
            } => {
                let cat = category
                    .as_deref()
                    .map(McpCategoryTag::parse)
                    .unwrap_or(McpCategoryTag::Other);
                let method_hash = fnv1a_32(method.as_bytes());
                Some(Action::McpCall {
                    category: cat,
                    method_hash,
                })
            }

            AgenticAction::McpResponse { method, .. } => {
                let method_hash = fnv1a_32(method.as_bytes());
                Some(Action::McpCall {
                    category: McpCategoryTag::Other,
                    method_hash,
                })
            }

            AgenticAction::Prompt {
                provider, stream, ..
            } => {
                let provider_tag = ProviderTag::parse(provider);
                let model_hash = event.model_hash().unwrap_or(0);
                Some(Action::LlmCall {
                    provider: provider_tag,
                    model_hash,
                    streaming: *stream,
                })
            }

            AgenticAction::Response { provider, .. } => {
                let provider_tag = ProviderTag::parse(provider);
                Some(Action::LlmStreamRecv {
                    provider: provider_tag,
                })
            }

            AgenticAction::ToolCall { provider, .. } => {
                let provider_tag = ProviderTag::parse(provider);
                Some(Action::LlmCall {
                    provider: provider_tag,
                    model_hash: 0,
                    streaming: false,
                })
            }

            AgenticAction::ToolResult { .. } => None,

            AgenticAction::Network { kind, provider, .. } => match kind {
                NetworkEventKind::Connect => provider.as_deref().map(|p| Action::Connect {
                    provider: ProviderTag::parse(p),
                }),
                NetworkEventKind::Close => {
                    if provider.is_some() {
                        Some(Action::Disconnect)
                    } else {
                        None
                    }
                }
                _ => None,
            },

            AgenticAction::FileAccess { .. } => None,
            AgenticAction::FileData { .. } => None,
        }
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
    use busted_types::agentic::ProcessInfo;

    fn network_event() -> BustedEvent {
        BustedEvent {
            timestamp: "12:00:00.000".into(),
            process: ProcessInfo {
                pid: 1234,
                uid: 1000,
                name: "python3".into(),
                container_id: String::new(),
                cgroup_id: 0,
                pod_name: None,
                pod_namespace: None,
                service_account: None,
            },
            session_id: "1234:net".into(),
            identity: None,
            policy: None,
            action: AgenticAction::Network {
                kind: NetworkEventKind::Connect,
                src_ip: "10.0.0.1".into(),
                src_port: 54321,
                dst_ip: "104.18.1.1".into(),
                dst_port: 443,
                bytes: 512,
                sni: None,
                provider: None,
            },
        }
    }

    #[test]
    fn bare_network_event_returns_none() {
        let event = network_event();
        assert!(Action::from_busted_event(&event).is_none());
    }

    #[test]
    fn llm_call_extracted() {
        let mut event = network_event();
        event.action = AgenticAction::Prompt {
            provider: "OpenAI".into(),
            model: Some("gpt-4".into()),
            user_message: None,
            system_prompt: None,
            stream: true,
            sdk: None,
            bytes: 512,
            sni: None,
            endpoint: None,
            fingerprint: None,
            pii_detected: None,
            confidence: None,
            sdk_hash: None,
            model_hash: Some(12345),
        };
        let action = Action::from_busted_event(&event).unwrap();
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
        let mut event = network_event();
        event.action = AgenticAction::McpRequest {
            method: "tools/call".into(),
            category: Some("Tools".into()),
            params_preview: None,
        };
        let action = Action::from_busted_event(&event).unwrap();
        match action {
            Action::McpCall { category, .. } => {
                assert_eq!(category, McpCategoryTag::Tools);
            }
            _ => panic!("expected McpCall"),
        }
    }

    #[test]
    fn pii_detected() {
        let mut event = network_event();
        event.action = AgenticAction::PiiDetected {
            direction: "write".into(),
            pii_types: Some(vec!["email".into()]),
        };
        let action = Action::from_busted_event(&event).unwrap();
        assert!(matches!(action, Action::PiiDetected));
    }

    #[test]
    fn connect_with_provider() {
        let mut event = network_event();
        event.action = AgenticAction::Network {
            kind: NetworkEventKind::Connect,
            src_ip: "10.0.0.1".into(),
            src_port: 54321,
            dst_ip: "104.18.1.1".into(),
            dst_port: 443,
            bytes: 0,
            sni: None,
            provider: Some("Anthropic".into()),
        };
        let action = Action::from_busted_event(&event).unwrap();
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
    fn response_extracted() {
        let mut event = network_event();
        event.action = AgenticAction::Response {
            provider: "OpenAI".into(),
            model: None,
            bytes: 1024,
            sni: None,
            confidence: None,
        };
        let action = Action::from_busted_event(&event).unwrap();
        assert!(matches!(action, Action::LlmStreamRecv { .. }));
    }
}
