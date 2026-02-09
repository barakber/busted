//! Protocol-specific parsers for LLM API request/response bodies.
//!
//! Each submodule understands the JSON schema of a specific LLM provider's API
//! and can extract structured fields (messages, model, system prompt, etc.)
//! from the raw request body. This enables fine-grained policy enforcement
//! on individual message contents rather than raw string matching.

pub mod anthropic;
pub mod openai;

use serde::{Deserialize, Serialize};

/// A parsed LLM API request with provider-independent fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmRequestParsed {
    /// Which provider's format was detected ("Anthropic", "OpenAI", etc.)
    pub provider: String,
    /// Model identifier (e.g., "claude-opus-4-6", "gpt-4o")
    pub model: Option<String>,
    /// Whether streaming is requested
    pub stream: bool,
    /// System prompt / instructions (if present)
    pub system_prompt: Option<String>,
    /// Conversation messages in order
    pub messages: Vec<LlmMessage>,
    /// The most recent user message text (convenience field for policy rules)
    pub user_message: Option<String>,
    /// Temperature parameter
    pub temperature: Option<f64>,
    /// Max tokens / max_completion_tokens
    pub max_tokens: Option<u64>,
}

/// A single message in the conversation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmMessage {
    /// Role: "user", "assistant", "system", "tool"
    pub role: String,
    /// Flattened text content (all text parts concatenated)
    pub content: String,
}

/// Try to parse a request body as a known LLM provider format.
///
/// Tries Anthropic first (looks for `"type":"text"` content blocks),
/// then OpenAI (looks for `"messages"` with string content).
/// Returns `None` if the body doesn't match any known format.
pub fn parse_llm_request(body: &str, sni_hint: Option<&str>) -> Option<LlmRequestParsed> {
    // Use SNI hint to prioritize the right parser
    if let Some(sni) = sni_hint {
        let sni_lower = sni.to_lowercase();
        if sni_lower.contains("anthropic") {
            if let Some(r) = anthropic::parse(body) {
                return Some(r);
            }
            return openai::parse(body);
        }
        if sni_lower.contains("openai") {
            if let Some(r) = openai::parse(body) {
                return Some(r);
            }
            return anthropic::parse(body);
        }
    }

    // No hint — try both
    anthropic::parse(body).or_else(|| openai::parse(body))
}
