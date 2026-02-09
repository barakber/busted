//! Parser for the Anthropic Messages API format.
//!
//! Anthropic's `/v1/messages` endpoint uses a distinct JSON schema where
//! message content can be either a plain string or an array of typed blocks:
//!
//! ```json
//! {
//!   "model": "claude-opus-4-6",
//!   "system": [{"type": "text", "text": "..."}],
//!   "messages": [
//!     {"role": "user", "content": "hello"},
//!     {"role": "user", "content": [{"type": "text", "text": "hello"}]}
//!   ]
//! }
//! ```

use super::{LlmMessage, LlmRequestParsed};
use serde::Deserialize;

/// Raw Anthropic request (serde model for parsing).
#[derive(Deserialize)]
struct AnthropicRequest {
    model: Option<String>,
    #[serde(default)]
    stream: bool,
    system: Option<SystemContent>,
    messages: Option<Vec<AnthropicMessage>>,
    temperature: Option<f64>,
    max_tokens: Option<u64>,
}

#[derive(Deserialize)]
struct AnthropicMessage {
    role: String,
    content: ContentField,
}

/// Content can be a plain string or an array of content blocks.
#[derive(Deserialize)]
#[serde(untagged)]
enum ContentField {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

/// System prompt can be a plain string or array of text blocks.
#[derive(Deserialize)]
#[serde(untagged)]
enum SystemContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    block_type: Option<String>,
    text: Option<String>,
    // tool_use blocks have name, id, input — we flatten them to text
    name: Option<String>,
    // tool_result blocks have content
    content: Option<ToolResultContent>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ToolResultContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

impl ContentField {
    fn flatten(&self) -> String {
        match self {
            ContentField::Text(s) => s.clone(),
            ContentField::Blocks(blocks) => {
                let mut parts = Vec::new();
                for block in blocks {
                    if let Some(ref text) = block.text {
                        parts.push(text.as_str());
                    }
                    if let Some(ref name) = block.name {
                        parts.push(name.as_str());
                    }
                    if let Some(ref content) = block.content {
                        match content {
                            ToolResultContent::Text(t) => parts.push(t.as_str()),
                            ToolResultContent::Blocks(inner) => {
                                for b in inner {
                                    if let Some(ref t) = b.text {
                                        parts.push(t.as_str());
                                    }
                                }
                            }
                        }
                    }
                }
                parts.join("\n")
            }
        }
    }
}

impl SystemContent {
    fn flatten(&self) -> String {
        match self {
            SystemContent::Text(s) => s.clone(),
            SystemContent::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| b.text.as_deref())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

/// Try to parse a JSON body as an Anthropic Messages API request.
pub fn parse(body: &str) -> Option<LlmRequestParsed> {
    let req: AnthropicRequest = serde_json::from_str(body).ok()?;

    // Require at least messages to be present
    let messages_raw = req.messages?;
    if messages_raw.is_empty() {
        return None;
    }

    let messages: Vec<LlmMessage> = messages_raw
        .iter()
        .map(|m| LlmMessage {
            role: m.role.clone(),
            content: m.content.flatten(),
        })
        .collect();

    // Find the last user message
    let user_message = messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.clone());

    let system_prompt = req.system.map(|s| s.flatten());

    Some(LlmRequestParsed {
        provider: "Anthropic".to_string(),
        model: req.model,
        stream: req.stream,
        system_prompt,
        messages,
        user_message,
        temperature: req.temperature,
        max_tokens: req.max_tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_string_content() {
        let body = r#"{
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "hello berko"}
            ],
            "max_tokens": 1024
        }"#;
        let parsed = parse(body).unwrap();
        assert_eq!(parsed.provider, "Anthropic");
        assert_eq!(parsed.model.as_deref(), Some("claude-opus-4-6"));
        assert_eq!(parsed.messages.len(), 1);
        assert_eq!(parsed.messages[0].content, "hello berko");
        assert_eq!(parsed.user_message.as_deref(), Some("hello berko"));
        assert_eq!(parsed.max_tokens, Some(1024));
    }

    #[test]
    fn test_parse_content_blocks() {
        let body = r#"{
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "system reminder"},
                    {"type": "text", "text": "hi I'm berko"}
                ]}
            ]
        }"#;
        let parsed = parse(body).unwrap();
        assert_eq!(parsed.messages.len(), 1);
        assert!(parsed.messages[0].content.contains("berko"));
        assert!(parsed.user_message.unwrap().contains("berko"));
    }

    #[test]
    fn test_parse_system_prompt() {
        let body = r#"{
            "model": "claude-sonnet-4-5-20250929",
            "system": [{"type": "text", "text": "You are Claude Code."}],
            "messages": [
                {"role": "user", "content": "hello"}
            ]
        }"#;
        let parsed = parse(body).unwrap();
        assert_eq!(
            parsed.system_prompt.as_deref(),
            Some("You are Claude Code.")
        );
    }

    #[test]
    fn test_parse_system_string() {
        let body = r#"{
            "model": "claude-3-haiku",
            "system": "Be helpful",
            "messages": [{"role": "user", "content": "hi"}]
        }"#;
        let parsed = parse(body).unwrap();
        assert_eq!(parsed.system_prompt.as_deref(), Some("Be helpful"));
    }

    #[test]
    fn test_parse_multi_turn() {
        let body = r#"{
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "hi im berko"},
                {"role": "assistant", "content": "Hi Berko!"},
                {"role": "user", "content": "hey im berko"}
            ],
            "stream": true
        }"#;
        let parsed = parse(body).unwrap();
        assert!(parsed.stream);
        assert_eq!(parsed.messages.len(), 3);
        assert_eq!(parsed.user_message.as_deref(), Some("hey im berko"));
    }

    #[test]
    fn test_parse_not_anthropic() {
        // OpenAI-style: plain string content without Anthropic-specific model names
        // This should still parse since the format is compatible
        let body = r#"{"not_an_api": true}"#;
        assert!(parse(body).is_none());
    }
}
