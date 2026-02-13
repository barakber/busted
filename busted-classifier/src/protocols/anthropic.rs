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

use super::{LlmMessage, LlmRequestParsed, LlmResponseParsed, ToolCallParsed, ToolResultParsed};
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
    block_type: Option<String>,
    text: Option<String>,
    // tool_use blocks
    name: Option<String>,
    id: Option<String>,
    input: Option<serde_json::Value>,
    // tool_result blocks
    tool_use_id: Option<String>,
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

    // Extract tool_result blocks from messages
    let mut tool_results = Vec::new();
    for msg in &messages_raw {
        if let ContentField::Blocks(blocks) = &msg.content {
            for block in blocks {
                if block.block_type.as_deref() == Some("tool_result") {
                    let output = block.content.as_ref().map(|c| {
                        let text = match c {
                            ToolResultContent::Text(t) => t.clone(),
                            ToolResultContent::Blocks(inner) => inner
                                .iter()
                                .filter_map(|b| b.text.as_deref())
                                .collect::<Vec<_>>()
                                .join("\n"),
                        };
                        truncate_preview(&text, 200)
                    });
                    tool_results.push(ToolResultParsed {
                        name: block.name.clone(),
                        tool_use_id: block.tool_use_id.clone(),
                        output_preview: output,
                    });
                }
            }
        }
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
        tool_results,
    })
}

// ---- Response parsing ----

/// Raw Anthropic response (serde model).
#[derive(Deserialize)]
struct AnthropicResponse {
    model: Option<String>,
    content: Option<Vec<ContentBlock>>,
    #[serde(rename = "type")]
    response_type: Option<String>,
}

/// Try to parse a JSON body as an Anthropic Messages API response.
pub fn parse_response(body: &str) -> Option<LlmResponseParsed> {
    let resp: AnthropicResponse = serde_json::from_str(body).ok()?;

    // Anthropic responses have type "message" and a content array
    if resp.response_type.as_deref() != Some("message") && resp.content.is_none() {
        return None;
    }

    let blocks = resp.content.unwrap_or_default();

    let mut text_parts = Vec::new();
    let mut tool_calls = Vec::new();

    for block in &blocks {
        match block.block_type.as_deref() {
            Some("text") => {
                if let Some(ref t) = block.text {
                    text_parts.push(t.as_str());
                }
            }
            Some("tool_use") => {
                if let Some(ref name) = block.name {
                    let input_json = block.input.as_ref().map(|v| v.to_string());
                    tool_calls.push(ToolCallParsed {
                        name: name.clone(),
                        input_json,
                        tool_call_id: block.id.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    let text = if text_parts.is_empty() {
        None
    } else {
        Some(text_parts.join("\n"))
    };

    Some(LlmResponseParsed {
        provider: "Anthropic".to_string(),
        model: resp.model,
        tool_calls,
        text,
    })
}

/// Truncate a string to `max_len` characters, appending "..." if truncated.
fn truncate_preview(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
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
