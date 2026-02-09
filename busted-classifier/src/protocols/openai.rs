//! Parser for the OpenAI Chat Completions API format.
//!
//! OpenAI's `/v1/chat/completions` endpoint uses messages with string content
//! or multipart content arrays:
//!
//! ```json
//! {
//!   "model": "gpt-4o",
//!   "messages": [
//!     {"role": "system", "content": "You are helpful."},
//!     {"role": "user", "content": "hello"},
//!     {"role": "user", "content": [{"type": "text", "text": "hello"}]}
//!   ]
//! }
//! ```
//!
//! Also covers compatible APIs: Azure OpenAI, Groq, Together, Mistral, DeepSeek, etc.

use super::{LlmMessage, LlmRequestParsed};
use serde::Deserialize;

#[derive(Deserialize)]
struct OpenAiRequest {
    model: Option<String>,
    #[serde(default)]
    stream: bool,
    messages: Option<Vec<OpenAiMessage>>,
    temperature: Option<f64>,
    max_tokens: Option<u64>,
    max_completion_tokens: Option<u64>,
}

#[derive(Deserialize)]
struct OpenAiMessage {
    role: String,
    content: Option<ContentField>,
}

/// Content can be a plain string or an array of content parts (vision/multimodal).
#[derive(Deserialize)]
#[serde(untagged)]
enum ContentField {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Deserialize)]
struct ContentPart {
    #[serde(rename = "type")]
    part_type: Option<String>,
    text: Option<String>,
}

impl ContentField {
    fn flatten(&self) -> String {
        match self {
            ContentField::Text(s) => s.clone(),
            ContentField::Parts(parts) => parts
                .iter()
                .filter_map(|p| {
                    if p.part_type.as_deref() == Some("text") {
                        p.text.clone()
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

/// Try to parse a JSON body as an OpenAI Chat Completions API request.
pub fn parse(body: &str) -> Option<LlmRequestParsed> {
    let req: OpenAiRequest = serde_json::from_str(body).ok()?;

    let messages_raw = req.messages?;
    if messages_raw.is_empty() {
        return None;
    }

    // Extract system prompt from system messages
    let system_prompt: Option<String> = {
        let parts: Vec<String> = messages_raw
            .iter()
            .filter(|m| m.role == "system")
            .filter_map(|m| m.content.as_ref().map(|c| c.flatten()))
            .collect();
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("\n"))
        }
    };

    let messages: Vec<LlmMessage> = messages_raw
        .iter()
        .map(|m| LlmMessage {
            role: m.role.clone(),
            content: m.content.as_ref().map(|c| c.flatten()).unwrap_or_default(),
        })
        .collect();

    // Find the last user message
    let user_message = messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.clone());

    let max_tokens = req.max_tokens.or(req.max_completion_tokens);

    Some(LlmRequestParsed {
        provider: "OpenAI".to_string(),
        model: req.model,
        stream: req.stream,
        system_prompt,
        messages,
        user_message,
        temperature: req.temperature,
        max_tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let body = r#"{
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "What is 2+2?"}
            ],
            "temperature": 0.7
        }"#;
        let parsed = parse(body).unwrap();
        assert_eq!(parsed.provider, "OpenAI");
        assert_eq!(parsed.model.as_deref(), Some("gpt-4o"));
        assert_eq!(parsed.messages.len(), 2);
        assert_eq!(parsed.system_prompt.as_deref(), Some("You are helpful."));
        assert_eq!(parsed.user_message.as_deref(), Some("What is 2+2?"));
        assert_eq!(parsed.temperature, Some(0.7));
    }

    #[test]
    fn test_parse_multipart_content() {
        let body = r#"{
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "Describe this image"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
                ]}
            ]
        }"#;
        let parsed = parse(body).unwrap();
        assert_eq!(parsed.user_message.as_deref(), Some("Describe this image"));
    }

    #[test]
    fn test_parse_streaming() {
        let body = r#"{
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true,
            "max_completion_tokens": 4096
        }"#;
        let parsed = parse(body).unwrap();
        assert!(parsed.stream);
        assert_eq!(parsed.max_tokens, Some(4096));
    }

    #[test]
    fn test_parse_multi_turn() {
        let body = r#"{
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "Be brief"},
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "Hello!"},
                {"role": "user", "content": "im berko"}
            ]
        }"#;
        let parsed = parse(body).unwrap();
        assert_eq!(parsed.messages.len(), 4);
        assert_eq!(parsed.user_message.as_deref(), Some("im berko"));
    }

    #[test]
    fn test_parse_not_openai() {
        let body = r#"{"random": "data"}"#;
        assert!(parse(body).is_none());
    }
}
