use busted_classifier::protocols;
use busted_classifier::protocols::anthropic;
use busted_classifier::protocols::openai;
use proptest::prelude::*;

// ===========================================================================
// OpenAI parser tests
// ===========================================================================

#[test]
fn openai_tool_calls_message() {
    let body = r#"{
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "What's the weather?"},
            {"role": "tool", "content": "The weather in SF is 65F and sunny."}
        ]
    }"#;
    let parsed = openai::parse(body).unwrap();
    assert_eq!(parsed.provider, "OpenAI");
    assert_eq!(parsed.messages.len(), 2);
    assert_eq!(parsed.messages[1].role, "tool");
    assert_eq!(
        parsed.messages[1].content,
        "The weather in SF is 65F and sunny."
    );
}

#[test]
fn openai_function_calling() {
    let body = r#"{
        "model": "gpt-4",
        "messages": [
            {"role": "assistant", "content": "Let me check.", "function_call": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}}
        ]
    }"#;
    let parsed = openai::parse(body).unwrap();
    assert_eq!(parsed.provider, "OpenAI");
    assert_eq!(parsed.messages.len(), 1);
    assert_eq!(parsed.messages[0].role, "assistant");
    assert_eq!(parsed.messages[0].content, "Let me check.");
}

#[test]
fn openai_null_content() {
    let body = r#"{
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": null}
        ]
    }"#;
    let parsed = openai::parse(body).unwrap();
    assert_eq!(parsed.messages.len(), 2);
    assert_eq!(parsed.messages[1].role, "assistant");
    assert_eq!(parsed.messages[1].content, "");
}

#[test]
fn openai_empty_messages_returns_none() {
    let body = r#"{
        "model": "gpt-4",
        "messages": []
    }"#;
    assert!(openai::parse(body).is_none());
}

#[test]
fn openai_multipart_with_image_url() {
    let body = r#"{
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "What is in this image?"},
                {"type": "image_url", "image_url": {"url": "https://example.com/cat.jpg"}}
            ]}
        ]
    }"#;
    let parsed = openai::parse(body).unwrap();
    assert_eq!(parsed.messages.len(), 1);
    // Only the text part should be extracted; image_url part is ignored
    assert_eq!(parsed.messages[0].content, "What is in this image?");
    assert_eq!(
        parsed.user_message.as_deref(),
        Some("What is in this image?")
    );
}

#[test]
fn openai_max_completion_tokens_alias() {
    let body = r#"{
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}],
        "max_completion_tokens": 2048
    }"#;
    let parsed = openai::parse(body).unwrap();
    assert_eq!(parsed.max_tokens, Some(2048));
}

#[test]
fn openai_no_model_field() {
    let body = r#"{
        "messages": [{"role": "user", "content": "hello"}]
    }"#;
    let parsed = openai::parse(body).unwrap();
    assert_eq!(parsed.provider, "OpenAI");
    assert!(parsed.model.is_none());
    assert_eq!(parsed.messages.len(), 1);
}

#[test]
fn openai_streaming_delta() {
    let body = r#"{
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    }"#;
    let parsed = openai::parse(body).unwrap();
    assert!(parsed.stream);
}

// ===========================================================================
// Anthropic parser tests
// ===========================================================================

#[test]
fn anthropic_tool_use_content_block() {
    let body = r#"{
        "model": "claude-opus-4-6",
        "messages": [
            {"role": "assistant", "content": [
                {"type": "text", "text": "I'll search for that."},
                {"type": "tool_use", "id": "toolu_123", "name": "web_search", "input": {"query": "rust programming"}}
            ]}
        ],
        "max_tokens": 1024
    }"#;
    let parsed = anthropic::parse(body).unwrap();
    assert_eq!(parsed.provider, "Anthropic");
    assert_eq!(parsed.messages.len(), 1);
    // Content should include text and tool_use name
    assert!(parsed.messages[0].content.contains("I'll search for that."));
    assert!(parsed.messages[0].content.contains("web_search"));
}

#[test]
fn anthropic_tool_result_content() {
    let body = r#"{
        "model": "claude-opus-4-6",
        "messages": [
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_123", "content": "Search returned 5 results about Rust."}
            ]}
        ],
        "max_tokens": 1024
    }"#;
    let parsed = anthropic::parse(body).unwrap();
    assert_eq!(parsed.messages.len(), 1);
    assert!(parsed.messages[0]
        .content
        .contains("Search returned 5 results about Rust."));
}

#[test]
fn anthropic_system_as_string() {
    let body = r#"{
        "model": "claude-sonnet-4-20250514",
        "system": "Be helpful and concise.",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 512
    }"#;
    let parsed = anthropic::parse(body).unwrap();
    assert_eq!(
        parsed.system_prompt.as_deref(),
        Some("Be helpful and concise.")
    );
}

#[test]
fn anthropic_system_as_blocks_array() {
    let body = r#"{
        "model": "claude-opus-4-6",
        "system": [
            {"type": "text", "text": "You are a coding assistant."},
            {"type": "text", "text": "Be concise."}
        ],
        "messages": [{"role": "user", "content": "help me"}],
        "max_tokens": 1024
    }"#;
    let parsed = anthropic::parse(body).unwrap();
    let sys = parsed.system_prompt.as_deref().unwrap();
    assert!(sys.contains("You are a coding assistant."));
    assert!(sys.contains("Be concise."));
}

#[test]
fn anthropic_empty_messages_returns_none() {
    let body = r#"{
        "model": "claude-opus-4-6",
        "messages": [],
        "max_tokens": 1024
    }"#;
    assert!(anthropic::parse(body).is_none());
}

#[test]
fn anthropic_no_model() {
    let body = r#"{
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 1024
    }"#;
    let parsed = anthropic::parse(body).unwrap();
    assert_eq!(parsed.provider, "Anthropic");
    assert!(parsed.model.is_none());
}

#[test]
fn anthropic_mixed_string_and_block_content() {
    let body = r#"{
        "model": "claude-opus-4-6",
        "messages": [
            {"role": "user", "content": "What is Rust?"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "Rust is a systems programming language."},
                {"type": "text", "text": "It focuses on safety and performance."}
            ]}
        ],
        "max_tokens": 1024
    }"#;
    let parsed = anthropic::parse(body).unwrap();
    assert_eq!(parsed.messages.len(), 2);
    // First message: plain string
    assert_eq!(parsed.messages[0].content, "What is Rust?");
    // Second message: blocks concatenated
    assert!(parsed.messages[1]
        .content
        .contains("Rust is a systems programming language."));
    assert!(parsed.messages[1]
        .content
        .contains("It focuses on safety and performance."));
}

#[test]
fn anthropic_nested_tool_result_blocks() {
    let body = r#"{
        "model": "claude-opus-4-6",
        "messages": [
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_456", "content": [
                    {"type": "text", "text": "Result line 1"},
                    {"type": "text", "text": "Result line 2"}
                ]}
            ]}
        ],
        "max_tokens": 1024
    }"#;
    let parsed = anthropic::parse(body).unwrap();
    assert_eq!(parsed.messages.len(), 1);
    assert!(parsed.messages[0].content.contains("Result line 1"));
    assert!(parsed.messages[0].content.contains("Result line 2"));
}

// ===========================================================================
// Integration tests for parse_llm_request
// ===========================================================================

#[test]
fn parse_llm_request_openai_sni() {
    let body = r#"{
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}],
        "temperature": 0.5
    }"#;
    let parsed = protocols::parse_llm_request(body, Some("api.openai.com")).unwrap();
    assert_eq!(parsed.provider, "OpenAI");
    assert_eq!(parsed.model.as_deref(), Some("gpt-4o"));
    assert_eq!(parsed.temperature, Some(0.5));
}

#[test]
fn parse_llm_request_anthropic_sni() {
    let body = r#"{
        "model": "claude-opus-4-6",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 1024
    }"#;
    let parsed = protocols::parse_llm_request(body, Some("api.anthropic.com")).unwrap();
    assert_eq!(parsed.provider, "Anthropic");
    assert_eq!(parsed.model.as_deref(), Some("claude-opus-4-6"));
}

#[test]
fn parse_llm_request_no_sni() {
    // With no SNI hint, Anthropic is tried first, then OpenAI.
    // This body is valid for both parsers, so Anthropic should win.
    let body = r#"{
        "model": "some-model",
        "messages": [{"role": "user", "content": "test"}],
        "max_tokens": 512
    }"#;
    let parsed = protocols::parse_llm_request(body, None).unwrap();
    assert_eq!(parsed.provider, "Anthropic");
}

#[test]
fn parse_llm_request_non_llm_body() {
    let body = r#"{"status": "ok", "data": [1, 2, 3]}"#;
    assert!(protocols::parse_llm_request(body, None).is_none());
}

// ===========================================================================
// Property tests: parsers never panic on arbitrary input
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn openai_parse_never_panics(data in "\\PC{0,1024}") {
        let _ = openai::parse(&data);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn anthropic_parse_never_panics(data in "\\PC{0,1024}") {
        let _ = anthropic::parse(&data);
    }
}
