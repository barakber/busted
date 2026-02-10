use busted_classifier::http;
use busted_classifier::json;
use busted_classifier::llm;

// ---------------------------------------------------------------------------
// All endpoint rules produce correct provider (host-specific)
// ---------------------------------------------------------------------------

#[test]
fn openai_chat_completions() {
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
    assert_eq!(info.endpoint, "chat_completions");
}

#[test]
fn openai_completions() {
    let raw = b"POST /v1/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
    assert_eq!(info.endpoint, "completions");
}

#[test]
fn openai_embeddings() {
    let raw = b"POST /v1/embeddings HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
    assert_eq!(info.endpoint, "embeddings");
}

#[test]
fn openai_images() {
    let raw = b"POST /v1/images/generations HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
    assert_eq!(info.endpoint, "images");
}

#[test]
fn openai_audio() {
    let raw = b"POST /v1/audio/transcriptions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
    assert_eq!(info.endpoint, "audio");
}

#[test]
fn openai_models() {
    let raw = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
    assert_eq!(info.endpoint, "models");
}

#[test]
fn anthropic_messages() {
    let raw = b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Anthropic");
    assert_eq!(info.endpoint, "messages");
}

#[test]
fn anthropic_complete() {
    let raw = b"POST /v1/complete HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Anthropic");
    assert_eq!(info.endpoint, "complete");
}

#[test]
fn google_gemini_v1beta() {
    let raw = b"POST /v1beta/models/gemini-pro:generateContent HTTP/1.1\r\nHost: generativelanguage.googleapis.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Google");
    assert_eq!(info.endpoint, "gemini");
}

#[test]
fn google_gemini_v1() {
    let raw = b"POST /v1/models/gemini-pro:generateContent HTTP/1.1\r\nHost: generativelanguage.googleapis.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Google");
}

#[test]
fn google_vertex() {
    let raw = b"POST /v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:predict HTTP/1.1\r\nHost: aiplatform.googleapis.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Google");
    assert_eq!(info.endpoint, "vertex");
}

#[test]
fn azure_openai() {
    let raw = b"POST /openai/deployments/gpt-4/chat/completions HTTP/1.1\r\nHost: my-resource.openai.azure.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Azure");
}

#[test]
fn aws_bedrock() {
    let raw = b"POST /model/anthropic.claude-v2/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-1.amazonaws.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "AWS Bedrock");
}

#[test]
fn ollama_chat() {
    let raw = b"POST /api/chat HTTP/1.1\r\nHost: localhost:11434\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Ollama");
    assert_eq!(info.endpoint, "chat");
}

#[test]
fn ollama_generate() {
    let raw = b"POST /api/generate HTTP/1.1\r\nHost: localhost:11434\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Ollama");
    assert_eq!(info.endpoint, "generate");
}

#[test]
fn ollama_embeddings() {
    let raw = b"POST /api/embeddings HTTP/1.1\r\nHost: localhost:11434\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Ollama");
    assert_eq!(info.endpoint, "embeddings");
}

#[test]
fn cohere_chat() {
    let raw = b"POST /v1/chat HTTP/1.1\r\nHost: api.cohere.ai\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Cohere");
}

#[test]
fn cohere_generate() {
    let raw = b"POST /v1/generate HTTP/1.1\r\nHost: api.cohere.ai\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Cohere");
    assert_eq!(info.endpoint, "generate");
}

#[test]
fn cohere_embed() {
    let raw = b"POST /v1/embed HTTP/1.1\r\nHost: api.cohere.ai\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Cohere");
    assert_eq!(info.endpoint, "embed");
}

#[test]
fn mistral_chat() {
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.mistral.ai\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Mistral");
}

#[test]
fn groq_chat() {
    let raw = b"POST /openai/v1/chat/completions HTTP/1.1\r\nHost: api.groq.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Groq");
}

#[test]
fn together_chat() {
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.together.xyz\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Together");
}

#[test]
fn deepseek_chat() {
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.deepseek.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "DeepSeek");
}

#[test]
fn perplexity_chat() {
    let raw = b"POST /chat/completions HTTP/1.1\r\nHost: api.perplexity.ai\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Perplexity");
}

// ---------------------------------------------------------------------------
// Host-specific rules override path-only fallbacks
// ---------------------------------------------------------------------------

#[test]
fn host_specific_overrides_generic() {
    // /v1/chat/completions with api.openai.com → "OpenAI" not "OpenAI-compatible"
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
}

#[test]
fn unknown_host_falls_back_to_generic() {
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: my-proxy.local\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "OpenAI-compatible");
}

#[test]
fn no_host_falls_back_to_generic() {
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "OpenAI-compatible");
}

// ---------------------------------------------------------------------------
// SNI hint used when no Host header
// ---------------------------------------------------------------------------

#[test]
fn sni_hint_matches_host_specific_rules() {
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, Some("api.openai.com")).unwrap();
    assert_eq!(info.provider, "OpenAI");
}

#[test]
fn sni_hint_anthropic() {
    let raw = b"POST /v1/messages HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, Some("api.anthropic.com")).unwrap();
    assert_eq!(info.provider, "Anthropic");
}

#[test]
fn sni_hint_overrides_host_header() {
    // SNI hint takes precedence over Host header
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: my-proxy.local\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let info = llm::match_request(&req, Some("api.openai.com")).unwrap();
    assert_eq!(info.provider, "OpenAI");
}

// ---------------------------------------------------------------------------
// Response classification
// ---------------------------------------------------------------------------

#[test]
fn response_with_choices_is_openai() {
    let body = br#"{"id":"cmpl-1","choices":[{"message":{"content":"hi"}}],"model":"gpt-4"}"#;
    let jf = json::analyze(body);
    let info = llm::classify_response(&jf, Some("api.openai.com")).unwrap();
    assert_eq!(info.provider, "OpenAI");
    assert_eq!(info.model.as_deref(), Some("gpt-4"));
}

#[test]
fn response_with_content_and_model_is_anthropic() {
    let body = br#"{"id":"msg-1","content":[{"type":"text","text":"hi"}],"model":"claude-3-opus"}"#;
    let jf = json::analyze(body);
    let info = llm::classify_response(&jf, None).unwrap();
    assert_eq!(info.provider, "Anthropic");
}

#[test]
fn response_with_completion_field() {
    let body = br#"{"completion":"Hello","model":"claude-v1"}"#;
    let jf = json::analyze(body);
    let info = llm::classify_response(&jf, None).unwrap();
    assert_eq!(info.endpoint, "completions");
}

#[test]
fn response_no_llm_indicators_returns_none() {
    let body = br#"{"status":"ok","data":[]}"#;
    let jf = json::analyze(body);
    assert!(llm::classify_response(&jf, None).is_none());
}

#[test]
fn response_sni_hint_used_for_provider() {
    let body = br#"{"choices":[{"message":{"content":"hi"}}],"model":"gpt-4"}"#;
    let jf = json::analyze(body);
    let info = llm::classify_response(&jf, Some("api.groq.com")).unwrap();
    assert_eq!(info.provider, "Groq");
}

// ---------------------------------------------------------------------------
// SSE detection patterns
// ---------------------------------------------------------------------------

#[test]
fn sse_openai_choices_delta() {
    let text = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n";
    let info = llm::detect_sse_stream(text, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
    assert_eq!(info.stream_type, "sse");
}

#[test]
fn sse_openai_done_marker() {
    let text = "data: {\"id\":\"1\"}\n\ndata: [DONE]\n\n";
    let info = llm::detect_sse_stream(text, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
}

#[test]
fn sse_anthropic_message_start() {
    let text = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
    let info = llm::detect_sse_stream(text, None).unwrap();
    assert_eq!(info.provider, "Anthropic");
}

#[test]
fn sse_anthropic_content_block() {
    let text = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n";
    let info = llm::detect_sse_stream(text, None).unwrap();
    assert_eq!(info.provider, "Anthropic");
}

#[test]
fn sse_with_sni_hint_overrides_default_provider() {
    let text = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
    let info = llm::detect_sse_stream(text, Some("api.groq.com")).unwrap();
    assert_eq!(info.provider, "Groq");
}

#[test]
fn sse_generic_with_model() {
    let text = "data: {\"model\":\"custom-v1\"}\n\n";
    let info = llm::detect_sse_stream(text, None).unwrap();
    assert_eq!(info.provider, "Unknown");
}

#[test]
fn non_sse_text_returns_none() {
    assert!(llm::detect_sse_stream("just plain text", None).is_none());
}

#[test]
fn sse_without_llm_content_returns_none() {
    // "data: {" but no LLM-related content
    let text = "data: {\"status\":\"ok\"}\n\n";
    assert!(llm::detect_sse_stream(text, None).is_none());
}

// ---------------------------------------------------------------------------
// match_request_with_body enriches with JSON fields
// ---------------------------------------------------------------------------

#[test]
fn match_request_with_body_extracts_model_and_stream() {
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{\"model\":\"gpt-4\",\"stream\":true}";
    let req = http::parse_request(raw).unwrap();
    let body = &raw[req.body_offset.unwrap()..];
    let jf = json::analyze(body);
    let info = llm::match_request_with_body(&req, None, &jf).unwrap();
    assert_eq!(info.model.as_deref(), Some("gpt-4"));
    assert_eq!(info.streaming, Some(true));
}

// ---------------------------------------------------------------------------
// Method mismatch → no match
// ---------------------------------------------------------------------------

#[test]
fn get_to_post_endpoint_no_match() {
    // /v1/chat/completions requires POST
    let raw = b"GET /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    // Host-specific rule requires POST, so it won't match.
    // Path-only fallback also requires POST.
    let info = llm::match_request(&req, None);
    assert!(info.is_none());
}

#[test]
fn unrelated_path_no_match() {
    let raw = b"GET /index.html HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    assert!(llm::match_request(&req, None).is_none());
}

// ===========================================================================
// Property tests (proptest)
// ===========================================================================

use proptest::prelude::*;
use std::collections::HashMap;

/// Build an HttpRequestInfo directly (bypassing HTTP parsing) for fuzz testing.
fn make_request(
    method: &str,
    path: &str,
    host: Option<&str>,
) -> busted_classifier::http::HttpRequestInfo {
    let mut headers = HashMap::new();
    if let Some(h) = host {
        headers.insert("host".to_string(), h.to_string());
    }
    busted_classifier::http::HttpRequestInfo {
        method: method.to_string(),
        path: path.to_string(),
        version: "HTTP/1.1".to_string(),
        headers,
        body_offset: None,
    }
}

/// Strategy for generating arbitrary JsonFields.
fn arb_json_fields() -> impl Strategy<Value = busted_classifier::json::JsonFields> {
    (
        proptest::option::of("[a-zA-Z0-9_/-]{0,30}"), // model
        any::<bool>(),                                // has_messages
        any::<bool>(),                                // has_prompt
        proptest::option::of(0.0f64..2.0),            // temperature
        proptest::option::of(1u64..4096),             // max_tokens
        proptest::option::of(0.0f64..1.0),            // top_p
        proptest::option::of(any::<bool>()),          // stream
        any::<bool>(),                                // has_choices
        any::<bool>(),                                // has_content
        any::<bool>(),                                // has_completion
    )
        .prop_map(
            |(
                model,
                has_messages,
                has_prompt,
                temperature,
                max_tokens,
                top_p,
                stream,
                has_choices,
                has_content,
                has_completion,
            )| {
                busted_classifier::json::JsonFields {
                    model,
                    has_messages,
                    has_prompt,
                    temperature,
                    max_tokens,
                    top_p,
                    stream,
                    has_choices,
                    has_content,
                    has_completion,
                    ..Default::default()
                }
            },
        )
}

/// Known SNI domains and their expected providers.
const SNI_PROVIDER_PAIRS: &[(&str, &str)] = &[
    ("api.openai.com", "OpenAI"),
    ("api.anthropic.com", "Anthropic"),
    ("generativelanguage.googleapis.com", "Google"),
    ("my-resource.openai.azure.com", "Azure"),
    ("bedrock-runtime.us-east-1.amazonaws.com", "AWS Bedrock"),
    ("api.cohere.ai", "Cohere"),
    ("api.mistral.ai", "Mistral"),
    ("api.groq.com", "Groq"),
    ("api.together.xyz", "Together"),
    ("api.deepseek.com", "DeepSeek"),
    ("api.perplexity.ai", "Perplexity"),
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    // 1. match_request never panics on arbitrary input
    #[test]
    fn match_request_never_panics(
        method in "[A-Z]{1,8}",
        path in "/[a-zA-Z0-9/_.-]{0,60}",
        host in proptest::option::of("[a-zA-Z0-9._:-]{1,40}"),
        sni in proptest::option::of("[a-zA-Z0-9._:-]{1,40}"),
    ) {
        let req = make_request(&method, &path, host.as_deref());
        let _ = llm::match_request(&req, sni.as_deref());
    }

    // 2. match_request_with_body never panics on arbitrary input
    #[test]
    fn match_request_with_body_never_panics(
        method in "[A-Z]{1,8}",
        path in "/[a-zA-Z0-9/_.-]{0,60}",
        host in proptest::option::of("[a-zA-Z0-9._:-]{1,40}"),
        sni in proptest::option::of("[a-zA-Z0-9._:-]{1,40}"),
        jf in arb_json_fields(),
    ) {
        let req = make_request(&method, &path, host.as_deref());
        let _ = llm::match_request_with_body(&req, sni.as_deref(), &jf);
    }

    // 3. classify_response never panics on arbitrary JsonFields + SNI
    #[test]
    fn classify_response_never_panics(
        jf in arb_json_fields(),
        sni in proptest::option::of("[a-zA-Z0-9._:-]{1,60}"),
    ) {
        let _ = llm::classify_response(&jf, sni.as_deref());
    }

    // 4. detect_sse_stream never panics on arbitrary UTF-8 + SNI
    #[test]
    fn detect_sse_stream_never_panics(
        text in "[ -~\n\r\t]{0,200}",
        sni in proptest::option::of("[a-zA-Z0-9._:-]{1,40}"),
    ) {
        let _ = llm::detect_sse_stream(&text, sni.as_deref());
    }

    // 5. match_request is deterministic: same input always produces same output
    #[test]
    fn match_request_deterministic(
        method in "[A-Z]{1,8}",
        path in "/[a-zA-Z0-9/_.-]{0,60}",
        host in proptest::option::of("[a-zA-Z0-9._:-]{1,40}"),
        sni in proptest::option::of("[a-zA-Z0-9._:-]{1,40}"),
    ) {
        let req = make_request(&method, &path, host.as_deref());
        let r1 = llm::match_request(&req, sni.as_deref());
        let r2 = llm::match_request(&req, sni.as_deref());
        match (&r1, &r2) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                prop_assert_eq!(&a.provider, &b.provider);
                prop_assert_eq!(&a.endpoint, &b.endpoint);
                prop_assert_eq!(&a.model, &b.model);
                prop_assert_eq!(&a.streaming, &b.streaming);
            }
            _ => prop_assert!(false, "match_request not deterministic"),
        }
    }

    // 6. Known SNI domains produce the correct provider via classify_response
    #[test]
    fn provider_consistency_with_sni(
        idx in 0..SNI_PROVIDER_PAIRS.len(),
    ) {
        let (sni, expected_provider) = SNI_PROVIDER_PAIRS[idx];
        // Build a JSON body with "choices" so classify_response always returns Some
        let body = br#"{"choices":[{"message":{"content":"hi"}}],"model":"test-model"}"#;
        let jf = json::analyze(body);
        let info = llm::classify_response(&jf, Some(sni)).unwrap();
        prop_assert_eq!(&info.provider, expected_provider);
    }

    // 7. GET on POST-only endpoints returns None
    #[test]
    fn method_filter_correctness(
        path in prop::sample::select(vec![
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/v1/messages",
            "/api/chat",
            "/api/generate",
            "/api/embeddings",
        ]),
    ) {
        // All of these paths require POST in their rules
        let req = make_request("GET", path, Some("some-unknown-host.local"));
        let result = llm::match_request(&req, None);
        prop_assert!(result.is_none(), "GET on POST-only endpoint {:?} should be None", path);
    }

    // 8. detect_sse_stream is deterministic: same text+SNI produces same result
    #[test]
    fn sse_detection_deterministic(
        text in "[ -~\n\r\t]{0,200}",
        sni in proptest::option::of("[a-zA-Z0-9._:-]{1,40}"),
    ) {
        let r1 = llm::detect_sse_stream(&text, sni.as_deref());
        let r2 = llm::detect_sse_stream(&text, sni.as_deref());
        match (&r1, &r2) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                prop_assert_eq!(&a.provider, &b.provider);
                prop_assert_eq!(&a.stream_type, &b.stream_type);
            }
            _ => prop_assert!(false, "detect_sse_stream not deterministic"),
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[test]
fn trailing_slash_on_endpoint_path() {
    // Path "/v1/chat/completions/" starts_with "/v1/chat/completions" → still matches
    let req = make_request("POST", "/v1/chat/completions/", Some("api.openai.com"));
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
    assert_eq!(info.endpoint, "chat_completions");
}

#[test]
fn sni_hint_uppercase() {
    // provider_from_sni lowercases the SNI, so classify_response handles uppercase SNI
    let body = br#"{"choices":[{"message":{"content":"hi"}}],"model":"gpt-4"}"#;
    let jf = json::analyze(body);
    let info = llm::classify_response(&jf, Some("API.OPENAI.COM")).unwrap();
    assert_eq!(info.provider, "OpenAI");
}

#[test]
fn response_choices_without_model() {
    // Response with "choices" but no "model" field → still Some
    let body = br#"{"choices":[{"message":{"content":"hello"}}]}"#;
    let jf = json::analyze(body);
    let info = llm::classify_response(&jf, None).unwrap();
    assert!(info.model.is_none());
    assert_eq!(info.endpoint, "chat_completions");
}

#[test]
fn sse_empty_data_json() {
    // "data: {}" contains "data: {" but no LLM-related content → None
    let text = "data: {}\n\n";
    assert!(llm::detect_sse_stream(text, None).is_none());
}

#[test]
fn ollama_on_non_standard_host() {
    // /api/chat is a path-only fallback rule (host: None), so it matches any host
    let req = make_request("POST", "/api/chat", Some("my-custom-server.example.com"));
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Ollama");
    assert_eq!(info.endpoint, "chat");
}

#[test]
fn azure_complex_deployment_name() {
    // Azure rule: path starts_with "/openai/deployments/" with no host constraint
    let req = make_request(
        "POST",
        "/openai/deployments/my-gpt4-2024-v3/chat/completions",
        Some("my-resource.openai.azure.com"),
    );
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "Azure");
    assert_eq!(info.endpoint, "openai");
}

#[test]
fn bedrock_non_standard_subdomain() {
    // bedrock-runtime rule uses host contains "bedrock-runtime", so any region works
    let req = make_request(
        "POST",
        "/model/anthropic.claude-v2/invoke",
        Some("bedrock-runtime.eu-west-1.amazonaws.com"),
    );
    let info = llm::match_request(&req, None).unwrap();
    assert_eq!(info.provider, "AWS Bedrock");
    assert_eq!(info.endpoint, "invoke");
}

#[test]
fn get_on_anthropic_messages() {
    // Anthropic /v1/messages requires POST; GET should not match
    let req = make_request("GET", "/v1/messages", Some("api.anthropic.com"));
    let info = llm::match_request(&req, None);
    assert!(info.is_none());
}

#[test]
fn multiple_sse_markers() {
    // Text containing both Anthropic and OpenAI SSE markers.
    // Anthropic markers are checked first in detect_sse_stream, so Anthropic wins.
    let text = "event: message_start\ndata: {\"type\":\"message_start\"}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
    let info = llm::detect_sse_stream(text, None).unwrap();
    assert_eq!(info.provider, "Anthropic");
}

#[test]
fn response_raw_json_no_http() {
    // classify_response works on just JSON fields, no HTTP framing needed
    let body = br#"{"id":"chatcmpl-abc","choices":[{"message":{"content":"world"}}],"model":"gpt-3.5-turbo"}"#;
    let jf = json::analyze(body);
    let info = llm::classify_response(&jf, None).unwrap();
    assert_eq!(info.provider, "OpenAI");
    assert_eq!(info.model.as_deref(), Some("gpt-3.5-turbo"));
}

#[test]
fn classify_response_all_sni_domains() {
    // Each known SNI domain should produce the correct provider in a response
    let body = br#"{"choices":[{"message":{"content":"test"}}],"model":"m"}"#;
    let jf = json::analyze(body);
    for &(sni, expected) in SNI_PROVIDER_PAIRS {
        let info = llm::classify_response(&jf, Some(sni))
            .unwrap_or_else(|| panic!("classify_response returned None for SNI {:?}", sni));
        assert_eq!(
            info.provider, expected,
            "SNI {:?} should produce provider {:?}, got {:?}",
            sni, expected, info.provider
        );
    }
}

#[test]
fn empty_path_no_match() {
    // A request with path "/" doesn't match any LLM endpoint rule
    let req = make_request("POST", "/", Some("api.openai.com"));
    let info = llm::match_request(&req, None);
    assert!(info.is_none());
}
