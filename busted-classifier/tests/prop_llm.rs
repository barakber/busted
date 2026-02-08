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
