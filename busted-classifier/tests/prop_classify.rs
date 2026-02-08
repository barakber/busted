use busted_classifier::{classify, Classification, ContentClass, Direction};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Proptest strategies
// ---------------------------------------------------------------------------

fn direction_strategy() -> impl Strategy<Value = Direction> {
    prop_oneof![Just(Direction::Write), Just(Direction::Read),]
}

fn optional_sni_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some("api.openai.com".to_string())),
        Just(Some("api.anthropic.com".to_string())),
        Just(Some("example.com".to_string())),
        "[a-z]{3,20}\\.[a-z]{2,6}".prop_map(Some),
    ]
}

// ---------------------------------------------------------------------------
// Property: classify() never panics on arbitrary bytes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn never_panics_on_arbitrary_bytes(
        payload in proptest::collection::vec(any::<u8>(), 0..2048),
        direction in direction_strategy(),
        sni in optional_sni_strategy(),
    ) {
        let _ = classify(&payload, direction, sni.as_deref());
    }
}

// ---------------------------------------------------------------------------
// Property: confidence is always in [0.0, 1.0]
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn confidence_always_in_bounds(
        payload in proptest::collection::vec(any::<u8>(), 0..2048),
        direction in direction_strategy(),
        sni in optional_sni_strategy(),
    ) {
        let c = classify(&payload, direction, sni.as_deref());
        prop_assert!(c.confidence >= 0.0, "confidence {} < 0.0", c.confidence);
        prop_assert!(c.confidence <= 1.0, "confidence {} > 1.0", c.confidence);
    }
}

// ---------------------------------------------------------------------------
// Property: is_interesting consistency — GenericHttp is never interesting,
// LlmApi/Mcp/LlmStream are always interesting
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn is_interesting_consistency(
        payload in proptest::collection::vec(any::<u8>(), 0..2048),
        direction in direction_strategy(),
        sni in optional_sni_strategy(),
    ) {
        let c = classify(&payload, direction, sni.as_deref());
        match &c.content {
            Some(ContentClass::GenericHttp) => {
                prop_assert!(!c.is_interesting, "GenericHttp should not be interesting");
            }
            Some(ContentClass::LlmApi(_)) | Some(ContentClass::Mcp(_)) | Some(ContentClass::LlmStream(_)) => {
                prop_assert!(c.is_interesting, "LlmApi/Mcp/LlmStream should be interesting");
            }
            Some(ContentClass::JsonRpc) => {
                prop_assert!(c.is_interesting, "JsonRpc should be interesting");
            }
            None => {
                prop_assert!(!c.is_interesting, "None content should not be interesting");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property: classification is deterministic
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn classification_is_deterministic(
        payload in proptest::collection::vec(any::<u8>(), 0..1024),
        direction in direction_strategy(),
        sni in optional_sni_strategy(),
    ) {
        let c1 = classify(&payload, direction, sni.as_deref());
        let c2 = classify(&payload, direction, sni.as_deref());
        prop_assert_eq!(c1.is_interesting, c2.is_interesting);
        prop_assert_eq!(c1.confidence, c2.confidence);
        prop_assert_eq!(c1.content_class_str(), c2.content_class_str());
        prop_assert_eq!(c1.provider(), c2.provider());
        prop_assert_eq!(c1.endpoint(), c2.endpoint());
        prop_assert_eq!(c1.model(), c2.model());
        prop_assert_eq!(c1.mcp_method(), c2.mcp_method());
        prop_assert_eq!(c1.signature_hash(), c2.signature_hash());
    }
}

// ---------------------------------------------------------------------------
// Unit: empty payload
// ---------------------------------------------------------------------------

#[test]
fn empty_payload_returns_valid_result() {
    let c = classify(b"", Direction::Write, None);
    assert!(!c.is_interesting);
    assert!(c.confidence >= 0.0 && c.confidence <= 1.0);

    let c = classify(b"", Direction::Read, None);
    assert!(!c.is_interesting);
}

// ---------------------------------------------------------------------------
// Unit: pure binary payload
// ---------------------------------------------------------------------------

#[test]
fn pure_binary_payload() {
    let payload: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let c = classify(&payload, Direction::Write, None);
    assert!(c.confidence >= 0.0 && c.confidence <= 1.0);
}

// ---------------------------------------------------------------------------
// Unit: real-world payload templates — all major providers
// ---------------------------------------------------------------------------

fn assert_provider(c: &Classification, expected: &str) {
    assert!(c.is_interesting, "expected interesting for provider {expected}");
    assert_eq!(c.provider(), Some(expected), "wrong provider, expected {expected}");
}

#[test]
fn openai_chat_completions() {
    let payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nUser-Agent: openai-python/1.12.0\r\n\r\n{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"temperature\":0.7}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "OpenAI");
    assert_eq!(c.model(), Some("gpt-4o"));
    assert!(c.confidence >= 0.9);
}

#[test]
fn anthropic_messages() {
    let payload = b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nAnthropic-Version: 2024-01-01\r\nX-Api-Key: secret\r\n\r\n{\"model\":\"claude-3-opus\",\"messages\":[],\"max_tokens\":1024}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "Anthropic");
    assert_eq!(c.model(), Some("claude-3-opus"));
}

#[test]
fn google_gemini() {
    let payload = b"POST /v1beta/models/gemini-pro:generateContent HTTP/1.1\r\nHost: generativelanguage.googleapis.com\r\nContent-Type: application/json\r\n\r\n{\"contents\":[{\"parts\":[{\"text\":\"hello\"}]}]}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "Google");
}

#[test]
fn azure_openai() {
    let payload = b"POST /openai/deployments/gpt-4/chat/completions?api-version=2024-02-01 HTTP/1.1\r\nHost: my-resource.openai.azure.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"gpt-4\",\"messages\":[]}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "Azure");
}

#[test]
fn aws_bedrock() {
    let payload = b"POST /model/anthropic.claude-v2/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-1.amazonaws.com\r\nContent-Type: application/json\r\n\r\n{\"prompt\":\"hello\",\"max_tokens_to_sample\":100}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "AWS Bedrock");
}

#[test]
fn ollama_chat() {
    let payload = b"POST /api/chat HTTP/1.1\r\nHost: localhost:11434\r\nContent-Type: application/json\r\n\r\n{\"model\":\"llama2\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "Ollama");
    assert_eq!(c.model(), Some("llama2"));
}

#[test]
fn cohere_chat() {
    let payload = b"POST /v1/chat HTTP/1.1\r\nHost: api.cohere.ai\r\nContent-Type: application/json\r\n\r\n{\"model\":\"command-r-plus\",\"message\":\"hello\"}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "Cohere");
}

#[test]
fn mistral_chat() {
    let payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.mistral.ai\r\nContent-Type: application/json\r\n\r\n{\"model\":\"mistral-large-latest\",\"messages\":[]}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "Mistral");
}

#[test]
fn groq_chat() {
    let payload = b"POST /openai/v1/chat/completions HTTP/1.1\r\nHost: api.groq.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"llama3-70b\",\"messages\":[]}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "Groq");
}

#[test]
fn together_chat() {
    let payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.together.xyz\r\nContent-Type: application/json\r\n\r\n{\"model\":\"meta-llama/Llama-3-70b\",\"messages\":[]}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "Together");
}

#[test]
fn deepseek_chat() {
    let payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.deepseek.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"deepseek-chat\",\"messages\":[]}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "DeepSeek");
}

#[test]
fn perplexity_chat() {
    let payload = b"POST /chat/completions HTTP/1.1\r\nHost: api.perplexity.ai\r\nContent-Type: application/json\r\n\r\n{\"model\":\"sonar-medium-online\",\"messages\":[]}";
    let c = classify(payload, Direction::Write, None);
    assert_provider(&c, "Perplexity");
}

// ---------------------------------------------------------------------------
// Unit: MCP via raw JSON (no HTTP framing)
// ---------------------------------------------------------------------------

#[test]
fn mcp_raw_json_tools_list() {
    let payload = br#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
    let c = classify(payload, Direction::Write, None);
    assert!(c.is_interesting);
    assert_eq!(c.mcp_method(), Some("tools/list"));
}

#[test]
fn mcp_raw_json_response() {
    let payload = br#"{"jsonrpc":"2.0","result":{"tools":[]},"id":1}"#;
    let c = classify(payload, Direction::Read, None);
    assert!(c.is_interesting);
    assert_eq!(c.content_class_str(), Some("Mcp"));
}

// ---------------------------------------------------------------------------
// Unit: SSE with various directions
// ---------------------------------------------------------------------------

#[test]
fn sse_not_detected_on_write_direction() {
    // SSE detection only triggers on Read direction
    let payload = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n";
    let c = classify(payload, Direction::Write, Some("api.openai.com"));
    // On write direction, SSE prefix check is skipped, so it goes through raw body path
    // It should still not crash
    assert!(c.confidence >= 0.0);
}

// ---------------------------------------------------------------------------
// Unit: unicode content
// ---------------------------------------------------------------------------

#[test]
fn unicode_payload_no_panic() {
    let payload = "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"\u{1F600}\u{1F680}\u{2764}\u{FE0F} \u{4F60}\u{597D}\u{4E16}\u{754C}\"}]}";
    let c = classify(payload.as_bytes(), Direction::Write, None);
    assert!(c.is_interesting);
    assert_eq!(c.provider(), Some("OpenAI"));
}

// ---------------------------------------------------------------------------
// Unit: very large payload
// ---------------------------------------------------------------------------

#[test]
fn large_payload_no_panic() {
    let mut payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"".to_vec();
    payload.extend(std::iter::repeat(b'A').take(100_000));
    payload.extend(b"\"}]}");
    let c = classify(&payload, Direction::Write, None);
    assert!(c.is_interesting);
}

// ---------------------------------------------------------------------------
// Unit: single-byte payloads
// ---------------------------------------------------------------------------

#[test]
fn single_byte_payloads() {
    for byte in 0..=255u8 {
        let c = classify(&[byte], Direction::Write, None);
        assert!(c.confidence >= 0.0 && c.confidence <= 1.0);
    }
}
