//! Tells you whether a decrypted TLS payload is an LLM API call, an MCP message, or
//! just normal HTTP — in microseconds, from a single buffer, with no connection state.
//!
//! # The problem
//!
//! Every major LLM provider (OpenAI, Anthropic, Google, AWS Bedrock, Cohere, Mistral,
//! Groq, and more) serves its API over HTTPS. To a traditional network monitor, a
//! `POST /v1/chat/completions` to `api.openai.com` looks identical to any other TLS
//! connection — just encrypted bytes on port 443. Even after you've intercepted the
//! plaintext (via eBPF uprobes on `SSL_write`/`SSL_read`), you're left with a raw byte
//! buffer. Is it a GPT-4 request? A Claude conversation? An MCP tool invocation? Or
//! someone browsing Reddit? This crate answers that question.
//!
//! `busted-classifier` encodes deep knowledge of LLM API shapes, MCP's JSON-RPC 2.0
//! protocol, SDK user-agent strings, and streaming response formats into a fast,
//! stateless classification pipeline. Hand it a `&[u8]` and a direction, and it tells
//! you exactly what you're looking at.
//!
//! # How it works
//!
//! Classification flows through four layers, each adding detail:
//!
//! First, we figure out if the payload is even HTTP. The [`http`] module uses [`nom`]
//! combinators to parse HTTP/1.1 request and response headers, detect HTTP/2 binary
//! framing, and identify Server-Sent Events streams. If we can't parse it as HTTP, we
//! still try — the payload might be a raw JSON body without framing.
//!
//! Next, we check whether the HTTP endpoint matches a known LLM provider. The [`llm`]
//! module maintains a registry of API paths and host patterns — `/v1/chat/completions`
//! on `api.openai.com`, `/v1/messages` on `api.anthropic.com`, and dozens more. It also
//! inspects JSON response bodies for telltale fields like `choices`, `model`, and
//! `completion`. The [`mcp`] module separately detects MCP JSON-RPC 2.0 methods
//! (`tools/call`, `resources/read`, etc.) and categorizes them.
//!
//! Then we fingerprint the SDK. The [`fingerprint`] module extracts the `User-Agent`
//! header (`openai-python/1.12.0`, `anthropic-typescript/0.19.0`), pulls model
//! parameters from the JSON body, and computes a behavioral signature hash that can
//! identify the same agent across requests.
//!
//! Finally, if the `pii` feature is enabled, the [`pii`] module scans the payload for
//! leaked personally identifiable information — email addresses, credit card numbers,
//! SSNs, phone numbers, and API keys — so you know when sensitive data is being sent
//! to an LLM.
//!
//! # Architecture
//!
//! The four layers map to these modules:
//!
//! 1. **Protocol detection** — HTTP/1.1 parsing (via [`nom`]), HTTP/2 binary framing,
//!    SSE stream identification.
//! 2. **Content classification** — LLM API endpoint matching, MCP JSON-RPC detection.
//! 3. **Agent fingerprinting** — SDK extraction, model params, behavioral signature.
//! 4. **PII detection** — Regex scanning for sensitive data patterns.
//!
//! # Integration with Busted
//!
//! In the Busted pipeline, `busted-agent` captures decrypted TLS payloads via eBPF
//! uprobes, then calls [`classify()`] on the first chunk of each connection. The
//! resulting [`Classification`] is folded into a
//! `ProcessedEvent` and forwarded to the UI
//! and SIEM sinks. The crate has no dependency on eBPF or aya — it's a pure Rust
//! library that works anywhere you have bytes to classify.
//!
//! # Usage
//!
//! ```
//! use busted_classifier::{classify, Direction};
//!
//! let payload = b"POST /v1/chat/completions HTTP/1.1\r\n\
//!     Host: api.openai.com\r\n\
//!     Content-Type: application/json\r\n\r\n\
//!     {\"model\":\"gpt-4\",\"messages\":[]}";
//!
//! let result = classify(payload, Direction::Write, None);
//! assert!(result.is_interesting);
//! assert_eq!(result.provider(), Some("OpenAI"));
//! assert_eq!(result.model(), Some("gpt-4"));
//! ```
//!
//! # Feature Flags
//!
//! - **`pii`** — Enables PII detection via regex scanning (adds `regex` dependency).
//!   When disabled, [`PiiFlags`] fields are always `false`.

/// Agent/SDK fingerprinting from User-Agent headers and request structure.
pub mod fingerprint;
/// HTTP/1.1 request and response parsing via [`nom`].
pub mod http;
/// Streaming JSON field extraction (handles truncated payloads).
pub mod json;
/// LLM API endpoint matching for known providers.
pub mod llm;
/// MCP (Model Context Protocol) JSON-RPC 2.0 detection.
pub mod mcp;
/// PII (personally identifiable information) scanning.
pub mod pii;
/// Protocol-specific LLM API request/response parsers (Anthropic, OpenAI, etc.).
pub mod protocols;

use fingerprint::AgentFingerprint;
use llm::{LlmApiInfo, LlmStreamInfo};
use mcp::McpInfo;
use pii::PiiFlags;

pub use fingerprint::{fnv1a_32, ModelParams, SdkInfo};
pub use mcp::{McpCategory, McpMsgType};

/// Direction of TLS data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outbound data (client to server, e.g. `SSL_write`).
    Write,
    /// Inbound data (server to client, e.g. `SSL_read`).
    Read,
}

/// Layer 1: Protocol detection result.
#[derive(Debug, Clone)]
pub enum Protocol {
    /// HTTP/1.1 request with parsed headers and body offset.
    Http1Request(http::HttpRequestInfo),
    /// HTTP/1.1 response with parsed headers and body offset.
    Http1Response(http::HttpResponseInfo),
    /// Server-Sent Events stream (`data: ...` lines).
    Sse,
    /// HTTP/2 binary framing (connection preface or frames).
    Http2Binary,
    /// Non-text binary data.
    Binary,
    /// Could not determine protocol.
    Unknown,
}

/// Layer 2: Content classification.
#[derive(Debug, Clone)]
pub enum ContentClass {
    /// LLM API request or response.
    LlmApi(LlmApiInfo),
    /// MCP JSON-RPC 2.0 message.
    Mcp(McpInfo),
    /// LLM streaming response (SSE).
    LlmStream(LlmStreamInfo),
    /// Generic JSON-RPC (non-MCP).
    JsonRpc,
    /// Generic HTTP (not LLM/MCP).
    GenericHttp,
}

/// Full classification result.
#[derive(Debug, Clone)]
pub struct Classification {
    /// Whether this payload is interesting (LLM/MCP related).
    pub is_interesting: bool,
    /// Layer 1: protocol detection.
    pub protocol: Protocol,
    /// Layer 2: content classification.
    pub content: Option<ContentClass>,
    /// Layer 3: agent/SDK fingerprint.
    pub fingerprint: Option<AgentFingerprint>,
    /// PII detection flags (all false when `pii` feature disabled).
    pub pii_flags: PiiFlags,
    /// Classification confidence (0.0–1.0).
    pub confidence: f32,
}

/// Classify a decrypted TLS payload chunk.
///
/// Stateless per-call — connection tracking stays in busted-agent.
pub fn classify(payload: &[u8], direction: Direction, sni_hint: Option<&str>) -> Classification {
    let pii_flags = pii::scan(payload);

    // Layer 1: detect protocol
    let protocol = detect_protocol(payload, direction);

    // Layer 2 + 3: classify content and extract fingerprint
    let (content, fp, confidence) = match &protocol {
        Protocol::Http1Request(req) => classify_http_request(req, payload, sni_hint),
        Protocol::Http1Response(resp) => classify_http_response(resp, payload, sni_hint),
        Protocol::Sse => classify_sse(payload, sni_hint),
        Protocol::Http2Binary => (None, None, 0.3),
        Protocol::Binary | Protocol::Unknown => classify_raw_body(payload, sni_hint),
    };

    let is_interesting = content
        .as_ref()
        .map(|c| !matches!(c, ContentClass::GenericHttp))
        .unwrap_or(false);

    Classification {
        is_interesting,
        protocol,
        content,
        fingerprint: fp,
        pii_flags,
        confidence,
    }
}

/// Layer 1: Detect protocol from raw payload bytes.
fn detect_protocol(payload: &[u8], direction: Direction) -> Protocol {
    if payload.is_empty() {
        return Protocol::Unknown;
    }

    // Check for HTTP/2 binary framing first
    if http::is_http2_binary(payload) {
        return Protocol::Http2Binary;
    }

    // Check for SSE (often in read direction)
    if direction == Direction::Read {
        let text = std::str::from_utf8(payload).unwrap_or("");
        if text.starts_with("data: ") || text.starts_with("event: ") || text.starts_with(": ") {
            return Protocol::Sse;
        }
    }

    // Try HTTP request/response
    if http::looks_like_http_request(payload) {
        if let Some(req) = http::parse_request(payload) {
            return Protocol::Http1Request(req);
        }
    }

    if http::looks_like_http_response(payload) {
        if let Some(resp) = http::parse_response(payload) {
            return Protocol::Http1Response(resp);
        }
    }

    // Check if it's text (potential JSON body without HTTP headers)
    if payload.iter().all(|&b| b >= 0x09 && b != 0x7f) || std::str::from_utf8(payload).is_ok() {
        return Protocol::Unknown;
    }

    Protocol::Binary
}

/// Classify an HTTP/1.1 request.
fn classify_http_request(
    req: &http::HttpRequestInfo,
    full_payload: &[u8],
    sni_hint: Option<&str>,
) -> (Option<ContentClass>, Option<AgentFingerprint>, f32) {
    // Parse JSON body if present
    let json_fields = req.body_offset.and_then(|offset| {
        if offset < full_payload.len() {
            Some(json::analyze(&full_payload[offset..]))
        } else {
            None
        }
    });

    let empty_json = json::JsonFields::default();
    let jf = json_fields.as_ref().unwrap_or(&empty_json);

    // Check for MCP first (JSON-RPC 2.0 with MCP methods)
    if let Some(mcp_info) = mcp::classify(jf) {
        let fp = fingerprint::build_fingerprint(req, jf);
        return (Some(ContentClass::Mcp(mcp_info)), Some(fp), 0.95);
    }

    // Check for LLM API endpoint
    if let Some(llm_info) = llm::match_request_with_body(req, sni_hint, jf) {
        let fp = fingerprint::build_fingerprint(req, jf);
        return (Some(ContentClass::LlmApi(llm_info)), Some(fp), 0.9);
    }

    // Generic JSON-RPC (non-MCP)
    if jf.jsonrpc.is_some() {
        let fp = fingerprint::build_fingerprint(req, jf);
        return (Some(ContentClass::JsonRpc), Some(fp), 0.6);
    }

    // Check for LLM-like body without matching endpoint
    let llm_indicators = count_llm_indicators(jf);
    if llm_indicators >= 2 {
        let fp = fingerprint::build_fingerprint(req, jf);
        let confidence = 0.5 + (llm_indicators as f32 * 0.1).min(0.4);
        let info = LlmApiInfo {
            provider: "Unknown".to_string(),
            endpoint: "unknown".to_string(),
            model: jf.model.clone(),
            streaming: jf.stream,
        };
        return (Some(ContentClass::LlmApi(info)), Some(fp), confidence);
    }

    // Generic HTTP
    (Some(ContentClass::GenericHttp), None, 0.3)
}

/// Classify an HTTP/1.1 response.
fn classify_http_response(
    resp: &http::HttpResponseInfo,
    full_payload: &[u8],
    sni_hint: Option<&str>,
) -> (Option<ContentClass>, Option<AgentFingerprint>, f32) {
    // Parse JSON body
    let json_fields = resp.body_offset.and_then(|offset| {
        if offset < full_payload.len() {
            Some(json::analyze(&full_payload[offset..]))
        } else {
            None
        }
    });

    let empty_json = json::JsonFields::default();
    let jf = json_fields.as_ref().unwrap_or(&empty_json);

    // Check for MCP response
    if let Some(mcp_info) = mcp::classify(jf) {
        return (Some(ContentClass::Mcp(mcp_info)), None, 0.9);
    }

    // Check for LLM response patterns
    if let Some(llm_info) = llm::classify_response(jf, sni_hint) {
        return (Some(ContentClass::LlmApi(llm_info)), None, 0.85);
    }

    // Generic JSON-RPC response
    if jf.jsonrpc.is_some() {
        return (Some(ContentClass::JsonRpc), None, 0.6);
    }

    (Some(ContentClass::GenericHttp), None, 0.3)
}

/// Classify SSE streaming data.
fn classify_sse(
    payload: &[u8],
    sni_hint: Option<&str>,
) -> (Option<ContentClass>, Option<AgentFingerprint>, f32) {
    let text = String::from_utf8_lossy(payload);
    if let Some(stream_info) = llm::detect_sse_stream(&text, sni_hint) {
        return (Some(ContentClass::LlmStream(stream_info)), None, 0.85);
    }
    (Some(ContentClass::GenericHttp), None, 0.3)
}

/// Classify raw body bytes (no HTTP framing detected).
fn classify_raw_body(
    payload: &[u8],
    sni_hint: Option<&str>,
) -> (Option<ContentClass>, Option<AgentFingerprint>, f32) {
    // Try to parse as JSON directly
    let jf = json::analyze(payload);

    // Check MCP
    if let Some(mcp_info) = mcp::classify(&jf) {
        return (Some(ContentClass::Mcp(mcp_info)), None, 0.8);
    }

    // Check LLM response
    if let Some(llm_info) = llm::classify_response(&jf, sni_hint) {
        return (Some(ContentClass::LlmApi(llm_info)), None, 0.7);
    }

    // Check LLM indicators in body
    let llm_indicators = count_llm_indicators(&jf);
    if llm_indicators >= 2 {
        let confidence = 0.4 + (llm_indicators as f32 * 0.1).min(0.3);
        let info = LlmApiInfo {
            provider: "Unknown".to_string(),
            endpoint: "unknown".to_string(),
            model: jf.model.clone(),
            streaming: jf.stream,
        };
        return (Some(ContentClass::LlmApi(info)), None, confidence);
    }

    // Check SSE patterns
    if let Ok(text) = std::str::from_utf8(payload) {
        if let Some(stream_info) = llm::detect_sse_stream(text, sni_hint) {
            return (Some(ContentClass::LlmStream(stream_info)), None, 0.7);
        }
    }

    (None, None, 0.0)
}

/// Count LLM-indicative fields in JSON.
fn count_llm_indicators(jf: &json::JsonFields) -> u32 {
    let mut count = 0u32;
    if jf.model.is_some() {
        count += 1;
    }
    if jf.has_messages {
        count += 1;
    }
    if jf.has_prompt {
        count += 1;
    }
    if jf.temperature.is_some() {
        count += 1;
    }
    if jf.max_tokens.is_some() {
        count += 1;
    }
    if jf.has_choices {
        count += 1;
    }
    if jf.has_content {
        count += 1;
    }
    if jf.has_completion {
        count += 1;
    }
    count
}

// ---- Convenience display helpers ----

impl Classification {
    /// Short string describing the content class.
    pub fn content_class_str(&self) -> Option<&'static str> {
        self.content.as_ref().map(|c| match c {
            ContentClass::LlmApi(_) => "LlmApi",
            ContentClass::Mcp(_) => "Mcp",
            ContentClass::LlmStream(_) => "LlmStream",
            ContentClass::JsonRpc => "JsonRpc",
            ContentClass::GenericHttp => "GenericHttp",
        })
    }

    /// Provider name if classified as LLM or MCP.
    pub fn provider(&self) -> Option<&str> {
        match &self.content {
            Some(ContentClass::LlmApi(info)) => Some(&info.provider),
            Some(ContentClass::LlmStream(info)) => Some(&info.provider),
            _ => None,
        }
    }

    /// Endpoint name if classified as LLM API.
    pub fn endpoint(&self) -> Option<&str> {
        match &self.content {
            Some(ContentClass::LlmApi(info)) => Some(&info.endpoint),
            _ => None,
        }
    }

    /// Model name if available.
    pub fn model(&self) -> Option<&str> {
        match &self.content {
            Some(ContentClass::LlmApi(info)) => info.model.as_deref(),
            _ => self
                .fingerprint
                .as_ref()
                .and_then(|fp| fp.model_params.model.as_deref()),
        }
    }

    /// MCP method if classified as MCP.
    pub fn mcp_method(&self) -> Option<&str> {
        match &self.content {
            Some(ContentClass::Mcp(info)) => info.method.as_deref(),
            _ => None,
        }
    }

    /// MCP category string if classified as MCP.
    pub fn mcp_category_str(&self) -> Option<String> {
        match &self.content {
            Some(ContentClass::Mcp(info)) => Some(info.category.to_string()),
            _ => None,
        }
    }

    /// SDK name+version string if fingerprinted.
    pub fn sdk_string(&self) -> Option<String> {
        self.fingerprint.as_ref().and_then(|fp| {
            fp.sdk.as_ref().map(|sdk| match &sdk.version {
                Some(v) => format!("{}/{}", sdk.name, v),
                None => sdk.name.clone(),
            })
        })
    }

    /// Signature hash if fingerprinted.
    pub fn signature_hash(&self) -> Option<u64> {
        self.fingerprint.as_ref().map(|fp| fp.signature_hash)
    }

    /// FNV-1a 32-bit hash of the SDK name, if fingerprinted.
    pub fn sdk_hash(&self) -> Option<u32> {
        self.fingerprint
            .as_ref()
            .map(|fp| fp.sdk_hash)
            .filter(|&h| h != 0)
    }

    /// FNV-1a 32-bit hash of the model name, if fingerprinted.
    pub fn model_hash(&self) -> Option<u32> {
        self.fingerprint
            .as_ref()
            .map(|fp| fp.model_hash)
            .filter(|&h| h != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_request() {
        let payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nUser-Agent: openai-python/1.12.0\r\nAuthorization: Bearer sk-1234567890abcdef\r\n\r\n{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}],\"temperature\":0.7}";
        let c = classify(payload, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("OpenAI"));
        assert_eq!(c.endpoint(), Some("chat_completions"));
        assert_eq!(c.model(), Some("gpt-4"));
        assert_eq!(c.sdk_string().as_deref(), Some("openai-python/1.12.0"));
        assert!(c.signature_hash().is_some());
        assert!(c.confidence >= 0.9);
    }

    #[test]
    fn test_anthropic_request() {
        let payload = b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nAnthropic-Version: 2024-01-01\r\nX-Api-Key: secret\r\n\r\n{\"model\":\"claude-3-opus\",\"messages\":[],\"max_tokens\":1024}";
        let c = classify(payload, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Anthropic"));
        assert_eq!(c.endpoint(), Some("messages"));
        assert_eq!(c.model(), Some("claude-3-opus"));
        let fp = c.fingerprint.as_ref().unwrap();
        assert_eq!(fp.api_version.as_deref(), Some("2024-01-01"));
    }

    #[test]
    fn test_mcp_tools_call() {
        let payload = br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search","arguments":{"query":"test"}},"id":1}"#;
        let c = classify(payload, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.content_class_str(), Some("Mcp"));
        assert_eq!(c.mcp_method(), Some("tools/call"));
        assert_eq!(c.mcp_category_str().as_deref(), Some("Tools"));
    }

    #[test]
    fn test_sse_stream() {
        let payload = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\ndata: [DONE]\n\n";
        let c = classify(payload, Direction::Read, Some("api.openai.com"));
        assert!(c.is_interesting);
        assert_eq!(c.content_class_str(), Some("LlmStream"));
    }

    #[test]
    fn test_boring_http() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let c = classify(payload, Direction::Write, None);
        assert!(!c.is_interesting);
    }

    #[test]
    fn test_sni_hint_used() {
        let payload = b"POST /v1/chat/completions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"model\":\"gpt-4\"}";
        let c = classify(payload, Direction::Write, Some("api.openai.com"));
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("OpenAI"));
    }

    #[test]
    fn test_http2_detection() {
        let payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let c = classify(payload, Direction::Write, None);
        assert!(matches!(c.protocol, Protocol::Http2Binary));
    }

    #[test]
    fn test_response_classification() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"chatcmpl-123\",\"choices\":[{\"message\":{\"content\":\"Hi\"}}],\"model\":\"gpt-4\"}";
        let c = classify(payload, Direction::Read, Some("api.openai.com"));
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("OpenAI"));
        assert_eq!(c.model(), Some("gpt-4"));
    }

    // ---- Edge-case tests ----

    #[test]
    fn test_raw_json_body_llm_fields() {
        // Raw JSON without HTTP framing, with LLM fields
        let payload =
            br#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"temperature":0.7}"#;
        let c = classify(payload, Direction::Write, None);
        // Should detect via raw body path
        assert!(c.is_interesting);
    }

    #[test]
    fn test_raw_mcp_body() {
        let payload = br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"test"},"id":1}"#;
        let c = classify(payload, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.content_class_str(), Some("Mcp"));
        assert!(c.confidence >= 0.8);
    }

    #[test]
    fn test_count_llm_indicators_zero() {
        let jf = json::JsonFields::default();
        assert_eq!(count_llm_indicators(&jf), 0);
    }

    #[test]
    fn test_count_llm_indicators_all() {
        let jf = json::JsonFields {
            model: Some("gpt-4".into()),
            has_messages: true,
            has_prompt: true,
            temperature: Some(0.7),
            max_tokens: Some(100),
            has_choices: true,
            has_content: true,
            has_completion: true,
            ..Default::default()
        };
        assert_eq!(count_llm_indicators(&jf), 8);
    }

    #[test]
    fn test_count_llm_indicators_threshold() {
        // 1 indicator: not enough for LLM classification via raw body
        let jf1 = json::JsonFields {
            model: Some("gpt-4".into()),
            ..Default::default()
        };
        assert_eq!(count_llm_indicators(&jf1), 1);

        // 2 indicators: meets threshold
        let jf2 = json::JsonFields {
            model: Some("gpt-4".into()),
            has_messages: true,
            ..Default::default()
        };
        assert_eq!(count_llm_indicators(&jf2), 2);
    }

    #[test]
    fn test_llm_api_confidence_high() {
        let payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"gpt-4\"}";
        let c = classify(payload, Direction::Write, None);
        assert!(c.confidence >= 0.9);
    }

    #[test]
    fn test_mcp_confidence() {
        let payload = b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1}";
        let c = classify(payload, Direction::Write, None);
        assert_eq!(c.confidence, 0.95);
    }

    #[test]
    fn test_generic_http_confidence() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let c = classify(payload, Direction::Write, None);
        assert!(!c.is_interesting);
        assert_eq!(c.confidence, 0.3);
    }

    #[test]
    fn test_http2_not_interesting() {
        let payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let c = classify(payload, Direction::Write, None);
        assert!(!c.is_interesting);
        assert!(matches!(c.protocol, Protocol::Http2Binary));
        assert_eq!(c.confidence, 0.3);
    }

    #[test]
    fn test_empty_payload() {
        let c = classify(b"", Direction::Write, None);
        assert!(!c.is_interesting);
        assert!(matches!(c.protocol, Protocol::Unknown));
    }

    #[test]
    fn test_content_class_str_variants() {
        // LlmApi
        let payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"gpt-4\"}";
        let c = classify(payload, Direction::Write, None);
        assert_eq!(c.content_class_str(), Some("LlmApi"));

        // GenericHttp
        let c2 = classify(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            Direction::Write,
            None,
        );
        assert_eq!(c2.content_class_str(), Some("GenericHttp"));
    }

    #[test]
    fn test_classification_convenience_methods() {
        let payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nUser-Agent: openai-python/1.12.0\r\n\r\n{\"model\":\"gpt-4\",\"messages\":[]}";
        let c = classify(payload, Direction::Write, None);

        assert_eq!(c.provider(), Some("OpenAI"));
        assert_eq!(c.endpoint(), Some("chat_completions"));
        assert_eq!(c.model(), Some("gpt-4"));
        assert!(c.sdk_string().is_some());
        assert!(c.signature_hash().is_some());
        // Not MCP
        assert!(c.mcp_method().is_none());
        assert!(c.mcp_category_str().is_none());
    }

    #[test]
    fn test_mcp_convenience_methods() {
        let payload =
            br#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"test"},"id":5}"#;
        let c = classify(payload, Direction::Write, None);
        assert_eq!(c.mcp_method(), Some("resources/read"));
        assert!(c.mcp_category_str().is_some());
        // Not LLM
        assert!(c.provider().is_none());
        assert!(c.endpoint().is_none());
    }

    #[test]
    fn test_sdk_hash_convenience() {
        let payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nUser-Agent: openai-python/1.12.0\r\n\r\n{\"model\":\"gpt-4\",\"messages\":[]}";
        let c = classify(payload, Direction::Write, None);
        let sdk_h = c.sdk_hash();
        let model_h = c.model_hash();
        assert!(sdk_h.is_some(), "sdk_hash should be populated");
        assert!(model_h.is_some(), "model_hash should be populated");
        assert_eq!(sdk_h.unwrap(), fingerprint::fnv1a_32(b"openai-python"));
        assert_eq!(model_h.unwrap(), fingerprint::fnv1a_32(b"gpt-4"));
    }

    #[test]
    fn test_sdk_hash_none_for_no_sdk() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let c = classify(payload, Direction::Write, None);
        assert!(c.sdk_hash().is_none());
        assert!(c.model_hash().is_none());
    }

    // ================================================================
    // Full classify() pipeline: every LLM provider
    // ================================================================
    //
    // These tests verify that every provider in ENDPOINT_RULES is correctly
    // identified when run through the full classify() pipeline (protocol
    // detection → endpoint matching → fingerprinting → PII scan).

    /// Helper: build an HTTP/1.1 POST request payload with JSON body.
    fn make_post(host: &str, path: &str, body: &str) -> Vec<u8> {
        format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             \r\n\
             {body}"
        )
        .into_bytes()
    }

    /// Helper: build an HTTP/1.1 GET request.
    fn make_get(host: &str, path: &str) -> Vec<u8> {
        format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             \r\n"
        )
        .into_bytes()
    }

    #[test]
    fn classify_openai_chat_completions() {
        let p = make_post(
            "api.openai.com",
            "/v1/chat/completions",
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("OpenAI"));
        assert_eq!(c.endpoint(), Some("chat_completions"));
        assert_eq!(c.model(), Some("gpt-4o"));
    }

    #[test]
    fn classify_openai_embeddings() {
        let p = make_post(
            "api.openai.com",
            "/v1/embeddings",
            r#"{"model":"text-embedding-3-small","input":"hello"}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("OpenAI"));
        assert_eq!(c.endpoint(), Some("embeddings"));
    }

    #[test]
    fn classify_openai_images() {
        let p = make_post(
            "api.openai.com",
            "/v1/images/generations",
            r#"{"model":"dall-e-3","prompt":"a cat"}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("OpenAI"));
        assert_eq!(c.endpoint(), Some("images"));
    }

    #[test]
    fn classify_openai_models() {
        let p = make_get("api.openai.com", "/v1/models");
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("OpenAI"));
        assert_eq!(c.endpoint(), Some("models"));
    }

    #[test]
    fn classify_anthropic_messages() {
        let p = make_post(
            "api.anthropic.com",
            "/v1/messages",
            r#"{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"hi"}],"max_tokens":1024}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Anthropic"));
        assert_eq!(c.endpoint(), Some("messages"));
        assert_eq!(c.model(), Some("claude-sonnet-4-20250514"));
    }

    #[test]
    fn classify_anthropic_complete() {
        let p = make_post(
            "api.anthropic.com",
            "/v1/complete",
            r#"{"model":"claude-2","prompt":"Hello"}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Anthropic"));
        assert_eq!(c.endpoint(), Some("complete"));
    }

    #[test]
    fn classify_google_gemini() {
        let p = make_post(
            "generativelanguage.googleapis.com",
            "/v1beta/models/gemini-pro:generateContent",
            r#"{"contents":[{"parts":[{"text":"hi"}]}]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Google"));
        assert_eq!(c.endpoint(), Some("gemini"));
    }

    #[test]
    fn classify_google_vertex() {
        let p = make_post(
            "aiplatform.googleapis.com",
            "/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-pro:predict",
            r#"{"instances":[{"content":"hi"}]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Google"));
        assert_eq!(c.endpoint(), Some("vertex"));
    }

    #[test]
    fn classify_azure_openai() {
        let p = make_post(
            "my-instance.openai.azure.com",
            "/openai/deployments/gpt-4/chat/completions?api-version=2024-02-01",
            r#"{"messages":[{"role":"user","content":"hi"}]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Azure"));
        assert_eq!(c.endpoint(), Some("openai"));
    }

    #[test]
    fn classify_aws_bedrock() {
        let p = make_post(
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/anthropic.claude-v2/invoke",
            r#"{"prompt":"hi","max_tokens_to_sample":100}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("AWS Bedrock"));
        assert_eq!(c.endpoint(), Some("invoke"));
    }

    #[test]
    fn classify_cohere_chat() {
        let p = make_post(
            "api.cohere.ai",
            "/v1/chat",
            r#"{"model":"command-r-plus","message":"hi"}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Cohere"));
        assert_eq!(c.endpoint(), Some("chat"));
    }

    #[test]
    fn classify_cohere_generate() {
        let p = make_post(
            "api.cohere.ai",
            "/v1/generate",
            r#"{"model":"command","prompt":"hi"}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Cohere"));
        assert_eq!(c.endpoint(), Some("generate"));
    }

    #[test]
    fn classify_cohere_embed() {
        let p = make_post(
            "api.cohere.ai",
            "/v1/embed",
            r#"{"model":"embed-english-v3.0","texts":["hi"]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Cohere"));
        assert_eq!(c.endpoint(), Some("embed"));
    }

    #[test]
    fn classify_mistral_chat() {
        let p = make_post(
            "api.mistral.ai",
            "/v1/chat/completions",
            r#"{"model":"mistral-large-latest","messages":[{"role":"user","content":"hi"}]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Mistral"));
        assert_eq!(c.endpoint(), Some("chat_completions"));
        assert_eq!(c.model(), Some("mistral-large-latest"));
    }

    #[test]
    fn classify_groq_chat() {
        let p = make_post(
            "api.groq.com",
            "/openai/v1/chat/completions",
            r#"{"model":"llama3-70b-8192","messages":[{"role":"user","content":"hi"}]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Groq"));
        assert_eq!(c.endpoint(), Some("chat_completions"));
        assert_eq!(c.model(), Some("llama3-70b-8192"));
    }

    #[test]
    fn classify_together_chat() {
        let p = make_post(
            "api.together.xyz",
            "/v1/chat/completions",
            r#"{"model":"meta-llama/Meta-Llama-3.1-70B","messages":[{"role":"user","content":"hi"}]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Together"));
        assert_eq!(c.endpoint(), Some("chat_completions"));
        assert_eq!(c.model(), Some("meta-llama/Meta-Llama-3.1-70B"));
    }

    #[test]
    fn classify_deepseek_chat() {
        let p = make_post(
            "api.deepseek.com",
            "/v1/chat/completions",
            r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("DeepSeek"));
        assert_eq!(c.endpoint(), Some("chat_completions"));
        assert_eq!(c.model(), Some("deepseek-chat"));
    }

    #[test]
    fn classify_perplexity_chat() {
        let p = make_post(
            "api.perplexity.ai",
            "/chat/completions",
            r#"{"model":"llama-3.1-sonar-large-128k-online","messages":[{"role":"user","content":"hi"}]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Perplexity"));
        assert_eq!(c.endpoint(), Some("chat_completions"));
        assert_eq!(c.model(), Some("llama-3.1-sonar-large-128k-online"));
    }

    #[test]
    fn classify_ollama_chat() {
        let p = make_post(
            "localhost:11434",
            "/api/chat",
            r#"{"model":"llama3","messages":[{"role":"user","content":"hi"}]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Ollama"));
        assert_eq!(c.endpoint(), Some("chat"));
        assert_eq!(c.model(), Some("llama3"));
    }

    #[test]
    fn classify_ollama_generate() {
        let p = make_post(
            "localhost:11434",
            "/api/generate",
            r#"{"model":"codellama","prompt":"write hello world"}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Ollama"));
        assert_eq!(c.endpoint(), Some("generate"));
    }

    #[test]
    fn classify_generic_openai_compatible() {
        let p = make_post(
            "llm-gateway.internal.corp",
            "/v1/chat/completions",
            r#"{"model":"gpt-4","messages":[]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("OpenAI-compatible"));
    }

    #[test]
    fn classify_generic_anthropic_compatible() {
        let p = make_post(
            "llm-gateway.internal.corp",
            "/v1/messages",
            r#"{"model":"claude-3","messages":[]}"#,
        );
        let c = classify(&p, Direction::Write, None);
        assert!(c.is_interesting);
        assert_eq!(c.provider(), Some("Anthropic-compatible"));
    }
}
