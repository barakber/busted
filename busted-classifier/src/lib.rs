//! `busted-classifier` — Standalone content classification for decrypted TLS payloads.
//!
//! Performs structured HTTP parsing, JSON analysis, LLM endpoint matching,
//! MCP protocol detection, agent fingerprinting, and optional PII detection.

pub mod fingerprint;
pub mod http;
pub mod json;
pub mod llm;
pub mod mcp;
pub mod pii;

use fingerprint::AgentFingerprint;
use llm::{LlmApiInfo, LlmStreamInfo};
use mcp::McpInfo;
use pii::PiiFlags;

// Re-export key types
pub use fingerprint::{ModelParams, SdkInfo};
pub use mcp::{McpCategory, McpMsgType};

/// Direction of TLS data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Write,
    Read,
}

/// Layer 1: Protocol detection result.
#[derive(Debug, Clone)]
pub enum Protocol {
    Http1Request(http::HttpRequestInfo),
    Http1Response(http::HttpResponseInfo),
    Sse,
    Http2Binary,
    Binary,
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
        return (
            Some(ContentClass::Mcp(mcp_info)),
            Some(fp),
            0.95,
        );
    }

    // Check for LLM API endpoint
    if let Some(llm_info) = llm::match_request_with_body(req, sni_hint, jf) {
        let fp = fingerprint::build_fingerprint(req, jf);
        return (
            Some(ContentClass::LlmApi(llm_info)),
            Some(fp),
            0.9,
        );
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
        return (
            Some(ContentClass::LlmApi(info)),
            Some(fp),
            confidence,
        );
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
}
