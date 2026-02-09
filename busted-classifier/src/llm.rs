use crate::http::HttpRequestInfo;
use crate::json::JsonFields;

/// LLM API classification result.
#[derive(Debug, Clone)]
pub struct LlmApiInfo {
    /// LLM provider name (e.g. `"OpenAI"`, `"Anthropic"`).
    pub provider: String,
    /// API endpoint identifier (e.g. `"chat_completions"`, `"messages"`).
    pub endpoint: String,
    /// Model name if extracted from the request body.
    pub model: Option<String>,
    /// Whether the request uses streaming (`stream: true`).
    pub streaming: Option<bool>,
}

/// LLM streaming response info.
#[derive(Debug, Clone)]
pub struct LlmStreamInfo {
    /// LLM provider name (e.g. `"OpenAI"`, `"Anthropic"`).
    pub provider: String,
    /// Stream format (e.g. `"sse_choices_delta"`, `"sse_content_block"`).
    pub stream_type: String,
}

/// Endpoint rule: host pattern, path prefix, HTTP method, provider, endpoint name.
struct EndpointRule {
    host: Option<&'static str>,
    path: &'static str,
    method: Option<&'static str>,
    provider: &'static str,
    endpoint: &'static str,
}

const ENDPOINT_RULES: &[EndpointRule] = &[
    // OpenAI
    EndpointRule {
        host: Some("api.openai.com"),
        path: "/v1/chat/completions",
        method: Some("POST"),
        provider: "OpenAI",
        endpoint: "chat_completions",
    },
    EndpointRule {
        host: Some("api.openai.com"),
        path: "/v1/completions",
        method: Some("POST"),
        provider: "OpenAI",
        endpoint: "completions",
    },
    EndpointRule {
        host: Some("api.openai.com"),
        path: "/v1/embeddings",
        method: Some("POST"),
        provider: "OpenAI",
        endpoint: "embeddings",
    },
    EndpointRule {
        host: Some("api.openai.com"),
        path: "/v1/images/generations",
        method: Some("POST"),
        provider: "OpenAI",
        endpoint: "images",
    },
    EndpointRule {
        host: Some("api.openai.com"),
        path: "/v1/audio",
        method: None,
        provider: "OpenAI",
        endpoint: "audio",
    },
    EndpointRule {
        host: Some("api.openai.com"),
        path: "/v1/models",
        method: None,
        provider: "OpenAI",
        endpoint: "models",
    },
    // Anthropic
    EndpointRule {
        host: Some("api.anthropic.com"),
        path: "/v1/messages",
        method: Some("POST"),
        provider: "Anthropic",
        endpoint: "messages",
    },
    EndpointRule {
        host: Some("api.anthropic.com"),
        path: "/v1/complete",
        method: Some("POST"),
        provider: "Anthropic",
        endpoint: "complete",
    },
    // Google
    EndpointRule {
        host: Some("generativelanguage.googleapis.com"),
        path: "/v1beta/models",
        method: None,
        provider: "Google",
        endpoint: "gemini",
    },
    EndpointRule {
        host: Some("generativelanguage.googleapis.com"),
        path: "/v1/models",
        method: None,
        provider: "Google",
        endpoint: "gemini",
    },
    EndpointRule {
        host: Some("aiplatform.googleapis.com"),
        path: "/v1/projects",
        method: None,
        provider: "Google",
        endpoint: "vertex",
    },
    // Azure OpenAI
    EndpointRule {
        host: None,
        path: "/openai/deployments/",
        method: None,
        provider: "Azure",
        endpoint: "openai",
    },
    // AWS Bedrock
    EndpointRule {
        host: Some("bedrock-runtime"),
        path: "/model/",
        method: Some("POST"),
        provider: "AWS Bedrock",
        endpoint: "invoke",
    },
    // Ollama
    EndpointRule {
        host: None,
        path: "/api/chat",
        method: Some("POST"),
        provider: "Ollama",
        endpoint: "chat",
    },
    EndpointRule {
        host: None,
        path: "/api/generate",
        method: Some("POST"),
        provider: "Ollama",
        endpoint: "generate",
    },
    EndpointRule {
        host: None,
        path: "/api/embeddings",
        method: Some("POST"),
        provider: "Ollama",
        endpoint: "embeddings",
    },
    // Cohere
    EndpointRule {
        host: Some("api.cohere.ai"),
        path: "/v1/chat",
        method: Some("POST"),
        provider: "Cohere",
        endpoint: "chat",
    },
    EndpointRule {
        host: Some("api.cohere.ai"),
        path: "/v1/generate",
        method: Some("POST"),
        provider: "Cohere",
        endpoint: "generate",
    },
    EndpointRule {
        host: Some("api.cohere.ai"),
        path: "/v1/embed",
        method: Some("POST"),
        provider: "Cohere",
        endpoint: "embed",
    },
    // Mistral
    EndpointRule {
        host: Some("api.mistral.ai"),
        path: "/v1/chat/completions",
        method: Some("POST"),
        provider: "Mistral",
        endpoint: "chat_completions",
    },
    // Groq
    EndpointRule {
        host: Some("api.groq.com"),
        path: "/openai/v1/chat/completions",
        method: Some("POST"),
        provider: "Groq",
        endpoint: "chat_completions",
    },
    // Together
    EndpointRule {
        host: Some("api.together.xyz"),
        path: "/v1/chat/completions",
        method: Some("POST"),
        provider: "Together",
        endpoint: "chat_completions",
    },
    // DeepSeek
    EndpointRule {
        host: Some("api.deepseek.com"),
        path: "/v1/chat/completions",
        method: Some("POST"),
        provider: "DeepSeek",
        endpoint: "chat_completions",
    },
    // Perplexity
    EndpointRule {
        host: Some("api.perplexity.ai"),
        path: "/chat/completions",
        method: Some("POST"),
        provider: "Perplexity",
        endpoint: "chat_completions",
    },
    // Generic OpenAI-compatible fallbacks (no host constraint)
    EndpointRule {
        host: None,
        path: "/v1/chat/completions",
        method: Some("POST"),
        provider: "OpenAI-compatible",
        endpoint: "chat_completions",
    },
    EndpointRule {
        host: None,
        path: "/v1/completions",
        method: Some("POST"),
        provider: "OpenAI-compatible",
        endpoint: "completions",
    },
    EndpointRule {
        host: None,
        path: "/v1/embeddings",
        method: Some("POST"),
        provider: "OpenAI-compatible",
        endpoint: "embeddings",
    },
    EndpointRule {
        host: None,
        path: "/v1/messages",
        method: Some("POST"),
        provider: "Anthropic-compatible",
        endpoint: "messages",
    },
    EndpointRule {
        host: None,
        path: "/chat/completions",
        method: Some("POST"),
        provider: "OpenAI-compatible",
        endpoint: "chat_completions",
    },
];

/// Match an HTTP request against the LLM endpoint rule table.
pub fn match_request(req: &HttpRequestInfo, sni_hint: Option<&str>) -> Option<LlmApiInfo> {
    let host = sni_hint.or_else(|| req.headers.get("host").map(|s| s.as_str()));

    // First pass: rules with host constraints (more specific)
    for rule in ENDPOINT_RULES.iter().filter(|r| r.host.is_some()) {
        if let Some(h) = host {
            let rule_host = rule.host.unwrap();
            if !h.contains(rule_host) {
                continue;
            }
        } else {
            continue;
        }

        if !req.path.starts_with(rule.path) {
            continue;
        }

        if let Some(m) = rule.method {
            if req.method != m {
                continue;
            }
        }

        return Some(LlmApiInfo {
            provider: rule.provider.to_string(),
            endpoint: rule.endpoint.to_string(),
            model: None,
            streaming: None,
        });
    }

    // Second pass: path-only fallback rules
    for rule in ENDPOINT_RULES.iter().filter(|r| r.host.is_none()) {
        if !req.path.starts_with(rule.path) {
            continue;
        }
        if let Some(m) = rule.method {
            if req.method != m {
                continue;
            }
        }
        return Some(LlmApiInfo {
            provider: rule.provider.to_string(),
            endpoint: rule.endpoint.to_string(),
            model: None,
            streaming: None,
        });
    }

    None
}

/// Match an HTTP request with JSON body fields to produce a full LLM API info.
pub fn match_request_with_body(
    req: &HttpRequestInfo,
    sni_hint: Option<&str>,
    json: &JsonFields,
) -> Option<LlmApiInfo> {
    let mut info = match_request(req, sni_hint)?;
    info.model = json.model.clone();
    info.streaming = json.stream;
    Some(info)
}

/// For responses (no HTTP request), infer provider from JSON structure.
pub fn classify_response(json: &JsonFields, sni_hint: Option<&str>) -> Option<LlmApiInfo> {
    // OpenAI-style response: has "choices"
    if json.has_choices {
        return Some(LlmApiInfo {
            provider: provider_from_sni(sni_hint).unwrap_or("OpenAI").to_string(),
            endpoint: "chat_completions".to_string(),
            model: json.model.clone(),
            streaming: None,
        });
    }

    // Anthropic-style response: has "content" array and model
    if json.has_content && json.model.is_some() {
        return Some(LlmApiInfo {
            provider: provider_from_sni(sni_hint)
                .unwrap_or("Anthropic")
                .to_string(),
            endpoint: "messages".to_string(),
            model: json.model.clone(),
            streaming: None,
        });
    }

    // Legacy completion response
    if json.has_completion {
        return Some(LlmApiInfo {
            provider: provider_from_sni(sni_hint).unwrap_or("Unknown").to_string(),
            endpoint: "completions".to_string(),
            model: json.model.clone(),
            streaming: None,
        });
    }

    None
}

/// Detect SSE streaming from payload content.
pub fn detect_sse_stream(text: &str, sni_hint: Option<&str>) -> Option<LlmStreamInfo> {
    // Check for SSE event patterns
    if text.contains("data: {") || text.contains("data:{") {
        // Anthropic SSE markers
        if text.contains("event: message_start")
            || text.contains("event: content_block")
            || text.contains("\"type\":\"message_start\"")
            || text.contains("\"type\":\"content_block_delta\"")
        {
            return Some(LlmStreamInfo {
                provider: provider_from_sni(sni_hint)
                    .unwrap_or("Anthropic")
                    .to_string(),
                stream_type: "sse".to_string(),
            });
        }

        // OpenAI-style SSE
        if text.contains("\"choices\"")
            || text.contains("\"delta\"")
            || text.contains("data: [DONE]")
        {
            return Some(LlmStreamInfo {
                provider: provider_from_sni(sni_hint).unwrap_or("OpenAI").to_string(),
                stream_type: "sse".to_string(),
            });
        }

        // Generic SSE with LLM indicators
        if text.contains("\"model\"") || text.contains("\"content\"") {
            return Some(LlmStreamInfo {
                provider: provider_from_sni(sni_hint).unwrap_or("Unknown").to_string(),
                stream_type: "sse".to_string(),
            });
        }
    }

    None
}

fn provider_from_sni(sni: Option<&str>) -> Option<&'static str> {
    let sni = sni?;
    let sni_lower = sni.to_lowercase();
    if sni_lower.contains("openai.com") {
        Some("OpenAI")
    } else if sni_lower.contains("anthropic.com") {
        Some("Anthropic")
    } else if sni_lower.contains("googleapis.com") {
        Some("Google")
    } else if sni_lower.contains("azure.com") {
        Some("Azure")
    } else if sni_lower.contains("amazonaws.com") {
        Some("AWS Bedrock")
    } else if sni_lower.contains("cohere.ai") {
        Some("Cohere")
    } else if sni_lower.contains("mistral.ai") {
        Some("Mistral")
    } else if sni_lower.contains("groq.com") {
        Some("Groq")
    } else if sni_lower.contains("together.xyz") {
        Some("Together")
    } else if sni_lower.contains("deepseek.com") {
        Some("DeepSeek")
    } else if sni_lower.contains("perplexity.ai") {
        Some("Perplexity")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http;
    use crate::json;

    #[test]
    fn test_openai_chat() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"gpt-4\",\"stream\":true}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "OpenAI");
        assert_eq!(info.endpoint, "chat_completions");
        assert_eq!(info.model.as_deref(), Some("gpt-4"));
        assert_eq!(info.streaming, Some(true));
    }

    #[test]
    fn test_anthropic_messages() {
        let raw = b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAnthropic-Version: 2024-01-01\r\n\r\n{\"model\":\"claude-3-opus\"}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "Anthropic");
        assert_eq!(info.endpoint, "messages");
        assert_eq!(info.model.as_deref(), Some("claude-3-opus"));
    }

    #[test]
    fn test_sni_override() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, Some("api.openai.com")).unwrap();
        assert_eq!(info.provider, "OpenAI");
    }

    #[test]
    fn test_generic_fallback() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: my-proxy.local\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "OpenAI-compatible");
    }

    #[test]
    fn test_ollama() {
        let raw = b"POST /api/chat HTTP/1.1\r\nHost: localhost:11434\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "Ollama");
    }

    #[test]
    fn test_response_classification() {
        let body =
            br#"{"id":"chatcmpl-123","choices":[{"message":{"content":"Hello"}}],"model":"gpt-4"}"#;
        let jf = json::analyze(body);
        let info = classify_response(&jf, Some("api.openai.com")).unwrap();
        assert_eq!(info.provider, "OpenAI");
        assert_eq!(info.model.as_deref(), Some("gpt-4"));
    }

    #[test]
    fn test_sse_detection() {
        let text = "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\ndata: [DONE]\n\n";
        let info = detect_sse_stream(text, Some("api.openai.com")).unwrap();
        assert_eq!(info.provider, "OpenAI");
        assert_eq!(info.stream_type, "sse");
    }
}
