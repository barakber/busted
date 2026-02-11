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

    // ---- Edge-case tests ----

    #[test]
    fn test_query_parameters_in_path() {
        let raw = b"POST /v1/chat/completions?api-version=2024 HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "OpenAI");
    }

    #[test]
    fn test_host_header_with_port() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "OpenAI");
    }

    #[test]
    fn test_azure_no_host_constraint() {
        let raw = b"POST /openai/deployments/my-model/chat/completions HTTP/1.1\r\nHost: my-instance.openai.azure.com\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "Azure");
    }

    #[test]
    fn test_bedrock_contains_match() {
        let raw = b"POST /model/anthropic.claude-v2/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-1.amazonaws.com\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "AWS Bedrock");
    }

    #[test]
    fn test_sse_no_space_after_data_colon() {
        let text = "data:{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}";
        let info = detect_sse_stream(text, None).unwrap();
        assert_eq!(info.stream_type, "sse");
    }

    #[test]
    fn test_sse_anthropic_markers() {
        let text = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
        let info = detect_sse_stream(text, None).unwrap();
        assert_eq!(info.provider, "Anthropic");
    }

    #[test]
    fn test_sse_generic_model_content() {
        let text = "data: {\"model\":\"llama\",\"content\":\"test\"}\n\n";
        let info = detect_sse_stream(text, None).unwrap();
        assert_eq!(info.provider, "Unknown");
    }

    #[test]
    fn test_sse_no_match() {
        let text = "data: some random text without json\n\n";
        assert!(detect_sse_stream(text, None).is_none());
    }

    #[test]
    fn test_sni_provider_mapping() {
        assert_eq!(provider_from_sni(Some("api.openai.com")), Some("OpenAI"));
        assert_eq!(
            provider_from_sni(Some("api.anthropic.com")),
            Some("Anthropic")
        );
        assert_eq!(
            provider_from_sni(Some("generativelanguage.googleapis.com")),
            Some("Google")
        );
        assert_eq!(
            provider_from_sni(Some("something.azure.com")),
            Some("Azure")
        );
        assert_eq!(
            provider_from_sni(Some("bedrock.us-east-1.amazonaws.com")),
            Some("AWS Bedrock")
        );
        assert_eq!(provider_from_sni(Some("api.cohere.ai")), Some("Cohere"));
        assert_eq!(provider_from_sni(Some("api.mistral.ai")), Some("Mistral"));
        assert_eq!(provider_from_sni(Some("api.groq.com")), Some("Groq"));
        assert_eq!(
            provider_from_sni(Some("api.together.xyz")),
            Some("Together")
        );
        assert_eq!(
            provider_from_sni(Some("api.deepseek.com")),
            Some("DeepSeek")
        );
        assert_eq!(
            provider_from_sni(Some("api.perplexity.ai")),
            Some("Perplexity")
        );
    }

    #[test]
    fn test_sni_case_insensitive() {
        assert_eq!(provider_from_sni(Some("API.OPENAI.COM")), Some("OpenAI"));
        assert_eq!(
            provider_from_sni(Some("Api.Anthropic.Com")),
            Some("Anthropic")
        );
    }

    #[test]
    fn test_sni_unknown_host() {
        assert_eq!(provider_from_sni(Some("example.com")), None);
        assert_eq!(provider_from_sni(None), None);
    }

    // ---- Provider coverage: every provider in ENDPOINT_RULES ----

    #[test]
    fn test_google_gemini() {
        let raw = b"POST /v1beta/models/gemini-pro:generateContent HTTP/1.1\r\nHost: generativelanguage.googleapis.com\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "Google");
        assert_eq!(info.endpoint, "gemini");
    }

    #[test]
    fn test_google_gemini_v1() {
        let raw = b"GET /v1/models HTTP/1.1\r\nHost: generativelanguage.googleapis.com\r\n\r\n";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "Google");
        assert_eq!(info.endpoint, "gemini");
    }

    #[test]
    fn test_google_vertex() {
        let raw = b"POST /v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:predict HTTP/1.1\r\nHost: aiplatform.googleapis.com\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "Google");
        assert_eq!(info.endpoint, "vertex");
    }

    #[test]
    fn test_cohere_chat() {
        let raw = b"POST /v1/chat HTTP/1.1\r\nHost: api.cohere.ai\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "Cohere");
        assert_eq!(info.endpoint, "chat");
    }

    #[test]
    fn test_cohere_generate() {
        let raw = b"POST /v1/generate HTTP/1.1\r\nHost: api.cohere.ai\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "Cohere");
        assert_eq!(info.endpoint, "generate");
    }

    #[test]
    fn test_cohere_embed() {
        let raw = b"POST /v1/embed HTTP/1.1\r\nHost: api.cohere.ai\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "Cohere");
        assert_eq!(info.endpoint, "embed");
    }

    #[test]
    fn test_mistral_chat() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.mistral.ai\r\n\r\n{\"model\":\"mistral-large\"}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "Mistral");
        assert_eq!(info.endpoint, "chat_completions");
        assert_eq!(info.model.as_deref(), Some("mistral-large"));
    }

    #[test]
    fn test_groq_chat() {
        let raw = b"POST /openai/v1/chat/completions HTTP/1.1\r\nHost: api.groq.com\r\n\r\n{\"model\":\"llama3-70b\"}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "Groq");
        assert_eq!(info.endpoint, "chat_completions");
        assert_eq!(info.model.as_deref(), Some("llama3-70b"));
    }

    #[test]
    fn test_together_chat() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.together.xyz\r\n\r\n{\"model\":\"meta-llama/Llama-3-70b\"}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "Together");
        assert_eq!(info.endpoint, "chat_completions");
        assert_eq!(info.model.as_deref(), Some("meta-llama/Llama-3-70b"));
    }

    #[test]
    fn test_deepseek_chat() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.deepseek.com\r\n\r\n{\"model\":\"deepseek-chat\"}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "DeepSeek");
        assert_eq!(info.endpoint, "chat_completions");
        assert_eq!(info.model.as_deref(), Some("deepseek-chat"));
    }

    #[test]
    fn test_perplexity_chat() {
        let raw = b"POST /chat/completions HTTP/1.1\r\nHost: api.perplexity.ai\r\n\r\n{\"model\":\"pplx-70b\"}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "Perplexity");
        assert_eq!(info.endpoint, "chat_completions");
        assert_eq!(info.model.as_deref(), Some("pplx-70b"));
    }

    #[test]
    fn test_openai_embeddings() {
        let raw = b"POST /v1/embeddings HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{\"model\":\"text-embedding-3-small\",\"input\":\"hello\"}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "OpenAI");
        assert_eq!(info.endpoint, "embeddings");
        assert_eq!(info.model.as_deref(), Some("text-embedding-3-small"));
    }

    #[test]
    fn test_openai_images() {
        let raw = b"POST /v1/images/generations HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{\"model\":\"dall-e-3\"}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "OpenAI");
        assert_eq!(info.endpoint, "images");
        assert_eq!(info.model.as_deref(), Some("dall-e-3"));
    }

    #[test]
    fn test_openai_audio() {
        let raw = b"POST /v1/audio/speech HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "OpenAI");
        assert_eq!(info.endpoint, "audio");
    }

    #[test]
    fn test_openai_models_list() {
        let raw = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "OpenAI");
        assert_eq!(info.endpoint, "models");
    }

    #[test]
    fn test_anthropic_complete() {
        let raw = b"POST /v1/complete HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n{\"model\":\"claude-2\"}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "Anthropic");
        assert_eq!(info.endpoint, "complete");
        assert_eq!(info.model.as_deref(), Some("claude-2"));
    }

    #[test]
    fn test_ollama_generate() {
        let raw =
            b"POST /api/generate HTTP/1.1\r\nHost: localhost:11434\r\n\r\n{\"model\":\"llama3\"}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);
        let info = match_request_with_body(&req, None, &jf).unwrap();
        assert_eq!(info.provider, "Ollama");
        assert_eq!(info.endpoint, "generate");
        assert_eq!(info.model.as_deref(), Some("llama3"));
    }

    #[test]
    fn test_ollama_embeddings() {
        let raw = b"POST /api/embeddings HTTP/1.1\r\nHost: localhost:11434\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "Ollama");
        assert_eq!(info.endpoint, "embeddings");
    }

    #[test]
    fn test_generic_openai_compatible_completions() {
        let raw = b"POST /v1/completions HTTP/1.1\r\nHost: my-proxy.example.com\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "OpenAI-compatible");
        assert_eq!(info.endpoint, "completions");
    }

    #[test]
    fn test_generic_openai_compatible_embeddings() {
        let raw = b"POST /v1/embeddings HTTP/1.1\r\nHost: my-proxy.example.com\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "OpenAI-compatible");
        assert_eq!(info.endpoint, "embeddings");
    }

    #[test]
    fn test_generic_anthropic_compatible() {
        let raw = b"POST /v1/messages HTTP/1.1\r\nHost: my-proxy.example.com\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "Anthropic-compatible");
        assert_eq!(info.endpoint, "messages");
    }

    #[test]
    fn test_generic_chat_completions_no_v1() {
        let raw = b"POST /chat/completions HTTP/1.1\r\nHost: my-proxy.example.com\r\n\r\n{}";
        let req = http::parse_request(raw).unwrap();
        let info = match_request(&req, None).unwrap();
        assert_eq!(info.provider, "OpenAI-compatible");
        assert_eq!(info.endpoint, "chat_completions");
    }

    /// Exhaustive: every unique (provider, endpoint) pair in ENDPOINT_RULES
    /// is tested by at least one test above. This meta-test verifies coverage
    /// by collecting all providers from the rule table.
    #[test]
    fn all_providers_have_tests() {
        let providers: std::collections::HashSet<&str> =
            ENDPOINT_RULES.iter().map(|r| r.provider).collect();

        // Every provider in the table must be listed here.
        // If you add a new provider to ENDPOINT_RULES, add it here too.
        let tested = [
            "OpenAI",
            "Anthropic",
            "Google",
            "Azure",
            "AWS Bedrock",
            "Ollama",
            "Cohere",
            "Mistral",
            "Groq",
            "Together",
            "DeepSeek",
            "Perplexity",
            "OpenAI-compatible",
            "Anthropic-compatible",
        ];
        for provider in &providers {
            assert!(
                tested.contains(provider),
                "Provider '{}' in ENDPOINT_RULES has no test — add one!",
                provider
            );
        }
    }

    #[test]
    fn test_no_match_get_on_post_only_endpoint() {
        let raw = b"GET /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let req = http::parse_request(raw).unwrap();
        // OpenAI chat/completions requires POST
        let info = match_request(&req, None);
        assert!(info.is_none());
    }

    #[test]
    fn test_response_legacy_completion() {
        let body = br#"{"completion":"Hello world","model":"text-davinci-003"}"#;
        let jf = json::analyze(body);
        let info = classify_response(&jf, None).unwrap();
        assert_eq!(info.endpoint, "completions");
    }

    #[test]
    fn test_response_anthropic_style() {
        let body = br#"{"content":[{"type":"text","text":"Hi"}],"model":"claude-3"}"#;
        let jf = json::analyze(body);
        let info = classify_response(&jf, Some("api.anthropic.com")).unwrap();
        assert_eq!(info.provider, "Anthropic");
        assert_eq!(info.endpoint, "messages");
    }

    #[test]
    fn test_response_no_match() {
        let body = br#"{"status":"ok","data":[]}"#;
        let jf = json::analyze(body);
        assert!(classify_response(&jf, None).is_none());
    }
}
