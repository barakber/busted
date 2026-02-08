use crate::http::HttpRequestInfo;
use crate::json::JsonFields;

/// SDK/agent info extracted from User-Agent header.
#[derive(Debug, Clone)]
pub struct SdkInfo {
    pub name: String,
    pub version: Option<String>,
}

/// Model parameters extracted from the request body.
#[derive(Debug, Clone, Default)]
pub struct ModelParams {
    pub model: Option<String>,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u64>,
    pub stream: Option<bool>,
}

/// Complete agent fingerprint.
#[derive(Debug, Clone)]
pub struct AgentFingerprint {
    pub sdk: Option<SdkInfo>,
    pub api_version: Option<String>,
    pub model_params: ModelParams,
    pub signature_hash: u64,
}

/// Known SDK patterns in User-Agent strings: (substring, sdk_name).
const SDK_PATTERNS: &[(&str, &str)] = &[
    ("openai-python", "openai-python"),
    ("openai-node", "openai-node"),
    ("openai-java", "openai-java"),
    ("openai-go", "openai-go"),
    ("openai-dotnet", "openai-dotnet"),
    ("anthropic-python", "anthropic-python"),
    ("anthropic-typescript", "anthropic-typescript"),
    ("langchain", "langchain"),
    ("llama-index", "llama-index"),
    ("llamaindex", "llama-index"),
    ("crewai", "crewai"),
    ("autogen", "autogen"),
    ("semantic-kernel", "semantic-kernel"),
    ("curl", "curl"),
    ("python-requests", "python-requests"),
];

/// Detect SDK from a User-Agent string.
pub fn detect_sdk(user_agent: &str) -> Option<SdkInfo> {
    let ua_lower = user_agent.to_lowercase();

    for &(pattern, name) in SDK_PATTERNS {
        if ua_lower.contains(pattern) {
            let version = extract_version(user_agent, pattern);
            return Some(SdkInfo {
                name: name.to_string(),
                version,
            });
        }
    }

    None
}

/// Extract version string following an SDK name pattern.
/// Looks for patterns like "sdk-name/1.2.3" or "sdk-name 1.2.3".
fn extract_version(ua: &str, pattern: &str) -> Option<String> {
    let lower = ua.to_lowercase();
    let idx = lower.find(pattern)?;
    let after = &ua[idx + pattern.len()..];

    // Skip separator (/ or space)
    let after = after.strip_prefix('/').or_else(|| after.strip_prefix(' '))?;

    // Take version chars (digits, dots, dashes, alphanumeric)
    let version: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect();

    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

/// Extract API version from provider-specific headers.
pub fn extract_api_version(headers: &std::collections::HashMap<String, String>) -> Option<String> {
    // Anthropic
    if let Some(v) = headers.get("anthropic-version") {
        return Some(v.clone());
    }
    // OpenAI doesn't have a version header but has organization
    // Azure has api-version query param (not in headers usually)
    None
}

/// Compute FNV-1a hash of the request "shape" for fingerprinting.
///
/// Hashes: method + path + sorted header names + ordered JSON body keys.
/// Different SDKs produce different key orderings and header sets.
pub fn compute_signature_hash(
    req: &HttpRequestInfo,
    json: &JsonFields,
) -> u64 {
    let mut hasher = Fnv1a::new();

    // Method + path
    hasher.write(req.method.as_bytes());
    hasher.write(req.path.as_bytes());

    // Sorted header names (not values — values change per request)
    let mut header_names: Vec<&str> = req.headers.keys().map(|k| k.as_str()).collect();
    header_names.sort();
    for name in header_names {
        hasher.write(name.as_bytes());
    }

    // Ordered JSON body keys (order matters — it's SDK-specific)
    for key in &json.top_level_keys {
        hasher.write(key.as_bytes());
    }

    hasher.finish()
}

/// Build a complete fingerprint from HTTP request and JSON body.
pub fn build_fingerprint(
    req: &HttpRequestInfo,
    json: &JsonFields,
) -> AgentFingerprint {
    let sdk = req
        .headers
        .get("user-agent")
        .and_then(|ua| detect_sdk(ua));

    let api_version = extract_api_version(&req.headers);

    let model_params = ModelParams {
        model: json.model.clone(),
        temperature: json.temperature,
        max_tokens: json.max_tokens,
        stream: json.stream,
    };

    let signature_hash = compute_signature_hash(req, json);

    AgentFingerprint {
        sdk,
        api_version,
        model_params,
        signature_hash,
    }
}

/// FNV-1a 64-bit hasher.
struct Fnv1a {
    state: u64,
}

impl Fnv1a {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001B3;

    fn new() -> Self {
        Fnv1a {
            state: Self::OFFSET_BASIS,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state ^= byte as u64;
            self.state = self.state.wrapping_mul(Self::PRIME);
        }
    }

    fn finish(&self) -> u64 {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_openai_python() {
        let sdk = detect_sdk("openai-python/1.12.0").unwrap();
        assert_eq!(sdk.name, "openai-python");
        assert_eq!(sdk.version.as_deref(), Some("1.12.0"));
    }

    #[test]
    fn test_detect_anthropic_typescript() {
        let sdk = detect_sdk("anthropic-typescript/0.20.0").unwrap();
        assert_eq!(sdk.name, "anthropic-typescript");
        assert_eq!(sdk.version.as_deref(), Some("0.20.0"));
    }

    #[test]
    fn test_detect_langchain() {
        let sdk = detect_sdk("Mozilla/5.0 langchain/0.1.0").unwrap();
        assert_eq!(sdk.name, "langchain");
        assert_eq!(sdk.version.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn test_detect_curl() {
        let sdk = detect_sdk("curl/8.4.0").unwrap();
        assert_eq!(sdk.name, "curl");
        assert_eq!(sdk.version.as_deref(), Some("8.4.0"));
    }

    #[test]
    fn test_unknown_agent() {
        assert!(detect_sdk("Mozilla/5.0 (Linux)").is_none());
    }

    #[test]
    fn test_signature_hash_stability() {
        use crate::http;
        use crate::json;

        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nUser-Agent: openai-python/1.12.0\r\n\r\n{\"model\":\"gpt-4\",\"messages\":[]}";
        let req = http::parse_request(raw).unwrap();
        let body = &raw[req.body_offset.unwrap()..];
        let jf = json::analyze(body);

        let h1 = compute_signature_hash(&req, &jf);
        let h2 = compute_signature_hash(&req, &jf);
        assert_eq!(h1, h2); // Same input → same hash

        // Different path → different hash
        let raw2 = b"POST /v1/embeddings HTTP/1.1\r\nHost: api.openai.com\r\nUser-Agent: openai-python/1.12.0\r\n\r\n{\"model\":\"gpt-4\",\"messages\":[]}";
        let req2 = http::parse_request(raw2).unwrap();
        let h3 = compute_signature_hash(&req2, &jf);
        assert_ne!(h1, h3);
    }
}
