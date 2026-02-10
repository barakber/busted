use busted_classifier::fingerprint;
use busted_classifier::http;
use busted_classifier::json;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Property: hash determinism — same request+json → same hash
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn hash_is_deterministic(
        path in "/[a-z/]{1,30}",
        model in "[a-z]{3,8}-[0-9]{1,2}",
    ) {
        let raw = format!(
            "POST {path} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test/1.0\r\n\r\n{{\"model\":\"{model}\",\"messages\":[]}}"
        );
        let req = http::parse_request(raw.as_bytes()).unwrap();
        let body = &raw.as_bytes()[req.body_offset.unwrap()..];
        let jf = json::analyze(body);

        let h1 = fingerprint::compute_signature_hash(&req, &jf);
        let h2 = fingerprint::compute_signature_hash(&req, &jf);
        prop_assert_eq!(h1, h2);
    }
}

// ---------------------------------------------------------------------------
// Property: hash sensitivity — changing any component produces different hash
// ---------------------------------------------------------------------------

#[test]
fn different_method_different_hash() {
    let raw1 = b"POST /v1/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{\"model\":\"gpt-4\"}";
    let raw2 = b"PUT /v1/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{\"model\":\"gpt-4\"}";
    let req1 = http::parse_request(raw1).unwrap();
    let req2 = http::parse_request(raw2).unwrap();
    let jf1 = json::analyze(&raw1[req1.body_offset.unwrap()..]);
    let jf2 = json::analyze(&raw2[req2.body_offset.unwrap()..]);
    assert_ne!(
        fingerprint::compute_signature_hash(&req1, &jf1),
        fingerprint::compute_signature_hash(&req2, &jf2),
    );
}

#[test]
fn different_path_different_hash() {
    let raw1 = b"POST /v1/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{\"model\":\"gpt-4\"}";
    let raw2 = b"POST /v1/embed HTTP/1.1\r\nHost: example.com\r\n\r\n{\"model\":\"gpt-4\"}";
    let req1 = http::parse_request(raw1).unwrap();
    let req2 = http::parse_request(raw2).unwrap();
    let jf1 = json::analyze(&raw1[req1.body_offset.unwrap()..]);
    let jf2 = json::analyze(&raw2[req2.body_offset.unwrap()..]);
    assert_ne!(
        fingerprint::compute_signature_hash(&req1, &jf1),
        fingerprint::compute_signature_hash(&req2, &jf2),
    );
}

#[test]
fn different_headers_different_hash() {
    let raw1 = b"POST /v1/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{\"model\":\"gpt-4\"}";
    let raw2 = b"POST /v1/chat HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test/1.0\r\n\r\n{\"model\":\"gpt-4\"}";
    let req1 = http::parse_request(raw1).unwrap();
    let req2 = http::parse_request(raw2).unwrap();
    let jf1 = json::analyze(&raw1[req1.body_offset.unwrap()..]);
    let jf2 = json::analyze(&raw2[req2.body_offset.unwrap()..]);
    assert_ne!(
        fingerprint::compute_signature_hash(&req1, &jf1),
        fingerprint::compute_signature_hash(&req2, &jf2),
    );
}

#[test]
fn different_json_keys_different_hash() {
    let raw1 =
        b"POST /v1/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{\"model\":\"gpt-4\",\"messages\":[]}";
    let raw2 = b"POST /v1/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{\"model\":\"gpt-4\",\"prompt\":\"hello\"}";
    let req1 = http::parse_request(raw1).unwrap();
    let req2 = http::parse_request(raw2).unwrap();
    let jf1 = json::analyze(&raw1[req1.body_offset.unwrap()..]);
    let jf2 = json::analyze(&raw2[req2.body_offset.unwrap()..]);
    assert_ne!(
        fingerprint::compute_signature_hash(&req1, &jf1),
        fingerprint::compute_signature_hash(&req2, &jf2),
    );
}

// ---------------------------------------------------------------------------
// SDK detection for all known patterns
// ---------------------------------------------------------------------------

#[test]
fn detect_openai_python() {
    let sdk = fingerprint::detect_sdk("openai-python/1.12.0").unwrap();
    assert_eq!(sdk.name, "openai-python");
    assert_eq!(sdk.version.as_deref(), Some("1.12.0"));
}

#[test]
fn detect_openai_node() {
    let sdk = fingerprint::detect_sdk("openai-node/4.28.0").unwrap();
    assert_eq!(sdk.name, "openai-node");
    assert_eq!(sdk.version.as_deref(), Some("4.28.0"));
}

#[test]
fn detect_openai_java() {
    let sdk = fingerprint::detect_sdk("openai-java/0.8.0").unwrap();
    assert_eq!(sdk.name, "openai-java");
    assert_eq!(sdk.version.as_deref(), Some("0.8.0"));
}

#[test]
fn detect_openai_go() {
    let sdk = fingerprint::detect_sdk("openai-go/1.0.0").unwrap();
    assert_eq!(sdk.name, "openai-go");
    assert_eq!(sdk.version.as_deref(), Some("1.0.0"));
}

#[test]
fn detect_openai_dotnet() {
    let sdk = fingerprint::detect_sdk("openai-dotnet/2.0.0").unwrap();
    assert_eq!(sdk.name, "openai-dotnet");
    assert_eq!(sdk.version.as_deref(), Some("2.0.0"));
}

#[test]
fn detect_anthropic_python() {
    let sdk = fingerprint::detect_sdk("anthropic-python/0.20.0").unwrap();
    assert_eq!(sdk.name, "anthropic-python");
    assert_eq!(sdk.version.as_deref(), Some("0.20.0"));
}

#[test]
fn detect_anthropic_typescript() {
    let sdk = fingerprint::detect_sdk("anthropic-typescript/0.20.0").unwrap();
    assert_eq!(sdk.name, "anthropic-typescript");
    assert_eq!(sdk.version.as_deref(), Some("0.20.0"));
}

#[test]
fn detect_langchain() {
    let sdk = fingerprint::detect_sdk("langchain/0.1.0").unwrap();
    assert_eq!(sdk.name, "langchain");
    assert_eq!(sdk.version.as_deref(), Some("0.1.0"));
}

#[test]
fn detect_llama_index_hyphen() {
    let sdk = fingerprint::detect_sdk("llama-index/0.9.0").unwrap();
    assert_eq!(sdk.name, "llama-index");
    assert_eq!(sdk.version.as_deref(), Some("0.9.0"));
}

#[test]
fn detect_llamaindex_no_hyphen() {
    let sdk = fingerprint::detect_sdk("llamaindex/0.10.0").unwrap();
    assert_eq!(sdk.name, "llama-index"); // Normalized name
    assert_eq!(sdk.version.as_deref(), Some("0.10.0"));
}

#[test]
fn detect_crewai() {
    let sdk = fingerprint::detect_sdk("crewai/0.1.0").unwrap();
    assert_eq!(sdk.name, "crewai");
}

#[test]
fn detect_autogen() {
    let sdk = fingerprint::detect_sdk("autogen/0.2.0").unwrap();
    assert_eq!(sdk.name, "autogen");
}

#[test]
fn detect_semantic_kernel() {
    let sdk = fingerprint::detect_sdk("semantic-kernel/1.0.0").unwrap();
    assert_eq!(sdk.name, "semantic-kernel");
}

#[test]
fn detect_curl() {
    let sdk = fingerprint::detect_sdk("curl/8.4.0").unwrap();
    assert_eq!(sdk.name, "curl");
    assert_eq!(sdk.version.as_deref(), Some("8.4.0"));
}

#[test]
fn detect_python_requests() {
    let sdk = fingerprint::detect_sdk("python-requests/2.31.0").unwrap();
    assert_eq!(sdk.name, "python-requests");
    assert_eq!(sdk.version.as_deref(), Some("2.31.0"));
}

// ---------------------------------------------------------------------------
// SDK detection: case insensitivity
// ---------------------------------------------------------------------------

#[test]
fn detect_sdk_case_insensitive() {
    let sdk = fingerprint::detect_sdk("OpenAI-Python/1.12.0").unwrap();
    assert_eq!(sdk.name, "openai-python");
    assert_eq!(sdk.version.as_deref(), Some("1.12.0"));
}

// ---------------------------------------------------------------------------
// SDK detection: embedded in longer UA string
// ---------------------------------------------------------------------------

#[test]
fn detect_sdk_embedded_in_ua() {
    let sdk = fingerprint::detect_sdk("Mozilla/5.0 langchain/0.1.0 (Linux)").unwrap();
    assert_eq!(sdk.name, "langchain");
    assert_eq!(sdk.version.as_deref(), Some("0.1.0"));
}

// ---------------------------------------------------------------------------
// Version extraction formats
// ---------------------------------------------------------------------------

#[test]
fn version_with_slash() {
    let sdk = fingerprint::detect_sdk("openai-python/1.2.3").unwrap();
    assert_eq!(sdk.version.as_deref(), Some("1.2.3"));
}

#[test]
fn version_with_space() {
    let sdk = fingerprint::detect_sdk("openai-python 1.2.3").unwrap();
    assert_eq!(sdk.version.as_deref(), Some("1.2.3"));
}

#[test]
fn version_with_prerelease() {
    let sdk = fingerprint::detect_sdk("openai-python/1.2.3-beta").unwrap();
    assert_eq!(sdk.version.as_deref(), Some("1.2.3-beta"));
}

#[test]
fn version_with_build_metadata() {
    let sdk = fingerprint::detect_sdk("openai-python/1.2.3-beta.1").unwrap();
    assert_eq!(sdk.version.as_deref(), Some("1.2.3-beta.1"));
}

// ---------------------------------------------------------------------------
// Unknown user agents → None
// ---------------------------------------------------------------------------

#[test]
fn unknown_ua_returns_none() {
    assert!(fingerprint::detect_sdk("Mozilla/5.0 (Linux)").is_none());
    assert!(fingerprint::detect_sdk("MyCustomApp/1.0").is_none());
    assert!(fingerprint::detect_sdk("").is_none());
}

// ---------------------------------------------------------------------------
// API version extraction
// ---------------------------------------------------------------------------

#[test]
fn extract_anthropic_version() {
    let mut headers = std::collections::HashMap::new();
    headers.insert("anthropic-version".to_string(), "2024-01-01".to_string());
    assert_eq!(
        fingerprint::extract_api_version(&headers),
        Some("2024-01-01".to_string())
    );
}

#[test]
fn no_api_version_header() {
    let headers = std::collections::HashMap::new();
    assert!(fingerprint::extract_api_version(&headers).is_none());
}

#[test]
fn non_anthropic_headers_no_api_version() {
    let mut headers = std::collections::HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("host".to_string(), "api.openai.com".to_string());
    assert!(fingerprint::extract_api_version(&headers).is_none());
}

// ---------------------------------------------------------------------------
// build_fingerprint integration
// ---------------------------------------------------------------------------

#[test]
fn build_fingerprint_full() {
    let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nUser-Agent: openai-python/1.12.0\r\nAnthropic-Version: 2024-01-01\r\n\r\n{\"model\":\"gpt-4\",\"temperature\":0.7,\"max_tokens\":100,\"stream\":true}";
    let req = http::parse_request(raw).unwrap();
    let body = &raw[req.body_offset.unwrap()..];
    let jf = json::analyze(body);
    let fp = fingerprint::build_fingerprint(&req, &jf);

    assert_eq!(fp.sdk.as_ref().unwrap().name, "openai-python");
    assert_eq!(fp.api_version.as_deref(), Some("2024-01-01"));
    assert_eq!(fp.model_params.model.as_deref(), Some("gpt-4"));
    assert!((fp.model_params.temperature.unwrap() - 0.7).abs() < f64::EPSILON);
    assert_eq!(fp.model_params.max_tokens, Some(100));
    assert_eq!(fp.model_params.stream, Some(true));
    assert_ne!(fp.signature_hash, 0);
}

#[test]
fn build_fingerprint_no_ua() {
    let raw =
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{\"model\":\"gpt-4\"}";
    let req = http::parse_request(raw).unwrap();
    let body = &raw[req.body_offset.unwrap()..];
    let jf = json::analyze(body);
    let fp = fingerprint::build_fingerprint(&req, &jf);

    assert!(fp.sdk.is_none());
    assert_eq!(fp.model_params.model.as_deref(), Some("gpt-4"));
}

// ---------------------------------------------------------------------------
// Property: build_fingerprint is deterministic
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn build_fingerprint_deterministic(
        model in "[a-z]{3,8}",
    ) {
        let raw = format!(
            "POST /v1/chat HTTP/1.1\r\nHost: example.com\r\nUser-Agent: openai-python/1.0\r\n\r\n{{\"model\":\"{model}\"}}"
        );
        let req = http::parse_request(raw.as_bytes()).unwrap();
        let body = &raw.as_bytes()[req.body_offset.unwrap()..];
        let jf = json::analyze(body);

        let fp1 = fingerprint::build_fingerprint(&req, &jf);
        let fp2 = fingerprint::build_fingerprint(&req, &jf);
        prop_assert_eq!(fp1.signature_hash, fp2.signature_hash);
        prop_assert_eq!(fp1.sdk.as_ref().map(|s| &s.name), fp2.sdk.as_ref().map(|s| &s.name));
    }
}

// ---------------------------------------------------------------------------
// Unit: multiple SDK patterns in one User-Agent — first match wins
// ---------------------------------------------------------------------------

#[test]
fn multiple_sdk_patterns_first_wins() {
    // UA contains both "openai-python" and "langchain" — openai-python is checked first
    let sdk = fingerprint::detect_sdk("openai-python/1.0 langchain/0.1").unwrap();
    assert_eq!(sdk.name, "openai-python");
    assert_eq!(sdk.version.as_deref(), Some("1.0"));
}

// ---------------------------------------------------------------------------
// Unit: SDK name without version separator → version is None
// ---------------------------------------------------------------------------

#[test]
fn sdk_name_without_version_separator() {
    // "langchain" followed by no separator character → version None
    let sdk = fingerprint::detect_sdk("MyApp langchain").unwrap();
    assert_eq!(sdk.name, "langchain");
    // No '/' or ' ' followed by a version → None
    assert!(sdk.version.is_none());
}

// ---------------------------------------------------------------------------
// Unit: version with +build suffix is truncated at +
// ---------------------------------------------------------------------------

#[test]
fn version_with_build_suffix_truncated() {
    // extract_version uses take_while(alphanumeric || '.' || '-')
    // '+' is not in that set, so the version stops at '+'
    let sdk = fingerprint::detect_sdk("openai-python/1.2.3+build42").unwrap();
    assert_eq!(sdk.version.as_deref(), Some("1.2.3"));
}

// ---------------------------------------------------------------------------
// Unit: signature hash with no interesting headers
// ---------------------------------------------------------------------------

#[test]
fn signature_hash_no_headers() {
    let req = http::HttpRequestInfo {
        method: "POST".to_string(),
        path: "/v1/test".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::HashMap::new(),
        body_offset: None,
    };
    let jf = json::JsonFields::default();
    let h = fingerprint::compute_signature_hash(&req, &jf);
    // Should produce a valid hash (not the FNV offset basis alone since method+path are hashed)
    assert_ne!(h, 0);
}

// ---------------------------------------------------------------------------
// Unit: signature hash with empty top_level_keys
// ---------------------------------------------------------------------------

#[test]
fn signature_hash_empty_keys() {
    let req = http::HttpRequestInfo {
        method: "GET".to_string(),
        path: "/health".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::HashMap::from([("host".to_string(), "example.com".to_string())]),
        body_offset: None,
    };
    let jf = json::JsonFields {
        top_level_keys: vec![],
        ..Default::default()
    };
    let h = fingerprint::compute_signature_hash(&req, &jf);
    assert_ne!(h, 0);

    // Adding a key should change the hash
    let jf2 = json::JsonFields {
        top_level_keys: vec!["model".to_string()],
        ..Default::default()
    };
    let h2 = fingerprint::compute_signature_hash(&req, &jf2);
    assert_ne!(h, h2);
}

// ---------------------------------------------------------------------------
// Unit: build_fingerprint with no body (body_offset=None)
// ---------------------------------------------------------------------------

#[test]
fn build_fingerprint_no_body() {
    let req = http::HttpRequestInfo {
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::HashMap::from([
            ("host".to_string(), "api.openai.com".to_string()),
            ("user-agent".to_string(), "openai-python/1.0.0".to_string()),
        ]),
        body_offset: None,
    };
    // No body → empty JsonFields
    let jf = json::JsonFields::default();
    let fp = fingerprint::build_fingerprint(&req, &jf);

    assert_eq!(fp.sdk.as_ref().unwrap().name, "openai-python");
    assert!(fp.model_params.model.is_none());
    assert!(fp.model_params.temperature.is_none());
    assert_ne!(fp.signature_hash, 0);
}

// ---------------------------------------------------------------------------
// Unit: empty headers map → no SDK, no API version
// ---------------------------------------------------------------------------

#[test]
fn empty_headers_map() {
    let req = http::HttpRequestInfo {
        method: "POST".to_string(),
        path: "/test".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: std::collections::HashMap::new(),
        body_offset: None,
    };
    let jf = json::JsonFields::default();
    let fp = fingerprint::build_fingerprint(&req, &jf);

    assert!(fp.sdk.is_none());
    assert!(fp.api_version.is_none());
}
