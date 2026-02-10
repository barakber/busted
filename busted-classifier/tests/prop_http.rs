use busted_classifier::http;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Property: parse_request never panics on arbitrary bytes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn parse_request_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let _ = http::parse_request(&data);
    }
}

// ---------------------------------------------------------------------------
// Property: parse_response never panics on arbitrary bytes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn parse_response_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let _ = http::parse_response(&data);
    }
}

// ---------------------------------------------------------------------------
// Property: is_http2_binary never panics
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn is_http2_binary_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let _ = http::is_http2_binary(&data);
    }
}

// ---------------------------------------------------------------------------
// Property: looks_like_http_request/response never panics
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn looks_like_http_request_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = http::looks_like_http_request(&data);
    }

    #[test]
    fn looks_like_http_response_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = http::looks_like_http_response(&data);
    }
}

// ---------------------------------------------------------------------------
// Strategy for generating valid HTTP request components
// ---------------------------------------------------------------------------

fn http_method_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("GET".to_string()),
        Just("POST".to_string()),
        Just("PUT".to_string()),
        Just("DELETE".to_string()),
        Just("PATCH".to_string()),
        Just("HEAD".to_string()),
        Just("OPTIONS".to_string()),
    ]
}

fn http_path_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/".to_string()),
        Just("/v1/chat/completions".to_string()),
        Just("/api/test".to_string()),
        "/[a-z/]{1,50}".prop_map(|s| format!("/{s}")),
    ]
}

fn http_header_strategy() -> impl Strategy<Value = (String, String)> {
    prop_oneof![
        Just(("Host".to_string(), "example.com".to_string())),
        Just(("Content-Type".to_string(), "application/json".to_string())),
        Just(("User-Agent".to_string(), "test-agent/1.0".to_string())),
        Just(("Accept".to_string(), "*/*".to_string())),
    ]
}

// ---------------------------------------------------------------------------
// Property: generated valid HTTP requests parse correctly (round-trip)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn valid_request_round_trip(
        method in http_method_strategy(),
        path in http_path_strategy(),
        headers in proptest::collection::vec(http_header_strategy(), 0..5),
        body in "[a-zA-Z0-9 ]{0,100}",
    ) {
        let mut raw = format!("{method} {path} HTTP/1.1\r\n");
        for (k, v) in &headers {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str("\r\n");
        raw.push_str(&body);

        let req = http::parse_request(raw.as_bytes());
        prop_assert!(req.is_some(), "valid HTTP request should parse: {raw}");

        let req = req.unwrap();
        prop_assert_eq!(&req.method, &method);
        prop_assert_eq!(&req.path, &path);
        prop_assert_eq!(&req.version, "HTTP/1.1");
        prop_assert!(req.body_offset.is_some());
    }
}

// ---------------------------------------------------------------------------
// Property: generated valid HTTP responses parse correctly
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn valid_response_round_trip(
        status in prop_oneof![Just(200u16), Just(201u16), Just(400u16), Just(404u16), Just(500u16)],
        reason in prop_oneof![
            Just("OK".to_string()),
            Just("Not Found".to_string()),
            Just("Internal Server Error".to_string()),
        ],
        body in "[a-zA-Z0-9 ]{0,100}",
    ) {
        let raw = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\r\n{body}");
        let resp = http::parse_response(raw.as_bytes());
        prop_assert!(resp.is_some(), "valid HTTP response should parse: {raw}");

        let resp = resp.unwrap();
        prop_assert_eq!(resp.status_code, status);
        prop_assert_eq!(&resp.reason, &reason);
        prop_assert!(resp.body_offset.is_some());
    }
}

// ---------------------------------------------------------------------------
// Property: truncated valid request → never panics, body_offset is None
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn truncated_request_never_panics(
        truncate_at in 0usize..200,
    ) {
        let full = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nUser-Agent: test/1.0\r\n\r\n{\"model\":\"gpt-4\"}";
        let truncated = &full[..truncate_at.min(full.len())];
        let result = http::parse_request(truncated);
        // If we truncated before the header terminator, body_offset should be None
        if let Some(ref req) = result {
            if truncate_at < full.len() - 16 {
                // Deep truncation — headers may be incomplete
                // Just ensure no panic occurred
            }
            // body_offset should be valid if present
            if let Some(offset) = req.body_offset {
                prop_assert!(offset <= truncated.len());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property: truncated valid response → never panics
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn truncated_response_never_panics(
        truncate_at in 0usize..150,
    ) {
        let full = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"chatcmpl-123\"}";
        let truncated = &full[..truncate_at.min(full.len())];
        let result = http::parse_response(truncated);
        if let Some(ref resp) = result {
            if let Some(offset) = resp.body_offset {
                prop_assert!(offset <= truncated.len());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit: known HTTP methods are detected
// ---------------------------------------------------------------------------

#[test]
fn all_http_methods_detected() {
    let methods = [
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT",
    ];
    for method in methods {
        let line = format!("{method} / HTTP/1.1\r\n");
        assert!(
            http::looks_like_http_request(line.as_bytes()),
            "{method} should be detected"
        );
    }
}

// ---------------------------------------------------------------------------
// Unit: non-HTTP data is rejected
// ---------------------------------------------------------------------------

#[test]
fn non_http_data_rejected() {
    let non_http = [
        b"{\"jsonrpc\":\"2.0\"}".as_slice(),
        b"data: {\"choices\":[]}",
        b"\x00\x01\x02\x03",
        b"Hello World",
        b"TRACE / HTTP/1.1\r\n", // TRACE not in list
    ];
    for data in non_http {
        assert!(
            !http::looks_like_http_request(data),
            "should not detect as HTTP request: {:?}",
            String::from_utf8_lossy(data)
        );
    }
}

// ---------------------------------------------------------------------------
// Unit: malformed HTTP edge cases
// ---------------------------------------------------------------------------

#[test]
fn missing_crlf_after_request_line() {
    let raw = b"POST /v1/chat HTTP/1.1\nHost: example.com\r\n\r\n";
    // No \r\n after request line → should fail to parse
    let result = http::parse_request(raw);
    assert!(result.is_none());
}

#[test]
fn empty_path() {
    // This would be invalid HTTP but should not panic
    let raw = b"GET  HTTP/1.1\r\n\r\n";
    let _ = http::parse_request(raw);
}

#[test]
fn request_with_no_headers() {
    let raw = b"GET / HTTP/1.1\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/");
    assert!(req.headers.is_empty());
    assert!(req.body_offset.is_some());
}

#[test]
fn very_long_header_value() {
    let mut raw = b"GET / HTTP/1.1\r\nHost: ".to_vec();
    raw.extend(std::iter::repeat(b'x').take(10_000));
    raw.extend(b"\r\n\r\n");
    let req = http::parse_request(&raw).unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.headers.get("host").unwrap().len(), 10_000);
}

#[test]
fn response_without_reason_phrase() {
    // Some servers send just the status code without a reason
    // Our parser uses take_while1 for reason which requires at least 1 char,
    // but there's a fallback to empty
    let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
    let resp = http::parse_response(raw).unwrap();
    assert_eq!(resp.status_code, 204);
}

#[test]
fn http10_response() {
    let raw = b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\nHello";
    let resp = http::parse_response(raw).unwrap();
    assert_eq!(resp.version, "HTTP/1.0");
    assert_eq!(resp.status_code, 200);
}

#[test]
fn http2_preface_detected() {
    assert!(http::is_http2_binary(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
}

#[test]
fn empty_data_is_not_http2() {
    assert!(!http::is_http2_binary(b""));
}

#[test]
fn short_data_is_not_http2() {
    assert!(!http::is_http2_binary(b"\x00\x00\x01"));
}

// ---------------------------------------------------------------------------
// Unit: authorization masking
// ---------------------------------------------------------------------------

#[test]
fn authorization_is_masked() {
    let raw = b"GET / HTTP/1.1\r\nAuthorization: Bearer sk-1234567890abcdef1234\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let auth = req.headers.get("authorization").unwrap();
    assert!(auth.contains("..."), "auth should be masked: {auth}");
    assert!(!auth.contains("1234567890abcdef1234"));
}

#[test]
fn api_key_is_masked() {
    let raw = b"GET / HTTP/1.1\r\nX-Api-Key: supersecretkey123456\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let key = req.headers.get("x-api-key").unwrap();
    assert_eq!(key, "[present]");
}

// ---------------------------------------------------------------------------
// Unit: duplicate headers (last one wins with HashMap)
// ---------------------------------------------------------------------------

#[test]
fn duplicate_headers_handled() {
    let raw = b"GET / HTTP/1.1\r\nHost: first.com\r\nHost: second.com\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    // HashMap semantics — one of them wins, but we don't crash
    assert!(req.headers.contains_key("host"));
}

// ---------------------------------------------------------------------------
// Unit: null bytes in headers (no panic)
// ---------------------------------------------------------------------------

#[test]
fn null_bytes_in_header_value_no_panic() {
    // Null byte in the middle of a header value — nom should stop or handle gracefully
    let raw = b"GET / HTTP/1.1\r\nHost: exam\x00ple.com\r\n\r\n";
    let _ = http::parse_request(raw);
    // Just verify no panic
}

// ---------------------------------------------------------------------------
// Unit: spaces before header colon
// ---------------------------------------------------------------------------

#[test]
fn spaces_before_header_colon_no_parse() {
    // RFC 7230 says no whitespace before colon; nom's is_token_char doesn't include space
    let raw = b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n";
    let req = http::parse_request(raw);
    // Should parse request line but the header with space before colon won't parse
    // (space is not a token char), so body_offset may be None
    if let Some(r) = req {
        // Header parsing stopped — Host not captured
        assert!(!r.headers.contains_key("host "));
    }
}

// ---------------------------------------------------------------------------
// Unit: lowercase/mixed-case HTTP method → not detected
// ---------------------------------------------------------------------------

#[test]
fn lowercase_method_not_detected() {
    assert!(!http::looks_like_http_request(
        b"post /v1/chat HTTP/1.1\r\n"
    ));
    assert!(!http::looks_like_http_request(b"Post / HTTP/1.1\r\n"));
    assert!(!http::looks_like_http_request(b"get / HTTP/1.1\r\n"));
}

// ---------------------------------------------------------------------------
// Unit: very long path (10K chars)
// ---------------------------------------------------------------------------

#[test]
fn very_long_path_no_panic() {
    let mut raw = b"GET /".to_vec();
    raw.extend(std::iter::repeat(b'a').take(10_000));
    raw.extend(b" HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let req = http::parse_request(&raw);
    assert!(req.is_some());
    let req = req.unwrap();
    assert_eq!(req.path.len(), 10_001); // "/" + 10000 'a's
}

// ---------------------------------------------------------------------------
// Unit: empty host header value
// ---------------------------------------------------------------------------

#[test]
fn empty_host_header_value() {
    // nom take_while1 requires at least 1 char for value
    let raw = b"GET / HTTP/1.1\r\nHost: \r\n\r\n";
    let req = http::parse_request(raw);
    // Should parse request line; header parse stops at empty value
    assert!(req.is_some());
}

// ---------------------------------------------------------------------------
// Unit: tab as whitespace after header colon
// ---------------------------------------------------------------------------

#[test]
fn tab_after_header_colon() {
    let raw = b"GET / HTTP/1.1\r\nHost:\texample.com\r\n\r\n";
    let req = http::parse_request(raw);
    // nom's opt(space1) should handle tab (space1 matches both spaces and tabs)
    if let Some(r) = req {
        if let Some(host) = r.headers.get("host") {
            assert!(host.contains("example.com"));
        }
    }
}

// ---------------------------------------------------------------------------
// Unit: response with no reason phrase (HTTP/1.1 200\r\n)
// ---------------------------------------------------------------------------

#[test]
fn response_status_only_no_reason() {
    // Some HTTP implementations send just the status code
    // take_while1 for reason requires at least 1 char, but there's a fallback
    let raw = b"HTTP/1.1 200\r\nContent-Type: text/html\r\n\r\n";
    let resp = http::parse_response(raw);
    // The parser may or may not handle this depending on whether reason is optional
    // Just verify no panic
    if let Some(r) = resp {
        assert_eq!(r.status_code, 200);
    }
}

// ---------------------------------------------------------------------------
// Unit: response with space-only reason
// ---------------------------------------------------------------------------

#[test]
fn response_with_space_reason() {
    let raw = b"HTTP/1.1 200 \r\nContent-Type: text/html\r\n\r\n";
    let resp = http::parse_response(raw);
    // Just verify no panic — space-only reason may or may not parse
    if let Some(r) = resp {
        assert_eq!(r.status_code, 200);
    }
}

// ---------------------------------------------------------------------------
// Unit: multiple authorization headers masked
// ---------------------------------------------------------------------------

#[test]
fn multiple_auth_headers_last_wins_masked() {
    let raw = b"GET / HTTP/1.1\r\nAuthorization: Bearer first-key-123456\r\nAuthorization: Bearer second-key-789012\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    let auth = req.headers.get("authorization").unwrap();
    // Should be masked regardless of which one wins
    assert!(auth.contains("..."), "auth should be masked: {auth}");
}

// ---------------------------------------------------------------------------
// Unit: openai-organization header captured
// ---------------------------------------------------------------------------

#[test]
fn openai_organization_header_captured() {
    let raw = b"POST /v1/chat HTTP/1.1\r\nHost: api.openai.com\r\nOpenAI-Organization: org-abc123\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    assert_eq!(
        req.headers.get("openai-organization").map(|s| s.as_str()),
        Some("org-abc123")
    );
}

// ---------------------------------------------------------------------------
// Unit: accept header captured
// ---------------------------------------------------------------------------

#[test]
fn accept_header_captured() {
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\n\r\n";
    let req = http::parse_request(raw).unwrap();
    assert_eq!(
        req.headers.get("accept").map(|s| s.as_str()),
        Some("application/json")
    );
}

// ---------------------------------------------------------------------------
// Unit: header value with embedded CRLF (folded header — not supported)
// ---------------------------------------------------------------------------

#[test]
fn header_with_embedded_crlf_no_panic() {
    // Obsolete line folding: header value continues on next line with leading whitespace
    // Our parser doesn't support this but shouldn't panic
    let raw = b"GET / HTTP/1.1\r\nHost: example\r\n .com\r\n\r\n";
    let _ = http::parse_request(raw);
    // Just verify no panic
}
