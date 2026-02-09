use nom::{
    bytes::complete::{tag, take_while1},
    character::complete::{char, space1},
    combinator::opt,
    sequence::tuple,
    IResult,
};
use std::collections::HashMap;

/// Parsed HTTP/1.1 request.
#[derive(Debug, Clone)]
pub struct HttpRequestInfo {
    /// HTTP method (e.g. `GET`, `POST`).
    pub method: String,
    /// Request path (e.g. `/v1/chat/completions`).
    pub path: String,
    /// HTTP version (e.g. `HTTP/1.1`).
    pub version: String,
    /// Headers (keys lowercased, values with sensitive data masked).
    pub headers: HashMap<String, String>,
    /// Byte offset where the body starts in the original payload.
    pub body_offset: Option<usize>,
}

/// Parsed HTTP/1.1 response.
#[derive(Debug, Clone)]
pub struct HttpResponseInfo {
    /// HTTP version (e.g. `HTTP/1.1`).
    pub version: String,
    /// Status code (e.g. `200`, `404`).
    pub status_code: u16,
    /// Reason phrase (e.g. `OK`, `Not Found`).
    pub reason: String,
    /// Headers (keys lowercased).
    pub headers: HashMap<String, String>,
    /// Byte offset where the body starts in the original payload.
    pub body_offset: Option<usize>,
}

/// Headers we extract for classification.
const INTERESTING_HEADERS: &[&str] = &[
    "host",
    "content-type",
    "user-agent",
    "authorization",
    "x-api-key",
    "anthropic-version",
    "openai-organization",
    "accept",
];

/// Quick check: does this look like an HTTP/2 binary frame?
pub fn is_http2_binary(data: &[u8]) -> bool {
    // HTTP/2 connection preface
    if data.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        return true;
    }
    // HTTP/2 frame: 3-byte length + 1-byte type + 1-byte flags + 4-byte stream ID
    // Type values 0-9 are defined; length is reasonable
    if data.len() >= 9 {
        let len = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
        let frame_type = data[3];
        // Valid frame types: DATA(0)..CONTINUATION(9)
        if frame_type <= 9 && len < 16_777_216 && len > 0 {
            // Heuristic: if the high bit of byte 5-8 is clear (stream ID is 31 bits)
            if data[5] & 0x80 == 0 {
                return true;
            }
        }
    }
    false
}

/// Quick check: does this look like the start of an HTTP request?
pub fn looks_like_http_request(data: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
    ];
    for m in METHODS {
        if data.starts_with(m) {
            return true;
        }
    }
    false
}

/// Quick check: does this look like the start of an HTTP response?
pub fn looks_like_http_response(data: &[u8]) -> bool {
    data.starts_with(b"HTTP/1.0 ") || data.starts_with(b"HTTP/1.1 ")
}

fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn parse_method(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(|c: u8| c.is_ascii_uppercase())(input)
}

#[allow(clippy::type_complexity)]
fn parse_request_line(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8], &[u8])> {
    let (input, method) = parse_method(input)?;
    let (input, _) = space1(input)?;
    let (input, path) = take_while1(|c: u8| c != b' ' && c != b'\r' && c != b'\n')(input)?;
    let (input, _) = space1(input)?;
    let (input, version) = take_while1(|c: u8| c != b'\r' && c != b'\n')(input)?;
    let (input, _) = tag(b"\r\n")(input)?;
    Ok((input, (method, path, version)))
}

#[allow(clippy::type_complexity)]
fn parse_status_line(input: &[u8]) -> IResult<&[u8], (&[u8], u16, &[u8])> {
    let (input, version) = take_while1(|c: u8| c != b' ' && c != b'\r')(input)?;
    let (input, _) = space1(input)?;
    let (input, code_bytes) = take_while1(|c: u8| c.is_ascii_digit())(input)?;
    let code: u16 = std::str::from_utf8(code_bytes)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (input, _) = opt(space1)(input)?;
    // Reason phrase is optional and runs to CRLF
    let (input, reason) =
        take_while1::<_, _, nom::error::Error<&[u8]>>(|c: u8| c != b'\r' && c != b'\n')(input)
            .unwrap_or((input, b"" as &[u8]));
    let (input, _) = tag(b"\r\n")(input)?;
    Ok((input, (version, code, reason)))
}

fn parse_header(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    let (input, name) = take_while1(is_token_char)(input)?;
    let (input, _) = tuple((char(':'), opt(space1)))(input)?;
    let (input, value) = take_while1(|c: u8| c != b'\r' && c != b'\n')(input)?;
    let (input, _) = tag(b"\r\n")(input)?;
    Ok((input, (name, value)))
}

/// Returns (headers, remaining_body, headers_complete).
/// `headers_complete` is true if the `\r\n\r\n` terminator was found.
fn parse_headers(mut input: &[u8]) -> (HashMap<String, String>, &[u8], bool) {
    let mut headers = HashMap::new();

    loop {
        // Check for end of headers
        if input.starts_with(b"\r\n") {
            return (headers, &input[2..], true);
        }
        if input.is_empty() {
            // Truncated before end of headers
            return (headers, input, false);
        }

        match parse_header(input) {
            Ok((rest, (name, value))) => {
                let name_str = String::from_utf8_lossy(name).to_lowercase();
                // Only store interesting headers
                if INTERESTING_HEADERS.contains(&name_str.as_str()) {
                    let val = String::from_utf8_lossy(value).to_string();
                    // Mask authorization values for security
                    let val = if name_str == "authorization" {
                        mask_auth(&val)
                    } else if name_str == "x-api-key" {
                        "[present]".to_string()
                    } else {
                        val
                    };
                    headers.insert(name_str, val);
                }
                input = rest;
            }
            Err(_) => {
                // Truncated or malformed header — stop parsing
                return (headers, input, false);
            }
        }
    }
}

fn mask_auth(val: &str) -> String {
    if val.len() > 12 {
        format!("{}...{}", &val[..8], &val[val.len() - 4..])
    } else {
        "[redacted]".to_string()
    }
}

/// Try to parse an HTTP/1.1 request from raw bytes.
/// Handles truncated payloads gracefully.
pub fn parse_request(data: &[u8]) -> Option<HttpRequestInfo> {
    let (rest, (method, path, version)) = parse_request_line(data).ok()?;
    let (headers, body, headers_complete) = parse_headers(rest);

    let body_offset = if headers_complete {
        Some(data.len() - body.len())
    } else {
        None
    };

    Some(HttpRequestInfo {
        method: String::from_utf8_lossy(method).to_string(),
        path: String::from_utf8_lossy(path).to_string(),
        version: String::from_utf8_lossy(version).to_string(),
        headers,
        body_offset,
    })
}

/// Try to parse an HTTP/1.1 response from raw bytes.
pub fn parse_response(data: &[u8]) -> Option<HttpResponseInfo> {
    let (rest, (version, status_code, reason)) = parse_status_line(data).ok()?;
    let (headers, body, headers_complete) = parse_headers(rest);

    let body_offset = if headers_complete {
        Some(data.len() - body.len())
    } else {
        None
    };

    Some(HttpResponseInfo {
        version: String::from_utf8_lossy(version).to_string(),
        status_code,
        reason: String::from_utf8_lossy(reason).to_string(),
        headers,
        body_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nAuthorization: Bearer sk-1234567890abcdef\r\nUser-Agent: openai-python/1.12.0\r\n\r\n{\"model\":\"gpt-4\"}";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/v1/chat/completions");
        assert_eq!(req.headers.get("host").unwrap(), "api.openai.com");
        assert_eq!(req.headers.get("content-type").unwrap(), "application/json");
        assert!(req.headers.get("authorization").unwrap().contains("..."));
        assert_eq!(
            req.headers.get("user-agent").unwrap(),
            "openai-python/1.12.0"
        );
        assert!(req.body_offset.is_some());
    }

    #[test]
    fn test_parse_response() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"chatcmpl-123\"}";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
        assert!(resp.body_offset.is_some());
    }

    #[test]
    fn test_truncated_headers() {
        let raw = b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Ty";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.headers.get("host").unwrap(), "api.anthropic.com");
        assert!(req.body_offset.is_none());
    }

    #[test]
    fn test_http2_detection() {
        assert!(is_http2_binary(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
        assert!(!is_http2_binary(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_quick_checks() {
        assert!(looks_like_http_request(b"POST /v1/chat HTTP/1.1\r\n"));
        assert!(looks_like_http_request(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_http_request(b"{\"jsonrpc\":\"2.0\"}"));
        assert!(looks_like_http_response(b"HTTP/1.1 200 OK\r\n"));
        assert!(!looks_like_http_response(b"POST / HTTP/1.1\r\n"));
    }

    // ---- Edge-case tests ----

    #[test]
    fn lf_only_line_endings_fail_parse() {
        let raw = b"POST /v1/chat HTTP/1.1\nHost: example.com\n\n";
        assert!(parse_request(raw).is_none());
    }

    #[test]
    fn header_value_with_colon() {
        let raw = b"POST / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.headers.get("host").unwrap(), "example.com:8080");
    }

    #[test]
    fn http_10_version() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.version, "HTTP/1.0");
        assert_eq!(resp.status_code, 200);
    }

    #[test]
    fn path_with_query_string() {
        let raw =
            b"POST /v1/chat/completions?api-version=2024 HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.path, "/v1/chat/completions?api-version=2024");
    }

    #[test]
    fn empty_header_value_fails_nom() {
        // nom take_while1 requires at least 1 char, so empty value fails
        let raw = b"POST / HTTP/1.1\r\nHost: \r\n\r\n";
        // This should still parse the request line but stop at the empty header
        let req = parse_request(raw);
        // The parse should succeed for request line but header value won't parse
        assert!(req.is_some());
    }

    #[test]
    fn mask_auth_short_value() {
        assert_eq!(mask_auth("sk-123"), "[redacted]");
        assert_eq!(mask_auth(""), "[redacted]");
        assert_eq!(mask_auth("exactlytwelv"), "[redacted]"); // 12 chars
    }

    #[test]
    fn mask_auth_13_chars() {
        let masked = mask_auth("1234567890abc");
        assert_eq!(masked, "12345678...0abc");
    }

    #[test]
    fn mask_auth_long_value() {
        let masked = mask_auth("Bearer sk-1234567890abcdefghij");
        assert!(masked.starts_with("Bearer s"));
        assert!(masked.contains("..."));
        assert!(masked.ends_with("ghij"));
    }

    #[test]
    fn http2_frame_type_boundary() {
        // Frame type 9 is CONTINUATION (last valid), should match
        let mut frame = vec![0x00, 0x00, 0x01, 9, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert!(is_http2_binary(&frame));

        // Frame type 10 is invalid
        frame[3] = 10;
        assert!(!is_http2_binary(&frame));
    }

    #[test]
    fn http2_frame_zero_length() {
        // length=0 should NOT match (our code requires len > 0)
        let frame = vec![0x00, 0x00, 0x00, 0, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert!(!is_http2_binary(&frame));
    }

    #[test]
    fn http2_frame_high_bit_set_in_stream_id() {
        // byte[5] high bit set → stream ID reserved bit → no match
        let frame = vec![0x00, 0x00, 0x01, 0, 0x00, 0x80, 0x00, 0x00, 0x01];
        assert!(!is_http2_binary(&frame));
    }

    #[test]
    fn non_interesting_headers_filtered() {
        let raw = b"POST / HTTP/1.1\r\nHost: example.com\r\nX-Custom: value\r\nConnection: keep-alive\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert!(req.headers.contains_key("host"));
        assert!(!req.headers.contains_key("x-custom"));
        assert!(!req.headers.contains_key("connection"));
    }

    #[test]
    fn x_api_key_masked() {
        let raw = b"POST / HTTP/1.1\r\nX-Api-Key: sk-secret-key-12345\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.headers.get("x-api-key").unwrap(), "[present]");
    }

    #[test]
    fn all_http_methods_detected() {
        for method in &[
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT",
        ] {
            let raw = format!("{} / HTTP/1.1\r\n", method);
            assert!(
                looks_like_http_request(raw.as_bytes()),
                "should detect {}",
                method
            );
        }
    }

    #[test]
    fn parse_response_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>Not Found</h1>";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason, "Not Found");
        assert!(resp.body_offset.is_some());
    }

    #[test]
    fn empty_input_returns_none() {
        assert!(parse_request(b"").is_none());
        assert!(parse_response(b"").is_none());
    }

    #[test]
    fn looks_like_http_response_http10() {
        assert!(looks_like_http_response(b"HTTP/1.0 301 Moved\r\n"));
    }
}
