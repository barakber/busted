use serde_json::Value;

/// Extracted fields from a JSON body (complete or truncated).
#[derive(Debug, Default)]
pub struct JsonFields {
    /// Model name from "model" key.
    pub model: Option<String>,
    /// Whether "messages" key is present.
    pub has_messages: bool,
    /// Whether "prompt" key is present.
    pub has_prompt: bool,
    /// Temperature value.
    pub temperature: Option<f64>,
    /// max_tokens or max_completion_tokens.
    pub max_tokens: Option<u64>,
    /// top_p value.
    pub top_p: Option<f64>,
    /// Stream flag.
    pub stream: Option<bool>,
    /// JSON-RPC version (e.g. "2.0").
    pub jsonrpc: Option<String>,
    /// JSON-RPC method.
    pub method: Option<String>,
    /// JSON-RPC id (as string).
    pub id: Option<String>,
    /// Whether "result" key is present.
    pub has_result: bool,
    /// Whether "error" key is present.
    pub has_error: bool,
    /// Response: "choices" present (OpenAI-style).
    pub has_choices: bool,
    /// Response: "content" present (may be Anthropic content blocks).
    pub has_content: bool,
    /// Response: "completion" present.
    pub has_completion: bool,
    /// Ordered list of top-level JSON keys (for fingerprinting).
    pub top_level_keys: Vec<String>,
    /// Whether the JSON was fully parsed (vs. fallback scanner).
    pub complete: bool,
}

/// Analyze a JSON body slice. Tries serde_json first, falls back to byte scanning.
pub fn analyze(body: &[u8]) -> JsonFields {
    // Fast path: try to parse complete JSON
    if let Ok(val) = serde_json::from_slice::<Value>(body) {
        return extract_from_value(&val);
    }

    // Fallback: byte-level key scanning for truncated JSON
    scan_truncated(body)
}

fn extract_from_value(val: &Value) -> JsonFields {
    let mut fields = JsonFields {
        complete: true,
        ..Default::default()
    };

    if let Value::Object(map) = val {
        fields.top_level_keys = map.keys().cloned().collect();

        if let Some(Value::String(m)) = map.get("model") {
            fields.model = Some(m.clone());
        }
        fields.has_messages = map.contains_key("messages");
        fields.has_prompt = map.contains_key("prompt");

        if let Some(Value::Number(n)) = map.get("temperature") {
            fields.temperature = n.as_f64();
        }
        if let Some(Value::Number(n)) = map.get("max_tokens") {
            fields.max_tokens = n.as_u64();
        }
        if let Some(Value::Number(n)) = map.get("max_completion_tokens") {
            fields.max_tokens = n.as_u64();
        }
        if let Some(Value::Number(n)) = map.get("top_p") {
            fields.top_p = n.as_f64();
        }
        if let Some(Value::Bool(b)) = map.get("stream") {
            fields.stream = Some(*b);
        }

        // JSON-RPC fields
        if let Some(Value::String(v)) = map.get("jsonrpc") {
            fields.jsonrpc = Some(v.clone());
        }
        if let Some(Value::String(m)) = map.get("method") {
            fields.method = Some(m.clone());
        }
        match map.get("id") {
            Some(Value::Number(n)) => fields.id = Some(n.to_string()),
            Some(Value::String(s)) => fields.id = Some(s.clone()),
            _ => {}
        }
        fields.has_result = map.contains_key("result");
        fields.has_error = map.contains_key("error");

        // Response indicators
        fields.has_choices = map.contains_key("choices");
        fields.has_content = map.contains_key("content");
        fields.has_completion = map.contains_key("completion");
    }

    fields
}

/// Byte-level scanner for truncated JSON. Finds `"key":` patterns.
fn scan_truncated(body: &[u8]) -> JsonFields {
    let mut fields = JsonFields::default();
    let text = String::from_utf8_lossy(body);

    // Extract keys and simple values
    let mut keys = Vec::new();

    let mut i = 0;
    let bytes = text.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'"' {
            // Try to extract a key
            if let Some(end) = find_closing_quote(bytes, i + 1) {
                let key = &text[i + 1..end];
                // Check if followed by ':'
                let after = skip_whitespace(bytes, end + 1);
                if after < bytes.len() && bytes[after] == b':' {
                    keys.push(key.to_string());
                    let val_start = skip_whitespace(bytes, after + 1);
                    match key {
                        "model" => {
                            fields.model = extract_string_value(bytes, val_start)
                                .map(|s| s.to_string());
                        }
                        "messages" => fields.has_messages = true,
                        "prompt" => fields.has_prompt = true,
                        "temperature" => {
                            fields.temperature = extract_number_value(bytes, val_start);
                        }
                        "max_tokens" | "max_completion_tokens" => {
                            fields.max_tokens =
                                extract_number_value(bytes, val_start).map(|n| n as u64);
                        }
                        "top_p" => {
                            fields.top_p = extract_number_value(bytes, val_start);
                        }
                        "stream" => {
                            fields.stream = extract_bool_value(bytes, val_start);
                        }
                        "jsonrpc" => {
                            fields.jsonrpc = extract_string_value(bytes, val_start)
                                .map(|s| s.to_string());
                        }
                        "method" => {
                            fields.method = extract_string_value(bytes, val_start)
                                .map(|s| s.to_string());
                        }
                        "id" => {
                            fields.id = extract_string_value(bytes, val_start)
                                .map(|s| s.to_string())
                                .or_else(|| {
                                    extract_number_value(bytes, val_start)
                                        .map(|n| format!("{}", n as i64))
                                });
                        }
                        "result" => fields.has_result = true,
                        "error" => fields.has_error = true,
                        "choices" => fields.has_choices = true,
                        "content" => fields.has_content = true,
                        "completion" => fields.has_completion = true,
                        _ => {}
                    }
                }
                i = end + 1;
            } else {
                break; // Truncated string
            }
        } else {
            i += 1;
        }
    }

    fields.top_level_keys = keys;
    fields
}

fn find_closing_quote(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // Skip escaped char
        } else if bytes[i] == b'"' {
            return Some(i);
        } else {
            i += 1;
        }
    }
    None
}

fn skip_whitespace(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r') {
        i += 1;
    }
    i
}

fn extract_string_value(bytes: &[u8], start: usize) -> Option<&str> {
    if start >= bytes.len() || bytes[start] != b'"' {
        return None;
    }
    let end = find_closing_quote(bytes, start + 1)?;
    std::str::from_utf8(&bytes[start + 1..end]).ok()
}

fn extract_number_value(bytes: &[u8], start: usize) -> Option<f64> {
    if start >= bytes.len() {
        return None;
    }
    let mut end = start;
    while end < bytes.len()
        && (bytes[end].is_ascii_digit() || bytes[end] == b'.' || bytes[end] == b'-' || bytes[end] == b'e' || bytes[end] == b'E')
    {
        end += 1;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .and_then(|s| s.parse().ok())
}

fn extract_bool_value(bytes: &[u8], start: usize) -> Option<bool> {
    if start + 4 <= bytes.len() && &bytes[start..start + 4] == b"true" {
        Some(true)
    } else if start + 5 <= bytes.len() && &bytes[start..start + 5] == b"false" {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_json() {
        let body = br#"{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}],"temperature":0.7,"max_tokens":100,"stream":false}"#;
        let fields = analyze(body);
        assert!(fields.complete);
        assert_eq!(fields.model.as_deref(), Some("gpt-4"));
        assert!(fields.has_messages);
        assert_eq!(fields.temperature, Some(0.7));
        assert_eq!(fields.max_tokens, Some(100));
        assert_eq!(fields.stream, Some(false));
    }

    #[test]
    fn test_jsonrpc() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search"},"id":1}"#;
        let fields = analyze(body);
        assert_eq!(fields.jsonrpc.as_deref(), Some("2.0"));
        assert_eq!(fields.method.as_deref(), Some("tools/call"));
        assert_eq!(fields.id.as_deref(), Some("1"));
    }

    #[test]
    fn test_truncated_json() {
        let body = br#"{"model":"claude-3-opus","messages":[{"role":"user","conte"#;
        let fields = analyze(body);
        assert!(!fields.complete);
        assert_eq!(fields.model.as_deref(), Some("claude-3-opus"));
        assert!(fields.has_messages);
    }

    #[test]
    fn test_response_openai() {
        let body = br#"{"id":"chatcmpl-123","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Hi"}}]}"#;
        let fields = analyze(body);
        assert!(fields.has_choices);
    }

    #[test]
    fn test_response_anthropic() {
        let body = br#"{"id":"msg_123","type":"message","content":[{"type":"text","text":"Hello"}],"model":"claude-3-opus"}"#;
        let fields = analyze(body);
        assert!(fields.has_content);
        assert_eq!(fields.model.as_deref(), Some("claude-3-opus"));
    }
}
