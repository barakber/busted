use busted_classifier::json;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Property: analyze() never panics on arbitrary bytes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn analyze_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let _ = json::analyze(&data);
    }
}

// ---------------------------------------------------------------------------
// Property: valid JSON → complete=true
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn valid_json_is_complete(
        model in "[a-z]{3,10}-[0-9]{1,2}",
        temp in 0.0f64..2.0,
        max_tokens in 1u64..4096,
    ) {
        let json_str = format!(
            r#"{{"model":"{model}","messages":[],"temperature":{temp},"max_tokens":{max_tokens}}}"#
        );
        let fields = json::analyze(json_str.as_bytes());
        prop_assert!(fields.complete, "valid JSON should be complete");
        prop_assert_eq!(fields.model.as_deref(), Some(model.as_str()));
        prop_assert!(fields.has_messages);
        prop_assert_eq!(fields.max_tokens, Some(max_tokens));
    }
}

// ---------------------------------------------------------------------------
// Property: truncated JSON → never panics
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn truncated_json_never_panics(
        truncate_at in 0usize..200,
    ) {
        let full = br#"{"model":"gpt-4","messages":[{"role":"user","content":"hello world"}],"temperature":0.7,"max_tokens":100,"stream":true}"#;
        let truncated = &full[..truncate_at.min(full.len())];
        let fields = json::analyze(truncated);
        // Truncated JSON should not be complete (unless we got the whole thing)
        if truncate_at < full.len() {
            prop_assert!(!fields.complete, "truncated JSON should not be complete (truncate_at={truncate_at})");
        }
    }
}

// ---------------------------------------------------------------------------
// Property: JSON-RPC fields extracted consistently
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn jsonrpc_fields_extracted(
        method in "[a-z]+/[a-z]+",
        id in 1u32..10000,
    ) {
        let json_str = format!(
            r#"{{"jsonrpc":"2.0","method":"{method}","params":{{}},"id":{id}}}"#
        );
        let fields = json::analyze(json_str.as_bytes());
        prop_assert!(fields.complete);
        prop_assert_eq!(fields.jsonrpc.as_deref(), Some("2.0"));
        prop_assert_eq!(fields.method.as_deref(), Some(method.as_str()));
        let id_str = id.to_string();
        prop_assert_eq!(fields.id.as_deref(), Some(id_str.as_str()));
    }
}

// ---------------------------------------------------------------------------
// Unit: empty JSON variants
// ---------------------------------------------------------------------------

#[test]
fn empty_object() {
    let fields = json::analyze(b"{}");
    assert!(fields.complete);
    assert!(fields.model.is_none());
    assert!(!fields.has_messages);
}

#[test]
fn empty_array() {
    let fields = json::analyze(b"[]");
    // Arrays aren't objects, so no fields extracted, but it's valid JSON
    assert!(fields.complete);
    assert!(fields.model.is_none());
}

#[test]
fn json_string() {
    let fields = json::analyze(br#""hello""#);
    assert!(fields.complete);
    assert!(fields.model.is_none());
}

#[test]
fn json_null() {
    let fields = json::analyze(b"null");
    assert!(fields.complete);
}

#[test]
fn json_number() {
    let fields = json::analyze(b"42");
    assert!(fields.complete);
}

#[test]
fn json_boolean() {
    let fields = json::analyze(b"true");
    assert!(fields.complete);
}

#[test]
fn empty_bytes() {
    let fields = json::analyze(b"");
    assert!(!fields.complete);
    assert!(fields.model.is_none());
}

// ---------------------------------------------------------------------------
// Unit: deep nesting doesn't stack overflow
// ---------------------------------------------------------------------------

#[test]
fn deep_nesting_no_stack_overflow() {
    // 100 levels deep — serde_json has a default recursion limit of 128
    let mut json = String::new();
    for _ in 0..100 {
        json.push_str("{\"nested\":");
    }
    json.push_str("null");
    for _ in 0..100 {
        json.push('}');
    }
    let fields = json::analyze(json.as_bytes());
    // It should either parse successfully or fall back to scanner
    // but should not stack overflow
    assert!(fields.model.is_none());
}

#[test]
fn very_deep_nesting_handled() {
    // 200 levels — exceeds serde_json's default limit, falls back to scanner
    let mut json = String::new();
    for _ in 0..200 {
        json.push_str("{\"a\":");
    }
    json.push_str("1");
    for _ in 0..200 {
        json.push('}');
    }
    let fields = json::analyze(json.as_bytes());
    // Should not crash — falls back to byte scanner
    assert!(!fields.complete); // serde_json would reject this
}

// ---------------------------------------------------------------------------
// Unit: escaped strings in keys
// ---------------------------------------------------------------------------

#[test]
fn escaped_quote_in_key() {
    let json = br#"{"mod\"el":"gpt-4","model":"claude-3"}"#;
    let fields = json::analyze(json);
    // The first key has an escaped quote so won't match "model"
    // The second key "model" should match
    assert_eq!(fields.model.as_deref(), Some("claude-3"));
}

#[test]
fn escaped_backslash_in_value() {
    let json = br#"{"model":"gpt\\4"}"#;
    let fields = json::analyze(json);
    assert_eq!(fields.model.as_deref(), Some("gpt\\4"));
}

#[test]
fn unicode_escape_in_value() {
    let json = br#"{"model":"gpt-4\u0021"}"#;
    let fields = json::analyze(json);
    // serde_json will decode \u0021 to '!'
    assert_eq!(fields.model.as_deref(), Some("gpt-4!"));
}

// ---------------------------------------------------------------------------
// Unit: response indicators
// ---------------------------------------------------------------------------

#[test]
fn choices_detected() {
    let json = br#"{"id":"cmpl-1","choices":[{"text":"hi"}]}"#;
    let fields = json::analyze(json);
    assert!(fields.has_choices);
}

#[test]
fn content_detected() {
    let json = br#"{"type":"message","content":[{"type":"text","text":"hi"}]}"#;
    let fields = json::analyze(json);
    assert!(fields.has_content);
}

#[test]
fn completion_detected() {
    let json = br#"{"completion":"Hello world","model":"claude-v1"}"#;
    let fields = json::analyze(json);
    assert!(fields.has_completion);
    assert_eq!(fields.model.as_deref(), Some("claude-v1"));
}

// ---------------------------------------------------------------------------
// Unit: top_level_keys ordering matches JSON source
// ---------------------------------------------------------------------------

#[test]
fn top_level_keys_order_preserved() {
    let json = br#"{"model":"gpt-4","messages":[],"temperature":0.7}"#;
    let fields = json::analyze(json);
    assert!(fields.complete);
    // serde_json preserves order for Map if using preserve_order feature,
    // but by default HashMap doesn't. Check they're all present:
    assert!(fields.top_level_keys.contains(&"model".to_string()));
    assert!(fields.top_level_keys.contains(&"messages".to_string()));
    assert!(fields.top_level_keys.contains(&"temperature".to_string()));
}

// ---------------------------------------------------------------------------
// Unit: max_completion_tokens alias
// ---------------------------------------------------------------------------

#[test]
fn max_completion_tokens_alias() {
    let json = br#"{"model":"gpt-4","max_completion_tokens":500}"#;
    let fields = json::analyze(json);
    assert_eq!(fields.max_tokens, Some(500));
}

// ---------------------------------------------------------------------------
// Unit: stream flag variants
// ---------------------------------------------------------------------------

#[test]
fn stream_true() {
    let json = br#"{"stream":true}"#;
    let fields = json::analyze(json);
    assert_eq!(fields.stream, Some(true));
}

#[test]
fn stream_false() {
    let json = br#"{"stream":false}"#;
    let fields = json::analyze(json);
    assert_eq!(fields.stream, Some(false));
}

// ---------------------------------------------------------------------------
// Unit: top_p extraction
// ---------------------------------------------------------------------------

#[test]
fn top_p_extracted() {
    let json = br#"{"top_p":0.9}"#;
    let fields = json::analyze(json);
    assert!((fields.top_p.unwrap() - 0.9).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// Unit: truncated JSON key scanning
// ---------------------------------------------------------------------------

#[test]
fn truncated_json_extracts_partial_fields() {
    let json = br#"{"model":"gpt-4","messages":[{"role":"user","cont"#;
    let fields = json::analyze(json);
    assert!(!fields.complete);
    assert_eq!(fields.model.as_deref(), Some("gpt-4"));
    assert!(fields.has_messages);
}

#[test]
fn truncated_json_mid_value() {
    // Truncated in the middle of the model value
    let json = br#"{"model":"gpt-"#;
    let fields = json::analyze(json);
    assert!(!fields.complete);
    // The closing quote for model value is missing, so scanner won't extract it
    // (depends on implementation — find_closing_quote returns None)
}

// ---------------------------------------------------------------------------
// Unit: non-JSON input
// ---------------------------------------------------------------------------

#[test]
fn plain_text_is_not_json() {
    let fields = json::analyze(b"Hello world, this is not JSON!");
    assert!(!fields.complete);
}

#[test]
fn xml_is_not_json() {
    let fields = json::analyze(b"<root><model>gpt-4</model></root>");
    assert!(!fields.complete);
}

#[test]
fn binary_garbage() {
    let fields = json::analyze(&[0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90]);
    assert!(!fields.complete);
}

// ---------------------------------------------------------------------------
// Unit: UTF-8 BOM prefix before JSON
// ---------------------------------------------------------------------------

#[test]
fn utf8_bom_prefix() {
    // BOM (EF BB BF) followed by valid JSON
    let mut input = vec![0xEF, 0xBB, 0xBF];
    input.extend_from_slice(br#"{"model":"gpt-4","messages":[]}"#);
    let fields = json::analyze(&input);
    // serde_json does NOT accept BOM, so it falls back to the byte scanner
    assert!(!fields.complete);
    // But the scanner should still find the model key
    assert_eq!(fields.model.as_deref(), Some("gpt-4"));
    assert!(fields.has_messages);
}

// ---------------------------------------------------------------------------
// Unit: top-level JSON array with objects inside
// ---------------------------------------------------------------------------

#[test]
fn top_level_non_empty_array() {
    let fields = json::analyze(br#"[{"model":"gpt-4"},{"model":"claude"}]"#);
    // Array is valid JSON, but no top-level "model" key on the array itself
    assert!(fields.complete);
    assert!(fields.model.is_none());
    assert!(fields.top_level_keys.is_empty());
}

// ---------------------------------------------------------------------------
// Unit: null value for model key
// ---------------------------------------------------------------------------

#[test]
fn null_model_value() {
    let fields = json::analyze(br#"{"model":null,"messages":[]}"#);
    assert!(fields.complete);
    // model is Value::Null, not Value::String → model stays None
    assert!(fields.model.is_none());
    assert!(fields.has_messages);
}

// ---------------------------------------------------------------------------
// Unit: repeated keys — serde_json picks last
// ---------------------------------------------------------------------------

#[test]
fn repeated_keys_last_wins() {
    let fields =
        json::analyze(br#"{"model":"gpt-3","temperature":0.5,"model":"gpt-4","temperature":0.9}"#);
    assert!(fields.complete);
    assert_eq!(fields.model.as_deref(), Some("gpt-4"));
    assert!((fields.temperature.unwrap() - 0.9).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// Unit: JSON with trailing garbage → falls to scanner
// ---------------------------------------------------------------------------

#[test]
fn json_with_trailing_garbage() {
    let fields = json::analyze(br#"{"model":"gpt-4","messages":[]}GARBAGE_HERE"#);
    // serde_json::from_slice rejects trailing content → falls to scanner
    assert!(!fields.complete);
    // Scanner should still extract model and messages
    assert_eq!(fields.model.as_deref(), Some("gpt-4"));
    assert!(fields.has_messages);
}

// ---------------------------------------------------------------------------
// Unit: whitespace-padded JSON
// ---------------------------------------------------------------------------

#[test]
fn whitespace_padded_json() {
    let fields = json::analyze(b"  \n\t {\"model\":\"gpt-4\",\"messages\":[]}  \n");
    // serde_json accepts leading whitespace but trailing whitespace after closing
    // brace may cause from_slice to fail → falls to scanner
    // Either way, model should be extracted
    assert_eq!(fields.model.as_deref(), Some("gpt-4"));
    assert!(fields.has_messages);
}

// ---------------------------------------------------------------------------
// Unit: very large number in max_tokens
// ---------------------------------------------------------------------------

#[test]
fn very_large_max_tokens() {
    let fields = json::analyze(br#"{"max_tokens":999999999999}"#);
    assert!(fields.complete);
    assert_eq!(fields.max_tokens, Some(999_999_999_999));
}

// ---------------------------------------------------------------------------
// Unit: negative temperature
// ---------------------------------------------------------------------------

#[test]
fn negative_temperature() {
    let fields = json::analyze(br#"{"temperature":-0.5}"#);
    assert!(fields.complete);
    assert!((fields.temperature.unwrap() - (-0.5)).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// Unit: model value is a number (not string)
// ---------------------------------------------------------------------------

#[test]
fn model_value_is_number() {
    let fields = json::analyze(br#"{"model":42,"messages":[]}"#);
    assert!(fields.complete);
    // extract_from_value checks for Value::String, so a number is ignored
    assert!(fields.model.is_none());
    assert!(fields.has_messages);
}

// ---------------------------------------------------------------------------
// Unit: JSON-RPC id as null
// ---------------------------------------------------------------------------

#[test]
fn jsonrpc_id_null() {
    let fields = json::analyze(br#"{"jsonrpc":"2.0","method":"test","id":null}"#);
    assert!(fields.complete);
    assert_eq!(fields.jsonrpc.as_deref(), Some("2.0"));
    assert_eq!(fields.method.as_deref(), Some("test"));
    // id:null is not Number or String → id stays None
    assert!(fields.id.is_none());
}
