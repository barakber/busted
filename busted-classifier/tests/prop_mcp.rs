use busted_classifier::json;
use busted_classifier::mcp;
use busted_classifier::{McpCategory, McpMsgType};

// ---------------------------------------------------------------------------
// All 22 MCP methods classified correctly with expected categories
// ---------------------------------------------------------------------------

#[test]
fn all_mcp_methods_classified() {
    let methods_and_categories = [
        // Tools
        ("tools/list", "Tools"),
        ("tools/call", "Tools"),
        ("tools/listChanged", "Tools"),
        // Resources
        ("resources/list", "Resources"),
        ("resources/read", "Resources"),
        ("resources/subscribe", "Resources"),
        ("resources/unsubscribe", "Resources"),
        ("resources/listChanged", "Resources"),
        ("resources/updated", "Resources"),
        // Prompts
        ("prompts/list", "Prompts"),
        ("prompts/get", "Prompts"),
        ("prompts/listChanged", "Prompts"),
        // Lifecycle
        ("initialize", "Lifecycle"),
        ("initialized", "Lifecycle"),
        ("ping", "Lifecycle"),
        ("cancelled", "Lifecycle"),
        ("shutdown", "Lifecycle"),
        // Completion
        ("completion/complete", "Completion"),
        // Logging
        ("logging/setLevel", "Logging"),
        ("logging/message", "Logging"),
        // Other
        ("notifications/roots/listChanged", "Other"),
        ("sampling/createMessage", "Other"),
    ];

    for (method, expected_category) in methods_and_categories {
        let json_str = format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":{{}},"id":1}}"#);
        let fields = json::analyze(json_str.as_bytes());
        let mcp_info = mcp::classify(&fields);
        assert!(
            mcp_info.is_some(),
            "MCP method '{method}' should be classified"
        );
        let info = mcp_info.unwrap();
        assert_eq!(
            info.category.to_string(),
            expected_category,
            "method '{method}' has wrong category"
        );
        assert_eq!(info.method.as_deref(), Some(method));
        assert_eq!(info.msg_type, McpMsgType::Request);
    }
}

// ---------------------------------------------------------------------------
// Non-MCP JSON-RPC methods are rejected
// ---------------------------------------------------------------------------

#[test]
fn non_mcp_jsonrpc_methods_rejected() {
    let non_mcp_methods = [
        "eth_blockNumber",
        "eth_getBalance",
        "web3_clientVersion",
        "net_version",
        "rpc.discover",
        "system_health",
        "getAccountInfo",
        "sendTransaction",
        "getBlock",
    ];

    for method in non_mcp_methods {
        let json_str = format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":{{}},"id":1}}"#);
        let fields = json::analyze(json_str.as_bytes());
        let result = mcp::classify(&fields);
        assert!(
            result.is_none(),
            "non-MCP method '{method}' should not be classified as MCP"
        );
    }
}

// ---------------------------------------------------------------------------
// Message type determination
// ---------------------------------------------------------------------------

#[test]
fn request_type_has_method_and_id() {
    let json = br#"{"jsonrpc":"2.0","method":"tools/call","params":{},"id":1}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields).unwrap();
    assert_eq!(info.msg_type, McpMsgType::Request);
}

#[test]
fn notification_type_has_method_no_id() {
    let json = br#"{"jsonrpc":"2.0","method":"initialized"}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields).unwrap();
    assert_eq!(info.msg_type, McpMsgType::Notification);
}

#[test]
fn response_type_has_result_and_id() {
    let json = br#"{"jsonrpc":"2.0","result":{"tools":[]},"id":1}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields).unwrap();
    assert_eq!(info.msg_type, McpMsgType::Response);
}

#[test]
fn error_type_has_error_and_id() {
    let json = br#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid"},"id":1}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields).unwrap();
    assert_eq!(info.msg_type, McpMsgType::Error);
}

#[test]
fn error_takes_precedence_over_result() {
    // If both error and result are present (unusual but possible), error wins
    let json = br#"{"jsonrpc":"2.0","error":{"code":-1,"message":"err"},"result":null,"id":1}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields).unwrap();
    assert_eq!(info.msg_type, McpMsgType::Error);
}

// ---------------------------------------------------------------------------
// JSON-RPC version check
// ---------------------------------------------------------------------------

#[test]
fn only_version_2_0_accepted() {
    let json = br#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
    let fields = json::analyze(json);
    assert!(mcp::classify(&fields).is_some());
}

#[test]
fn version_1_0_rejected() {
    let json = br#"{"jsonrpc":"1.0","method":"tools/list","id":1}"#;
    let fields = json::analyze(json);
    assert!(mcp::classify(&fields).is_none());
}

#[test]
fn missing_jsonrpc_rejected() {
    let json = br#"{"method":"tools/list","id":1}"#;
    let fields = json::analyze(json);
    assert!(mcp::classify(&fields).is_none());
}

#[test]
fn empty_jsonrpc_rejected() {
    let json = br#"{"jsonrpc":"","method":"tools/list","id":1}"#;
    let fields = json::analyze(json);
    assert!(mcp::classify(&fields).is_none());
}

// ---------------------------------------------------------------------------
// MCP-prefixed methods that aren't in the exact table
// ---------------------------------------------------------------------------

#[test]
fn unknown_tools_prefix_classified_as_mcp() {
    // tools/custom is not in the table but starts with "tools/"
    let json = br#"{"jsonrpc":"2.0","method":"tools/custom","id":1}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields);
    assert!(info.is_some(), "tools/custom should be MCP (prefix match)");
    let info = info.unwrap();
    assert_eq!(info.category, McpCategory::Other); // lookup_category returns None → Other
}

#[test]
fn unknown_resources_prefix_classified_as_mcp() {
    let json = br#"{"jsonrpc":"2.0","method":"resources/custom","id":1}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields);
    assert!(info.is_some());
}

#[test]
fn unknown_logging_prefix_classified_as_mcp() {
    let json = br#"{"jsonrpc":"2.0","method":"logging/custom","id":1}"#;
    let fields = json::analyze(json);
    assert!(mcp::classify(&fields).is_some());
}

// ---------------------------------------------------------------------------
// ID field formats
// ---------------------------------------------------------------------------

#[test]
fn numeric_id() {
    let json = br#"{"jsonrpc":"2.0","method":"tools/list","id":42}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields).unwrap();
    assert_eq!(info.id.as_deref(), Some("42"));
}

#[test]
fn string_id() {
    let json = br#"{"jsonrpc":"2.0","method":"tools/list","id":"req-123"}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields).unwrap();
    assert_eq!(info.id.as_deref(), Some("req-123"));
}

// ---------------------------------------------------------------------------
// Notification methods (no id)
// ---------------------------------------------------------------------------

#[test]
fn tools_list_changed_notification() {
    let json = br#"{"jsonrpc":"2.0","method":"tools/listChanged"}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields).unwrap();
    assert_eq!(info.msg_type, McpMsgType::Notification);
    assert_eq!(info.category, McpCategory::Tools);
}

#[test]
fn resources_updated_notification() {
    let json = br#"{"jsonrpc":"2.0","method":"resources/updated"}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields).unwrap();
    assert_eq!(info.msg_type, McpMsgType::Notification);
    assert_eq!(info.category, McpCategory::Resources);
}

#[test]
fn cancelled_notification() {
    let json = br#"{"jsonrpc":"2.0","method":"cancelled"}"#;
    let fields = json::analyze(json);
    let info = mcp::classify(&fields).unwrap();
    assert_eq!(info.msg_type, McpMsgType::Notification);
    assert_eq!(info.category, McpCategory::Lifecycle);
}

// ---------------------------------------------------------------------------
// McpCategory and McpMsgType Display
// ---------------------------------------------------------------------------

#[test]
fn category_display() {
    assert_eq!(McpCategory::Tools.to_string(), "Tools");
    assert_eq!(McpCategory::Resources.to_string(), "Resources");
    assert_eq!(McpCategory::Prompts.to_string(), "Prompts");
    assert_eq!(McpCategory::Lifecycle.to_string(), "Lifecycle");
    assert_eq!(McpCategory::Completion.to_string(), "Completion");
    assert_eq!(McpCategory::Logging.to_string(), "Logging");
    assert_eq!(McpCategory::Other.to_string(), "Other");
}

#[test]
fn msg_type_display() {
    assert_eq!(McpMsgType::Request.to_string(), "Request");
    assert_eq!(McpMsgType::Notification.to_string(), "Notification");
    assert_eq!(McpMsgType::Response.to_string(), "Response");
    assert_eq!(McpMsgType::Error.to_string(), "Error");
}

// ===========================================================================
// Property-based tests (proptest)
// ===========================================================================

use busted_classifier::json::JsonFields;
use proptest::prelude::*;

fn arb_option_string() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), "[a-zA-Z0-9_./]{0,50}".prop_map(Some),]
}

fn arb_json_fields() -> impl Strategy<Value = JsonFields> {
    (
        arb_option_string(), // jsonrpc
        arb_option_string(), // method
        arb_option_string(), // id
        any::<bool>(),       // has_result
        any::<bool>(),       // has_error
    )
        .prop_map(|(jsonrpc, method, id, has_result, has_error)| JsonFields {
            jsonrpc,
            method,
            id,
            has_result,
            has_error,
            ..Default::default()
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Feeding arbitrary JsonFields to classify must never panic.
    #[test]
    fn classify_never_panics_arbitrary_fields(fields in arb_json_fields()) {
        let _ = mcp::classify(&fields);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Calling classify twice on identical fields must produce the same result.
    #[test]
    fn classify_deterministic(fields in arb_json_fields()) {
        let a = mcp::classify(&fields);
        let b = mcp::classify(&fields);
        match (&a, &b) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                assert_eq!(a.method, b.method);
                assert_eq!(a.category, b.category);
                assert_eq!(a.msg_type, b.msg_type);
                assert_eq!(a.id, b.id);
            }
            _ => panic!("classify returned different Some/None for identical input"),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Any jsonrpc value that is NOT "2.0" must cause classify to return None.
    #[test]
    fn non_2_0_jsonrpc_always_none(version in "[a-zA-Z0-9.]{0,10}".prop_filter(
        "must not be 2.0",
        |v| v != "2.0",
    )) {
        let fields = JsonFields {
            jsonrpc: Some(version),
            method: Some("tools/call".into()),
            id: Some("1".into()),
            ..Default::default()
        };
        assert!(mcp::classify(&fields).is_none());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// A JSON-RPC 2.0 response (has_result + id) without a method field is still
    /// identified as MCP with msg_type Response.
    #[test]
    fn response_without_method_is_mcp(id in "[a-zA-Z0-9]{1,20}") {
        let fields = JsonFields {
            jsonrpc: Some("2.0".into()),
            has_result: true,
            id: Some(id),
            ..Default::default()
        };
        let info = mcp::classify(&fields);
        assert!(info.is_some(), "response with result+id should be classified");
        let info = info.unwrap();
        assert_eq!(info.msg_type, McpMsgType::Response);
    }
}

/// The 22 known MCP methods for property testing.
const KNOWN_METHODS: &[&str] = &[
    "tools/list",
    "tools/call",
    "tools/listChanged",
    "resources/list",
    "resources/read",
    "resources/subscribe",
    "resources/unsubscribe",
    "resources/listChanged",
    "resources/updated",
    "prompts/list",
    "prompts/get",
    "prompts/listChanged",
    "initialize",
    "initialized",
    "ping",
    "cancelled",
    "shutdown",
    "completion/complete",
    "logging/setLevel",
    "logging/message",
    "notifications/roots/listChanged",
    "sampling/createMessage",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Every known MCP method, wrapped in valid JSON-RPC 2.0, must always classify.
    #[test]
    fn known_method_always_classified(idx in 0..22usize) {
        let method = KNOWN_METHODS[idx];
        let fields = JsonFields {
            jsonrpc: Some("2.0".into()),
            method: Some(method.into()),
            id: Some("1".into()),
            ..Default::default()
        };
        let info = mcp::classify(&fields);
        assert!(info.is_some(), "known method '{}' must be classified", method);
        assert_eq!(info.unwrap().method.as_deref(), Some(method));
    }
}

// ===========================================================================
// Additional unit tests
// ===========================================================================

#[test]
fn null_id_in_response() {
    // json::analyze sees "id":null — null is neither number nor string, so id = None
    let data = br#"{"jsonrpc":"2.0","result":{},"id":null}"#;
    let fields = json::analyze(data);
    // id should be None (null is not captured)
    assert!(fields.id.is_none());
    // has_result is true, but id is None so determine_msg_type falls through
    // to the method-based branches. No method either, so it defaults to Response.
    let info = mcp::classify(&fields);
    assert!(
        info.is_some(),
        "jsonrpc 2.0 with result should still classify"
    );
    // With has_result=true but id=None, the Response branch (has_result && id.is_some())
    // is not taken, so it falls to the default Response type.
    let info = info.unwrap();
    assert_eq!(info.msg_type, McpMsgType::Response);
}

#[test]
fn params_as_array() {
    let data = br#"{"jsonrpc":"2.0","method":"tools/call","params":[1,2],"id":1}"#;
    let fields = json::analyze(data);
    let info = mcp::classify(&fields);
    assert!(
        info.is_some(),
        "tools/call with array params should classify"
    );
    let info = info.unwrap();
    assert_eq!(info.msg_type, McpMsgType::Request);
    assert_eq!(info.category, McpCategory::Tools);
}

#[test]
fn very_long_method_name() {
    // 1000-char method name that starts with "tools/" — prefix match should work
    let method = format!("tools/{}", "x".repeat(994));
    assert_eq!(method.len(), 1000);
    let json_str = format!(r#"{{"jsonrpc":"2.0","method":"{}","id":1}}"#, method);
    let fields = json::analyze(json_str.as_bytes());
    let info = mcp::classify(&fields);
    assert!(
        info.is_some(),
        "very long method starting with 'tools/' should classify via prefix match"
    );
    assert_eq!(info.unwrap().category, McpCategory::Other); // not in exact table → Other
}

#[test]
fn batch_jsonrpc_array() {
    // JSON-RPC batch: top-level array. json::analyze produces default fields for arrays.
    let data = br#"[{"jsonrpc":"2.0","method":"tools/list","id":1}]"#;
    let fields = json::analyze(data);
    // Array input means no top-level "jsonrpc" field is extracted
    assert!(fields.jsonrpc.is_none());
    let info = mcp::classify(&fields);
    assert!(info.is_none(), "batch array should not classify as MCP");
}

#[test]
fn jsonrpc_1_0_rejected() {
    let data = br#"{"jsonrpc":"1.0","method":"tools/call","id":1}"#;
    let fields = json::analyze(data);
    assert_eq!(fields.jsonrpc.as_deref(), Some("1.0"));
    let info = mcp::classify(&fields);
    assert!(info.is_none(), "jsonrpc 1.0 must be rejected");
}

#[test]
fn response_with_null_result() {
    // "result":null — the key exists, so has_result is true
    let data = br#"{"jsonrpc":"2.0","result":null,"id":1}"#;
    let fields = json::analyze(data);
    assert!(fields.has_result);
    let info = mcp::classify(&fields);
    assert!(
        info.is_some(),
        "null result should still be a valid response"
    );
    assert_eq!(info.unwrap().msg_type, McpMsgType::Response);
}

#[test]
fn error_with_nested_data() {
    let data =
        br#"{"jsonrpc":"2.0","error":{"code":-1,"message":"err","data":{"detail":"x"}},"id":1}"#;
    let fields = json::analyze(data);
    assert!(fields.has_error);
    let info = mcp::classify(&fields);
    assert!(info.is_some(), "error with nested data should classify");
    assert_eq!(info.unwrap().msg_type, McpMsgType::Error);
}

#[test]
fn non_mcp_method_prefix() {
    // "custom/" is not a recognized MCP prefix
    let data = br#"{"jsonrpc":"2.0","method":"custom/unknown","id":1}"#;
    let fields = json::analyze(data);
    let info = mcp::classify(&fields);
    assert!(
        info.is_none(),
        "'custom/unknown' is not an MCP method or prefix"
    );
}

#[test]
fn notifications_custom_prefix() {
    // "notifications/" is a recognized MCP prefix
    let data = br#"{"jsonrpc":"2.0","method":"notifications/custom"}"#;
    let fields = json::analyze(data);
    let info = mcp::classify(&fields);
    assert!(
        info.is_some(),
        "'notifications/custom' should classify via prefix match"
    );
    let info = info.unwrap();
    assert_eq!(info.msg_type, McpMsgType::Notification); // no id → notification
    assert_eq!(info.category, McpCategory::Other); // not in exact table → Other
}

#[test]
fn sampling_custom_prefix() {
    // "sampling/" is a recognized MCP prefix
    let data = br#"{"jsonrpc":"2.0","method":"sampling/custom","id":1}"#;
    let fields = json::analyze(data);
    let info = mcp::classify(&fields);
    assert!(
        info.is_some(),
        "'sampling/custom' should classify via prefix match"
    );
    let info = info.unwrap();
    assert_eq!(info.msg_type, McpMsgType::Request); // has method + id → request
    assert_eq!(info.category, McpCategory::Other); // not in exact table → Other
}
