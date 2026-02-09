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
