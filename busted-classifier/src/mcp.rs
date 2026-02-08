use crate::json::JsonFields;

/// MCP method category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpCategory {
    Tools,
    Resources,
    Prompts,
    Lifecycle,
    Completion,
    Logging,
    Other,
}

impl std::fmt::Display for McpCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpCategory::Tools => write!(f, "Tools"),
            McpCategory::Resources => write!(f, "Resources"),
            McpCategory::Prompts => write!(f, "Prompts"),
            McpCategory::Lifecycle => write!(f, "Lifecycle"),
            McpCategory::Completion => write!(f, "Completion"),
            McpCategory::Logging => write!(f, "Logging"),
            McpCategory::Other => write!(f, "Other"),
        }
    }
}

/// Type of JSON-RPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpMsgType {
    Request,
    Notification,
    Response,
    Error,
}

impl std::fmt::Display for McpMsgType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpMsgType::Request => write!(f, "Request"),
            McpMsgType::Notification => write!(f, "Notification"),
            McpMsgType::Response => write!(f, "Response"),
            McpMsgType::Error => write!(f, "Error"),
        }
    }
}

/// MCP classification result.
#[derive(Debug, Clone)]
pub struct McpInfo {
    pub method: Option<String>,
    pub category: McpCategory,
    pub msg_type: McpMsgType,
    pub id: Option<String>,
}

/// MCP method table: method → category.
const MCP_METHODS: &[(&str, McpCategory)] = &[
    // Tools
    ("tools/list", McpCategory::Tools),
    ("tools/call", McpCategory::Tools),
    ("tools/listChanged", McpCategory::Tools),
    // Resources
    ("resources/list", McpCategory::Resources),
    ("resources/read", McpCategory::Resources),
    ("resources/subscribe", McpCategory::Resources),
    ("resources/unsubscribe", McpCategory::Resources),
    ("resources/listChanged", McpCategory::Resources),
    ("resources/updated", McpCategory::Resources),
    // Prompts
    ("prompts/list", McpCategory::Prompts),
    ("prompts/get", McpCategory::Prompts),
    ("prompts/listChanged", McpCategory::Prompts),
    // Lifecycle
    ("initialize", McpCategory::Lifecycle),
    ("initialized", McpCategory::Lifecycle),
    ("ping", McpCategory::Lifecycle),
    ("cancelled", McpCategory::Lifecycle),
    ("shutdown", McpCategory::Lifecycle),
    // Completion
    ("completion/complete", McpCategory::Completion),
    // Logging
    ("logging/setLevel", McpCategory::Logging),
    ("logging/message", McpCategory::Logging),
    // Other
    ("notifications/roots/listChanged", McpCategory::Other),
    ("sampling/createMessage", McpCategory::Other),
];

/// Try to classify JSON fields as MCP JSON-RPC 2.0.
/// Returns None if this doesn't look like MCP.
pub fn classify(fields: &JsonFields) -> Option<McpInfo> {
    // Must have jsonrpc: "2.0"
    if fields.jsonrpc.as_deref() != Some("2.0") {
        return None;
    }

    let msg_type = determine_msg_type(fields);
    let method = fields.method.clone();
    let category = method
        .as_deref()
        .and_then(lookup_category)
        .unwrap_or(McpCategory::Other);

    // For responses/errors without a method, we can still identify them as MCP
    // if they have the JSON-RPC 2.0 structure
    let is_mcp = method.as_deref().map(is_mcp_method).unwrap_or(false)
        || matches!(msg_type, McpMsgType::Response | McpMsgType::Error);

    if !is_mcp {
        return None;
    }

    Some(McpInfo {
        method,
        category,
        msg_type,
        id: fields.id.clone(),
    })
}

fn determine_msg_type(fields: &JsonFields) -> McpMsgType {
    if fields.has_error && fields.id.is_some() {
        McpMsgType::Error
    } else if fields.has_result && fields.id.is_some() {
        McpMsgType::Response
    } else if fields.method.is_some() && fields.id.is_some() {
        McpMsgType::Request
    } else if fields.method.is_some() {
        McpMsgType::Notification
    } else {
        McpMsgType::Response // Default for ambiguous structures
    }
}

fn lookup_category(method: &str) -> Option<McpCategory> {
    for &(m, ref cat) in MCP_METHODS {
        if m == method {
            return Some(cat.clone());
        }
    }
    None
}

fn is_mcp_method(method: &str) -> bool {
    MCP_METHODS.iter().any(|&(m, _)| m == method)
        || method.starts_with("tools/")
        || method.starts_with("resources/")
        || method.starts_with("prompts/")
        || method.starts_with("logging/")
        || method.starts_with("completion/")
        || method.starts_with("notifications/")
        || method.starts_with("sampling/")
        || method == "initialize"
        || method == "initialized"
        || method == "ping"
        || method == "shutdown"
        || method == "cancelled"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    #[test]
    fn test_tools_call_request() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search"},"id":1}"#;
        let fields = json::analyze(body);
        let mcp = classify(&fields).unwrap();
        assert_eq!(mcp.method.as_deref(), Some("tools/call"));
        assert_eq!(mcp.category, McpCategory::Tools);
        assert_eq!(mcp.msg_type, McpMsgType::Request);
    }

    #[test]
    fn test_initialize_notification() {
        let body = br#"{"jsonrpc":"2.0","method":"initialized"}"#;
        let fields = json::analyze(body);
        let mcp = classify(&fields).unwrap();
        assert_eq!(mcp.category, McpCategory::Lifecycle);
        assert_eq!(mcp.msg_type, McpMsgType::Notification);
    }

    #[test]
    fn test_response() {
        let body = br#"{"jsonrpc":"2.0","result":{"tools":[]},"id":1}"#;
        let fields = json::analyze(body);
        let mcp = classify(&fields).unwrap();
        assert_eq!(mcp.msg_type, McpMsgType::Response);
    }

    #[test]
    fn test_error() {
        let body = br#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid"},"id":1}"#;
        let fields = json::analyze(body);
        let mcp = classify(&fields).unwrap();
        assert_eq!(mcp.msg_type, McpMsgType::Error);
    }

    #[test]
    fn test_non_mcp_jsonrpc() {
        let body = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","id":1}"#;
        let fields = json::analyze(body);
        assert!(classify(&fields).is_none());
    }

    #[test]
    fn test_non_jsonrpc() {
        let body = br#"{"model":"gpt-4","messages":[]}"#;
        let fields = json::analyze(body);
        assert!(classify(&fields).is_none());
    }
}
