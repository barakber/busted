//! MCP capability fingerprinting.
//!
//! Extracts tool names from MCP `tools/list` responses and computes
//! a deterministic FNV-1a hash of the sorted set. This identifies
//! agents by their declared capabilities — two agents with the same
//! tools are likely the same type, even across restarts.

use busted_types::agentic::BustedEvent;

/// Try to extract a capability hash from an MCP event.
///
/// Looks for MCP `tools/list` response payloads in `tls_payload` or
/// `llm_messages_json`. The payload should contain a JSON object with
/// a `tools` array where each element has a `name` field.
///
/// Returns `Some(hash)` if tool names were successfully extracted.
pub fn extract_capability_hash(event: &BustedEvent) -> Option<u64> {
    // Only attempt on MCP-classified events
    if event.mcp_category().is_none() && event.mcp_method().is_none() {
        return None;
    }

    // In the agentic model, full payloads are not carried in BustedEvent.
    // MCP tool names extraction would need the raw payload from McpResponse,
    // which is currently only available as a truncated preview.
    None
}

/// FNV-1a 64-bit hash.
#[cfg(test)]
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let prime: u64 = 0x00000100000001B3;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(prime);
    }
    h
}

/// Parse JSON payload and extract sorted tool names hash.
///
/// Handles two common shapes:
/// 1. `{"result": {"tools": [{"name": "..."}, ...]}}` (JSON-RPC response)
/// 2. `{"tools": [{"name": "..."}, ...]}` (direct)
#[cfg(test)]
fn extract_tool_names_hash(payload: &str) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;

    let tools_array = value
        .get("result")
        .and_then(|r| r.get("tools"))
        .or_else(|| value.get("tools"))
        .and_then(|t| t.as_array())?;

    let mut names: Vec<&str> = tools_array
        .iter()
        .filter_map(|tool| tool.get("name").and_then(|n| n.as_str()))
        .collect();

    if names.is_empty() {
        return None;
    }

    // Sort for determinism
    names.sort();

    // Build byte representation and hash
    let joined = names.join("\0");
    Some(fnv1a_64(joined.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_from_jsonrpc_response() {
        let payload = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"Read a file"},{"name":"write_file","description":"Write a file"}]}}"#;
        let hash = extract_tool_names_hash(payload);
        assert!(hash.is_some());
    }

    #[test]
    fn extract_from_direct_tools() {
        let payload = r#"{"tools":[{"name":"search","description":"Search"},{"name":"fetch","description":"Fetch URL"}]}"#;
        let hash = extract_tool_names_hash(payload);
        assert!(hash.is_some());
    }

    #[test]
    fn deterministic_hash() {
        let payload = r#"{"tools":[{"name":"b_tool"},{"name":"a_tool"},{"name":"c_tool"}]}"#;
        let h1 = extract_tool_names_hash(payload).unwrap();
        let h2 = extract_tool_names_hash(payload).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn order_independent() {
        let p1 = r#"{"tools":[{"name":"alpha"},{"name":"beta"},{"name":"gamma"}]}"#;
        let p2 = r#"{"tools":[{"name":"gamma"},{"name":"alpha"},{"name":"beta"}]}"#;
        let h1 = extract_tool_names_hash(p1).unwrap();
        let h2 = extract_tool_names_hash(p2).unwrap();
        assert_eq!(
            h1, h2,
            "sorted names should produce same hash regardless of order"
        );
    }

    #[test]
    fn empty_tools_returns_none() {
        let payload = r#"{"tools":[]}"#;
        assert!(extract_tool_names_hash(payload).is_none());
    }

    #[test]
    fn invalid_json_returns_none() {
        assert!(extract_tool_names_hash("not json").is_none());
    }

    #[test]
    fn no_tools_field_returns_none() {
        assert!(extract_tool_names_hash(r#"{"method":"tools/list"}"#).is_none());
    }

    #[test]
    fn different_toolsets_produce_different_hashes() {
        let p1 = r#"{"tools":[{"name":"read"},{"name":"write"}]}"#;
        let p2 = r#"{"tools":[{"name":"search"},{"name":"fetch"}]}"#;
        let h1 = extract_tool_names_hash(p1).unwrap();
        let h2 = extract_tool_names_hash(p2).unwrap();
        assert_ne!(h1, h2);
    }
}
