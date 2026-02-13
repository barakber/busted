//! Converts accumulated TLS buffers into typed [`AgenticAction`]s.
//!
//! Called after session completion (direction transition or idle timeout)
//! on the accumulated write/read buffers.

use busted_classifier::{
    classify, parse_llm_request, parse_llm_response, Classification, ContentClass, Direction,
};
use busted_types::agentic::AgenticAction;

use crate::tls::payload_to_string;

/// Parse an accumulated write (outbound) buffer into typed actions.
pub fn parse_write_actions(write_buf: &[u8], sni: Option<&str>) -> Vec<AgenticAction> {
    let mut actions = Vec::new();
    if write_buf.is_empty() {
        return actions;
    }

    let classification = classify(write_buf, Direction::Write, sni);
    let body_text = payload_to_string(write_buf);
    let bytes = write_buf.len() as u64;

    // Try to parse as LLM request
    if let Some(parsed) = parse_llm_request(&body_text, sni) {
        // Extract tool results first (they appear in the request as role="tool" / tool_result blocks)
        for tr in &parsed.tool_results {
            actions.push(AgenticAction::ToolResult {
                tool_name: tr.name.clone().unwrap_or_else(|| "unknown".to_string()),
                output_preview: tr.output_preview.clone(),
            });
        }

        // Main prompt action
        actions.push(AgenticAction::Prompt {
            provider: parsed.provider,
            model: parsed.model,
            user_message: parsed.user_message,
            system_prompt: parsed.system_prompt,
            stream: parsed.stream,
            sdk: classification.sdk_string(),
            bytes,
            sni: sni.map(|s| s.to_string()),
            endpoint: classification.endpoint().map(|s| s.to_string()),
            fingerprint: classification.signature_hash(),
            pii_detected: if classification.pii_flags.any() {
                Some(true)
            } else {
                None
            },
            confidence: Some(classification.confidence),
            sdk_hash: classification.sdk_hash(),
            model_hash: classification.model_hash(),
        });

        // PII action if detected
        if classification.pii_flags.any() {
            actions.push(AgenticAction::PiiDetected {
                direction: "write".to_string(),
                pii_types: Some(pii_type_list(&classification)),
            });
        }

        return actions;
    }

    // Try MCP
    if let Some(ContentClass::Mcp(ref mcp_info)) = classification.content {
        actions.push(AgenticAction::McpRequest {
            method: mcp_info
                .method
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            category: Some(mcp_info.category.to_string()),
            params_preview: None,
        });
        return actions;
    }

    // Fallback: if interesting but not parsed, still emit a generic prompt
    if classification.is_interesting {
        actions.push(make_fallback_prompt(&classification, bytes, sni));
    }

    actions
}

/// Parse an accumulated read (inbound) buffer into typed actions.
pub fn parse_read_actions(read_buf: &[u8], sni: Option<&str>) -> Vec<AgenticAction> {
    let mut actions = Vec::new();
    if read_buf.is_empty() {
        return actions;
    }

    let classification = classify(read_buf, Direction::Read, sni);
    let body_text = payload_to_string(read_buf);
    let bytes = read_buf.len() as u64;

    // Try to parse as LLM response
    if let Some(parsed) = parse_llm_response(&body_text, sni) {
        // Extract tool calls from the response
        for tc in &parsed.tool_calls {
            actions.push(AgenticAction::ToolCall {
                tool_name: tc.name.clone(),
                input_json: tc.input_json.clone(),
                provider: parsed.provider.clone(),
            });
        }

        // Main response action
        actions.push(AgenticAction::Response {
            provider: parsed.provider,
            model: parsed.model,
            bytes,
            sni: sni.map(|s| s.to_string()),
            confidence: Some(classification.confidence),
        });

        // PII in response
        if classification.pii_flags.any() {
            actions.push(AgenticAction::PiiDetected {
                direction: "read".to_string(),
                pii_types: Some(pii_type_list(&classification)),
            });
        }

        return actions;
    }

    // Try MCP response
    if let Some(ContentClass::Mcp(ref mcp_info)) = classification.content {
        actions.push(AgenticAction::McpResponse {
            method: mcp_info
                .method
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            result_preview: None,
        });
        return actions;
    }

    // LLM stream response
    if let Some(ContentClass::LlmStream(ref stream_info)) = classification.content {
        actions.push(AgenticAction::Response {
            provider: stream_info.provider.clone(),
            model: None,
            bytes,
            sni: sni.map(|s| s.to_string()),
            confidence: Some(classification.confidence),
        });
        return actions;
    }

    // Fallback: generic LLM response
    if classification.is_interesting {
        let provider = classification.provider().unwrap_or("unknown").to_string();
        actions.push(AgenticAction::Response {
            provider,
            model: classification.model().map(|s| s.to_string()),
            bytes,
            sni: sni.map(|s| s.to_string()),
            confidence: Some(classification.confidence),
        });
    }

    actions
}

fn make_fallback_prompt(
    classification: &Classification,
    bytes: u64,
    sni: Option<&str>,
) -> AgenticAction {
    let provider = classification.provider().unwrap_or("unknown").to_string();
    AgenticAction::Prompt {
        provider,
        model: classification.model().map(|s| s.to_string()),
        user_message: None,
        system_prompt: None,
        stream: false,
        sdk: classification.sdk_string(),
        bytes,
        sni: sni.map(|s| s.to_string()),
        endpoint: classification.endpoint().map(|s| s.to_string()),
        fingerprint: classification.signature_hash(),
        pii_detected: if classification.pii_flags.any() {
            Some(true)
        } else {
            None
        },
        confidence: Some(classification.confidence),
        sdk_hash: classification.sdk_hash(),
        model_hash: classification.model_hash(),
    }
}

fn pii_type_list(classification: &Classification) -> Vec<String> {
    let mut types = Vec::new();
    let f = &classification.pii_flags;
    if f.has_email {
        types.push("email".to_string());
    }
    if f.has_credit_card {
        types.push("credit_card".to_string());
    }
    if f.has_ssn {
        types.push("ssn".to_string());
    }
    if f.has_phone {
        types.push("phone".to_string());
    }
    if f.has_api_key {
        types.push("api_key".to_string());
    }
    types
}
