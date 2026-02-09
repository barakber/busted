# Default Busted policy — edit or replace to customize.
#
# Input:  a ProcessedEvent (JSON), available as `input.*`
# Output: data.busted.decision  → "allow" | "audit" | "deny"
#         data.busted.reasons   → set of human-readable strings
#
# Static data (optional): place a `data.json` next to this file.
# It is accessible as `data.*` in rules (e.g. `data.allowed_providers`).
#
# Examples:
#   input.provider          – IP/SNI-based provider name ("OpenAI", "Anthropic", …)
#   input.llm_provider      – content-classified provider
#   input.pii_detected      – true when PII found in payload
#   input.content_class     – classifier label ("LlmApi", "Mcp", …)
#   input.mcp_method        – MCP JSON-RPC method name
#   input.pid / input.uid   – process and user identifiers
#   input.container_id      – short container ID
#   input.pod_namespace     – Kubernetes namespace (if enriched)

package busted

default decision = "allow"

# --- Deny: PII in outbound LLM traffic ---
decision = "deny" {
    input.pii_detected == true
    _is_llm_traffic
}

# --- Audit: any traffic to a known LLM provider ---
decision = "audit" {
    _is_llm_traffic
    not input.pii_detected
}

# --- Reasons ---
reasons[reason] {
    input.pii_detected == true
    _is_llm_traffic
    reason := "PII detected in outbound LLM traffic"
}

reasons[reason] {
    input.provider != null
    reason := concat("", ["Traffic to LLM provider: ", input.provider])
}

reasons[reason] {
    input.llm_provider != null
    reason := concat("", ["Content classified as LLM API call to: ", input.llm_provider])
}

reasons[reason] {
    input.mcp_method != null
    reason := concat("", ["MCP tool invocation detected: ", input.mcp_method])
}

# Helper: true when the event is related to LLM/AI traffic.
_is_llm_traffic {
    input.provider != null
}

_is_llm_traffic {
    input.llm_provider != null
}

_is_llm_traffic {
    input.content_class == "LlmApi"
}
