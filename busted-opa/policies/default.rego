# Default Busted policy — edit or replace to customize.
#
# Input:  a BustedEvent (JSON), available as `input.*`
# Output: data.busted.decision  -> "allow" | "audit" | "deny"
#         data.busted.reasons   -> set of human-readable strings
#
# Static data (optional): place a `data.json` next to this file.
# It is accessible as `data.*` in rules (e.g. `data.allowed_providers`).
#
# Examples:
#   input.action.type       – action variant ("Network", "Prompt", "McpRequest", …)
#   input.action.provider   – provider name ("OpenAI", "Anthropic", …)
#   input.action.pii_detected – true when PII found in payload (Prompt only)
#   input.action.method     – MCP JSON-RPC method name (McpRequest/McpResponse)
#   input.process.pid / input.process.uid – process and user identifiers
#   input.process.container_id – short container ID
#   input.process.pod_namespace – Kubernetes namespace (if enriched)

package busted

default decision = "allow"

# --- Deny: PII in outbound LLM traffic ---
decision = "deny" {
    input.action.pii_detected == true
    _is_llm_traffic
}

# --- Audit: any traffic to a known LLM provider ---
decision = "audit" {
    _is_llm_traffic
    not input.action.pii_detected
}

# --- Reasons ---
reasons[reason] {
    input.action.pii_detected == true
    _is_llm_traffic
    reason := "PII detected in outbound LLM traffic"
}

reasons[reason] {
    input.action.provider != null
    reason := concat("", ["Traffic to LLM provider: ", input.action.provider])
}

reasons[reason] {
    input.action.method != null
    reason := concat("", ["MCP tool invocation detected: ", input.action.method])
}

# Helper: true when the event is related to LLM/AI traffic.
_is_llm_traffic {
    input.action.provider != null
}

_is_llm_traffic {
    input.action.type == "Prompt"
}

_is_llm_traffic {
    input.action.type == "McpRequest"
}
