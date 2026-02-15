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

# --- Deny: sensitive file access (e.g. .env, credentials, secrets) ---
decision = "deny" {
    _is_sensitive_file_access
    not input.action.pii_detected
    not _is_llm_traffic
}

# --- Audit: any file access event ---
decision = "audit" {
    input.action.type == "FileAccess"
    not _is_sensitive_file_access
}

# --- Reasons ---
reasons[reason] {
    input.action.type == "FileAccess"
    reason := concat("", ["File access: ", input.action.path, " (", input.action.mode, ")"])
}

reasons[reason] {
    _is_sensitive_file_access
    reason := concat("", ["Sensitive file access: ", input.action.path])
}

# --- Deny: file data write to sensitive files ---
decision = "deny" {
    _is_sensitive_file_write
    not input.action.pii_detected
    not _is_llm_traffic
    not _is_sensitive_file_access
}

# --- Audit: file data read events ---
decision = "audit" {
    input.action.type == "FileData"
    not _is_sensitive_file_write
}

# --- Reasons ---
reasons[reason] {
    input.action.type == "FileData"
    bytes_str := sprintf("%d", [input.action.bytes])
    reason := concat("", ["File data ", input.action.direction, ": ", input.action.path, " (", bytes_str, " bytes)"])
}

reasons[reason] {
    _is_sensitive_file_write
    reason := concat("", ["Sensitive file write: ", input.action.path])
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

# Helper: true when a FileAccess event targets a sensitive file.
_is_sensitive_file_access {
    input.action.type == "FileAccess"
    contains(input.action.path, ".env")
}

_is_sensitive_file_access {
    input.action.type == "FileAccess"
    contains(input.action.path, "credentials")
}

_is_sensitive_file_access {
    input.action.type == "FileAccess"
    contains(input.action.path, "secrets")
}

# Helper: true when a FileData event writes to a sensitive file.
_is_sensitive_file_write {
    input.action.type == "FileData"
    input.action.direction == "write"
    contains(input.action.path, ".env")
}

_is_sensitive_file_write {
    input.action.type == "FileData"
    input.action.direction == "write"
    contains(input.action.path, "credentials")
}

_is_sensitive_file_write {
    input.action.type == "FileData"
    input.action.direction == "write"
    contains(input.action.path, "secrets")
}
