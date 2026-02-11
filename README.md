# Busted

**eBPF-based LLM/AI Communication Monitoring and Policy Enforcement**

Busted is a high-performance, kernel-native observability and policy enforcement system for tracking, classifying, and controlling LLM/AI communications. Built entirely in Rust with eBPF, it provides real-time visibility into AI agent behavior without requiring application changes.

## Demo

Real-time policy enforcement blocking an AI agent from sending specific content to Anthropic's API:

<img src="busted.gif" alt="Busted policy enforcement demo" width="600">

```bash
sudo busted monitor --enforce --rule '
  package busted
  default decision = "allow"
  decision = "deny" {
      input.llm_provider == "Anthropic"
      contains(input.tls_payload, "berko")
  }'
```

## Key Features

- **Kernel-Native Monitoring**: eBPF kprobes/uprobes with minimal overhead via RingBuf transport
- **TLS Plaintext Capture**: Intercepts decrypted data from OpenSSL SSL_write/SSL_read to see actual LLM prompts and responses
- **LLM & MCP Detection**: Automatically identifies API calls to 15+ LLM providers and MCP JSON-RPC traffic
- **OPA Policy Enforcement**: Evaluate events against Rego policies for allow/audit/deny decisions with optional kernel-level enforcement
- **Agent Identity Tracking**: Correlates events across time to resolve stable AI agent identities from weak signals
- **TLS SNI Extraction**: Captures server hostnames from TLS handshakes via SSL_ctrl uprobe
- **ML Behavioral Classification**: Optional machine learning classifier detects LLM traffic patterns by network behavior
- **Container & Kubernetes Awareness**: Resolves container IDs, pod names, namespaces, and service accounts
- **SIEM Integration**: Output to webhooks, files, or syslog alongside stdout
- **Native Dashboard**: Real-time egui desktop UI with live event table, provider stats, and identity columns
- **No Application Changes**: Agentless monitoring requiring no SDK instrumentation or code modifications
- **Pure Rust**: End-to-end Rust implementation from eBPF programs to userspace agent and UI

## Architecture

```
┌──────────────────────────── Kernel Space (eBPF) ────────────────────────────┐
│                                                                             │
│  Kprobes                          Uprobes (OpenSSL)         LSM            │
│  ┌─────────────┐                  ┌──────────────────┐   ┌──────────────┐  │
│  │tcp_connect   │                  │ssl_ctrl_sni      │   │socket_connect│  │
│  │tcp_sendmsg   │                  │ssl_write_entry   │   │  (enforce)   │  │
│  │tcp_recvmsg   │                  │ssl_read_entry    │   └──────────────┘  │
│  │tcp_close     │                  │ssl_read_ret      │                     │
│  │udp_sendmsg   │                  │ssl_free_cleanup  │                     │
│  └──────┬───────┘                  └────────┬─────────┘                     │
│         │                                   │                               │
│         └───────────┬───────────────────────┘                               │
│                     │                                                       │
│              ┌──────▼──────┐    ┌───────────────────┐                       │
│              │  EVENTS     │    │ TLS_CONN_VERDICT   │◄── userspace writes  │
│              │ (RingBuf    │    │ (HashMap)          │    verdict back      │
│              │  512KB)     │    └───────────────────┘                       │
│              └──────┬──────┘                                                │
└─────────────────────┼──────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────────────────┐
│                         Userspace Agent (Rust/Tokio)                        │
│                                                                             │
│  ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐   │
│  │ Event Dispatch   │  │ TLS Analysis     │  │ Provider Classification │   │
│  │ • NetworkEvent   │  │ • First-chunk    │  │ • DNS resolution        │   │
│  │ • TlsHandshake   │  │   LLM/MCP detect │  │ • IP/subnet matching   │   │
│  │ • TlsDataEvent   │  │ • Verdict→eBPF   │  │ • SNI classification   │   │
│  └────────┬────────┘  └──────────────────┘  └──────────────────────────┘   │
│           │                                                                 │
│  ┌────────▼────────────────────────────────────────────────┐               │
│  │              Broadcast Channel (tokio)                   │               │
│  └──┬──────────┬──────────────┬─────────────┬──────────────┘               │
│     │          │              │             │                               │
│  ┌──▼──┐  ┌───▼────┐  ┌─────▼─────┐  ┌───▼──────┐                        │
│  │ CLI │  │ Socket │  │   SIEM    │  │ ML       │                        │
│  │ out │  │ server │  │ (webhook, │  │ classify │                        │
│  └─────┘  └───┬────┘  │  file,    │  └──────────┘                        │
│               │       │  syslog)  │                                       │
│               │       └───────────┘                                       │
└───────────────┼───────────────────────────────────────────────────────────┘
                │
        ┌───────▼───────┐
        │  busted-ui    │
        │  (egui native │
        │   dashboard)  │
        └───────────────┘
```

## Project Structure

```
busted/
├── busted-types/       # Shared types between eBPF and userspace (#![no_std])
├── busted-ebpf/        # eBPF programs (kernel-side, #![no_std], #![no_main])
├── busted-agent/       # Userspace agent (loads eBPF, processes events, broadcasts)
├── busted-classifier/  # Stateless TLS payload classifier (HTTP/LLM/MCP/PII)
├── busted-identity/    # Cross-event agent identity resolution and timeline tracking
├── busted-ml/          # ML behavioral traffic classifier (linfa/hdbscan)
├── busted-opa/         # OPA/Rego policy engine (regorus)
├── busted-ui/          # Native egui dashboard (live + demo mode)
├── busted-cli/         # Unified CLI: `busted monitor`, `busted policy`, `busted ui`
├── deploy/             # Helm chart, Dockerfiles, systemd unit, docker-compose
├── xtask/              # Build automation
└── Cargo.toml          # Workspace configuration
```

## Installation

### APT (Debian/Ubuntu)

```bash
echo "deb [trusted=yes] https://barakber.github.io/busted/repos/apt ./" \
  | sudo tee /etc/apt/sources.list.d/busted.list
sudo apt-get update
sudo apt-get install busted
```

### YUM/DNF (RHEL/Fedora/CentOS)

```bash
sudo tee /etc/yum.repos.d/busted.repo <<EOF
[busted]
name=Busted
baseurl=https://barakber.github.io/busted/repos/yum
enabled=1
gpgcheck=0
EOF
sudo dnf install busted
```

### APK (Alpine)

Download the `.apk` from [GitHub Releases](https://github.com/barakber/busted/releases) and install:

```bash
apk add --allow-untrusted busted-*.apk
```

### Direct Download

Pre-built binaries and packages (`.deb`, `.rpm`, `.apk`) are attached to each [GitHub Release](https://github.com/barakber/busted/releases).

### From Source

See [Getting Started](#getting-started) below for building from source.

## Getting Started

### Prerequisites

1. **Rust toolchain** (with nightly for eBPF):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install stable
rustup toolchain install nightly --component rust-src
```

2. **bpf-linker** (for linking eBPF programs):
```bash
cargo install bpf-linker
```

3. **Linux kernel** with eBPF support (5.4+, 5.15+ recommended)

4. **Root privileges** (required for loading eBPF programs)

### Building

Build the entire project (eBPF + userspace):

```bash
cargo xtask build
```

Build with optional features:

```bash
# TLS plaintext capture (SSL_write/SSL_read uprobes)
cargo xtask build --features tls

# All features
cargo xtask build --features tls,ml,opa,identity

# Release mode
cargo xtask build --release --features tls
```

Build the UI dashboard separately:

```bash
cargo build -p busted-ui
```

### Running

The unified CLI provides subcommands for monitoring, policy management, and the dashboard:

```bash
# Monitor LLM traffic (requires sudo for eBPF)
sudo busted monitor

# With TLS plaintext capture and verbose output
sudo busted monitor --verbose

# JSON output format
sudo busted monitor --format json

# Enable policy enforcement (LSM blocking + process kill on deny)
sudo busted monitor --enforce --policy-dir ./policies/

# Inline Rego rule
sudo busted monitor --enforce --rule 'package busted
  default decision = "allow"
  decision = "deny" { input.llm_provider == "Anthropic" }'

# Output to SIEM
sudo busted monitor --output webhook:https://siem.example.com/events
sudo busted monitor --output file:/var/log/busted.jsonl
sudo busted monitor --output syslog:siem-host:514
```

Dashboard:

```bash
# Launch the UI (connects to agent via /tmp/busted.sock)
sudo busted ui

# Demo mode (no agent required — synthetic events)
busted ui --demo
```

Policy management:

```bash
# Validate policy files
busted policy check --dir ./policies/

# Evaluate a policy against sample JSON input
busted policy eval --dir ./policies/ --input event.json

# Run policy unit tests
busted policy test --dir ./policies/
```

## What Gets Monitored

### Network Metadata (always captured)

- **Process Information**: PID, TID, UID, GID, process name, cgroup ID
- **Network Information**: Source/destination IPs and ports, bytes transferred, connection lifecycle
- **Container/Cgroup**: Container ID (Docker/containerd), cgroup path
- **Kubernetes** (with `k8s` feature): Pod name, namespace, service account
- **Traffic Patterns**: Per-PID request rate, session byte totals
- **DNS Queries**: Destination port 53 UDP traffic

### TLS Intelligence (with `tls` feature)

- **SNI Hostnames**: Server name extracted from TLS handshakes (SSL_ctrl uprobe)
- **Decrypted Payloads**: First 512 bytes of SSL_write/SSL_read plaintext
- **LLM API Detection**: HTTP request paths, auth headers, JSON body analysis
- **MCP Protocol Detection**: JSON-RPC 2.0 methods (tools/list, tools/call, resources/read, etc.)
- **Connection Verdicts**: Interesting connections continue to be captured; boring ones are skipped in-kernel

### LLM Provider Classification

Detected via DNS resolution, IP/subnet matching, SNI hostname, and content analysis:

| Provider | Endpoints |
|----------|-----------|
| OpenAI | api.openai.com |
| Anthropic | api.anthropic.com |
| Google | generativelanguage.googleapis.com, aiplatform.googleapis.com |
| Azure | openai.azure.com, cognitiveservices.azure.com |
| AWS Bedrock | bedrock-runtime.*.amazonaws.com |
| Cohere | api.cohere.ai |
| HuggingFace | api-inference.huggingface.co |
| Mistral | api.mistral.ai |
| Groq | api.groq.com |
| Together | api.together.xyz |
| DeepSeek | api.deepseek.com |
| Perplexity | api.perplexity.ai |
| Ollama | localhost:11434 (local) |
| OpenAI-compatible | Any endpoint serving /v1/chat/completions |
| Anthropic-compatible | Any endpoint serving /v1/messages |

## Example Output

### Text mode (default)

```
14:32:01 python3 (1234) >>> Anthropic claude-sonnet-4-20250514 messages [sdk:anthropic-python | stream]
  user: Write me a haiku about eBPF
  system: You are a helpful assistant
14:32:02 python3 (1234) <<< Anthropic claude-sonnet-4-20250514 messages (1.2 KB)
14:32:05 node (5678) >>> OpenAI gpt-4 chat/completions [sdk:openai-node | PII! | policy:audit]
  user: Summarize this document: ...
```

### JSON mode (`--format json`)

```json
{
  "event_type": "TLS_DATA_WRITE",
  "timestamp": "14:32:01.125",
  "pid": 1234,
  "uid": 1000,
  "process_name": "python3",
  "src_ip": "10.0.1.5",
  "src_port": 54321,
  "dst_ip": "160.79.104.5",
  "dst_port": 443,
  "bytes": 312,
  "provider": "Anthropic",
  "policy": "audit",
  "container_id": "",
  "cgroup_id": 1,
  "sni": "api.anthropic.com",
  "content_class": "LLM_REQUEST",
  "llm_provider": "Anthropic",
  "llm_endpoint": "/v1/messages",
  "llm_model": "claude-sonnet-4-20250514",
  "agent_sdk": "anthropic-python",
  "classifier_confidence": 0.98,
  "pii_detected": false,
  "llm_user_message": "Write me a haiku about eBPF",
  "llm_system_prompt": "You are a helpful assistant",
  "llm_stream": true,
  "identity_id": 42,
  "identity_instance": "python3-1234-anthropic",
  "identity_confidence": 0.92,
  "identity_narrative": "Anthropic claude-sonnet-4-20250514 agent via anthropic-python SDK"
}
```

## Feature Flags

| Feature | Flag | Description |
|---------|------|-------------|
| TLS Capture | `tls` | SSL_write/SSL_read plaintext interception, SNI extraction |
| ML Classifier | `ml` | Behavioral traffic classification using linfa decision trees + HDBSCAN clustering |
| Kubernetes | `k8s` | Pod metadata resolution via kube API watcher |
| OPA Policies | `opa` | Rego policy evaluation with allow/audit/deny decisions |
| Identity | `identity` | Cross-event agent identity correlation and timeline tracking |
| Prometheus | `prometheus` | Metrics exporter on configurable port |
| UI | `ui` | egui native dashboard (unified CLI only) |
| Full | `full` | All features enabled |

Build with features:
```bash
# Agent with specific features
cargo build -p busted-agent --features tls,opa,identity

# Unified CLI with all features
cargo build -p busted --features full

# CLI for CI/CD (policy tools only, no eBPF)
cargo build -p busted --no-default-features --features policy
```

## Policy Engine (OPA/Rego)

Busted integrates an OPA/Rego policy engine for LLM communication governance. Policies evaluate every `ProcessedEvent` and return allow, audit, or deny decisions.

### Example policy

```rego
package busted

default decision = "allow"

# Deny requests containing PII to external providers
decision = "deny" {
    input.pii_detected == true
    input.llm_provider != "Ollama"
}

# Audit all Anthropic traffic
decision = "audit" {
    input.llm_provider == "Anthropic"
}
```

### CLI commands

```bash
# Run agent with policies from a directory
sudo busted monitor --policy-dir ./policies/

# Run agent with an inline Rego rule
sudo busted monitor --rule 'package busted
  default decision = "allow"
  decision = "deny" { input.pii_detected == true }'

# Validate policy syntax
busted policy check --dir ./policies/

# Run policy unit tests
busted policy test --dir ./policies/

# Evaluate a policy against sample input
echo '{"llm_provider":"Anthropic","pii_detected":true}' | busted policy eval --dir ./policies/
```

With `--enforce`, deny decisions trigger kernel-level enforcement: the eBPF verdict map is updated and the offending process is sent SIGKILL.

## Identity Tracking

The `identity` feature correlates events across time to resolve stable AI agent identities. Each event carries weak signals — PID, SDK name, model, container ID, fingerprint hash — that individually aren't unique. The identity tracker combines these signals to assign a stable `identity_id` and build per-agent action timelines.

This enables:
- Tracking which agent instances are active and what they're doing
- Correlating prompts and responses across multiple API calls
- Building narrative descriptions of agent behavior over time
- Writing OPA policies that reference identity fields

## Deployment

### Docker

```bash
# Build the image
docker build -f deploy/Dockerfile -t busted:latest .

# Run (requires privileged for eBPF)
docker run --privileged --pid=host -v /sys:/sys:ro busted:latest
```

### Docker Compose

```bash
cd deploy
docker-compose up
```

### systemd

```bash
sudo cp deploy/systemd/busted.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now busted
```

### Helm (Kubernetes)

```bash
helm install busted deploy/helm/busted \
  --set features.tls=true \
  --set features.opa=true
```

The chart deploys busted as a DaemonSet with privileged containers, host PID namespace access, and a ConfigMap for OPA policies. See `deploy/helm/busted/values.yaml` for all options.

## Testing

```bash
# All tests
cargo test --workspace --exclude busted-ebpf

# Per-crate
cargo test -p busted-classifier
cargo test -p busted-identity
cargo test -p busted-ml
cargo test -p busted-opa

# Policy unit tests
busted policy test --dir ./policies/

# Integration test (requires sudo)
# Terminal 1: start agent
sudo busted monitor --verbose

# Terminal 2: generate LLM traffic
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-test123" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

## eBPF Programs

| Program | Type | Hook | Purpose |
|---------|------|------|---------|
| `tcp_connect` | kprobe | `tcp_connect` | Outgoing TCP connections |
| `tcp_sendmsg` | kprobe | `tcp_sendmsg` | Data transmission |
| `tcp_recvmsg` | kprobe | `tcp_recvmsg` | Data reception |
| `tcp_close` | kprobe | `tcp_close` | Connection teardown |
| `udp_sendmsg` | kprobe | `udp_sendmsg` | DNS queries (port 53) |
| `ssl_ctrl_sni` | uprobe | `SSL_ctrl` | TLS SNI hostname extraction |
| `ssl_write_entry` | uprobe | `SSL_write` | Outgoing plaintext capture |
| `ssl_read_entry` | uprobe | `SSL_read` | Stash read buffer pointer |
| `ssl_read_ex_entry` | uprobe | `SSL_read_ex` | Stash read buffer + readbytes pointer |
| `ssl_read_ret` | uretprobe | `SSL_read` | Incoming plaintext capture |
| `ssl_free_cleanup` | uprobe | `SSL_free` | Connection state cleanup |
| `lsm_socket_connect` | LSM | `socket_connect` | Policy enforcement (block/allow) |

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for the full development guide, including build process, code structure, debugging, and contributing guidelines.

## Security & Privacy

### What Busted Does

- Monitors network metadata and optionally captures decrypted TLS payloads
- Requires explicit installation with root privileges
- Provides full audit trails of LLM/AI communications
- Enforces policies via kernel LSM hooks and process signals

### Legal & Ethical Considerations

Deploying this tool requires:
- **Consent**: Users must be informed about monitoring
- **Authorization**: Proper authorization in enterprise environments
- **Jurisdiction**: Compliance with local privacy and wiretap laws
- **Data minimization**: Only collect what's necessary

This tool is designed for:
- Enterprise IT security teams
- Compliance monitoring
- Authorized security research
- Educational purposes

## License

MIT License - see LICENSE file for details

## Acknowledgments

- Built with [Aya](https://github.com/aya-rs/aya) - the Rust eBPF framework
- Inspired by modern observability and zero-trust security principles
- Thanks to the Rust and eBPF communities

## Resources

- [Aya Documentation](https://aya-rs.dev/)
- [eBPF Introduction](https://ebpf.io/)
- [Linux Observability with BPF](https://www.oreilly.com/library/view/linux-observability-with/9781492050193/)
