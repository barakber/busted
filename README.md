# Busted

**eBPF-based LLM/AI Communication Monitoring and Identity Management**

Busted is a high-performance, kernel-native observability and policy enforcement system for tracking, classifying, and controlling LLM/AI communications. Built entirely in Rust with eBPF, it provides real-time visibility into AI agent behavior without requiring application changes.

## Key Features

- **Kernel-Native Monitoring**: eBPF kprobes/uprobes with minimal overhead via RingBuf transport
- **TLS Plaintext Capture**: Intercepts decrypted data from OpenSSL SSL_write/SSL_read to see actual LLM prompts and responses
- **LLM & MCP Detection**: Automatically identifies API calls to OpenAI, Anthropic, Google, Azure, AWS Bedrock, and MCP JSON-RPC traffic
- **TLS SNI Extraction**: Captures server hostnames from TLS handshakes via SSL_ctrl uprobe
- **Policy Enforcement**: LSM hook on socket_connect to block or audit LLM traffic per-process
- **ML Behavioral Classification**: Optional machine learning classifier detects LLM traffic patterns by network behavior
- **Container & Kubernetes Awareness**: Resolves container IDs, pod names, namespaces, and service accounts
- **SIEM Integration**: Output to webhooks, files, or syslog alongside stdout
- **Native Dashboard**: Real-time egui desktop UI with live event table, provider stats, and process views
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
├── busted-ebpf/        # eBPF programs (kernel-side, #![no_std])
├── busted-agent/       # Userspace agent (loads eBPF, processes events)
│   └── src/
│       ├── main.rs     # CLI, probe attachment, event dispatch
│       ├── events.rs   # ProcessedEvent construction
│       ├── tls.rs      # TLS content analysis, SNI cache, connection tracker
│       ├── server.rs   # Unix socket server for UI
│       ├── siem.rs     # SIEM output sinks
│       └── ml/         # ML behavioral classifier (behind `ml` feature)
├── busted-ui/          # Native egui dashboard
├── xtask/              # Build automation
└── Cargo.toml          # Workspace configuration
```

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

# ML behavioral classifier
cargo xtask build --features ml

# Multiple features
cargo xtask build --features tls,ml

# Release mode
cargo xtask build --release --features tls
```

Build the UI dashboard separately:

```bash
cargo build -p busted-ui
```

### Running

Run with sudo (required for eBPF):

```bash
# Basic monitoring
sudo ./target/debug/busted

# With TLS plaintext capture and verbose output
sudo ./target/debug/busted --verbose

# JSON output format
sudo ./target/debug/busted --format json

# Enable policy enforcement (LSM blocking)
sudo ./target/debug/busted --enforce

# Output to SIEM
sudo ./target/debug/busted --output webhook:https://siem.example.com/events
sudo ./target/debug/busted --output file:/var/log/busted.jsonl
sudo ./target/debug/busted --output syslog:siem-host:514
```

Run the UI dashboard (connects via Unix socket):

```bash
# The agent creates /tmp/busted.sock owned by root.
# Either run the UI as root, or chmod the socket after agent starts:
#   sudo chmod 777 /tmp/busted.sock
sudo ./target/debug/busted-ui

# Demo mode (no agent required — synthetic events):
./target/debug/busted-ui --demo
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

Detected via DNS resolution, IP/subnet matching, and SNI hostname:

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

## Example Output

### Text mode (default)

```
[TCP_CONNECT] 14:32:01.123 | PID: 1234 (python3) | UID: 1000 | 10.0.1.5:54321 -> 162.159.140.245:443 | Provider: OpenAI | Policy: audit
TLS SNI: PID 1234 (python3) -> api.openai.com
[TLS_DATA_WRITE] 14:32:01.125 | PID: 1234 (python3) | 312 bytes | HTTP/LLM (OpenAI chat completions)
---
POST /v1/chat/completions HTTP/1.1
Host: api.openai.com
Authorization: Bearer sk-...
Content-Type: application/json

{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
---
[TLS_DATA_READ] 14:32:01.450 | PID: 1234 (python3) | 265 bytes | HTTP/LLM
---
{"choices":[{"message":{"role":"assistant","content":"Hello! How can I help?"}}]}
---
```

### JSON mode (`--format json`)

```json
{
  "event_type": "TLS_DATA_WRITE",
  "timestamp": "14:32:01.125",
  "pid": 1234,
  "process_name": "python3",
  "bytes": 312,
  "provider": "HTTP/LLM",
  "tls_protocol": "HTTP/LLM",
  "tls_details": "OpenAI chat completions",
  "tls_payload": "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n..."
}
```

## Feature Flags

| Feature | Flag | Description |
|---------|------|-------------|
| TLS Capture | `--features tls` | SSL_write/SSL_read plaintext interception, SNI extraction |
| ML Classifier | `--features ml` | Behavioral traffic classification using linfa decision trees + HDBSCAN clustering |
| Kubernetes | `--features k8s` | Pod metadata resolution via kube API watcher |

## Testing

```bash
# Run the integration test (requires sudo)
sudo bash test-tls.sh

# Or manually:
# Terminal 1: start agent
sudo ./target/debug/busted --verbose

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
| `ssl_read_ret` | uretprobe | `SSL_read` | Incoming plaintext capture |
| `ssl_free_cleanup` | uprobe | `SSL_free` | Connection state cleanup |
| `lsm_socket_connect` | LSM | `socket_connect` | Policy enforcement (block/allow) |

## Development

### Adding New Probes

1. Define event type in `busted-types/src/lib.rs`
2. Implement probe in `busted-ebpf/src/main.rs`
3. Add dispatch handler in `busted-agent/src/main.rs`

### Debugging eBPF Programs

Enable eBPF logging:
```rust
use aya_log_ebpf::info;
info!(&ctx, "Debug message: {}", value);
```

View logs:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Check attached uprobes:
```bash
sudo cat /sys/kernel/debug/tracing/uprobe_events
```

## Security & Privacy

### What Busted Does

- Monitors network metadata and optionally captures decrypted TLS payloads
- Requires explicit installation with root privileges
- Provides full audit trails of LLM/AI communications
- Enforces policies via kernel LSM hooks

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
