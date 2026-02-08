# Busted

**eBPF-based LLM/AI Communication Monitoring and Identity Management**

Busted is a high-performance, kernel-native observability and policy enforcement system for tracking, classifying, and controlling LLM/AI communications. Built entirely in Rust with eBPF, it provides real-time visibility into AI agent behavior without requiring application changes.

## 🎯 Key Features

- **Kernel-Native Monitoring**: eBPF-based network observability with minimal overhead
- **Identity Anchoring**: Kernel-enforced identity for AI agents based on PID, cgroup, executable hash
- **LLM Provider Classification**: Automatically detect and classify communications with OpenAI, Anthropic, Google, Azure, AWS, and more
- **Policy Enforcement**: Block or audit LLM traffic based on process, container, or user identity
- **Metadata Collection**: Capture connection patterns, timing, data volumes, and request frequencies
- **No Application Changes**: Agentless monitoring requiring no SDK instrumentation or code modifications
- **Pure Rust**: End-to-end Rust implementation from eBPF programs to userspace agent

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Kernel Space (eBPF)                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │tcp_connect │  │tcp_sendmsg │  │tcp_recvmsg │            │
│  │   probe    │  │   probe    │  │   probe    │            │
│  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘            │
│         │                │                │                  │
│         └────────────────┴────────────────┘                  │
│                          │                                   │
│                   ┌──────▼────────┐                          │
│                   │  Event Buffer │                          │
│                   │ (PerfEventArray)                         │
│                   └──────┬────────┘                          │
└───────────────────────────┼──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│                    Userspace (Rust)                           │
│  ┌────────────────────────────────────────────────────────┐  │
│  │               Busted Agent                              │  │
│  │  • Load & attach eBPF programs                         │  │
│  │  • Process events from ring buffer                     │  │
│  │  • Classify LLM providers                              │  │
│  │  • Enforce policies                                    │  │
│  │  • Maintain agent identity mappings                    │  │
│  │  • Export metrics & logs                               │  │
│  └────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

## 📦 Project Structure

This is a Cargo workspace with multiple packages:

```
busted/
├── busted-types/       # Shared types between eBPF and userspace (#![no_std])
├── busted-ebpf/        # eBPF programs (kernel-side, #![no_std])
├── busted-agent/       # Userspace agent (loads eBPF, processes events)
├── xtask/              # Build automation
└── Cargo.toml          # Workspace configuration
```

### Package Breakdown

- **busted-types**: Common types and structures used by both kernel and userspace code
  - `NetworkEvent`: Captured network events
  - `AgentIdentity`: AI agent identity information
  - `LlmProvider`: Known LLM provider enumeration
  - `PolicyDecision`: Allow/deny/audit decisions

- **busted-ebpf**: eBPF programs that run in kernel space
  - `tcp_connect`: Probe for outgoing TCP connections
  - `tcp_sendmsg`: Probe for data transmission
  - `tcp_recvmsg`: Probe for data reception

- **busted-agent**: Userspace control plane
  - Loads and attaches eBPF programs
  - Reads events from perf buffer
  - Classifies LLM providers
  - Applies policy rules
  - Outputs structured logs

## 🚀 Getting Started

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

Or build individual components:

```bash
# Build only eBPF programs
cargo xtask build-ebpf

# Build in release mode
cargo xtask build --release
```

### Running

Run with sudo (required for eBPF):

```bash
sudo cargo xtask run
```

With options:

```bash
# Verbose output
sudo cargo xtask run -- --verbose

# JSON output format
sudo cargo xtask run -- --format json

# Enable policy enforcement (blocking)
sudo cargo xtask run -- --enforce
```

## 🔍 What Gets Monitored

Busted captures metadata about LLM/AI communications **without breaking TLS encryption**:

### Collected Metadata

✅ **Process Information**
- PID, TID, UID, GID
- Process name/command
- Executable path

✅ **Network Information**
- Source/destination IP addresses
- Source/destination ports
- Connection timing
- Data volume (bytes sent/received)

✅ **Container/Cgroup Information**
- Container ID
- Cgroup path
- Pod/namespace (Kubernetes)

✅ **Behavioral Patterns**
- Request frequency
- Connection duration
- Traffic volume over time

### What Cannot Be Monitored (TLS Encrypted)

❌ Prompt content
❌ Model responses
❌ Exact token counts
❌ Request payloads

## 🎯 Use Cases

### 1. **Shadow AI Detection**
Discover unauthorized LLM usage across your infrastructure:
```
[TCP_CONNECT] PID: 42315 (python3) | UID: 1000 | 10.0.1.5:54321 -> 20.42.73.21:443 | Provider: OpenAI
```

### 2. **Cost Attribution**
Track which teams/services are generating LLM API costs by observing request patterns.

### 3. **Compliance & Audit**
Create immutable audit trails of all LLM interactions for regulatory compliance.

### 4. **Policy Enforcement**
Block unauthorized LLM traffic:
```bash
# Only allow approved services to communicate with LLMs
sudo busted --enforce
```

### 5. **AI Agent Identity Management**
Anchor each AI agent's identity to kernel-verifiable primitives:
- Process ID + executable hash
- Container/cgroup ID
- User credentials

## 🛠️ Development

### Adding New Probes

1. Define event type in `busted-types/src/lib.rs`
2. Implement probe in `busted-ebpf/src/main.rs`
3. Add handler in `busted-agent/src/main.rs`

### Testing

```bash
# Build and run with verbose logging
sudo cargo xtask run -- --verbose

# Generate test traffic
curl https://api.openai.com/v1/models
```

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

## 🔒 Security & Privacy

### What Busted Does

✅ Monitors metadata only
✅ Requires explicit installation (not stealth)
✅ Runs with full visibility (not hidden)
✅ Provides audit trails

### What Busted Does NOT Do

❌ Decrypt TLS traffic
❌ Capture prompt/response content
❌ Keylog or screen capture
❌ Evade detection

### Legal & Ethical Considerations

⚠️ **Important**: Deploying this tool requires:
- **Consent**: Users must be informed about monitoring
- **Authorization**: Proper authorization in enterprise environments
- **Jurisdiction**: Compliance with local privacy and wiretap laws
- **Data minimization**: Only collect what's necessary

This tool is designed for:
- ✅ Enterprise IT security teams
- ✅ Compliance monitoring
- ✅ Authorized security research
- ✅ Educational purposes

NOT for:
- ❌ Unauthorized surveillance
- ❌ Privacy violations
- ❌ Malicious monitoring

## 🤝 Contributing

Contributions are welcome! Areas of interest:

- [ ] Enhanced LLM provider detection (IP ranges, ASN lookups)
- [ ] Support for LSM hooks (stronger enforcement)
- [ ] Kubernetes integration (pod labels, service accounts)
- [ ] Machine learning for traffic classification
- [ ] Integration with SIEM systems
- [ ] Performance optimizations
- [ ] Additional eBPF probes (file I/O, DNS, etc.)

## 📝 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- Built with [Aya](https://github.com/aya-rs/aya) - the Rust eBPF framework
- Inspired by modern observability and zero-trust security principles
- Thanks to the Rust and eBPF communities

## 📚 Resources

- [Aya Documentation](https://aya-rs.dev/)
- [eBPF Introduction](https://ebpf.io/)
- [Linux Observability with BPF](https://www.oreilly.com/library/view/linux-observability-with/9781492050193/)
