# Development Guide

## Platform Support

### eBPF Programs
eBPF programs (`busted-ebpf`) can only run on Linux with kernel 5.4+. They must be cross-compiled for the `bpfel-unknown-none` target.

### Userspace Agent
The userspace agent (`busted-agent`) currently requires Linux for development due to `aya` dependencies on Linux-specific syscalls.

### Development on macOS/Windows

If you're developing on macOS or Windows, you have several options:

#### Option 1: Linux VM (Recommended)
```bash
# Using multipass
multipass launch --name busted-dev --cpus 4 --memory 4G
multipass shell busted-dev

# Install Rust and dependencies
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

#### Option 2: Docker Development Container
```dockerfile
FROM rust:latest

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    linux-headers-generic \
    build-essential

RUN rustup toolchain install nightly --component rust-src
RUN cargo install bpf-linker

WORKDIR /workspace
```

#### Option 3: Cross-Compilation (Advanced)
You can compile the eBPF programs on macOS/Windows for Linux targets, but testing requires a Linux environment.

## Build Process

### Full Build
```bash
cargo xtask build
```

This will:
1. Build eBPF programs for `bpfel-unknown-none` target
2. Build the userspace agent
3. Embed eBPF bytecode into the agent binary

### Development Workflow

1. **Make changes to eBPF programs** (`busted-ebpf/src/`)
2. **Rebuild eBPF**: `cargo xtask build-ebpf`
3. **Make changes to userspace** (`busted-agent/src/`)
4. **Rebuild agent**: `cargo build --package busted-agent`
5. **Test**: `sudo cargo xtask run -- --verbose`

### Testing eBPF Programs

eBPF programs require root privileges:

```bash
# Run with verbose logging
sudo cargo xtask run -- --verbose

# In another terminal, generate traffic
curl https://api.openai.com/v1/models
```

View eBPF logs:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Code Structure

### busted-types
Shared types between eBPF and userspace. Must be `#![no_std]` compatible.

**Key constraints:**
- No heap allocation
- No floating point
- No panics
- Fixed-size structures
- `#[repr(C)]` for ABI compatibility

**Adding new types:**
1. Define in `busted-types/src/lib.rs`
2. Use `#[repr(C)]` for cross-boundary types
3. Add helper methods in `#[cfg(feature = "user")]` block for userspace-only functionality

### busted-ebpf
eBPF programs that run in the kernel.

**Key constraints:**
- `#![no_std]`, `#![no_main]`
- Stack limit: ~512 bytes
- No unbounded loops (verifier requirement)
- No dynamic allocations
- Simple control flow

**Adding new probes:**

```rust
#[kprobe]
pub fn my_probe(ctx: ProbeContext) -> u32 {
    match try_my_probe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_my_probe(ctx: ProbeContext) -> Result<u32, u32> {
    // Your logic here
    Ok(0)
}
```

**Common probe points:**
- `tcp_connect` - Outgoing TCP connections
- `tcp_sendmsg` - Data transmission
- `tcp_recvmsg` - Data reception
- `tcp_close` - Connection termination
- `inet_csk_accept` - Incoming connections

### busted-classifier
Stateless content classification for decrypted TLS payloads.

**Modules:**
- `http` — nom-based HTTP/1.1 parser, HTTP/2 detection, SSE stream identification
- `llm` — LLM provider registry (API paths, host patterns, 14+ providers)
- `mcp` — MCP JSON-RPC 2.0 method detection (tools/list, tools/call, resources/read, etc.)
- `fingerprint` — SDK user-agent fingerprinting, fnv1a hash-based signatures
- `pii` — PII detection layer (email, phone, SSN patterns)
- `protocols` — LLM request body parser (Anthropic/OpenAI message extraction)

**Key design:**
- Zero allocation on the hot path where possible
- Single `classify(&[u8], direction, sni_hint) -> Classification` entry point
- No connection state — operates on individual buffers

### busted-identity
Cross-event AI agent identity resolution and timeline tracking.

**Purpose:** Correlates weak per-event signals (PID, SDK, model, container, fingerprint hash) into stable agent identities across multiple events. Maintains action timelines per identity.

**Key types:**
- `IdentityTracker` — synchronous `&mut self` tracker called from agent event loop
- `IdentityMatch` — result containing identity_id, confidence, narrative, timeline summary

### busted-ml
ML behavioral traffic classifier (behind `ml` feature flag).

**Stack:** ndarray 0.15, linfa 0.7, linfa-trees 0.7, hdbscan 0.12

**Key types:**
- `MlClassifier` — maintains per-PID feature windows, trains incrementally
- `BehaviorClass` — classification result (LlmApi, Generic, Unknown)

### busted-opa
OPA/Rego policy engine (behind `opa` feature flag).

**Stack:** regorus 0.9 (pure-Rust OPA implementation)

**Key types:**
- `PolicyEngine` — loads Rego policies from a directory or inline string
- `PolicyDecision` — action (Allow/Audit/Deny) with optional reason

**Notes:**
- Uses `set_rego_v0(true)` for traditional OPA syntax (no `if` keyword required)
- `evaluate(&ProcessedEvent)` serializes the event as JSON input to the Rego engine

### busted-agent
Userspace control plane.

**Responsibilities:**
- Load eBPF programs via `aya`
- Attach probes to kernel functions
- Read events from RingBuf
- Classify traffic (LLM provider detection via DNS, IP, SNI, and content analysis)
- Enrich events with identity tracking, ML classification, K8s metadata
- Evaluate OPA policies and write enforcement verdicts back to eBPF
- Broadcast ProcessedEvents to CLI, Unix socket, and SIEM sinks

**Adding event handlers:**

1. Events arrive via RingBuf (already implemented in main loop)
2. Add handler logic in `handle_event()` function
3. Classify and route based on event type

### busted-cli (crate name: `busted`)
Unified CLI binary combining monitoring, policy management, and UI dashboard.

**Subcommands:**
- `busted monitor` — run the eBPF monitoring agent
- `busted policy check` — validate Rego policy files
- `busted policy eval` — evaluate a policy against sample input
- `busted policy test` — run policy unit tests
- `busted ui` — launch the egui dashboard (requires `ui` feature)

**Feature flags:** `monitor` (default), `policy` (default), `ui`, `full` (all)

### xtask
Build automation following the xtask pattern.

**Commands:**
- `cargo xtask build-ebpf` — Build only eBPF programs for `bpfel-unknown-none`
- `cargo xtask build` — Build everything (eBPF + userspace)
- `cargo xtask run` — Build and run with arguments
- `cargo xtask version-bump <version>` — Bump workspace version
- `cargo xtask version-check` — Verify version consistency across crates

## Debugging

### eBPF Debugging

**Verifier errors:**
```bash
# Increase verifier log verbosity
echo 1 | sudo tee /proc/sys/net/core/bpf_jit_enable
echo 1 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled
```

**Common issues:**
- Stack overflow: Reduce local variable sizes
- Unbounded loops: Add explicit bounds checking
- Invalid memory access: Ensure all pointers are validated

**eBPF logging:**
```rust
use aya_log_ebpf::info;
info!(&ctx, "Debug: pid={}, value={}", pid, value);
```

### Userspace Debugging

Standard Rust debugging works:
```bash
RUST_LOG=debug cargo xtask run
```

## Performance Considerations

### eBPF Side
- Keep stack usage low (<256 bytes recommended)
- Minimize per-event processing
- Use maps for large/persistent data
- Batch writes to ring buffer when possible

### Userspace Side
- Process events in batches
- Use async I/O for external integrations
- Cache classification results
- Consider aggregation windows for metrics

## Makefile

The project includes a Makefile for common workflows. Run `make help` for all targets:

| Category | Target | Description |
|----------|--------|-------------|
| Build | `make build` | Full build (eBPF + CLI) |
| Build | `make build-release` | Release mode build |
| Build | `make build-cli` | Unified CLI with full features |
| Build | `make build-ui` | Dashboard only |
| Run | `make run` | Build and run monitoring agent |
| Run | `make run-verbose` | Run with verbose logging |
| Run | `make run-json` | Run with JSON output |
| Quality | `make check` | Type-check all crates |
| Quality | `make clippy` | Run clippy lints |
| Quality | `make fmt` | Format all code |
| Quality | `make test` | Run all tests |
| Docs | `make docs` | Build rustdoc + landing page |
| Deploy | `make docker-build` | Build production Docker image |
| Deploy | `make helm-lint` | Lint the Helm chart |
| Deploy | `make helm-test` | Run Helm chart tests |
| Install | `make install` | Install to /usr/local/bin |

## Helm Chart Development

The Helm chart is at `deploy/helm/busted/`.

```bash
# Lint the chart
make helm-lint

# Run chart template tests
make helm-test

# Run full E2E tests (requires kind, builds real image)
make helm-e2e
```

The chart deploys busted as a DaemonSet with:
- Privileged containers (required for eBPF)
- Host PID namespace access
- ConfigMap for OPA policies
- Optional ServiceMonitor for Prometheus
- Configurable feature flags via `values.yaml`

## Testing

### All tests
```bash
make test
# or:
cargo test --workspace --exclude busted-ebpf
```

### Per-crate tests
```bash
cargo test -p busted-types
cargo test -p busted-classifier
cargo test -p busted-identity
cargo test -p busted-ml
cargo test -p busted-opa
cargo test -p busted-ui
cargo test -p busted   # CLI crate
```

### Policy tests
```bash
# Validate policy files
busted policy check --dir policies/

# Run policy unit tests
busted policy test --dir policies/
```

### Integration tests (requires Linux + root)
```bash
sudo cargo test --package busted-agent --test integration
```

### Load testing
Generate artificial traffic:
```bash
# Install hey (HTTP load generator)
go install github.com/rakyll/hey@latest

# Generate load
hey -n 1000 -c 10 https://api.openai.com/v1/models
```

## Contributing

### Code Style
```bash
cargo fmt
cargo clippy --workspace --all-targets
```

### Before Submitting PR
- [ ] All tests pass
- [ ] Code is formatted
- [ ] No clippy warnings
- [ ] Documentation updated
- [ ] CHANGELOG updated

## Kernel Compatibility

### Tested Kernels
- Linux 5.15 (Ubuntu 22.04)
- Linux 6.1 (Debian 12)
- Linux 6.5+ (recommended)

### Kernel Features Required
- CONFIG_BPF=y
- CONFIG_BPF_SYSCALL=y
- CONFIG_BPF_JIT=y
- CONFIG_HAVE_EBPF_JIT=y
- CONFIG_BPF_EVENTS=y
- CONFIG_DEBUG_INFO_BTF=y (for CO-RE)

Check your kernel:
```bash
grep CONFIG_BPF /boot/config-$(uname -r)
```

## Troubleshooting

### "Operation not permitted"
Run with sudo: `sudo cargo xtask run`

### "BTF is required"
Install kernel headers:
```bash
# Ubuntu/Debian
sudo apt-get install linux-headers-$(uname -r)

# RHEL/CentOS
sudo yum install kernel-devel
```

### "Failed to attach probe"
The kernel function may not exist or has been renamed. Check:
```bash
sudo cat /proc/kallsyms | grep tcp_connect
```

## Resources

- [Aya Book](https://aya-rs.dev/book/)
- [eBPF Documentation](https://ebpf.io/)
- [BPF Features by Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)
