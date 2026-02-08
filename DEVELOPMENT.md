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

### busted-agent
Userspace control plane.

**Responsibilities:**
- Load eBPF programs via `aya`
- Attach probes to kernel functions
- Read events from perf buffers
- Classify traffic (LLM provider detection)
- Apply policies
- Export logs/metrics

**Adding event handlers:**

1. Read events from perf buffer (already implemented in main loop)
2. Add handler logic in `handle_event()` function
3. Classify and route based on event type

### xtask
Build automation following the xtask pattern.

**Commands:**
- `cargo xtask build-ebpf` - Build only eBPF programs
- `cargo xtask build` - Build everything
- `cargo xtask run` - Build and run with arguments

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

## Testing

### Unit Tests
```bash
cargo test --workspace
```

### Integration Tests
Requires Linux:
```bash
sudo cargo test --package busted-agent --test integration
```

### Load Testing
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
