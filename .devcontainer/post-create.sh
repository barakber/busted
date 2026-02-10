#!/bin/bash
set -e

echo "==> Creating eBPF stub directories..."
mkdir -p target/bpfel-unknown-none/debug target/bpfel-unknown-none/release
touch target/bpfel-unknown-none/debug/busted-ebpf
touch target/bpfel-unknown-none/release/busted-ebpf

echo "==> Verifying toolchain..."
rustc --version
cargo --version
echo -n "bpf-linker: " && bpf-linker --version 2>/dev/null || echo "(run 'cargo install bpf-linker' if missing)"

echo ""
echo "Ready! Build commands:"
echo "  cargo xtask build          # Full build (eBPF + userspace)"
echo "  cargo xtask build-ebpf     # eBPF only"
echo "  make build                 # Full build via Makefile"
echo "  make test                  # Run tests"
echo "  make clippy                # Lint"
