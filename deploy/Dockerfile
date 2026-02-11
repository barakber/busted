# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    curl \
    ca-certificates \
    git \
    llvm-18 \
    clang-18 \
    lld-18 \
    libelf-dev \
    zlib1g-dev \
    libssl-dev \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 \
    && update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-18 100 \
    && update-alternatives --install /usr/bin/lld lld /usr/bin/lld-18 100 \
    && update-alternatives --install /usr/bin/llc llc /usr/bin/llc-18 100 \
    && update-alternatives --install /usr/bin/opt opt /usr/bin/opt-18 100

# Install Rust nightly with rust-src (required for eBPF cross-compilation)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain nightly \
    --component rust-src

ENV PATH="/root/.cargo/bin:${PATH}"

RUN cargo install bpf-linker

WORKDIR /build

# Copy workspace manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY xtask/Cargo.toml xtask/Cargo.toml
COPY busted-types/Cargo.toml busted-types/Cargo.toml
COPY busted-ebpf/Cargo.toml busted-ebpf/Cargo.toml
COPY busted-agent/Cargo.toml busted-agent/Cargo.toml
COPY busted-classifier/Cargo.toml busted-classifier/Cargo.toml
COPY busted-ml/Cargo.toml busted-ml/Cargo.toml
COPY busted-opa/Cargo.toml busted-opa/Cargo.toml
COPY busted-ui/Cargo.toml busted-ui/Cargo.toml
COPY busted-cli/Cargo.toml busted-cli/Cargo.toml
COPY busted-identity/Cargo.toml busted-identity/Cargo.toml

# Copy full source
COPY . .

# Build everything in release mode (eBPF + userspace with full features)
RUN cargo xtask build --release

# Strip the binary
RUN strip target/release/busted

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    libssl3t64 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/busted /usr/bin/busted

ENTRYPOINT ["busted"]
CMD ["monitor", "--format", "json"]
