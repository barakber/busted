FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# Core build tools + eBPF toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    cmake \
    curl \
    ca-certificates \
    git \
    # LLVM/Clang for bpf-linker
    llvm-18 \
    clang-18 \
    libclang-18-dev \
    lld-18 \
    # eBPF / kernel
    linux-headers-generic \
    linux-tools-generic \
    libelf-dev \
    zlib1g-dev \
    # OpenSSL (for reqwest / TLS features)
    libssl-dev \
    # egui / X11 / graphics
    libxcb1-dev \
    libxcb-render0-dev \
    libxcb-shape0-dev \
    libxcb-xfixes0-dev \
    libxkbcommon-dev \
    libfontconfig1-dev \
    libgtk-3-dev \
    # Wayland
    libwayland-dev \
    # Misc
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Symlink llvm/clang-18 to unversioned names
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 \
    && update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-18 100 \
    && update-alternatives --install /usr/bin/lld lld /usr/bin/lld-18 100 \
    && update-alternatives --install /usr/bin/llc llc /usr/bin/llc-18 100 \
    && update-alternatives --install /usr/bin/opt opt /usr/bin/opt-18 100

# Create non-root user (handle pre-existing GID/UID in base image)
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN if getent group $USER_GID >/dev/null; then \
      groupmod -n $USERNAME $(getent group $USER_GID | cut -d: -f1); \
    else \
      groupadd --gid $USER_GID $USERNAME; \
    fi \
    && if id -u $USER_UID >/dev/null 2>&1; then \
      usermod -l $USERNAME -d /home/$USERNAME -m $(id -nu $USER_UID); \
    else \
      useradd --uid $USER_UID --gid $USER_GID -m $USERNAME; \
    fi \
    && echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/$USERNAME

USER $USERNAME
WORKDIR /home/$USERNAME

# Install Rust nightly with required components
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain nightly \
    --component rust-src,rustfmt,clippy

ENV PATH="/home/${USERNAME}/.cargo/bin:${PATH}"

# Install bpf-linker (required for eBPF compilation)
RUN cargo install bpf-linker

# Pre-add the eBPF target
RUN rustup target add x86_64-unknown-linux-gnu

WORKDIR /workspaces/busted
