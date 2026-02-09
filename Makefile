.PHONY: build build-release build-ebpf build-agent build-cli build-ui build-ml run run-release clean check clippy fmt test help

AGENT_FEATURES ?=

## Build targets ---------------------------------------------------------------

build: ## Build everything (eBPF + CLI with all features)
	cargo xtask build

build-release: ## Build everything in release mode
	cargo xtask build --release

build-ebpf: ## Build only the eBPF programs
	cargo xtask build-ebpf

build-agent: ## Build only the standalone agent binary
	cargo build -p busted-agent $(if $(AGENT_FEATURES),--features $(AGENT_FEATURES),)

build-cli: ## Build the unified CLI with full features
	cargo build -p busted-cli --features full

build-ui: ## Build the egui dashboard
	cargo build -p busted-ui

build-ml: ## Build the agent with ML behavioral classifier
	cargo build -p busted-agent --features ml

build-k8s: ## Build the agent with Kubernetes enrichment
	cargo build -p busted-agent --features k8s

build-all-features: ## Build the CLI with all optional features
	cargo build -p busted-cli --features full

## Run targets -----------------------------------------------------------------

run: build ## Build and run the monitoring agent
	sudo ./target/debug/busted monitor

run-release: build-release ## Build and run in release mode
	sudo ./target/release/busted monitor

run-verbose: build ## Build and run with verbose logging
	sudo ./target/debug/busted monitor --verbose

run-json: build ## Build and run with JSON output
	sudo ./target/debug/busted monitor --format json

run-ui: build ## Run the dashboard UI
	./target/debug/busted ui

## Quality targets -------------------------------------------------------------

check: ## Type-check all crates (no codegen)
	cargo check --workspace
	cargo check -p busted-cli --features full

clippy: ## Run clippy lints
	cargo clippy --workspace -- -D warnings
	cargo clippy -p busted-cli --features full -- -D warnings

fmt: ## Format all code
	cargo fmt --all

fmt-check: ## Check formatting without modifying
	cargo fmt --all -- --check

test: ## Run all tests
	cargo test --workspace

## Maintenance -----------------------------------------------------------------

clean: ## Remove build artifacts
	cargo clean

## Help ------------------------------------------------------------------------

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
