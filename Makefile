.PHONY: build build-release build-ebpf build-tui build-ui build-wasm run run-release run-tui run-tui-demo run-ui run-ui-live serve-wasm clean check clippy fmt test docs install uninstall docker-build helm-lint helm-test helm-e2e help

## Build targets ---------------------------------------------------------------

build: ## Build everything (eBPF + userspace)
	cargo xtask build

build-release: ## Build everything in release mode
	cargo xtask build --release

build-ebpf: ## Build only the eBPF programs
	cargo xtask build-ebpf

build-tui: ## Build the terminal dashboard
	cargo build -p busted-tui

build-ui: ## Build the GUI dashboard
	cargo build -p busted-ui

build-wasm: ## Build the WASM web dashboard (requires trunk)
	cd busted-ui && trunk build --release

## Run targets -----------------------------------------------------------------

run: build ## Build and run the monitoring agent (needs sudo)
	sudo ./target/debug/busted monitor

run-release: build-release ## Build and run in release mode (needs sudo)
	sudo ./target/release/busted monitor

run-tui: build-tui ## Run the terminal dashboard (live mode)
	./target/debug/busted-tui

run-tui-demo: build-tui ## Run the terminal dashboard (demo mode)
	./target/debug/busted-tui --demo

run-ui: build-ui ## Run the GUI dashboard (demo mode)
	./target/debug/busted-ui --demo

run-ui-live: build-ui ## Run the GUI dashboard (live mode)
	./target/debug/busted-ui

serve-wasm: ## Build and serve WASM dashboard at http://localhost:8080 (requires trunk)
	cd busted-ui && trunk serve --release

## Quality targets -------------------------------------------------------------

check: ## Type-check all crates
	cargo check --workspace --exclude busted-ebpf
	cargo check -p busted --features full

clippy: ## Run clippy lints
	cargo clippy --workspace --exclude busted-ebpf -- -D warnings
	cargo clippy -p busted --features full -- -D warnings

fmt: ## Format all code
	cargo fmt --all

test: ## Run all tests
	cargo test --workspace --exclude busted-ebpf

## Docs targets ----------------------------------------------------------------

docs: ## Build rustdoc + landing page locally
	BUSTED_SKIP_EBPF_BUILD=1 cargo doc --workspace --exclude busted-ebpf --no-deps
	rm -rf docs && cp -r target/doc docs
	cp docs-landing/index.html docs/index.html
	cp busted.gif docs/busted.gif 2>/dev/null || true
	touch docs/.nojekyll

## Install / Deploy ------------------------------------------------------------

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

install: ## Install busted to $(BINDIR) (run make build-release first)
	@test -f target/release/busted || { echo "Error: run 'make build-release' first."; exit 1; }
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 target/release/busted $(DESTDIR)$(BINDIR)/busted

uninstall: ## Remove busted from $(BINDIR)
	rm -f $(DESTDIR)$(BINDIR)/busted

docker-build: ## Build production Docker image
	docker build -f deploy/Dockerfile -t busted:latest .

helm-lint: ## Lint the Helm chart
	helm lint deploy/helm/busted

helm-test: ## Run Helm chart tests
	deploy/helm/test.sh

helm-e2e: build-release ## Run Helm E2E tests (kind + real eBPF)
	cargo test -p xtask --test helm_integration -- --ignored --nocapture

## Maintenance -----------------------------------------------------------------

clean: ## Remove build artifacts
	cargo clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
