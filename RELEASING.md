# Releasing Busted

## Prerequisites

- `CARGO_REGISTRY_TOKEN` secret configured in GitHub repository settings
- GitHub environment `crates-io` created (for publish job protection)

## Release Process

### 1. Bump versions

```bash
cargo xtask version-bump 0.2.0
```

This updates:
- `workspace.package.version` in the root `Cargo.toml`
- All path dependency `version` fields across workspace crates

### 2. Verify consistency

```bash
cargo xtask version-check
```

### 3. Commit and tag

```bash
git add -A
git commit -m "Release v0.2.0"
git tag v0.2.0
```

### 4. Push

```bash
git push origin main --tags
```

The `release.yml` workflow will:
1. Run CI checks (fmt, clippy, test, version-check)
2. Verify the tag version matches the workspace version
3. Publish crates to crates.io in dependency order
4. Create a GitHub Release with auto-generated notes

## Publish Order

Crates are published in tiers with delays for index propagation:

1. `busted-types`, `busted-classifier`
2. `busted-ebpf` (--no-verify), `busted-ml`, `busted-opa`, `busted-ui`
3. `busted-agent` (--no-verify)
4. `busted` (the CLI)

## Manual / Dry Run

Use the GitHub Actions "Run workflow" button on the Release workflow to trigger a manual run. Set `dry_run` to `true` to run CI checks and version verification without publishing.
