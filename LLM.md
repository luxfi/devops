# Lux Devops — LLM Context

## Scope

This repo (`luxfi/devops`) is the **AWS deployment tooling workspace** for Lux Network. It contains Rust crates that orchestrate node deployments on EC2, run load tests, and manage staking keys fetched from S3.

**What lives here:** AWS daemon/control-plane, load-testing agents, S3 init-container downloaders, devnet faucet, and the shared core library.

**What does NOT live here:**
- K8s operator → `luxfi/operator` (Go + Rust, canonical; legacy Rust on its `legacy/` branch)
- K8s manifests → `luxfi/universe k8s/` (Kustomize only, per PHILOSOPHY.md)
- Helm charts → **deleted** (PHILOSOPHY.md forbids Helm; replaced by Kustomize overlays in `luxfi/universe k8s/`)

## Workspace Crates

| Crate | Role |
|-------|------|
| `lux-core` | Shared library: types, config, spec — used by luxd / luxup / bench |
| `luxd` | AWS daemon agent running on each EC2 node |
| `luxup` | AWS deployment control-plane CLI |
| `bench` | Load-testing agent targeting AWS deployments |
| `benchup` | Load-testing control-plane |
| `lux-faucet` | Devnet token-distribution service (**queued to move** to `luxfi/stack services/faucet/` — stays here until that migration lands) |
| `staking-key-downloader` | S3 init-container: downloads TLS key/cert |
| `staking-signer-downloader` | S3 init-container: downloads BLS signer key |

## Migration Notes

- **lux-operator** was removed from this workspace (2026-05-29). Canonical implementation: `luxfi/operator` (GHCR: `ghcr.io/luxfi/operator`). The legacy Rust version lives on its `legacy/` branch.
- **charts/** was removed (2026-05-29). Helm is forbidden by PHILOSOPHY.md. K8s manifests for Lux mainnet/testnet/devnet live in `luxfi/universe k8s/lux-k8s/`, `luxfi/universe k8s/lux-mainnet/`, etc. Kustomize only.
- **k8s/** stub was removed (2026-05-29). Namespace and operator manifests are canonical at `luxfi/universe k8s/` and `luxfi/operator config/default/`.
- **deploy-all.sh** was removed (2026-05-29). Deployment is via `luxfi/universe` + `luxfi/operator`.
- **repository** field in Cargo.toml fixed from `luxfi/lux-ops` (old repo name) to `luxfi/devops`.

## AWS Deployment Flow

```
luxup (control plane) → provisions EC2 instances → installs luxd agent
luxd (daemon)         → manages local luxd process + reports health
bench / benchup       → drive load tests against live AWS targets
staking-*-downloader  → K8s init containers that pull keys from S3 on boot
```

## Build

```bash
cargo build --workspace
cargo test --workspace
```

## K8s / Operator Reference

For K8s-based Lux deployments, see:
- `luxfi/operator` — Go operator, CRDs (LuxNetwork / LuxChain / LuxIndexer / LuxExplorer / LuxGateway)
- `luxfi/universe k8s/lux-k8s/` — Kustomize overlays for the production cluster
- `luxfi/universe k8s/lux-mainnet/` / `lux-testnet/` / `lux-devnet/` — per-network overlays

## Critical Rules

- Use `luxfi/*` packages, not `go-ethereum`, not `ava-labs`
- Never use EWOQ keys
- Secrets via KMS (kms.hanzo.ai / kms.lux.network), never plaintext
- Container images: `ghcr.io/luxfi/<service>:<semver>` — never `:latest`
- Kustomize manifests only; no Helm
