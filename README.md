# Lux Devops

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

AWS deployment tooling for Lux Network nodes. Rust workspace.

## Crates

| Crate | Description |
|-------|-------------|
| `lux-core` | Shared library: types, config, spec |
| `luxd` | AWS daemon agent (runs on each EC2 node) |
| `luxup` | AWS deployment control-plane CLI |
| `bench` | Load-testing agent |
| `benchup` | Load-testing control-plane |
| `lux-faucet` | Devnet token distribution service |
| `staking-key-downloader` | S3 init-container: TLS key/cert |
| `staking-signer-downloader` | S3 init-container: BLS signer key |

## Build

```bash
cargo build --workspace
cargo test --workspace
```

## AWS Deployment

```bash
# Generate deployment spec
./target/release/luxup default-spec --target aws --regions us-west-2 --output spec.yaml

# Apply
./target/release/luxup apply --spec-file spec.yaml

# Query endpoints
./target/release/luxup endpoints --spec-file spec.yaml
```

## K8s Operator

The Kubernetes operator (CRDs, controller) lives at [luxfi/operator](https://github.com/luxfi/operator).
K8s manifests live in [luxfi/universe](https://github.com/luxfi/universe) under `k8s/` (Kustomize only).

## License

BSD 3-Clause — see [LICENSE](LICENSE).
