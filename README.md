# Lux Ops

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

Operations toolkits for Lux Network nodes and infrastructure.

## Overview

**Lux Ops** provides infrastructure automation for deploying and operating Lux Network nodes. Primary deployment target is **Kubernetes** with the `lux-operator`, with AWS deployment support available.

- 🦀 Written in Rust
- ☸️ Kubernetes-native with CRDs
- ✅ Fully automates node provisioning
- ✅ Fully automates custom network setups
- ✅ Fully automates subnet/VM deployment
- 🔐 Integrates with Lux MPC for key management
- 📊 Built-in metrics and monitoring

## Components

| Crate | Description |
|-------|-------------|
| `lux-core` | Core library with types, config, and specifications |
| `lux-operator` | Kubernetes operator for LuxNetwork/LuxSubnet CRDs |
| `luxup` | Control plane CLI for deployments |
| `luxd` | Agent daemon for cloud deployments |
| `blizzard` | Load testing agent |
| `blizzardup` | Load testing control plane |
| `lux-faucet` | Devnet token distribution service |
| `staking-key-downloader` | TLS key/cert downloader from S3 |
| `staking-signer-downloader` | BLS signer key downloader from S3 |

## Quick Start

### Kubernetes Deployment (Recommended)

```bash
# Build the operator
cargo build --release -p lux-operator

# Install CRDs
kubectl apply -f lux-operator/crds/

# Run the operator
./target/release/lux-operator \
    --namespace lux-network \
    --mpc-endpoint https://mpc.lux.network
```

Create a LuxNetwork resource:

```yaml
apiVersion: lux.network/v1alpha1
kind: LuxNetwork
metadata:
  name: devnet
  namespace: lux-network
spec:
  networkId: 12345
  nodeCount: 5
  nodeConfig:
    httpPort: 9650
    stakingPort: 9651
  mpc:
    enabled: true
    endpoint: https://mpc.lux.network
```

### AWS Deployment

```bash
# Generate default spec
./target/release/luxup default-spec \
    --target aws \
    --regions us-west-2 \
    --output lux-spec.yaml

# Apply deployment
./target/release/luxup apply --spec-file lux-spec.yaml

# Query endpoints
./target/release/luxup endpoints --spec-file lux-spec.yaml
```

## Building

```bash
# Build all crates
cargo build --release

# Build specific crate
cargo build --release -p lux-operator

# Run tests
cargo test
```

## Architecture

### Kubernetes Operator

The `lux-operator` manages Lux Network deployments using Custom Resource Definitions:

- **LuxNetwork**: Defines a complete network deployment
- **LuxSubnet**: Defines subnet configurations

The operator reconciles desired state and manages:
- Node pods and services
- Key generation via Lux MPC
- Network configuration
- Metrics collection

### AWS Deployment

For AWS deployments:
- `luxup` runs on operator machine (control plane)
- `luxd` agent runs on each EC2 instance
- Keys managed via Lux MPC with S3 encrypted storage

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `LUX_NETWORK_ID` | Network ID for the deployment |
| `LUX_MPC_ENDPOINT` | Lux MPC service endpoint |
| `AWS_REGION` | AWS region for deployments |
| `AWS_PROFILE` | AWS profile name |

## License

BSD 3-Clause License - see [LICENSE](LICENSE) for details.

## Related Projects

- [luxd](https://github.com/luxfi/node) - Lux Network node implementation
- [lux-cli](https://github.com/luxfi/cli) - Command line interface
- [lux-wallet](https://github.com/luxfi/wallet) - Wallet SDK
