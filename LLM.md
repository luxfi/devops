# Lux Ops - LLM Context

## Project Overview

Lux Ops is a Rust workspace providing infrastructure automation for deploying and operating Lux Network nodes. It was rewritten from the original avalanche-ops repository, forked from commit `1631a68a` (the last BSD-3-Clause licensed version before the restrictive license change).

## Key Changes from Original

1. **License**: Maintained BSD-3-Clause, added Lux Partners copyright
2. **Removed**: `avalanche-kms` and `cdk` directories (using Lux MPC instead)
3. **Renamed**: All avalanche-* directories to lux-*
4. **Added**: `lux-operator` - Kubernetes operator as primary deployment target
5. **Updated**: Modern dependencies (AWS SDK 1.x, kube-rs 0.87, clap 4.x)

## Directory Structure

```
lux-ops/
├── Cargo.toml           # Workspace manifest
├── LICENSE              # BSD-3-Clause
├── README.md            # Project documentation
├── LLM.md               # This file
├── lux-core/            # Core library (types, config, spec)
├── lux-operator/        # K8s operator (CRDs, controller)
├── luxd/                # Agent daemon for cloud deployments
├── luxup/               # Control plane CLI
├── blizzard/            # Load testing agent
├── blizzardup/          # Load testing control plane
├── lux-faucet/          # Devnet token distribution service
├── staking-key-downloader/      # TLS key/cert downloader
└── staking-signer-downloader/   # BLS signer key downloader
```

## Crate Descriptions

### lux-core
Core library with shared types and configurations:
- `types.rs`: NetworkId, NodeId, ChainType, KeyInfo, NodeInfo, units
- `config.rs`: LuxdConfig, CChainConfig
- `spec.rs`: DeploymentTarget (AWS/Kubernetes), Spec, NetworkConfig
- `k8s.rs`: K8s-specific types for operator
- `aws.rs`: AWS-specific types (CloudFormation templates)
- `artifacts.rs`: Embedded artifacts (metrics rules)

### lux-operator
Kubernetes operator for managing Lux Network deployments:
- `crd.rs`: LuxNetwork and LuxSubnet CustomResource definitions
- `controller.rs`: Reconciliation logic
- `error.rs`: Error types

CRDs:
- `LuxNetwork`: Deploys a complete network cluster
- `LuxSubnet`: Deploys subnet configurations

### luxd (luxd-daemon)
Agent daemon that runs on cloud instances:
- Handles node installation and configuration
- Manages certificates and keys via Lux MPC
- Subnet chain installation

### luxup
Control plane CLI for managing deployments:
- `default-spec`: Generate deployment specification
- `apply`: Deploy infrastructure
- `delete`: Tear down infrastructure
- `endpoints`: Query network endpoints
- `validators`: Query validator info

### blizzard & blizzardup
Load testing infrastructure:
- `blizzard`: Agent running on instances generating load
- `blizzardup`: Control plane managing test deployments

### lux-faucet
HTTP service for devnet token distribution:
- Axum-based HTTP server
- Rate limiting per IP
- `/health` and `/drip` endpoints

### staking-key-downloader & staking-signer-downloader
Utilities to download staking keys from S3 with KMS decryption:
- TLS key/cert for node identity
- BLS signer key for staking

## Build Commands

```bash
# Build all crates
cargo build --release

# Build specific crate
cargo build --release -p lux-operator

# Run tests
cargo test

# List binaries
ls target/release/
```

## Dependencies

Key workspace dependencies:
- `tokio` 1.35 - Async runtime
- `kube` 0.87 - Kubernetes client/operator
- `k8s-openapi` 0.20 - K8s API types (v1.28)
- `clap` 4.4 - CLI parsing with derive
- `aws-sdk-*` 1.x - Modern AWS SDK
- `axum` 0.7 - HTTP server
- `tracing` 0.3 - Structured logging

## Integration Points

### Lux MPC
The operator integrates with Lux MPC for key management:
- Configured via `MpcSpec` in CRDs
- Endpoint specified at runtime
- TSS (threshold signatures) support

### AWS
For AWS deployments:
- EC2 instances managed via CloudFormation
- S3 for artifact storage
- KMS for encryption
- CloudWatch for metrics

### Kubernetes
Primary deployment target:
- CRDs for declarative network management
- StatefulSets for validators
- Services and Ingress
- ServiceMonitor for Prometheus

## Current Status

- All crates compile successfully
- Stub implementations for most functionality
- TODO comments mark areas needing implementation
- Ready for incremental feature implementation
