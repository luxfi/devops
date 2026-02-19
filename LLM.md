# Lux Ops - LLM Context

## Project Overview

Lux Ops is a Rust workspace providing infrastructure automation for deploying and operating Lux Network nodes. Forked from avalanche-ops at commit `1631a68a` (last BSD-3-Clause version). Primary deployment mechanism is the Helm chart.

## Directory Structure

```
lux-ops/
├── Cargo.toml           # Workspace manifest
├── charts/lux/          # Helm chart (primary deployment mechanism)
├── deploy-all.sh        # Deploy all networks via Helm
├── k8s/base/            # K8s namespace definitions
├── lux-core/            # Core library (types, config, spec)
├── lux-operator/        # K8s operator (CRDs, controller)
├── luxd/                # Agent daemon for cloud deployments
├── luxup/               # Control plane CLI
├── bench/               # Load testing agent (was blizzard)
├── benchup/             # Load testing control plane (was blizzardup)
├── lux-faucet/          # Devnet token distribution service
├── staking-key-downloader/      # TLS key/cert downloader
└── staking-signer-downloader/   # BLS signer key downloader
```

## Production State (2026-02-14)

### Cluster Topology

All three networks run on **one** DigitalOcean K8s cluster:

- **Cluster**: `do-sfo3-hanzo-k8s` (UUID: `1a153000-90a6-48ad-9375-7ef901a9bf7f`)
- **Namespaces**: `lux-mainnet`, `lux-testnet`, `lux-devnet`
- **Total pods**: 15 (5 per network), all Running + Healthy
- **Auto-scaling**: DO node pool auto-scales (currently 7+ nodes)

| Network | NetworkID | C-Chain ID | HTTP Port | Staking Port | Namespace | LB IP |
|---------|-----------|------------|-----------|--------------|-----------|-------|
| mainnet | 1 | 96369 | 9630 | 9631 | lux-mainnet | 209.38.7.197 |
| testnet | 2 | 96368 | 9640 | 9641 | lux-testnet | 209.38.5.162 |
| devnet | 3 | 96370 | 9650 | 9651 | lux-devnet | 209.38.7.201 |

### Image

```
registry.digitalocean.com/hanzo/bootnode:luxd-v1.23.14
```

Image pull secret: `registry-hanzo` (DO container registry).

### Key Fix: dialEndpointOnly (v1.23.14)

The `--bootstrap-nodes` flag uses endpoint-only bootstrap where NodeID is `EmptyNodeID` until TLS handshake. The original `ManuallyTrack()` had two bugs:
1. All endpoints collided on `trackedIPs[EmptyNodeID]` map key
2. `ipTracker.ManuallyTrack(EmptyNodeID)` was NOT called, so `WantsConnection()` returned false

**Fix**: Added `dialEndpointOnly()` method in `/lux/node/network/network.go` that:
- Skips the WantsConnection check entirely
- Doesn't use trackedIPs map (avoiding key collision)
- Directly dials TCP, upgrades TLS, discovers real NodeID

### Node IDs (shared across all 3 networks)

```
NodeID-Mf3JfSY91oDwfBqf7rCLmhg4NDtDghw1f  (pod 0)
NodeID-2TwSZ2oyeBK2mv7JiseEQ8m74rotDj4QR  (pod 1)
NodeID-Ld9VFBQ9zGbd79z2vzaAqkQ3jHuqbtRpo  (pod 2)
NodeID-8mY2fhUehN27v3LCU84BnnKEoeRfd2weC  (pod 3)
NodeID-4smuFz5Z9cm8BEyQU1oPQ9nwgXyMgaNqu  (pod 4)
```

## Helm Chart Architecture

### Key Design Decisions

1. **ConfigMap-based startup scripts** (NOT inline args): The `luxd-startup` ConfigMap contains a full shell script that runs luxd in the background with `&`, waits for health, sets up chain aliases, and imports RLP data.

2. **Parallel pod management**: `podManagementPolicy: Parallel` so all 5 validators start together (required for peer discovery).

3. **Per-pod LoadBalancer services**: Each validator gets its own stable external IP for P2P identity.

4. **Internal DNS bootstrap**: Pods bootstrap via K8s DNS (`luxd-{i}.luxd-headless.{ns}.svc.cluster.local`) using `--bootstrap-nodes` (endpoint-only, NodeID from TLS cert).

5. **LB discovery via K8s API**: Startup script discovers public IP from per-pod LoadBalancer service using K8s API with `curl` (NOT wget, busybox wget lacks --ca-certificate).

6. **Sybil protection**: Enabled for mainnet (networkID=1) and testnet (networkID=2). Disabled for devnet (networkID=3).

### Templates

| Template | Purpose |
|----------|---------|
| `statefulset.yaml` | 5-replica StatefulSet with init container + startup script |
| `services.yaml` | Headless service + per-pod LoadBalancer + round-robin LB |
| `configmap.yaml` | Genesis JSON from `genesis/{network}.json` |
| `startup-configmap.yaml` | Startup script (background luxd + health wait + RLP import) |
| `namespace.yaml` | Namespace creation |
| `rbac.yaml` | ServiceAccount + Role for LB IP discovery |

### Values Files

| File | Purpose |
|------|---------|
| `values.yaml` | Base defaults (devnet config, 5 replicas, consensus params) |
| `values-mainnet.yaml` | Mainnet overrides (specific tracked chains, RLP multi-part import) |
| `values-testnet.yaml` | Testnet overrides (track-all-chains, single-file RLP import) |
| `values-devnet.yaml` | Devnet overrides (sybil off, track-all-chains) |

### Key Values

```yaml
# Chain tracking (mainnet: specific, testnet/devnet: all)
chainTracking:
  trackAllChains: true|false
  trackedChains: ["chain-id-1", "chain-id-2"]
  aliases: ["zoo", "hanzo", "spc", "pars"]

# RLP import for C-chain bootstrap
bootstrap:
  rlpImport:
    enabled: true
    baseUrl: "https://..."
    rlpFilename: "lux-mainnet-96369.rlp"
    multiPart: true
    parts: ["aa", "ab", ...]
    minHeight: 1
    timeout: 7200

# Init container mode
initMode:
  clearData: false  # true = delete chain data on restart (for re-genesis)
```

## Operational Runbook

### Deploy a Network

```bash
# Mainnet (with sybil protection)
helm upgrade --install luxd-mainnet charts/lux \
  -f charts/lux/values.yaml -f charts/lux/values-mainnet.yaml \
  --set consensus.sybilProtectionEnabled=true \
  --namespace lux-mainnet

# Testnet (with sybil protection)
helm upgrade --install luxd-testnet charts/lux \
  -f charts/lux/values.yaml -f charts/lux/values-testnet.yaml \
  --set consensus.sybilProtectionEnabled=true \
  --namespace lux-testnet

# Devnet (no sybil)
helm upgrade --install luxd-devnet charts/lux \
  -f charts/lux/values.yaml -f charts/lux/values-devnet.yaml \
  --namespace lux-devnet
```

### Build and Push Docker Image

```bash
# IMPORTANT: Must build with --platform linux/amd64 (K8s nodes are amd64, dev machine is arm64)
cd /Users/z/work/lux/node
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/luxd-linux-amd64 ./main
docker build --platform linux/amd64 -t registry.digitalocean.com/hanzo/bootnode:luxd-v1.23.14 -f Dockerfile.bootnode .
docker push registry.digitalocean.com/hanzo/bootnode:luxd-v1.23.14
```

### Re-genesis (Clear Chain Data)

```bash
helm upgrade luxd-testnet charts/lux ... --set initMode.clearData=true
kubectl delete pods -l app=luxd -n lux-testnet
# After pods recover:
helm upgrade luxd-testnet charts/lux ... --set initMode.clearData=false
```

### Check All Networks Health

```bash
for ns in lux-mainnet lux-testnet lux-devnet; do
  port=$(kubectl get svc luxd-headless -n $ns -o jsonpath='{.spec.ports[0].port}')
  for i in 0 1 2 3 4; do
    kubectl exec luxd-${i} -n $ns -c luxd -- curl -sf http://127.0.0.1:${port}/ext/health
  done
done
```

### Helm Namespace Adoption

When creating namespaces/resources manually before Helm install, they MUST have:
```bash
kubectl label namespace lux-$NET app.kubernetes.io/managed-by=Helm
kubectl annotate namespace lux-$NET meta.helm.sh/release-name=luxd-$NET meta.helm.sh/release-namespace=lux-$NET
```

## Critical Gotchas

1. **NetworkID vs C-Chain ID**: They are DIFFERENT. NetworkID (1/2/3) goes in genesis.json `networkID` field. C-Chain ID (96369/96368/96370) is the EVM chain ID in the C-Chain genesis config.

2. **Docker platform**: Always use `--platform linux/amd64` when building on Apple Silicon. K8s nodes are amd64.

3. **busybox wget**: Does NOT support `--ca-certificate`. Use `curl` for K8s API calls in startup scripts.

4. **Parallel pod management**: StatefulSet must use `podManagementPolicy: Parallel` for validators to discover each other. This field CANNOT be patched — must delete and recreate the StatefulSet.

5. **DO LB naming**: Use `k8s-` prefix in annotations to avoid conflicts with existing VM-backed LBs.

6. **Sybil protection**: Required for networkID 1 and 2 (mainnet/testnet). Node refuses to start without it.

## Operator Architecture (v2 - 2026-02-18)

### CRDs

| CRD | Purpose |
|-----|---------|
| `LuxNetwork` | Manages a full network (mainnet/testnet/devnet). Creates StatefulSet, Services, RBAC, PDB. |
| `LuxChain` | Manages individual subnet chain deployments. Links to parent LuxNetwork. |

### Key CRD Features

**HealthPolicy** (per-network):
- `requireInboundValidators`: Enforce inbound peer connections
- `minInbound`: Minimum inbound peers before marking Degraded
- `gracePeriodSeconds`: Grace period after pod start
- `maxHeightSkew`: Max P-chain height difference before Degraded

**StartupGate** (prevents bootstrap race):
- InitContainer waits for N peers on staking port before luxd starts
- Prevents "bootstrapped at height 0 with 0 peers"
- Configurable `minPeers`, `timeoutSeconds`, `checkIntervalSeconds`

**SeedRestore** (fast bootstrap):
- Checks `/data/.seeded` marker before restoring
- Sources: `ObjectStore` (tarball URL), `PVCClone`, `VolumeSnapshot`, `None`
- `restorePolicy`: `IfNotSeeded` (default) or `Always`

**UpgradeStrategy**:
- `OnDelete` (safest, default) or `RollingCanary`
- `maxUnavailable`: Pods restarted at a time during recovery
- `healthCheckBetweenRestarts`: Wait for health between pod restarts

**Scale Protection**:
- `allowValidatorRemoval: false` (default) blocks scale-down
- Must explicitly set `true` to remove validators

### Status Reporting

Per-node status includes: `nodeID`, `externalIP`, `pChainHeight`, `cChainHeight`, `chainsCount`, `connectedPeers`, `inboundPeers`, `outboundPeers`, `bootstrapped`, `healthy`.

Degraded conditions: `BootstrapBlocked`, `HeightSkew`, `InboundPeersTooLow`, `ChainUnhealthy`, `PodNotReady`, `NodeUnhealthy`.

Network metrics: `minPHeight`, `maxPHeight`, `heightSkew`, `bootstrappedChains`, `totalPeers`.

### Reconciliation Flow

```
Pending → Creating → Bootstrapping → Running ⇄ Degraded
                                         ↑          |
                                         └──────────┘
                                      (attempt_recovery)
```

- **Creating**: StatefulSet pods starting
- **Bootstrapping**: Pods ready, checking node health API
- **Running**: All nodes healthy + no degraded conditions
- **Degraded**: < 100% healthy OR height skew OR low inbound peers

### Helm Chart Changes (v2)

- **startup-gate initContainer**: Waits for peers before luxd
- **HTTP health probes**: Replaced TCP probes with `/ext/health` HTTP checks
- **startupProbe**: Added startup probe (TCP) with 5min budget for slow bootstrap
- **PVC retention**: `whenDeleted: Retain`, `whenScaled: Retain`
- **serviceAccountName**: `luxd` (for RBAC LB IP discovery)
- **seedRestore**: Optional snapshot restore in init container
- **upgradeStrategy**: Configurable (OnDelete default)
