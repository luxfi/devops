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

## Production State (2026-02-10)

### Cluster Topology

All three networks run on **one** DigitalOcean K8s cluster:

- **Cluster**: `do-sfo3-hanzo-k8s` (UUID: `1a153000-90a6-48ad-9375-7ef901a9bf7f`)
- **Namespaces**: `lux-mainnet`, `lux-testnet`, `lux-devnet`
- **Total pods**: 15 (5 per network), all Running

| Network | NetworkID | HTTP Port | Staking Port | Namespace | Status |
|---------|-----------|-----------|--------------|-----------|--------|
| mainnet | 1 | 9630 | 9631 | lux-mainnet | Running, C-chain ~98% imported |
| testnet | 2 | 9640 | 9641 | lux-testnet | Running, all chains tracked |
| devnet | 3 | 9650 | 9651 | lux-devnet | Running, all chains tracked |

### Image

```
registry.digitalocean.com/hanzo/bootnode:luxd-v1.23.11
```

Image pull secret: `registry-hanzo` (DO container registry).

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

2. **OnDelete update strategy**: Pathdb trie corruption makes rolling restarts dangerous. Pods must be manually deleted to pick up changes.

3. **Per-pod LoadBalancer services**: Each validator gets its own stable external IP for P2P identity.

4. **Internal DNS bootstrap**: Pods bootstrap via K8s DNS (`luxd-{i}.luxd-headless.{ns}.svc.cluster.local`) rather than external IPs.

### Templates

| Template | Purpose |
|----------|---------|
| `statefulset.yaml` | 5-replica StatefulSet with init container + startup script |
| `services.yaml` | Headless service + per-pod LoadBalancer + round-robin LB |
| `configmap.yaml` | Genesis JSON from `genesis/{network}.json` |
| `startup-configmap.yaml` | Startup script (background luxd + health wait + RLP import) |
| `namespace.yaml` | Namespace creation |

### Values Files

| File | Purpose |
|------|---------|
| `values.yaml` | Base defaults (devnet config, 5 replicas, consensus params) |
| `values-mainnet.yaml` | Mainnet overrides (specific tracked chains, RLP multi-part import) |
| `values-testnet.yaml` | Testnet overrides (track-all-chains, single-file RLP import) |

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

## Startup Script Pattern

The startup script runs luxd in the background to allow post-start bootstrap:

```bash
# 1. Start luxd in background
/luxd/build/luxd $ARGS &
LUXD_PID=$!

# 2. Wait for health (up to 180s)
while ! curl -sf http://127.0.0.1:$PORT/ext/health; do sleep 1; done

# 3. Set up chain aliases
curl -X POST ... admin.aliasChain ...

# 4. Download and import RLP data (if needed)
curl ... admin_importChain ...

# 5. Wait for luxd process
wait "$LUXD_PID"
```

**CRITICAL**: Must use `&` NOT `exec`. Using `exec` replaces the shell and prevents post-start logic.

## Operational Runbook

### Deploy All Networks

```bash
./deploy-all.sh                    # All networks
./deploy-all.sh mainnet            # Mainnet only
KUBECONTEXT=my-ctx ./deploy-all.sh # Custom context
```

### Rolling Upgrade (Zero-Downtime)

```bash
# 1. Update Helm chart (changes ConfigMap + StatefulSet spec)
helm upgrade --install luxd-mainnet charts/lux -f charts/lux/values-mainnet.yaml \
  --namespace lux-mainnet --kube-context do-sfo3-hanzo-k8s

# 2. Delete pods ONE AT A TIME (OnDelete strategy)
kubectl --context do-sfo3-hanzo-k8s -n lux-mainnet delete pod luxd-0
# Wait for luxd-0 to be Running + healthy
kubectl --context do-sfo3-hanzo-k8s -n lux-mainnet wait pod/luxd-0 --for=condition=Ready --timeout=300s

# 3. Repeat for remaining pods
for i in 1 2 3 4; do
  kubectl --context do-sfo3-hanzo-k8s -n lux-mainnet delete pod luxd-$i
  kubectl --context do-sfo3-hanzo-k8s -n lux-mainnet wait pod/luxd-$i --for=condition=Ready --timeout=300s
done
```

### Re-import C-Chain (After Trie Corruption)

```bash
# 1. Set initMode.clearData=true to clear stale data
helm upgrade --install luxd-mainnet charts/lux -f charts/lux/values-mainnet.yaml \
  --set initMode.clearData=true --namespace lux-mainnet

# 2. Delete the affected pod
kubectl -n lux-mainnet delete pod luxd-0

# 3. Monitor import progress
kubectl -n lux-mainnet logs luxd-0 -f | grep BOOTSTRAP

# 4. Reset clearData back to false after all pods recovered
helm upgrade --install luxd-mainnet charts/lux -f charts/lux/values-mainnet.yaml \
  --namespace lux-mainnet
```

### Check Block Heights

```bash
for i in 0 1 2 3 4; do
  echo -n "luxd-$i: "
  kubectl -n lux-mainnet exec luxd-$i -- \
    curl -s -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    http://localhost:9630/ext/bc/C/rpc
  echo
done
```

### Check Health

```bash
kubectl -n lux-mainnet exec luxd-0 -- wget -qO- http://localhost:9630/ext/health
```

### Add Subnet Chain Tracking

1. Edit `values-mainnet.yaml`: add chain ID to `chainTracking.trackedChains`
2. Add alias to `chainTracking.aliases`
3. Run `helm upgrade`
4. Delete pods one at a time (rolling)

### Scale Replicas

```bash
helm upgrade --install luxd-mainnet charts/lux -f charts/lux/values-mainnet.yaml \
  --set replicas=7 --namespace lux-mainnet
```

## Lux-Operator CRDs

### LuxNetwork

```yaml
apiVersion: lux.network/v1alpha1
kind: LuxNetwork
metadata:
  name: mainnet
spec:
  networkId: 1
  validators: 5
  image:
    repository: registry.digitalocean.com/hanzo/bootnode
    tag: luxd-v1.23.11
  storage:
    size: 100Gi
    storageClass: do-block-storage
  chainTracking:
    trackAllChains: false
    trackedChains: ["chain-id-1", "chain-id-2"]
    aliases: ["zoo", "hanzo"]
  rlpImport:
    enabled: true
    baseUrl: "https://..."
    filename: "lux-mainnet-96369.rlp"
    multiPart: true
    parts: ["aa", "ab", ...]
  snapshot:
    enabled: false
    url: "https://..."
```

### LuxSubnet

```yaml
apiVersion: lux.network/v1alpha1
kind: LuxSubnet
metadata:
  name: zoo
spec:
  networkRef: mainnet
  subnetId: "2fxVbTJfynNyMym6n7Eu2FM4VHYvuRM3PX5P4ZrGFPjak1LTPT"
  validators:
    - nodeId: NodeID-Mf3JfSY91oDwfBqf7rCLmhg4NDtDghw1f
      weight: 100
  vm:
    vmType: subnet-evm
```

### Controller Phases

```
Pending → Creating → Bootstrapping → Running → (Degraded → Recovery)
```

- **Creating**: StatefulSet, Services, ConfigMap created; waiting for pods
- **Bootstrapping**: Pods running, checking `/ext/health` for bootstrap completion
- **Running**: All nodes healthy, periodic health checks every 60s
- **Degraded**: < 2/3 quorum healthy, triggers pod recovery (delete + recreate)

## Pathdb Trie Corruption

Luxd v1.23.x uses pathdb for C-chain state storage. After importing 1M+ blocks, the genesis parent trie layer is pruned away. **ANY restart causes trie corruption** because the node cannot reconstruct state.

**Consequences**:
- OnDelete update strategy prevents accidental corruption from rolling restarts
- After pod restart, C-chain data must be deleted and re-imported from RLP
- Snapshot restore (faster) is the planned improvement

## Key Patterns

- `exec` in startup replaces the shell → use `&` + `wait` for post-start logic
- Pathdb makes C-chain data non-portable across restarts → plan for re-import
- Per-pod LoadBalancers are expensive but necessary for P2P identity
- Node IDs derived from staking certificates → must be consistent across genesis, secrets, values
- TCP socket probes (not HTTP) for liveness/readiness (more reliable during import)

## Build

```bash
cargo check -p lux-operator   # Type-check operator
cargo build --release          # Build all crates
```

## Multi-Tenant Fleet Management

For managing multiple tenant networks (bootnode, lux, etc):

1. **Namespace isolation**: Each tenant gets `lux-{tenant}-{network}` namespace
2. **Shared cluster**: All tenants on `do-sfo3-hanzo-k8s`
3. **Per-tenant values**: Override `bootstrap.nodeIDs`, `staking.secretName`, `genesis.configMapName`
4. **Bootnode UI**: `cloud.lux.network` provides web dashboard for fleet management
5. **API**: `api.cloud.lux.network` (FastAPI) manages clusters via K8s API
