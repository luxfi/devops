#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[deploy-infra] root: ${ROOT_DIR}"

# -------------------------------------------------------------------
# 1) Apply CRDs (idempotent - safe to re-apply)
# -------------------------------------------------------------------
echo "[deploy-infra] 1) Apply all CRDs"
kubectl apply -f "${ROOT_DIR}/crds/"
echo "  Waiting for CRDs to be established..."
for crd in luxnetworks luxchains luxindexers luxexplorers luxgateways; do
  kubectl wait --for=condition=Established "crd/${crd}.lux.network" --timeout=30s
done
echo "  All CRDs established."

# -------------------------------------------------------------------
# 2) Ensure namespaces exist
# -------------------------------------------------------------------
echo "[deploy-infra] 2) Ensure namespaces"
for ns in lux-mainnet lux-testnet lux-devnet; do
  kubectl get namespace "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns"
done

# -------------------------------------------------------------------
# 3) Apply indexers for all networks
# -------------------------------------------------------------------
echo "[deploy-infra] 3) Apply indexers"
for net in mainnet testnet; do
  if [ -f "${ROOT_DIR}/indexers-${net}.yaml" ]; then
    echo "  Applying indexers-${net}.yaml"
    kubectl apply -f "${ROOT_DIR}/indexers-${net}.yaml"
  fi
done

# -------------------------------------------------------------------
# 4) Apply explorer for mainnet
# -------------------------------------------------------------------
echo "[deploy-infra] 4) Apply explorer (mainnet)"
if [ -f "${ROOT_DIR}/explorer-mainnet.yaml" ]; then
  kubectl apply -f "${ROOT_DIR}/explorer-mainnet.yaml"
fi

# -------------------------------------------------------------------
# 5) Apply gateway for mainnet
# -------------------------------------------------------------------
echo "[deploy-infra] 5) Apply gateway (mainnet)"
if [ -f "${ROOT_DIR}/gateway-mainnet.yaml" ]; then
  kubectl apply -f "${ROOT_DIR}/gateway-mainnet.yaml"
fi

# -------------------------------------------------------------------
# 6) Status report
# -------------------------------------------------------------------
echo
echo "========================================="
echo "[status] CRDs:"
kubectl get crd | grep lux.network || true

echo
echo "[status] Indexers:"
kubectl get luxindexers -A 2>/dev/null || echo "  (no indexers yet)"

echo
echo "[status] Explorers:"
kubectl get luxexplorers -A 2>/dev/null || echo "  (no explorers yet)"

echo
echo "[status] Gateways:"
kubectl get luxgateways -A 2>/dev/null || echo "  (no gateways yet)"

echo
echo "[status] Networks:"
kubectl get luxnetworks -A 2>/dev/null || echo "  (no networks yet)"

echo
echo "[deploy-infra] done"
