#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[deploy] root: ${ROOT_DIR}"

echo "[deploy] 1) Apply CRDs (must be first)"
kubectl apply -f "${ROOT_DIR}/crds/"

echo "[deploy] 2) Apply operator namespace"
kubectl apply -f "${ROOT_DIR}/namespace.yaml"

echo "[deploy] 3) Verify KMS auth credentials"
echo "         (universal-auth-credentials in hanzo namespace, shared cluster-wide)"
if ! kubectl get secret universal-auth-credentials -n hanzo >/dev/null 2>&1; then
  echo "  ERROR: universal-auth-credentials not found in hanzo namespace"
  echo "  This is the bootstrap secret for Hanzo KMS. Create it with:"
  echo "    kubectl -n hanzo create secret generic universal-auth-credentials \\"
  echo "      --from-literal=clientId=<id> --from-literal=clientSecret=<secret>"
  exit 1
fi

echo "[deploy] 4) Apply KMS secret syncs (GHCR + DO registry pull secrets)"
kubectl apply -f "${ROOT_DIR}/kms-secrets.yaml"

echo "[deploy] 5) Wait for KMS secrets to sync (up to 30s)"
for secret_check in "ghcr-luxfi:lux-system" "registry-hanzo:lux-system"; do
  name="${secret_check%%:*}"
  ns="${secret_check##*:}"
  for i in $(seq 1 6); do
    if kubectl get secret "$name" -n "$ns" >/dev/null 2>&1; then
      echo "  OK: $name in $ns"
      break
    fi
    [ "$i" -eq 6 ] && echo "  WARNING: $name not yet synced in $ns (KMS may need time)"
    sleep 5
  done
done

echo "[deploy] 6) Apply RBAC + deployment + service"
kubectl apply -f "${ROOT_DIR}/rbac/"
kubectl apply -f "${ROOT_DIR}/deployment.yaml"
kubectl apply -f "${ROOT_DIR}/service.yaml"

echo "[deploy] 7) Wait for operator rollout"
kubectl rollout status deployment/lux-operator -n lux-system --timeout=120s

echo "[deploy] 8) Apply network CRs (adoptExisting: true, KMS staking)"
kubectl apply -f "${ROOT_DIR}/networks/"

echo "[deploy] done"

echo
echo "[verify] Operator:"
kubectl get pods -n lux-system -o wide
echo
echo "[verify] CRDs:"
kubectl get crd | grep lux.network || true
echo
echo "[verify] Networks:"
kubectl get luxnetwork -A || true
echo
echo "[verify] KMS Secrets:"
kubectl get kmssecrets -A 2>/dev/null || echo "  (KMS operator CRD not installed)"
echo
echo "[verify] Managed Secrets:"
for ns in lux-system lux-mainnet lux-testnet lux-devnet; do
  echo "  $ns:"
  kubectl get secrets -n "$ns" -o custom-columns='  NAME:.metadata.name,TYPE:.type' --no-headers 2>/dev/null | grep -v 'helm.sh' || true
done
