#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[deploy] root: ${ROOT_DIR}"

echo "[deploy] 1) Apply CRDs (must be first)"
kubectl apply -f "${ROOT_DIR}/crds/"

echo "[deploy] 2) Apply operator namespace"
kubectl apply -f "${ROOT_DIR}/namespace.yaml"

echo "[deploy] 3) Apply KMS secret sync (ghcr pull secret)"
kubectl apply -f "${ROOT_DIR}/kms-secrets.yaml"

echo "[deploy] 4) Apply RBAC + deployment + service"
kubectl apply -f "${ROOT_DIR}/rbac/"
kubectl apply -f "${ROOT_DIR}/deployment.yaml"
kubectl apply -f "${ROOT_DIR}/service.yaml"

echo "[deploy] 5) Wait for operator rollout"
kubectl rollout status deployment/lux-operator -n lux-system --timeout=120s

echo "[deploy] 6) Apply network CRs (adoptExisting: true)"
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
