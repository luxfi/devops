#!/bin/bash
# Deploy all Lux networks to K8s
#
# Usage:
#   ./deploy-all.sh                    # Deploy all networks
#   ./deploy-all.sh mainnet            # Deploy mainnet only
#   ./deploy-all.sh testnet devnet     # Deploy testnet and devnet
#   KUBECONTEXT=my-ctx ./deploy-all.sh # Use specific kubectl context

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHART_DIR="${SCRIPT_DIR}/charts/lux"
KUBECONTEXT="${KUBECONTEXT:-do-sfo3-hanzo-k8s}"

deploy_network() {
  local network=$1
  local namespace="lux-${network}"
  local values_file="${CHART_DIR}/values-${network}.yaml"

  echo "=== Deploying ${network} to ${namespace} ==="

  # Build helm args
  HELM_ARGS="upgrade --install luxd-${network} ${CHART_DIR}"
  HELM_ARGS="${HELM_ARGS} --namespace ${namespace} --create-namespace"
  HELM_ARGS="${HELM_ARGS} --kube-context ${KUBECONTEXT}"

  # Use network-specific values file if it exists, otherwise just set network
  if [ -f "${values_file}" ]; then
    HELM_ARGS="${HELM_ARGS} -f ${values_file}"
  else
    HELM_ARGS="${HELM_ARGS} --set network=${network}"
  fi

  helm ${HELM_ARGS}
  echo "  ${network} deployed."
}

# Parse arguments
NETWORKS="${@:-mainnet testnet devnet}"

for network in ${NETWORKS}; do
  deploy_network "${network}"
done

echo ""
echo "=== Deployment complete ==="
kubectl --context "${KUBECONTEXT}" get pods -A -l app=luxd -o wide
