#!/bin/bash
# Deploy all Lux networks to K8s

set -e

CHART_DIR="$(dirname "$0")/charts/luxd"

echo "Deploying mainnet..."
helm upgrade --install luxd-mainnet "$CHART_DIR" \
  --set network=mainnet \
  --namespace lux-mainnet --create-namespace

echo "Deploying testnet..."
helm upgrade --install luxd-testnet "$CHART_DIR" \
  --set network=testnet \
  --namespace lux-testnet --create-namespace

echo "Deploying devnet..."
helm upgrade --install luxd-devnet "$CHART_DIR" \
  --set network=devnet \
  --namespace lux-devnet --create-namespace

echo "All networks deployed!"
kubectl get pods -A | grep lux
