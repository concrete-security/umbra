#!/bin/bash
set -e

MODE=${1:-"prod"}
WITH_BASSE_VLLM=${2:-"false"}
SERVICE_LIST=()

if [[ "$WITH_BASSE_VLLM" == "true" ]]; then
    SERVICE_LIST+=("vllm_service")
fi

echo "Mode: $MODE"
echo "Detected platform: $OSTYPE"
echo "Services to build: ${SERVICE_LIST[*]}"

echo "🏗️  Building images for: ${SERVICE_LIST[*]}..."
docker compose build "${SERVICE_LIST[@]}"

echo "✅ Build completed successfully."
