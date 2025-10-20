#!/bin/bash
set -e

MODE=${1:-"prod"}
WITH_BASSE_VLLM=${2:-"false"}
ENV_FILE=".env_${MODE}"

SERVICE_LIST=("proxy_api_service" "prometheus_service" "grafana_service")

if [[ "$WITH_BASSE_VLLM" == "true" ]]; then
    SERVICE_LIST+=("vllm_service")
fi

echo "Mode: $MODE"
echo "Detected platform: $OSTYPE"
echo "Env file: $ENV_FILE"
echo "Services to build: ${SERVICE_LIST[*]}"

# Load .env
if [[ -f "$ENV_FILE" ]]; then
    set -o allexport
    source "$ENV_FILE"
    set +o allexport
fi

echo "🏗️  Building images for: ${SERVICE_LIST[*]}..."
docker compose --env-file "$ENV_FILE" build "${SERVICE_LIST[@]}"

echo "✅ Build completed successfully."
