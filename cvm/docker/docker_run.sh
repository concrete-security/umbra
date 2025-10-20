#!/bin/bash
set -e

OS="$(uname -s)"

MODE=${1:-"prod"}
WITH_BASSE_VLLM=${2:-"false"}
ENV_FILE=".env_${MODE}"

# Load .env
if [[ -f "$ENV_FILE" ]]; then
  set -o allexport
  source "$ENV_FILE"
  set +o allexport
fi

if [ "$(uname)" = "Darwin" ]; then
  export HOST_MODEL_STORAGE_DIR="$(pwd)/tee/models"
  export HOST_HF_CACHE="$(pwd)/huggingface"
  export CONTAINER_MODEL_STORAGE_DIR="/tee/models"
  mkdir -p "${HOST_MODEL_STORAGE_DIR}" "${HOST_HF_CACHE}"
fi

echo "Using model storage dir: $HOST_MODEL_STORAGE_DIR"
echo "Using container model storage dir: $CONTAINER_MODEL_STORAGE_DIR"
echo "Using HF cache dir: $HOST_HF_CACHE"

SERVICE_LIST=("proxy_api_service" "prometheus_service" "grafana_service")
CONTAINER_LIST=("proxy_api_container" "prometheus_container" "grafana_container")

if [[ "$WITH_BASSE_VLLM" == "true" ]]; then
    CONTAINER_LIST+=("vllm_container")
    SERVICE_LIST+=("vllm_service")
fi

echo "Mode: $MODE"
echo "Detected platform: $OSTYPE"
echo "Env file: $ENV_FILE"
echo "Containers to handle: ${CONTAINER_LIST[*]}"
echo "Services to handle: ${SERVICE_LIST[*]}"

# Stop / Remove existing containers
echo "🛑 Shutting down running containers..."
for container in "${CONTAINER_LIST[@]}"; do
    echo "Checking container: $container"
    if docker ps -a --format '{{.Names}}' | grep -q "$container"; then
        echo "🛑 Stopping container: $container"
        docker stop "$container" >/dev/null 2>&1 || true
        echo "🗑️  Removing container: $container"
        docker rm "$container" >/dev/null 2>&1 || true
    else
        echo "[ERROR] Container $container not found, skipping."
    fi
done

# Restart containers
echo "🚀 Starting containers..."
docker compose --env-file "$ENV_FILE" up -d --force-recreate "${SERVICE_LIST[@]}"

# Show logs
echo "📜 Showing live logs..."
docker compose logs -f
