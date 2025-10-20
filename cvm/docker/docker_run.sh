#!/bin/bash
set -e

OS="$(uname -s)"

MODE=${1:-"prod"}
WITH_BASSE_VLLM=${2:-"false"}

SERVICE_LIST=()
CONTAINER_LIST=()

if [[ "$WITH_BASSE_VLLM" == "true" ]]; then
    CONTAINER_LIST+=("vllm_container")
    SERVICE_LIST+=("vllm_service")
fi

echo "Mode: $MODE"
echo "Detected platform: $OSTYPE"
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
docker compose up -d --force-recreate "${SERVICE_LIST[@]}"

# Show logs
echo "📜 Showing live logs..."
docker compose logs -f
