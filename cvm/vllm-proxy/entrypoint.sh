#!/bin/bash
set -e

# --- Logs utiles
echo "[entrypoint] Starting vllm proxy api"
echo "[entrypoint] BASE_VLLM_URL=${BASE_VLLM_URL}"
echo "[entrypoint] HOST=${HOST}"
echo "[entrypoint] PORT=${PORT}"

exec uv run fastapi run proxy_app.py \
        --host ${HOST} \
        --port ${PORT}
