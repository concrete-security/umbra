#!/bin/bash
set -e

HOST=${HOST:-0.0.0.0}
PORT=${PORT:-8080}
# Keep it to 1 if you want replication at the container orchestration level
WORKERS=${WORKERS:-1}

echo "Starting Attestation Service..."
echo "Host: ${HOST}"
echo "Port: ${PORT}"
echo "Workers: ${WORKERS}"

exec uv run fastapi run attestation_service.py \
        --host ${HOST} \
        --port ${PORT} \
        --workers ${WORKERS} \
        --proxy-headers
