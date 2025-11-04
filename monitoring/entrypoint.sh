#!/bin/bash
set -e

echo "[entrypoint] Starting Prometheus..."

# Lancer Prometheus avec les bons arguments
exec /bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus \
  --storage.tsdb.retention.time=15d
