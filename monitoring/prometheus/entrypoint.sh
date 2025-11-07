#!/bin/sh
set -e

echo "[entrypoint] Starting Prometheus..."

exec /bin/prometheus \
  --config.file="$CONFIG_FILE" \
  --storage.tsdb.path="$STORAGE_TSDB_PATH" \
  --storage.tsdb.retention.time="$STORAGE_TSDB_RETENTION_TIME" \
  --log.level="$LOG_LEVEL"
