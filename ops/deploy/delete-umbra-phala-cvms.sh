#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "clean-phala: .env not found; skipping Phala CVM cleanup" >&2
  exit 0
fi

set -a
. ./.env
set +a

if [ -z "${PHALA_API_TOKEN:-}" ]; then
  echo "clean-phala: PHALA_API_TOKEN is not set; skipping Phala CVM cleanup" >&2
  exit 0
fi

uv run --locked --project console python -m umbra_console.cleanup_phala
