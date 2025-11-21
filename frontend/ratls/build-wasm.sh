#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
WASM_DIR="$ROOT_DIR/wasm"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack not found in PATH. Install it via 'cargo install wasm-pack'." >&2
  exit 1
fi

TARGET="${WASM_TARGET:-web}"
OUT_DIR="${WASM_OUT_DIR:-pkg}"

echo "Building ratls-wasm (target=${TARGET}, out-dir=${OUT_DIR})"
(
  cd "$WASM_DIR"
  wasm-pack build --target "$TARGET" --out-dir "$OUT_DIR" "$@"

  # Ship the fetch shim alongside the generated package so consumers can import
  # `ratls-wasm/ratls-fetch.js` directly.
  cp ratls-fetch.js ratls-fetch.d.ts "$OUT_DIR"/
  OUT_DIR_ENV="$OUT_DIR" python3 - <<'PY'
import json
import os
from pathlib import Path

out_dir = os.environ.get("OUT_DIR_ENV") or "pkg"
pkg = Path(out_dir) / "package.json"
if not pkg.exists():
    raise SystemExit(0)
data = json.loads(pkg.read_text())
files = set(data.get("files", []))
files.update(["ratls-fetch.js", "ratls-fetch.d.ts"])
data["files"] = sorted(files)
pkg.write_text(json.dumps(data, indent=2))
print("Embedded ratls-fetch into package.json files list")
PY
)
