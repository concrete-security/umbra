#!/usr/bin/env bash
set -euo pipefail
# This builds local developer artifacts only; it does not publish or enroll devices.
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
out=${1:?Usage: local/build-preview.sh NEW_BUNDLE_DIRECTORY}
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || { echo 'Build on an Apple-silicon Mac.' >&2; exit 1; }
[[ ! -e "$out" ]] || { echo 'Output already exists; choose a new bundle directory.' >&2; exit 1; }
umask 077
swift build --package-path "$root/local/native" -c release
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd)
docker buildx build --platform linux/arm64 -f "$root/local/guest/Dockerfile" --output "type=local,dest=$out" "$root"
cp "$root/local/native/.build/release/umbra-local-vm" "$out/umbra-local-vm"
codesign --force --sign - --entitlements "$root/local/native/entitlements.plist" "$out/umbra-local-vm"
python3 - "$out" <<'PY'
import hashlib, json, pathlib, sys
folder = pathlib.Path(sys.argv[1])
files = {}
for name in ("Image", "initrd", "rootfs.raw", "umbra-local-vm"):
    with (folder / name).open("rb") as source:
        files[name] = hashlib.file_digest(source, "sha256").hexdigest()
(folder / "manifest.json").write_text(json.dumps({"version": 2, "architecture": "aarch64", "files": files}, indent=2) + "\n")
PY
printf 'Preview bundle: %s\n' "$out"
printf '%s\n' 'Ad-hoc signed for local testing only. Not a managed or release-signed installation.' >&2
