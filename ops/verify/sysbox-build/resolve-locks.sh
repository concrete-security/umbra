#!/usr/bin/env bash
# Maintenance output only: no runtime binaries, installation, scan or qualification.
set -euo pipefail
bash /recipe/prepare.sh
for component in sysbox-runc sysbox-fs sysbox-mgr; do
  cp "/recipe/locks/$component/go.mod" "/recipe/locks/$component/go.sum" "/src/$component/"
done
for component in sysbox-runc sysbox-fs sysbox-mgr; do
  cd "/src/$component"
  if [[ "$component" = sysbox-runc || "$component" = sysbox-fs ]]; then
    go get github.com/cilium/ebpf@v0.22.0
  fi
  go mod tidy
  go mod verify
  mkdir -p "/out/locks/$component"
  cp go.mod go.sum "/out/locks/$component/"
done
