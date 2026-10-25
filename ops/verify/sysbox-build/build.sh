#!/usr/bin/env bash
# Qualification build only: no installation, publication, or live guest changes.
set -euo pipefail
bash /recipe/prepare.sh
mkdir -p /out/bin /out/tests

for component in sysbox-runc sysbox-fs sysbox-mgr; do
  cd "/src/$component"
  # These locks came from the reviewed resolution build. Never resolve new
  # versions here; all local fork replacements remain bound to sources.txt.
  cp "/recipe/locks/$component/go.mod" "/recipe/locks/$component/go.sum" .
  go mod verify
  mkdir "/out/evidence/$component"
  cp go.mod go.sum "/out/evidence/$component/"
  case "$component" in
    sysbox-runc)
      commit=081856cc5d17e7095f066b08d0eca6bb0b515c47
      tags='seccomp apparmor idmapped_mnt netgo osusergo'
      package=. ;;
    sysbox-fs)
      commit=c3d2ebc65102e32e74e383675f03b45556326888
      tags='netgo osusergo'
      package=./cmd/sysbox-fs ;;
    sysbox-mgr)
      commit=2d45af01bcfd8641e6641f76104c6003bf501cd7
      tags='idmapped_mnt netgo osusergo'
      package=. ;;
  esac
  metadata="-X 'main.edition=Community Edition (CE)' -X main.version=0.7.1+umbra.1 -X main.commitId=$commit -X main.builtAt=2026-10-25T00:00:00Z -X main.builtBy=Umbra"
  go build -mod=readonly -buildvcs=false -trimpath -tags "$tags" \
    -ldflags "-extldflags -static $metadata" -o "/out/bin/$component" "$package"
  cmp go.mod "/out/evidence/$component/go.mod"
  cmp go.sum "/out/evidence/$component/go.sum"
  go version -m "/out/bin/$component" > "/out/evidence/$component.buildinfo.txt"
  readelf -h -l -d "/out/bin/$component" > "/out/evidence/$component.elf.txt"
  if grep -Eq 'INTERP|\(NEEDED\)' "/out/evidence/$component.elf.txt"; then
    echo "$component is not a static ELF" >&2
    exit 1
  fi
  (cd /out/bin && sha256sum "$component") >> /out/evidence/binaries.sha256
  if [[ "$component" = sysbox-runc ]]; then
    go test -mod=readonly -tags "$tags" ./libcontainer/cgroups/ebpf/devicefilter
    go test -mod=readonly -buildvcs=false -trimpath -tags "$tags" \
      -ldflags '-extldflags -static' -c -o /out/tests/device-filter.test ./libcontainer/cgroups/ebpf
  fi
done

# A clean, independent build must reproduce the reviewed binary bytes.
cat /out/evidence/binaries.sha256
(cd /out/bin && sha256sum --check --strict /recipe/binaries.expected.sha256)
