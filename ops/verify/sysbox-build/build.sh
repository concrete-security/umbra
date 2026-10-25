#!/usr/bin/env bash
# Qualification build only: no installation, publication, or live guest changes.
set -euo pipefail
[[ "$(go env GOVERSION)" = go1.27.3 && "$(go env GOARCH)" = amd64 ]]
mkdir -p /src /out/bin /out/evidence
cd /src
while read -r repository commit checksum destination; do
  [[ -n "$repository" && "$repository" != \#* ]] || continue
  curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 120 --max-filesize 25000000 --retry 3 \
    "https://codeload.github.com/nestybox/$repository/tar.gz/$commit" -o /tmp/source.tar.gz
  printf '%s  %s\n' "$checksum" /tmp/source.tar.gz | sha256sum --check --strict
  mkdir -p "$destination"
  tar -xzf /tmp/source.tar.gz -C "$destination" --strip-components=1 --no-same-owner
  rm /tmp/source.tar.gz
done < /recipe/sources.txt
cp /recipe/sources.txt /out/evidence/sources.txt
dpkg-query -W -f='${Package} ${Version}\n' > /out/evidence/build-packages.txt
# The pinned legacy generator supports the source's plugins=grpc API.
go install github.com/golang/protobuf/protoc-gen-go@v1.5.4
go version -m /go/bin/protoc-gen-go > /out/evidence/protoc-gen-go.buildinfo.txt
protoc --version > /out/evidence/protoc.txt
make -C sysbox-ipc sysbox-ipc
find sysbox-ipc -name '*.pb.go' -type f -print0 | sort -z | xargs -0 sha256sum \
  > /out/evidence/generated-protobuf.sha256

for component in sysbox-runc sysbox-fs sysbox-mgr; do
  cd "/src/$component"
  # Resolve this diagnostic graph once; retain complete locks for review before
  # accepting it as a release build. No local fork replacements are removed.
  GOFLAGS='' go get github.com/opencontainers/selinux@v1.13.0 \
    golang.org/x/net@v0.60.0 google.golang.org/grpc@v1.83.2
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
  sha256sum "/out/bin/$component" >> /out/evidence/binaries.sha256
done
