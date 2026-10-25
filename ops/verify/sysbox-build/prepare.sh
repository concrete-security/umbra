#!/usr/bin/env bash
# Fetch only the immutable source inputs shared by lock resolution and builds.
set -euo pipefail
[[ "$(go env GOVERSION)" = go1.27.3 && "$(go env GOARCH)" = amd64 ]]
mkdir -p /src /out/evidence
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
patch --batch --fuzz=0 -d sysbox-runc -p1 < /recipe/cilium-api.patch
cp /recipe/device_filter_test.go sysbox-runc/libcontainer/cgroups/ebpf/umbra_qualification_test.go
cp /recipe/sources.txt /recipe/cilium-api.patch /out/evidence/
dpkg-query -W -f='${Package} ${Version}\n' > /out/evidence/build-packages.txt
# The pinned legacy generator supports the source's plugins=grpc API.
go install github.com/golang/protobuf/protoc-gen-go@v1.5.4
go version -m /go/bin/protoc-gen-go > /out/evidence/protoc-gen-go.buildinfo.txt
protoc --version > /out/evidence/protoc.txt
make -C sysbox-ipc sysbox-ipc
find sysbox-ipc -name '*.pb.go' -type f -print0 | sort -z | xargs -0 sha256sum \
  > /out/evidence/generated-protobuf.sha256
