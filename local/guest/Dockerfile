# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# Build from the repository root with --platform linux/arm64.
# Preview build only: not a reproducibility or publication gate.
FROM rust:1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS roots
FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea AS packages
COPY --from=roots /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG UBUNTU_SNAPSHOT=20260826T120000Z
ENV DEBIAN_FRONTEND=noninteractive
RUN test "$(dpkg --print-architecture)" = arm64 \
    && sed -i -E "s#https?://(ports.ubuntu.com/ubuntu-ports|archive.ubuntu.com/ubuntu|security.ubuntu.com/ubuntu)/?#https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/#g" /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates systemd-sysv \
       linux-image-virtual initramfs-tools openssh-server python3 sudo curl git \
       build-essential dtach nodejs npm docker.io e2fsprogs gzip zstd \
    && rm -rf /var/lib/apt/lists/* /var/log/apt/*

FROM packages AS guest
# Reuse the reviewed Codex lockfile, including its Linux arm64 binary and integrity pins.
COPY cvms/dev/user-sandbox/codex-package/ /usr/local/lib/umbra/codex/
RUN npm ci --prefix /usr/local/lib/umbra/codex --omit=dev --ignore-scripts --no-audit --no-fund \
    && ln -s /usr/local/lib/umbra/codex/node_modules/@openai/codex/bin/codex.js /usr/local/bin/codex \
    && rm -rf /root/.npm
RUN useradd --uid 1001 --create-home --shell /bin/bash dev \
    && usermod -p '*' dev \
    && install -d -o dev -g dev /home/dev/workspaces \
    && printf 'dev ALL=(ALL) NOPASSWD: ALL\nDefaults env_keep += "HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE GIT_SSL_CAINFO NODE_EXTRA_CA_CERTS"\n' > /etc/sudoers.d/umbra-local \
    && chmod 0440 /etc/sudoers.d/umbra-local \
    && rm -f /etc/ssh/ssh_host_* \
    && systemctl disable ssh.service ssh.socket docker.service docker.socket || exit 1
COPY local/guest/guest.py /usr/lib/umbra-local/guest.py
COPY local/guest/sshd_config /etc/ssh/sshd_config
COPY local/guest/umbra-local.service /etc/systemd/system/umbra-local.service
COPY local/guest/environment /etc/environment
RUN sed 's/^/export /' /etc/environment > /etc/profile.d/umbra-local.sh \
    && printf 'Acquire::http::Proxy "http://127.0.0.1:3128";\nAcquire::https::Proxy "http://127.0.0.1:3128";\nAcquire::https::CaInfo "/run/umbra/ca-bundle.pem";\n' > /etc/apt/apt.conf.d/99umbra-local \
    && mkdir -p /etc/systemd/system/docker.service.d \
    && printf '[Service]\nEnvironmentFile=/etc/environment\n' > /etc/systemd/system/docker.service.d/umbra.conf \
    && printf 'virtio_blk\nvirtio_pci\nvirtio_console\nvmw_vsock_virtio_transport\n' >> /etc/initramfs-tools/modules \
    && update-initramfs -u -k all \
    && systemctl enable umbra-local.service \
    && : > /etc/machine-id

FROM packages AS pack
COPY --from=guest / /rootfs/
RUN mkdir /out \
    && truncate -s 12G /out/rootfs.raw \
    && mkfs.ext4 -q -F -d /rootfs /out/rootfs.raw \
    && cp /rootfs/boot/vmlinuz-* /out/Image \
    && cp /rootfs/boot/initrd.img-* /out/initrd \
    && python3 -c 'from pathlib import Path; import gzip; p=Path("/out/Image"); b=p.read_bytes(); b=gzip.decompress(b) if b[:2]==b"\x1f\x8b" else b; assert b[56:60]==b"ARM\x64", "expected an ARM64 Linux Image"; p.write_bytes(b)'
FROM scratch AS bundle
COPY --from=pack /out/ /
