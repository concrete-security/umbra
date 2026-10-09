# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# BuildKit normalizes image metadata and generated layer timestamps to this
# reviewed value. Release builds override it with the source commit timestamp.
ARG SOURCE_DATE_EPOCH=0

FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS go-base
ENV CGO_ENABLED=0 GOTOOLCHAIN=local

FROM go-base AS compose-builder
ARG COMPOSE_VERSION=5.6.0
ARG COMPOSE_SOURCE_SHA256=51ad60cc28d38a0850678053f0a259dfee931d150dd1d50ee9e6d758125b1d47
RUN curl -fsSL "https://github.com/docker/compose/archive/refs/tags/v${COMPOSE_VERSION}.tar.gz" -o /tmp/compose.tar.gz \
    && echo "${COMPOSE_SOURCE_SHA256}  /tmp/compose.tar.gz" | sha256sum -c - \
    && mkdir -p /src \
    && tar -xzf /tmp/compose.tar.gz -C /src --strip-components=1 \
    && rm /tmp/compose.tar.gz
WORKDIR /src
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 make build VERSION="v${COMPOSE_VERSION}" GO_BUILDTAGS=e2e DESTDIR=/out

FROM go-base AS buildx-builder
COPY cvms/dev/user-sandbox/tool-versions.env /tmp/tool-versions.env
WORKDIR /src
# The released Buildx binary still embeds an older Go compiler and archive
# dependency. Replace only its vendored archive module with a pinned release.
RUN set -a \
    && . /tmp/tool-versions.env \
    && set +a \
    && curl -fsSL "https://github.com/docker/buildx/archive/refs/tags/v${BUILDX_VERSION}.tar.gz" -o /tmp/buildx.tar.gz \
    && curl -fsSL "https://github.com/moby/go-archive/archive/refs/tags/v${BUILDX_GO_ARCHIVE_VERSION}.tar.gz" -o /tmp/go-archive.tar.gz \
    && printf '%s  %s\n' \
      "${BUILDX_SOURCE_SHA256}" /tmp/buildx.tar.gz \
      "${BUILDX_GO_ARCHIVE_SHA256}" /tmp/go-archive.tar.gz \
      | sha256sum -c - \
    && tar -xzf /tmp/buildx.tar.gz -C /src --strip-components=1 \
    && grep -Fq 'github.com/moby/go-archive v0.2.0' go.mod \
    && grep -Fq 'github.com/moby/go-archive v0.2.0' vendor/modules.txt \
    && rm -rf vendor/github.com/moby/go-archive \
    && mkdir -p vendor/github.com/moby/go-archive \
    && tar -xzf /tmp/go-archive.tar.gz -C vendor/github.com/moby/go-archive --strip-components=1 \
    && sed -i "s|github.com/moby/go-archive v0.2.0|github.com/moby/go-archive v${BUILDX_GO_ARCHIVE_VERSION}|g" go.mod vendor/modules.txt \
    && go build -mod=vendor -trimpath -buildvcs=false \
      -ldflags "-s -w -X github.com/docker/buildx/version.Version=v${BUILDX_VERSION}+umbra.1" \
      -o /out/docker-buildx ./cmd/buildx

FROM go-base AS gh-builder
COPY cvms/dev/user-sandbox/tool-versions.env /tmp/tool-versions.env
WORKDIR /src
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -a \
    && . /tmp/tool-versions.env \
    && set +a \
    && curl -fsSL "https://github.com/cli/cli/archive/refs/tags/v${GH_VERSION}.tar.gz" -o /tmp/gh.tar.gz \
    && echo "${GH_SOURCE_SHA256}  /tmp/gh.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gh.tar.gz -C /src --strip-components=1 \
    && cp go.sum /tmp/locked-go.sum \
    && go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags "-s -w -X github.com/cli/cli/v2/internal/build.Version=${GH_VERSION}" \
      -o /out/gh ./cmd/gh \
    && cmp go.sum /tmp/locked-go.sum

FROM rust:1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS rust-base

FROM rust-base AS atls-connect-builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY cli/Cargo.toml cli/Cargo.toml
COPY cvms/dev/user-sandbox/atls-connect/Cargo.toml cvms/dev/user-sandbox/atls-connect/Cargo.toml
COPY cvms/dev/user-sandbox/atls-connect/src cvms/dev/user-sandbox/atls-connect/src
RUN cargo build --locked --release -p umbra-atls-connect --target-dir /tmp/atls-connect-target

FROM ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded AS uv

FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

# Ubuntu's minimal rootfs has no CA bundle, but the immutable archive is HTTPS.
# Bootstrap trust from another immutable base; the snapshot-pinned
# ca-certificates package replaces it during the first install.
COPY --from=rust-base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Canonical retains Ubuntu snapshots for at least two years. Advance this only
# after rebuilding and exercising the sandbox image; it deliberately freezes
# all packages from the Ubuntu archive. Docker's exact amd64 package filenames
# and content digests are pinned separately in tool-versions.env below.
ARG UBUNTU_SNAPSHOT=20261008T120000Z

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY cvms/dev/user-sandbox/tool-versions.env /tmp/tool-versions.env

RUN sed -i \
      -e "s|http://archive.ubuntu.com/ubuntu|https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}|g" \
      -e "s|http://security.ubuntu.com/ubuntu|https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}|g" \
      /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      openssh-server \
      dtach \
      git \
      xz-utils \
      build-essential \
      python3 \
      python3-pip \
      rsync \
      jq \
      vim \
      less \
      psmisc \
      lsof \
      sudo \
    && rm -rf \
      /var/lib/apt/lists/* \
      /var/log/apt/* \
      /var/log/alternatives.log \
      /var/log/dpkg.log \
      /var/cache/ldconfig/aux-cache \
      /etc/ssh/ssh_host_* \
    && chage --lastday -1 sshd \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && rm -f /usr/lib/python*/EXTERNALLY-MANAGED

RUN set -a \
    && . /tmp/tool-versions.env \
    && set +a \
    && test "$(dpkg --print-architecture)" = amd64 \
    && curl -fsSL "${DOCKER_DEB_BASE_URL}/${DOCKER_CE_DEB}" -o /tmp/docker-ce.deb \
    && curl -fsSL "${DOCKER_DEB_BASE_URL}/${DOCKER_CE_CLI_DEB}" -o /tmp/docker-ce-cli.deb \
    && curl -fsSL "${DOCKER_DEB_BASE_URL}/${CONTAINERD_DEB}" -o /tmp/containerd.deb \
    && printf '%s  %s\n' \
      "${DOCKER_CE_SHA256}" /tmp/docker-ce.deb \
      "${DOCKER_CE_CLI_SHA256}" /tmp/docker-ce-cli.deb \
      "${CONTAINERD_SHA256}" /tmp/containerd.deb \
      | sha256sum -c - \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      /tmp/containerd.deb \
      /tmp/docker-ce-cli.deb \
      /tmp/docker-ce.deb \
    && rm -rf \
      /var/lib/apt/lists/* \
      /var/log/apt/* \
      /var/log/alternatives.log \
      /var/log/dpkg.log \
      /var/cache/ldconfig/aux-cache \
      /tmp/*.deb

COPY --from=compose-builder --chmod=0755 /out/docker-compose /usr/libexec/docker/cli-plugins/docker-compose
COPY --from=buildx-builder --chmod=0755 /out/docker-buildx /usr/libexec/docker/cli-plugins/docker-buildx
COPY --from=gh-builder --chmod=0755 /out/gh /usr/local/bin/gh
COPY cvms/dev/user-sandbox/docker-daemon.json /etc/docker/daemon.json
COPY cvms/dev/user-sandbox/codex-package ./tmp/codex-package
COPY --from=uv /uv /uvx /bin/

RUN set -a \
    && . /tmp/tool-versions.env \
    && set +a \
    && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" -o /tmp/node.tar.xz \
    && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
    && rm /tmp/node.tar.xz \
    && npm install --global "npm@${NPM_VERSION}" --ignore-scripts --no-audit --no-fund \
    # npm 12.0.2 predates fixed releases of four top-level bundled dependencies.
    # Keep these checksummed replacements until NPM_VERSION bundles them itself.
    && curl -fsSL "https://registry.npmjs.org/brace-expansion/-/brace-expansion-${NPM_BRACE_EXPANSION_VERSION}.tgz" -o /tmp/npm-brace-expansion.tgz \
    && curl -fsSL "https://registry.npmjs.org/ip-address/-/ip-address-${NPM_IP_ADDRESS_VERSION}.tgz" -o /tmp/npm-ip-address.tgz \
    && curl -fsSL "https://registry.npmjs.org/tar/-/tar-${NPM_TAR_VERSION}.tgz" -o /tmp/npm-tar.tgz \
    && curl -fsSL "https://registry.npmjs.org/undici/-/undici-${NPM_UNDICI_VERSION}.tgz" -o /tmp/npm-undici.tgz \
    && printf '%s  %s\n' \
      "${NPM_BRACE_EXPANSION_SHA256}" /tmp/npm-brace-expansion.tgz \
      "${NPM_IP_ADDRESS_SHA256}" /tmp/npm-ip-address.tgz \
      "${NPM_TAR_SHA256}" /tmp/npm-tar.tgz \
      "${NPM_UNDICI_SHA256}" /tmp/npm-undici.tgz \
      | sha256sum -c - \
    && rm -rf \
      /usr/local/lib/node_modules/npm/node_modules/brace-expansion \
      /usr/local/lib/node_modules/npm/node_modules/ip-address \
      /usr/local/lib/node_modules/npm/node_modules/tar \
      /usr/local/lib/node_modules/npm/node_modules/undici \
    && install -d \
      /usr/local/lib/node_modules/npm/node_modules/brace-expansion \
      /usr/local/lib/node_modules/npm/node_modules/ip-address \
      /usr/local/lib/node_modules/npm/node_modules/tar \
      /usr/local/lib/node_modules/npm/node_modules/undici \
    && tar -xzf /tmp/npm-brace-expansion.tgz -C /usr/local/lib/node_modules/npm/node_modules/brace-expansion --strip-components=1 \
    && tar -xzf /tmp/npm-ip-address.tgz -C /usr/local/lib/node_modules/npm/node_modules/ip-address --strip-components=1 \
    && tar -xzf /tmp/npm-tar.tgz -C /usr/local/lib/node_modules/npm/node_modules/tar --strip-components=1 \
    && tar -xzf /tmp/npm-undici.tgz -C /usr/local/lib/node_modules/npm/node_modules/undici --strip-components=1 \
    && rm /tmp/npm-brace-expansion.tgz /tmp/npm-ip-address.tgz /tmp/npm-tar.tgz /tmp/npm-undici.tgz \
    && test "$(node -p "require('/usr/local/lib/node_modules/npm/node_modules/brace-expansion/package.json').version")" = "${NPM_BRACE_EXPANSION_VERSION}" \
    && test "$(node -p "require('/usr/local/lib/node_modules/npm/node_modules/ip-address/package.json').version")" = "${NPM_IP_ADDRESS_VERSION}" \
    && test "$(node -p "require('/usr/local/lib/node_modules/npm/node_modules/tar/package.json').version")" = "${NPM_TAR_VERSION}" \
    && test "$(node -p "require('/usr/local/lib/node_modules/npm/node_modules/undici/package.json').version")" = "${NPM_UNDICI_VERSION}" \
    && test "$(npm --version)" = "${NPM_VERSION}" \
    && curl -fsSL "https://github.com/anthropics/claude-code/releases/download/v${CLAUDE_VERSION}/claude-linux-x64.tar.gz" -o /tmp/claude.tar.gz \
    && echo "${CLAUDE_SHA256}  /tmp/claude.tar.gz" | sha256sum -c - \
    && install -d /usr/local/lib/umbra \
    && tar -xzf /tmp/claude.tar.gz -C /usr/local/lib/umbra \
    && mv /usr/local/lib/umbra/claude /usr/local/lib/umbra/claude.real \
    && chmod 0755 /usr/local/lib/umbra/claude.real \
    && printf '%s\n' "${CLAUDE_VERSION}" >/usr/local/lib/umbra/claude.version \
    && chmod 0644 /usr/local/lib/umbra/claude.version \
    && rm /tmp/claude.tar.gz \
    && test "$(node -p "require('/tmp/codex-package/package-lock.json').packages['node_modules/@openai/codex'].version")" = "${CODEX_VERSION}" \
    && npm ci --prefix /tmp/codex-package --omit=dev --ignore-scripts --no-audit --no-fund \
    && install -d /usr/local/lib/umbra/codex \
    && mv /tmp/codex-package/node_modules /usr/local/lib/umbra/codex/node_modules \
    && rm -rf \
      /root/.npm \
      /tmp/codex-package \
      /tmp/node-compile-cache \
    && rm /tmp/tool-versions.env

# OpenSSH rejects shadow entries that start with "!" before public-key auth.
# Keep password login impossible without leaving the account locked.
RUN groupadd --gid 1001 dev \
    && useradd --uid 1001 --gid 1001 --create-home --home-dir /home/dev --shell /bin/bash dev \
    && usermod --password '*' dev \
    && chage --lastday -1 dev \
    && usermod -aG sudo,docker dev \
    && { \
      echo 'dev ALL=(ALL) NOPASSWD:ALL'; \
      echo 'Defaults:dev env_keep += "HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy REQUESTS_CA_BUNDLE SSL_CERT_FILE CURL_CA_BUNDLE GIT_SSL_CAINFO NODE_EXTRA_CA_CERTS"'; \
    } >/etc/sudoers.d/dev \
    && chmod 0440 /etc/sudoers.d/dev \
    && visudo -cf /etc/sudoers.d/dev \
    && echo 'dev:100000:65536' >/etc/subuid \
    && echo 'dev:100000:65536' >/etc/subgid \
    && mkdir -p \
      /home/dev/workspaces \
      /home/dev/.local/bin \
      /home/dev/.local/share/gh \
      /home/dev/.cache \
      /home/dev/.npm \
      /home/dev/.claude \
      /home/dev/.codex \
      /home/dev/.cursor-server \
      /home/dev/.vscode-server \
    && chown -R dev:dev /home/dev \
    && git config --file /home/dev/.gitconfig \
      credential.https://github.com.helper '!gh auth git-credential' \
    && git config --file /home/dev/.gitconfig \
      credential.https://gist.github.com.helper '!gh auth git-credential' \
    && chown dev:dev /home/dev/.gitconfig

COPY cvms/dev/user-sandbox/sshd_config /etc/ssh/sshd_config
COPY cvms/dev/user-sandbox/apt-umbra-proxy.conf /etc/apt/apt.conf.d/95umbra-proxy
COPY cvms/dev/user-sandbox/umbra-env-profile.sh /etc/profile.d/umbra-env.sh
COPY cvms/dev/user-sandbox/umbra-update-agents.sh /usr/local/lib/umbra/umbra-update-agents.sh
COPY cvms/dev/user-sandbox/umbra-agent-claude.sh /usr/local/bin/claude
COPY cvms/dev/user-sandbox/umbra-agent-codex.sh /usr/local/bin/codex
COPY cvms/dev/user-sandbox/entrypoint.sh /entrypoint.sh
COPY cvms/dev/user-sandbox/umbra-dev-tunnel.py /usr/local/bin/umbra-dev-tunnel
COPY cvms/dev/user-sandbox/umbra-dev-egress-forwarder.py /usr/local/bin/umbra-dev-egress-forwarder
COPY cvms/dev/user-sandbox/umbra-ca-refresh.py /usr/local/bin/umbra-ca-refresh
COPY --from=atls-connect-builder /tmp/atls-connect-target/release/umbra-atls-connect /usr/local/bin/umbra-atls-connect

RUN chmod +x \
      /entrypoint.sh \
      /usr/local/bin/umbra-dev-tunnel \
      /usr/local/bin/umbra-dev-egress-forwarder \
      /usr/local/bin/umbra-ca-refresh \
      /usr/local/bin/umbra-atls-connect \
      /usr/local/lib/umbra/umbra-update-agents.sh \
      /usr/local/bin/claude \
      /usr/local/bin/codex

EXPOSE 22

HEALTHCHECK --interval=500ms --timeout=2s --start-period=3s --retries=5 \
  CMD pgrep -x sshd >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
