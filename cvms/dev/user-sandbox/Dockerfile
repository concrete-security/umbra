FROM rust:1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS rust-base

FROM rust-base AS atls-connect-builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY cli/Cargo.toml cli/Cargo.toml
COPY cvms/dev/user-sandbox/atls-connect/Cargo.toml cvms/dev/user-sandbox/atls-connect/Cargo.toml
COPY cvms/dev/user-sandbox/atls-connect/src cvms/dev/user-sandbox/atls-connect/src
RUN cargo build --locked --release -p umbra-atls-connect --target-dir /tmp/atls-connect-target

FROM ghcr.io/astral-sh/uv:0.7.8@sha256:0178a92d156b6f6dbe60e3b52b33b421021f46d634aa9f81f42b91445bb81cdf AS uv

FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

# Ubuntu's minimal rootfs has no CA bundle, but the immutable archive is HTTPS.
# Bootstrap trust from another immutable base; the snapshot-pinned
# ca-certificates package replaces it during the first install.
COPY --from=rust-base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Canonical retains Ubuntu snapshots for at least two years. Advance this only
# after rebuilding and exercising the sandbox image; it deliberately freezes
# all packages from the Ubuntu archive while Docker's separate repository is
# version-pinned below.
ARG UBUNTU_SNAPSHOT=20260731T000000Z
ARG DOCKER_GPG_SHA256=1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570
ARG DOCKER_CE_VERSION=5:29.7.1-1~ubuntu.24.04~noble
ARG CONTAINERD_VERSION=2.2.6-1~ubuntu.24.04~noble
ARG DOCKER_BUILDX_VERSION=0.36.0-1~ubuntu.24.04~noble
ARG DOCKER_COMPOSE_VERSION=5.4.0-1~ubuntu.24.04~noble

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN sed -i \
      -e "s|http://archive.ubuntu.com/ubuntu|https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}|g" \
      -e "s|http://security.ubuntu.com/ubuntu|https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}|g" \
      /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      gnupg \
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
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && rm -f /usr/lib/python*/EXTERNALLY-MANAGED

RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /tmp/docker.asc \
    && echo "${DOCKER_GPG_SHA256}  /tmp/docker.asc" | sha256sum -c - \
    && gpg --batch --dearmor -o /etc/apt/keyrings/docker.gpg /tmp/docker.asc \
    && rm /tmp/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && arch="$(dpkg --print-architecture)" \
    && { \
      echo "Types: deb"; \
      echo "URIs: https://download.docker.com/linux/ubuntu"; \
      echo "Suites: noble"; \
      echo "Components: stable"; \
      echo "Architectures: ${arch}"; \
      echo "Signed-By: /etc/apt/keyrings/docker.gpg"; \
      echo "Snapshot: no"; \
    } >/etc/apt/sources.list.d/docker.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      "docker-ce=${DOCKER_CE_VERSION}" \
      "docker-ce-cli=${DOCKER_CE_VERSION}" \
      "containerd.io=${CONTAINERD_VERSION}" \
      "docker-buildx-plugin=${DOCKER_BUILDX_VERSION}" \
      "docker-compose-plugin=${DOCKER_COMPOSE_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

COPY cvms/dev/user-sandbox/docker-daemon.json /etc/docker/daemon.json
COPY cvms/dev/user-sandbox/tool-versions.env /tmp/tool-versions.env
COPY cvms/dev/user-sandbox/codex-package ./tmp/codex-package
COPY --from=uv /uv /uvx /bin/

RUN set -a \
    && . /tmp/tool-versions.env \
    && set +a \
    && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" -o /tmp/node.tar.xz \
    && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
    && rm /tmp/node.tar.xz \
    && curl -fsSL "https://github.com/anthropics/claude-code/releases/download/v${CLAUDE_VERSION}/claude-linux-x64.tar.gz" -o /tmp/claude.tar.gz \
    && echo "${CLAUDE_SHA256}  /tmp/claude.tar.gz" | sha256sum -c - \
    && install -d /usr/local/lib/umbra \
    && tar -xzf /tmp/claude.tar.gz -C /usr/local/lib/umbra \
    && mv /usr/local/lib/umbra/claude /usr/local/lib/umbra/claude.real \
    && chmod 0755 /usr/local/lib/umbra/claude.real \
    && printf '%s\n' "${CLAUDE_VERSION}" >/usr/local/lib/umbra/claude.version \
    && chmod 0644 /usr/local/lib/umbra/claude.version \
    && rm /tmp/claude.tar.gz \
    && curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" -o /tmp/gh.tar.gz \
    && echo "${GH_SHA256}  /tmp/gh.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gh.tar.gz -C /tmp \
    && install -m 0755 "/tmp/gh_${GH_VERSION}_linux_amd64/bin/gh" /usr/local/bin/gh \
    && rm -rf /tmp/gh.tar.gz "/tmp/gh_${GH_VERSION}_linux_amd64" \
    && test "$(node -p "require('/tmp/codex-package/package-lock.json').packages['node_modules/@openai/codex'].version")" = "${CODEX_VERSION}" \
    && npm ci --prefix /tmp/codex-package --omit=dev --ignore-scripts --no-audit --no-fund \
    && install -d /usr/local/lib/umbra/codex \
    && mv /tmp/codex-package/node_modules /usr/local/lib/umbra/codex/node_modules \
    && rm -rf /tmp/codex-package \
    && rm /tmp/tool-versions.env

# OpenSSH rejects shadow entries that start with "!" before public-key auth.
# Keep password login impossible without leaving the account locked.
RUN groupadd --gid 1001 dev \
    && useradd --uid 1001 --gid 1001 --create-home --home-dir /home/dev --shell /bin/bash dev \
    && usermod --password '*' dev \
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
