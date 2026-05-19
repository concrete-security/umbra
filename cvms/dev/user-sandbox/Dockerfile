FROM rust:1-bookworm AS atls-connect-builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY cli/Cargo.toml cli/Cargo.toml
COPY cvms/dev/user-sandbox/atls-connect/Cargo.toml cvms/dev/user-sandbox/atls-connect/Cargo.toml
COPY cvms/dev/user-sandbox/atls-connect/src cvms/dev/user-sandbox/atls-connect/src
RUN cargo build --locked --release -p concrete-atls-connect --target-dir /tmp/atls-connect-target

FROM ghcr.io/astral-sh/uv:0.7.8 AS uv

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
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
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && arch="$(dpkg --print-architecture)" \
    && echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" \
      >/etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      docker-ce \
      docker-ce-cli \
      containerd.io \
      docker-buildx-plugin \
      docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

COPY cvms/dev/user-sandbox/docker-daemon.json /etc/docker/daemon.json
COPY cvms/dev/user-sandbox/tool-versions.env /tmp/tool-versions.env
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
    && install -d /usr/local/lib/concrete \
    && tar -xzf /tmp/claude.tar.gz -C /usr/local/lib/concrete \
    && mv /usr/local/lib/concrete/claude /usr/local/lib/concrete/claude.real \
    && chmod 0755 /usr/local/lib/concrete/claude.real \
    && rm /tmp/claude.tar.gz \
    && curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" -o /tmp/gh.tar.gz \
    && echo "${GH_SHA256}  /tmp/gh.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gh.tar.gz -C /tmp \
    && install -m 0755 "/tmp/gh_${GH_VERSION}_linux_amd64/bin/gh" /usr/local/bin/gh \
    && rm -rf /tmp/gh.tar.gz "/tmp/gh_${GH_VERSION}_linux_amd64" \
    && NPM_CONFIG_IGNORE_SCRIPTS=true NPM_CONFIG_AUDIT=false \
      npm install -g "@openai/codex@${CODEX_VERSION}" --ignore-scripts \
    && rm -f /usr/local/bin/codex \
    && rm /tmp/tool-versions.env

RUN groupadd --gid 1001 dev \
    && useradd --uid 1001 --gid 1001 --create-home --home-dir /home/dev --shell /bin/bash dev \
    && usermod -aG sudo,docker dev \
    && echo 'dev ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/dev \
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
COPY cvms/dev/user-sandbox/concrete-env-profile.sh /etc/profile.d/concrete-env.sh
COPY cvms/dev/user-sandbox/concrete-update-agents.sh /usr/local/lib/concrete/concrete-update-agents.sh
COPY cvms/dev/user-sandbox/concrete-agent-claude.sh /usr/local/bin/claude
COPY cvms/dev/user-sandbox/concrete-agent-codex.sh /usr/local/bin/codex
COPY cvms/dev/user-sandbox/entrypoint.sh /entrypoint.sh
COPY cvms/dev/user-sandbox/concrete-dev-tunnel.py /usr/local/bin/concrete-dev-tunnel
COPY cvms/dev/user-sandbox/concrete-dev-egress-forwarder.py /usr/local/bin/concrete-dev-egress-forwarder
COPY --from=atls-connect-builder /tmp/atls-connect-target/release/concrete-atls-connect /usr/local/bin/concrete-atls-connect

RUN chmod +x \
      /entrypoint.sh \
      /usr/local/bin/concrete-dev-tunnel \
      /usr/local/bin/concrete-dev-egress-forwarder \
      /usr/local/bin/concrete-atls-connect \
      /usr/local/lib/concrete/concrete-update-agents.sh \
      /usr/local/bin/claude \
      /usr/local/bin/codex

EXPOSE 22

HEALTHCHECK --interval=500ms --timeout=2s --start-period=3s --retries=5 \
  CMD pgrep -x sshd >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
