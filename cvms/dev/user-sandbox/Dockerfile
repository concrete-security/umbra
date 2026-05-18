FROM rust:1-bookworm AS atls-connect-builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY cli/Cargo.toml cli/Cargo.toml
COPY cvms/dev/user-sandbox/atls-connect/Cargo.toml cvms/dev/user-sandbox/atls-connect/Cargo.toml
COPY cvms/dev/user-sandbox/atls-connect/src cvms/dev/user-sandbox/atls-connect/src
RUN cargo build --locked --release -p concrete-atls-connect --target-dir /tmp/atls-connect-target

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

RUN echo 'dev:100000:65536' >/etc/subuid \
    && echo 'dev:100000:65536' >/etc/subgid \
    && useradd -u 0 -o -m -d /home/dev -s /bin/bash dev \
    && passwd -d dev \
    && mkdir -p \
      /home/dev/.local/bin \
      /home/dev/.cache \
      /home/dev/.npm \
      /home/dev/.claude \
      /home/dev/.codex \
    && chown -R dev:dev /home/dev

COPY cvms/dev/user-sandbox/sshd_config /etc/ssh/sshd_config
COPY cvms/dev/user-sandbox/concrete-update-agents.sh /etc/profile.d/concrete-update-agents.sh
COPY cvms/dev/user-sandbox/entrypoint.sh /entrypoint.sh
COPY cvms/dev/user-sandbox/concrete-dev-tunnel.py /usr/local/bin/concrete-dev-tunnel
COPY cvms/dev/user-sandbox/concrete-dev-egress-forwarder.py /usr/local/bin/concrete-dev-egress-forwarder
COPY --from=atls-connect-builder /tmp/atls-connect-target/release/concrete-atls-connect /usr/local/bin/concrete-atls-connect

RUN chmod +x /entrypoint.sh /usr/local/bin/concrete-dev-tunnel /usr/local/bin/concrete-dev-egress-forwarder /usr/local/bin/concrete-atls-connect

EXPOSE 22

HEALTHCHECK --interval=500ms --timeout=2s --start-period=3s --retries=5 \
  CMD pgrep -x sshd >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
