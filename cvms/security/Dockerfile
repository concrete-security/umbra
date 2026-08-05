# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded AS uv

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:/home/security-cvm/.local/bin:${PATH}"

WORKDIR /app

RUN sed -i \
      -e 's|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20260713T000000Z|' \
      -e 's|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20260713T000000Z|' \
      /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --uid 10001 security-cvm
COPY --from=uv /uv /uvx /bin/

COPY pyproject.toml README.md uv.lock ./
RUN uv sync --frozen --no-dev --extra mitmproxy --no-install-project
COPY src ./src

RUN uv sync --frozen --no-dev --extra mitmproxy --no-editable

USER security-cvm

EXPOSE 8080 8081 8082

CMD ["umbra-security-mitmproxy"]
