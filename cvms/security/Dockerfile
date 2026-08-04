FROM ghcr.io/astral-sh/uv:0.7.8@sha256:0178a92d156b6f6dbe60e3b52b33b421021f46d634aa9f81f42b91445bb81cdf AS uv

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:/home/security-cvm/.local/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
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
