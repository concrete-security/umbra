# ghcr.io/astral-sh/uv:debian-slim
FROM ghcr.io/astral-sh/uv@sha256:2301babdaa11591889ea3933304912ba0814503fd89242819fdd8e7610d80c88

WORKDIR /vllm_proxy

COPY entrypoint.sh app/entrypoint.sh
COPY proxy_app.py utils.py data/tee_info.txt prompts/ README.md ./
COPY pyproject.toml uv.lock ./

RUN chmod +x app/entrypoint.sh
RUN uv sync --locked --no-cache
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

HEALTHCHECK --interval=10s --timeout=5s --retries=6 --start-period=10s \
  CMD curl -f http://localhost:7000/health || exit 1

ENTRYPOINT ["app/entrypoint.sh"]
