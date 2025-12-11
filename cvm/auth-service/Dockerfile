# ghcr.io/astral-sh/uv:debian-slim
FROM ghcr.io/astral-sh/uv@sha256:2301babdaa11591889ea3933304912ba0814503fd89242819fdd8e7610d80c88

WORKDIR /app

COPY pyproject.toml uv.lock /app/
COPY src/ /app/src/

RUN uv sync --locked --no-cache

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD uv run python -c \
    'import urllib.request; res = urllib.request.urlopen("http://localhost:8081/health"); exit(0 if res.status == 200 else 1)'

CMD ["uv", "run", "python", "-m", "auth_service.main"]
