# ghcr.io/astral-sh/uv:debian-slim
FROM ghcr.io/astral-sh/uv@sha256:2301babdaa11591889ea3933304912ba0814503fd89242819fdd8e7610d80c88

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml /app/
COPY uv.lock /app/
RUN uv sync --locked --no-cache && uv sync --group test --locked --no-cache

COPY entrypoint.sh /app/
COPY attestation_service.py /app/
RUN chmod +x /app/entrypoint.sh

# Expose port 8080
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD uv run python -c \
    'import requests; res = requests.get("http://localhost:8080/health"); exit(res.status_code != 200)'

ENTRYPOINT ["/app/entrypoint.sh"]
