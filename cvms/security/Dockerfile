FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/security-cvm/.local/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --uid 10001 security-cvm
RUN pip install --no-cache-dir uv==0.7.8

COPY pyproject.toml README.md uv.lock ./
COPY src ./src

RUN uv pip install --system --no-cache ".[mitmproxy]"

USER security-cvm

EXPOSE 8080 8081

CMD ["concrete-security-mitmproxy"]
