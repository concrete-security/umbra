FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHALA_CLI_PATH=/usr/local/bin/phala

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv==0.7.8

COPY pyproject.toml README.md alembic.ini ./
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev --no-audit --no-fund \
    && ln -sf /app/node_modules/.bin/phala /usr/local/bin/phala \
    && ln -sf /app/node_modules/.bin/phala /usr/bin/phala
COPY alembic ./alembic
COPY src ./src
COPY tests ./tests
COPY entrypoint.sh /entrypoint.sh

RUN uv pip install --system --no-cache .

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "concrete_console.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
