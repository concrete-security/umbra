FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir uv==0.7.8

COPY pyproject.toml README.md alembic.ini ./
COPY alembic ./alembic
COPY src ./src
COPY tests ./tests

RUN uv pip install --system --no-cache .

EXPOSE 8000

CMD ["uvicorn", "concrete_console.app:app", "--host", "0.0.0.0", "--port", "8000"]
