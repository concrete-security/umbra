# ---- atlas verifier (Rust, out-of-process attestation verifier) ----
# Built from console/atlas-verify against the PUBLISHED atlas-rs crate — atlas stays
# untouched. Same Debian bookworm base as the runtime stage below, so the binary's
# glibc matches the Console container and it runs without ABI surprises. Rust pin must
# be recent enough for the dependency tree's edition2024 crates (e.g. indexmap >=2.14).
FROM rust:1.96-slim-bookworm AS atlas-verify-builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build/atlas-verify
COPY atlas-verify/Cargo.toml ./Cargo.toml
COPY atlas-verify/Cargo.lock ./Cargo.lock
COPY atlas-verify/src ./src
RUN cargo build --release --locked \
    && install -m 0755 target/release/concrete-atlas-verify /concrete-atlas-verify

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
COPY static ./static
COPY tests ./tests
COPY entrypoint.sh /entrypoint.sh

RUN uv pip install --system --no-cache .

# Attestation verifier invoked by the Console via ATLAS_VERIFIER_CMD. Baked into the
# image (no host bind-mount) so it ships with the Console and its glibc matches.
COPY --from=atlas-verify-builder /concrete-atlas-verify /usr/local/bin/concrete-atlas-verify

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "concrete_console.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
