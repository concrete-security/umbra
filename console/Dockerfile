# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# ---- atlas verifier (Rust, out-of-process attestation verifier) ----
# Built from console/atlas-verify against the PUBLISHED atlas-rs crate — atlas stays
# untouched. Same Debian bookworm base as the runtime stage below, so the binary's
# glibc matches the Console container and it runs without ABI surprises. Rust pin must
# be recent enough for the dependency tree's edition2024 crates (e.g. indexmap >=2.14).
FROM ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded AS uv

FROM rust:1.96-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3 AS atlas-verify-builder
RUN sed -i \
      -e 's|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20260623T000000Z|' \
      -e 's|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20260623T000000Z|' \
      /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends cmake clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build/atlas-verify
COPY atlas-verify/Cargo.toml ./Cargo.toml
COPY atlas-verify/Cargo.lock ./Cargo.lock
COPY atlas-verify/src ./src
RUN cargo build --release --locked \
    && install -m 0755 target/release/umbra-atlas-verify /umbra-atlas-verify

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS console-base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHALA_CLI_PATH=/usr/local/bin/phala \
    PATH="/app/.venv/bin:${PATH}"

WORKDIR /app

RUN sed -i \
      -e 's|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20260713T000000Z|' \
      -e 's|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20260713T000000Z|' \
      /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*
COPY --from=uv /uv /uvx /bin/

# The dashboard source is reviewed in static/admin. Build its only generated
# asset from the npm lock in an isolated stage, then retain just the runtime
# Phala dependency. console/.dockerignore keeps the checked-in CSS out of this
# context, so the image cannot accidentally bake a stale opaque copy.
FROM console-base AS webapp-builder
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tailwind.config.js ./
COPY static ./static
RUN npm run build:webapp \
    && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM console-base
WORKDIR /app

COPY pyproject.toml README.md uv.lock alembic.ini ./
RUN uv sync --frozen --no-dev --no-install-project
COPY --from=webapp-builder /build/node_modules ./node_modules
RUN ln -sf /app/node_modules/.bin/phala /usr/local/bin/phala \
    && ln -sf /app/node_modules/.bin/phala /usr/bin/phala
COPY alembic ./alembic
COPY src ./src
COPY static ./static
COPY --from=webapp-builder /build/static/admin/tailwind.css ./static/admin/tailwind.css
COPY tests ./tests
COPY entrypoint.sh /entrypoint.sh

RUN uv sync --frozen --no-dev --no-editable

# Attestation verifier invoked by the Console via ATLAS_VERIFIER_CMD. Baked into the
# image (no host bind-mount) so it ships with the Console and its glibc matches.
COPY --from=atlas-verify-builder /umbra-atlas-verify /usr/local/bin/umbra-atlas-verify

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "umbra_console.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
