# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# ---- atlas verifier (Rust, out-of-process attestation verifier) ----
# Built from console/atlas-verify against the PUBLISHED atlas-rs crate — atlas stays
# untouched. The runtime's newer Debian glibc remains compatible with this
# bookworm-built binary. Rust must be recent enough for the dependency tree's
# edition2024 crates (e.g. indexmap >=2.14).
FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

FROM node:22.23.5-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS node

FROM rust:1.96-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3 AS atlas-verify-builder
RUN sed -i \
      -e 's|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20261117T000000Z|' \
      -e 's|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20261117T000000Z|' \
      /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates cmake clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build/atlas-verify
COPY atlas-verify/Cargo.toml ./Cargo.toml
COPY atlas-verify/Cargo.lock ./Cargo.lock
COPY atlas-verify/src ./src
RUN cargo build --release --locked \
    && install -m 0755 target/release/umbra-atlas-verify /umbra-atlas-verify

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS console-base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHALA_CLI_PATH=/usr/local/bin/phala \
    PATH="/app/.venv/bin:${PATH}"

WORKDIR /app

RUN sed -i \
      -e 's|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20261117T000000Z|' \
      -e 's|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20261117T000000Z|' \
      /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf \
        /var/lib/apt/lists/* \
        /var/log/apt/* \
        /var/log/alternatives.log \
        /var/log/dpkg.log \
        /var/cache/ldconfig/aux-cache
COPY --from=uv /uv /uvx /bin/
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/LICENSE /usr/local/share/doc/node/LICENSE
# Use the same hash-verified upstream wheel for pip and ensurepip.
RUN python3 - <<'PYBOOTSTRAP'
import hashlib
import importlib.util
from pathlib import Path
import shutil
from urllib.request import urlopen

wheel_name = "pip-26.3-py3-none-any.whl"
sha256 = "f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13"
wheel_path = Path("/tmp") / wheel_name
url = (
    "https://files.pythonhosted.org/packages/07/25/"
    "ee8c38ae72d66b844ce8eb9711ba905dba21ca1a8a0c960057c41cd23337/" + wheel_name
)
with urlopen(url, timeout=60) as response:
    wheel = response.read()
if hashlib.sha256(wheel).hexdigest() != sha256:
    raise RuntimeError("pip bootstrap wheel checksum mismatch")
wheel_path.write_bytes(wheel)
if importlib.util.find_spec("ensurepip") is not None:
    import ensurepip
    module = Path(ensurepip.__file__)
    source = module.read_text()
    old_version = '_PIP_VERSION = "25.0.1"'
    if source.count(old_version) != 1:
        raise RuntimeError("unexpected Python ensurepip version")
    for old in module.with_name("_bundled").glob("pip-*.whl"):
        old.unlink()
    shutil.copyfile(wheel_path, module.with_name("_bundled") / wheel_name)
    module.write_text(source.replace(old_version, '_PIP_VERSION = "26.3"'))
    shutil.rmtree(module.with_name("__pycache__"), ignore_errors=True)
Path("/tmp/umbra-pip-requirements.txt").write_text(
    f"pip @ file://{wheel_path} --hash=sha256:{sha256}\n"
)
PYBOOTSTRAP
RUN uv pip install --python "$(command -v python3)" --system --no-deps --no-cache --no-installer-metadata --require-hashes -r /tmp/umbra-pip-requirements.txt \
    && rm -f /tmp/pip-26.3-py3-none-any.whl /tmp/umbra-pip-requirements.txt \
    && rm -rf /tmp/uv-*.lock

# The dashboard source is reviewed in static/admin. Build its only generated
# asset from the npm lock in an isolated stage, then retain just the runtime
# Phala dependency. console/.dockerignore keeps the checked-in CSS out of this
# context, so the image cannot accidentally bake a stale opaque copy.
FROM console-base AS webapp-builder
WORKDIR /build
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tailwind.config.js ./
COPY static ./static
RUN npm run build:webapp \
    && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM console-base
# Anchor generated account metadata to the release source timestamp.
ARG SOURCE_DATE_EPOCH
WORKDIR /app

# Install without uv's build-host bookkeeping, which is nondeterministic by
# construction: the global cache names archive buckets randomly, and installer
# metadata records the install wall-clock time and build-container inode numbers
# (`uv_cache.json`, hashed into `RECORD`). Runtime material — modules, entry
# points, `METADATA`/`RECORD` — is unaffected. The digest-pinned uv above fixes
# these flags; its build-environment lock files are litter, so each layer drops
# the ones it created rather than leaving a later layer to whiteout them.
COPY pyproject.toml README.md uv.lock alembic.ini ./
RUN uv sync --frozen --no-dev --no-install-project \
      --no-cache --no-installer-metadata \
    && rm -rf /tmp/uv-*.lock
COPY --from=webapp-builder /build/node_modules ./node_modules
RUN ln -sf /app/node_modules/.bin/phala /usr/local/bin/phala \
    && ln -sf /app/node_modules/.bin/phala /usr/bin/phala
COPY alembic ./alembic
COPY src ./src
COPY static ./static
COPY --from=webapp-builder /build/static/admin/tailwind.css ./static/admin/tailwind.css
COPY tests ./tests
# Exercise the provider boundary with this image's exact Node and locked packages.
RUN node --test tests/test_phala_zod.mjs
COPY entrypoint.sh /entrypoint.sh

RUN uv sync --frozen --no-dev --no-editable \
      --no-cache --no-installer-metadata \
    && rm -rf /tmp/uv-*.lock

# Attestation verifier invoked by the Console via ATLAS_VERIFIER_CMD. Baked into the
# image (no host bind-mount) so it ships with the Console and its glibc matches.
COPY --from=atlas-verify-builder /umbra-atlas-verify /usr/local/bin/umbra-atlas-verify

EXPOSE 8000

RUN groupadd --gid 10001 console \
    && useradd --uid 10001 --gid console --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin console \
    && chmod -R u=rwX,go=rX /app \
    && chmod 0755 /entrypoint.sh

USER 10001:10001

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "umbra_console.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
