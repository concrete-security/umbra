# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
# Anchor generated account metadata to the release source timestamp.
ARG SOURCE_DATE_EPOCH

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:/home/security-cvm/.local/bin:${PATH}"

WORKDIR /app

RUN sed -i \
      -e 's|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20261117T000000Z|' \
      -e 's|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20261117T000000Z|' \
      /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libffi-dev \
    && rm -rf \
        /var/lib/apt/lists/* \
        /var/log/apt/* \
        /var/log/alternatives.log \
        /var/log/dpkg.log \
        /var/cache/ldconfig/aux-cache

RUN useradd --system --create-home --uid 10001 security-cvm
COPY --from=uv /uv /uvx /bin/
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

# Install without uv's build-host bookkeeping, which is nondeterministic by
# construction: the global cache names archive buckets randomly, and installer
# metadata records the install wall-clock time and build-container inode numbers
# (`uv_cache.json`, hashed into `RECORD`). Runtime material — modules, entry
# points, `METADATA`/`RECORD` — is unaffected. The digest-pinned uv above fixes
# these flags; its build-environment lock files are litter, so each layer drops
# the ones it created rather than leaving a later layer to whiteout them.
COPY pyproject.toml README.md uv.lock ./
RUN uv sync --frozen --no-dev --extra mitmproxy --no-install-project \
      --no-cache --no-installer-metadata \
    && rm -rf /tmp/uv-*.lock
COPY src ./src

RUN uv sync --frozen --no-dev --extra mitmproxy --no-editable \
      --no-cache --no-installer-metadata \
    && rm -rf /tmp/uv-*.lock

USER security-cvm

EXPOSE 8080 8081 8082

CMD ["umbra-security-mitmproxy"]
