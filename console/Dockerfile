# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# ---- atlas verifier (Rust, out-of-process attestation verifier) ----
# Built from console/atlas-verify against the PUBLISHED atlas-rs crate — atlas stays
# untouched. The runtime's newer Debian glibc remains compatible with this
# bookworm-built binary. Rust must be recent enough for the dependency tree's
# edition2024 crates (e.g. indexmap >=2.14).
FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS node

FROM rust:1.96-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3 AS atlas-verify-builder
RUN sed -i \
      -e 's|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20261023T000000Z|' \
      -e 's|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20261023T000000Z|' \
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

FROM python:3.12-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS console-base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHALA_CLI_PATH=/usr/local/bin/phala \
    PATH="/app/.venv/bin:${PATH}"

WORKDIR /app

RUN sed -i \
      -e 's|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20261023T000000Z|' \
      -e 's|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20261023T000000Z|' \
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
# pip's latest wheel fixes its CA store but still vendors urllib3 2.7.0.
# Rebuild only that vendor, preserving pip's three upstream compatibility patches.
# Use the same verified wheel for global pip and ensurepip-created environments.
RUN python3 - <<'PYBOOTSTRAP'
import base64
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import sys
from urllib.request import urlopen
import zipfile

def download(url, digest):
    data = urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError("bootstrap wheel checksum mismatch")
    return zipfile.ZipFile(io.BytesIO(data))

pip = download(
    "https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl",
    "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70",
)
urllib3 = download(
    "https://files.pythonhosted.org/packages/92/9d/c4e665119135114480843e7ab388fa94d8480650450e6f8e26b70d323a4c/urllib3-2.8.0-py3-none-any.whl",
    "0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3",
)
files = {name: pip.read(name) for name in pip.namelist() if not name.startswith("pip/_vendor/urllib3/")}
for name in urllib3.namelist():
    if name.startswith("urllib3/") and not name.endswith("/"):
        files["pip/_vendor/" + name] = urllib3.read(name)

def replace(path, old, new, count=1):
    source = files[path].decode()
    if source.count(old) != count:
        raise RuntimeError("unexpected vendored source: " + path)
    files[path] = source.replace(old, new).encode()

# Keep the same Brotli opt-out as pip's urllib3-disable-brotli.patch.
for path, start, end, replacement in (
    ("pip/_vendor/urllib3/response.py", "try:\n    try:\n        import brotlicffi", "\nfrom . import util", "brotli = None\n"),
    ("pip/_vendor/urllib3/util/request.py", "try:\n    try:\n        import brotlicffi", "\ntry:\n    if sys.version_info", ""),
):
    source = files[path].decode()
    if source.count(start) != 1 or source.count(end) != 1:
        raise RuntimeError("unexpected Brotli patch context: " + path)
    first = source.index(start)
    last = source.index(end, first)
    files[path] = (source[:first] + replacement + source[last:]).encode()
replace("pip/_vendor/urllib3/contrib/pyopenssl.py",
        "import urllib3.contrib.pyopenssl\n        urllib3.contrib.pyopenssl.inject_into_urllib3()",
        "import urllib3.contrib.pyopenssl as pyopenssl\n        pyopenssl.inject_into_urllib3()")
replace("pip/_vendor/urllib3/contrib/emscripten/__init__.py",
        "import urllib3.connection\n", "import urllib3.connection as urllib3_connection\n")
replace("pip/_vendor/urllib3/contrib/emscripten/__init__.py",
        "    urllib3.connection.", "    urllib3_connection.", count=3)
for name in list(files):
    if name.startswith("pip/_vendor/urllib3/") and name.endswith(".py"):
        source = files[name].decode()
        source = re.sub(r"(?m)^(\s*)import (urllib3|idna)$", r"\1from pip._vendor import \2", source)
        source = source.replace("import urllib3.", "import pip._vendor.urllib3.")
        if re.search(r"(?m)^\s*(from|import) (urllib3|idna)\b", source):
            raise RuntimeError("unrewritten vendor import: " + name)
        files[name] = source.encode()

license_bytes = urllib3.read("urllib3-2.8.0.dist-info/licenses/LICENSE.txt")
files["pip/_vendor/urllib3/LICENSE.txt"] = license_bytes
files["pip-26.2.2.dist-info/licenses/src/pip/_vendor/urllib3/LICENSE.txt"] = license_bytes
replace("pip/_vendor/vendor.txt", "urllib3==2.7.0", "urllib3==2.8.0")
bom_path = "pip/_vendor/bom.cdx.json"
bom = json.loads(files[bom_path])
components = [item for item in bom["components"] if item["name"] == "urllib3"]
if len(components) != 1 or components[0]["version"] != "2.7.0":
    raise RuntimeError("unexpected pip urllib3 SBOM")
components[0]["version"] = "2.8.0"
# Replace the component identity and every dependency reference; retain all others.
bom_text = json.dumps(bom, indent=2, sort_keys=True)
if bom_text.count("pkg:pypi/urllib3@2.7.0") != 4:
    raise RuntimeError("unexpected pip urllib3 SBOM references")
files[bom_path] = (bom_text.replace("pkg:pypi/urllib3@2.7.0", "pkg:pypi/urllib3@2.8.0") + "\n").encode()

record_path = "pip-26.2.2.dist-info/RECORD"
record = io.StringIO(newline="")
writer = csv.writer(record, lineterminator="\n")
for name in sorted(files):
    if name != record_path:
        digest = base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b"=").decode()
        writer.writerow((name, "sha256=" + digest, len(files[name])))
writer.writerow((record_path, "", ""))
files[record_path] = record.getvalue().encode()
wheel_name = "pip-26.2.2-py3-none-any.whl"
wheel_path = Path("/tmp") / wheel_name
with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
    for name in sorted(files):
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.create_system = 3
        info.external_attr = 0o100644 << 16
        output.writestr(info, files[name])
# Check RECORD against the actual rebuilt archive before installation.
with zipfile.ZipFile(wheel_path) as output:
    rows = list(csv.reader(io.StringIO(output.read(record_path).decode())))
    if {row[0] for row in rows} != set(output.namelist()):
        raise RuntimeError("rebuilt pip RECORD file list mismatch")
    for name, digest, size in rows:
        if name != record_path:
            data = output.read(name)
            actual = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            if digest != "sha256=" + actual or size != str(len(data)):
                raise RuntimeError("rebuilt pip RECORD checksum mismatch")
sys.path.insert(0, str(wheel_path))
from pip._vendor import urllib3 as patched_urllib3
if patched_urllib3.__version__ != "2.8.0" or str(wheel_path) not in patched_urllib3.__file__:
    raise RuntimeError("rebuilt pip did not load patched urllib3")
if importlib.util.find_spec("ensurepip") is not None:
    import ensurepip
    module = Path(ensurepip.__file__)
    source = module.read_text()
    if source.count('_PIP_VERSION = "25.0.1"') != 1:
        raise RuntimeError("unexpected Python ensurepip version")
    for old in module.with_name("_bundled").glob("pip-*.whl"):
        old.unlink()
    shutil.copyfile(wheel_path, module.with_name("_bundled") / wheel_name)
    module.write_text(source.replace('_PIP_VERSION = "25.0.1"', '_PIP_VERSION = "26.2.2"'))
    shutil.rmtree(module.with_name("__pycache__"), ignore_errors=True)
digest = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
Path("/tmp/umbra-pip-requirements.txt").write_text(
    "pip @ file://" + str(wheel_path) + " --hash=sha256:" + digest + "\n"
)
PYBOOTSTRAP
RUN uv pip install --python "$(command -v python3)" --system --no-deps --no-cache --no-installer-metadata --require-hashes -r /tmp/umbra-pip-requirements.txt \
    && rm -f /tmp/pip-26.2.2-py3-none-any.whl /tmp/umbra-pip-requirements.txt \
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
