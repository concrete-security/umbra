from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any

from umbra_console.config import load_settings
from umbra_console.tee_provider import (
    INSTANCE_TYPE_NAME_RE,
    MAX_INSTANCE_TYPE_ENTRIES,
    MAX_INSTANCE_TYPES_RESPONSE_BYTES,
    PROVIDER_ERROR_INSTANCE_TYPES_SCHEMA_DRIFT,
    PROVIDER_ERROR_NOT_CONFIGURED,
    instance_type_hourly_rate,
    instance_type_memory_gb,
    instance_type_vcpu,
)
from umbra_console.readiness import DEFAULT_PHALA_CLI_PATH

APP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MANAGED_CVM_NAME_RE = re.compile(r"^umbra-v0-(?:cvm|sc)-[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
DNS_HOST_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
INSTANCE_TYPE_CURRENCY = "USD"
# Authoring-time snapshot of `phala instance-types` in the adapter's normalized
# shape. Seeds the Console catalog on a virgin database until the first live
# fetch; provider-specific data stays behind the adapter boundary.
BOOTSTRAP_INSTANCE_TYPES: tuple[dict[str, Any], ...] = (
    {"name": "tdx.small", "family": "cpu", "vcpu": 1, "memory_gb": 2, "hourly_rate": 0.058, "currency": "USD"},
    {"name": "tdx.medium", "family": "cpu", "vcpu": 2, "memory_gb": 4, "hourly_rate": 0.116, "currency": "USD"},
    {"name": "tdx.large", "family": "cpu", "vcpu": 4, "memory_gb": 8, "hourly_rate": 0.232, "currency": "USD"},
    {"name": "tdx.xlarge", "family": "cpu", "vcpu": 8, "memory_gb": 16, "hourly_rate": 0.464, "currency": "USD"},
    {"name": "tdx.2xlarge", "family": "cpu", "vcpu": 16, "memory_gb": 32, "hourly_rate": 0.928, "currency": "USD"},
    {"name": "tdx.4xlarge", "family": "cpu", "vcpu": 32, "memory_gb": 64, "hourly_rate": 1.856, "currency": "USD"},
    {"name": "tdx.8xlarge", "family": "cpu", "vcpu": 64, "memory_gb": 128, "hourly_rate": 3.712, "currency": "USD"},
    {"name": "h200.small", "family": "gpu", "vcpu": 24, "memory_gb": 192, "hourly_rate": 4.8, "currency": "USD"},
    {"name": "h200.16xlarge", "family": "gpu", "vcpu": 64, "memory_gb": 256, "hourly_rate": 32.0, "currency": "USD"},
    {"name": "h200.8x.large", "family": "gpu", "vcpu": 192, "memory_gb": 1536, "hourly_rate": 32.0, "currency": "USD"},
)
VM_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
SENSITIVE_OUTPUT_KEY_RE = re.compile(
    r"(authorization|bearer|token|secret|password|private_key|device_code|polling_secret|id_token|access_token|api_key)",
    re.IGNORECASE,
)
SENSITIVE_OUTPUT_ENV_ASSIGNMENT_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:AUTHORIZATION|BEARER|TOKEN|SECRET|PASSWORD|PRIVATE_KEY|DEVICE_CODE|POLLING_SECRET|ID_TOKEN|ACCESS_TOKEN|API_KEY)[A-Za-z0-9_]*)=([^\s]+)",
    re.IGNORECASE,
)
SENSITIVE_OUTPUT_JSON_FIELD_RE = re.compile(
    r'("?[A-Za-z_][A-Za-z0-9_]*(?:AUTHORIZATION|BEARER|TOKEN|SECRET|PASSWORD|PRIVATE_KEY|DEVICE_CODE|POLLING_SECRET|ID_TOKEN|ACCESS_TOKEN|API_KEY)[A-Za-z0-9_]*"?\s*:\s*)"([^"]*)"',
    re.IGNORECASE,
)
PHALA_STATUS_MAP = {
    "running": "RUNNING",
    "active": "RUNNING",
    "healthy": "RUNNING",
    "starting": "PENDING",
    "creating": "PENDING",
    "provisioning": "PENDING",
    "booting": "PENDING",
    "initializing": "PENDING",
    "pulling": "PENDING",
    "updating": "PENDING",
    "stopped": "STOPPED",
    "stopping": "STOPPED",
    "paused": "STOPPED",
    "exited": "STOPPED",
    "failed": "FAILED",
    "error": "FAILED",
    "errored": "FAILED",
    "crashed": "FAILED",
    "terminated": "TERMINATED",
    "deleted": "TERMINATED",
    "removed": "TERMINATED",
}
SUBPROCESS_ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL")
PHALA_COMPOSE_FILE_HASH_HELPER = r"""
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

async function importPhalaCloud() {
  try {
    return await import("@phala/cloud");
  } catch (_error) {
    const moduleDir = process.env.PHALA_NODE_MODULES_DIR || "/app/node_modules";
    return await import(`${pathToFileURL(moduleDir).href}/@phala/cloud/dist/index.mjs`);
  }
}

function cleanAppId(value) {
  return String(value || "").replace(/^app_/, "").replace(/^0x/, "").toLowerCase();
}

async function main() {
  const [rawAppId] = process.argv.slice(1);
  if (!rawAppId) {
    throw new Error("usage: <app-id>");
  }

  const appId = cleanAppId(rawAppId);
  const { createClient, getCvmComposeFile } = await importPhalaCloud();
  const client = createClient({ apiKey: process.env.PHALA_CLOUD_API_KEY });
  const appCompose = await getCvmComposeFile(client, { app_id: appId }, { schema: false });
  const composeYaml = appCompose && typeof appCompose.docker_compose_file === "string" ? appCompose.docker_compose_file : "";
  if (!composeYaml) {
    throw new Error("provider did not return docker_compose_file");
  }
  console.log(JSON.stringify({
    sha256: createHash("sha256").update(composeYaml, "utf8").digest("hex"),
  }));
}

main().catch((error) => {
  console.error(JSON.stringify({
    error: {
      name: error && error.name ? error.name : "Error",
      message: error && error.message ? error.message : String(error),
      status: error && error.status ? error.status : undefined,
      code: error && error.code ? error.code : undefined,
    },
  }));
  process.exit(1);
});
"""


class PhalaError(RuntimeError):
    def __init__(self, code: str, *, output: str = "", field: str | None = None):
        super().__init__(code)
        self.code = code
        self.output = output
        self.field = field


class PhalaNotFound(PhalaError):
    def __init__(self, *, output: str = ""):
        super().__init__("not_found", output=output)


@dataclass(frozen=True)
class PhalaDeployResult:
    app_id: str
    gateway_host: str
    status: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class PhalaClient:
    cli_path: str
    api_token: str
    node_path: str = "node"
    redaction_patterns: tuple[re.Pattern[str], ...] = ()
    timeout_seconds: float = 300.0

    @classmethod
    def from_settings(cls, *, timeout_seconds: float | None = None) -> PhalaClient:
        raw = load_settings().raw
        api_token = raw.get("PHALA_API_TOKEN", "").strip()
        if not api_token:
            raise PhalaError(PROVIDER_ERROR_NOT_CONFIGURED)
        patterns = compile_redaction_patterns(raw.get("PHALA_OUTPUT_REDACTION_PATTERNS", ""))
        return cls(
            cli_path=raw.get("PHALA_CLI_PATH", DEFAULT_PHALA_CLI_PATH).strip() or DEFAULT_PHALA_CLI_PATH,
            api_token=api_token,
            node_path=raw.get("PHALA_NODE_PATH", "node").strip() or "node",
            redaction_patterns=patterns,
            timeout_seconds=300.0 if timeout_seconds is None else timeout_seconds,
        )

    async def deploy(
        self,
        *,
        name: str,
        compose_yaml: str,
        env: dict[str, str],
        instance_type: str | None = None,
        region: str | None = None,
        disk_size_gb: int | None = None,
    ) -> PhalaDeployResult:
        validate_managed_cvm_name(name)
        async with staged_compose_and_env(compose_yaml=compose_yaml, env=env) as staged:
            args = [
                "deploy",
                "--name",
                name,
                "--compose",
                str(staged.compose_path),
                "-e",
                str(staged.env_path),
                "--no-dev-os",
            ]
            append_optional_arg(args, "--instance-type", instance_type)
            append_optional_arg(args, "--region", region)
            # `phala deploy --disk-size` expects a size *with unit* (e.g. "50G");
            # a bare integer is not accepted. Omitting it uses Phala's own 40GB
            # default (matching DEV_CVM_DEFAULT_DISK_GB).
            if disk_size_gb:
                append_optional_arg(args, "--disk-size", f"{disk_size_gb}G")
            args.extend(["--wait", "--json"])
            stdout = await self._run_text(args)
        return await self._deploy_result_from_stdout(stdout, fallback_lookup=name)

    async def update(self, *, app_id: str, compose_yaml: str, env: dict[str, str]) -> PhalaDeployResult:
        validate_app_id(app_id)
        info = await self.info(app_id)
        update_identifier = update_identifier_from_info(info.raw) or app_id
        async with staged_compose_and_env(compose_yaml=compose_yaml, env=env) as staged:
            stdout = await self._run_text(
                [
                    "deploy",
                    "--cvm-id",
                    update_identifier,
                    "--compose",
                    str(staged.compose_path),
                    "-e",
                    str(staged.env_path),
                    "--no-dev-os",
                    "--json",
                ]
            )
        return await self._deploy_result_from_stdout(stdout, fallback_lookup=app_id)

    async def compose_file_sha256(self, app_id: str) -> str:
        validate_app_id(app_id)
        stdout = await self._run_node_text(
            [
                "--input-type=module",
                "-e",
                PHALA_COMPOSE_FILE_HASH_HELPER,
                app_id,
            ]
        )
        payload = json_object_from_text(stdout)
        digest = payload.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PhalaError("invalid_response", output=scrub_output(stdout, self.api_token, self.redaction_patterns))
        return digest

    async def info(self, app_id: str) -> PhalaDeployResult:
        validate_app_id(app_id)
        payload = await self._run_json(["cvms", "get", app_id, "--json"])
        return deploy_result_from_payload(payload)

    async def status(self, app_id: str) -> str:
        return (await self.info(app_id)).status

    async def logs(self, app_id: str) -> str:
        validate_app_id(app_id)
        return await self._run_text(["cvms", "logs", app_id])

    async def start(self, app_id: str) -> None:
        validate_app_id(app_id)
        await self._run_text(["cvms", "start", app_id])

    async def stop(self, app_id: str) -> None:
        validate_app_id(app_id)
        await self._run_text(["cvms", "stop", app_id])

    async def delete(self, app_id: str) -> None:
        validate_app_id(app_id)
        try:
            await self._run_text(["cvms", "delete", app_id, "--force"])
        except PhalaNotFound:
            return

    async def list(self) -> list[dict[str, Any]]:
        payload = await self._run_json(["cvms", "list", "--json"])
        rows = payload if isinstance(payload, list) else payload.get("cvms", [])
        if not isinstance(rows, list):
            raise PhalaError("invalid_response", field="cvms")
        return [row for row in rows if isinstance(row, dict) and managed_cvm_name(row)]

    async def list_instance_types(self) -> list[dict[str, Any]]:
        # Bound the decoded size: a real catalog is a few KB, so the generous cap
        # only trips on a hostile/broken response and stops it before json.loads
        # allocates a huge tree. (The subprocess stdout buffer itself is bounded by
        # the fetch timeout; a fully streaming read is a separate hardening.)
        payload = await self._run_json(["instance-types", "--json"], max_bytes=MAX_INSTANCE_TYPES_RESPONSE_BYTES)
        return instance_types_from_payload(payload)

    async def _deploy_result_from_stdout(self, stdout: str, *, fallback_lookup: str) -> PhalaDeployResult:
        if stdout.strip():
            try:
                payload = json_object_from_text(stdout)
            except json.JSONDecodeError as exc:
                raise PhalaError(
                    "invalid_json",
                    output=scrub_output(stdout, self.api_token, self.redaction_patterns),
                ) from exc
            if payload.get("success") is False:
                raise PhalaError("cli_failed", output=scrub_output(stdout, self.api_token, self.redaction_patterns))
            try:
                return deploy_result_from_payload(payload)
            except PhalaError as exc:
                if exc.code == "invalid_response":
                    lookup = first_string(payload, ("app_id", "appId", "id"), ("app", "cvm"), required=False)
                    if lookup:
                        return await self.info(lookup)
                raise
        return await self.info(fallback_lookup)

    async def _run_json(self, args: list[str], *, max_bytes: int | None = None) -> Any:
        stdout = await self._run_text(args)
        if max_bytes is not None and len(stdout) > max_bytes:
            raise PhalaError("invalid_json", output=f"response exceeded {max_bytes} bytes")
        try:
            return json.loads(stdout or "{}")
        # RecursionError: a hostile deeply-nested payload must degrade like any
        # other unparseable output, not escape as an unhandled exception.
        except (json.JSONDecodeError, RecursionError) as exc:
            raise PhalaError("invalid_json", output=scrub_output(stdout, self.api_token, self.redaction_patterns)) from exc

    async def _run_text(self, args: list[str]) -> str:
        return await self._run_command_text(self.cli_path, args)

    async def _run_node_text(self, args: list[str]) -> str:
        return await self._run_command_text(self.node_path, args)

    async def _run_command_text(self, command: str, args: list[str]) -> str:
        try:
            process = await asyncio.create_subprocess_exec(
                command,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=phala_subprocess_env(self.api_token),
            )
        except OSError as exc:
            # A missing/broken CLI binary must surface as a provider failure
            # (callers catch PhalaError/CvmProviderError), not an unhandled 500.
            raise PhalaError("cli_failed", output=str(exc)) from exc
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=self.timeout_seconds)
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.wait()
            raise PhalaError("cli_timeout") from exc
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        output = scrub_output("\n".join(part for part in (stdout, stderr) if part), self.api_token, self.redaction_patterns)
        if process.returncode != 0:
            if "not found" in output.lower():
                raise PhalaNotFound(output=output)
            raise PhalaError("cli_failed", output=output)
        return stdout


@dataclass(frozen=True)
class StagedFiles:
    directory: Path
    compose_path: Path
    env_path: Path


class staged_compose_and_env:
    def __init__(self, *, compose_yaml: str, env: dict[str, str]):
        self.compose_yaml = compose_yaml
        self.env = env
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.files: StagedFiles | None = None

    async def __aenter__(self) -> StagedFiles:
        root = staging_root()
        self._tmpdir = tempfile.TemporaryDirectory(prefix="umbra-phala-", dir=str(root))
        directory = Path(self._tmpdir.name)
        compose_path = directory / "docker-compose.yml"
        env_path = directory / "deploy.env"
        write_secret_file(compose_path, self.compose_yaml.encode("utf-8"))
        write_secret_file(env_path, render_env_file(self.env).encode("utf-8"))
        self.files = StagedFiles(directory=directory, compose_path=compose_path, env_path=env_path)
        return self.files

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.files is not None:
            secure_delete(self.files.compose_path)
            secure_delete(self.files.env_path)
        if self._tmpdir is not None:
            self._tmpdir.cleanup()


def deploy_result_from_payload(payload: Any) -> PhalaDeployResult:
    if not isinstance(payload, dict):
        raise PhalaError("invalid_response")
    app_id = first_string(payload, ("app_id", "appId", "id"), ("app", "cvm"))
    gateway_host = gateway_host_from_payload(payload)
    validate_app_id(app_id)
    validate_gateway_host(gateway_host)
    raw_status = first_string(payload, ("status", "state"), ("app", "cvm"), required=False) or ""
    return PhalaDeployResult(
        app_id=app_id,
        gateway_host=gateway_host,
        status=normalize_status(raw_status),
        raw=payload,
    )


def instance_types_from_payload(payload: Any) -> list[dict[str, Any]]:
    """Tolerant parse of `phala instance-types --json`.

    Only `result[].items[].id` is load-bearing: an unusable envelope or zero
    parseable items raises `instance_types_schema_drift` (with `field` naming
    the broken layer). Descriptive fields degrade to None when absent or
    renamed; unknown fields are ignored.
    """
    if not isinstance(payload, dict):
        raise PhalaError(PROVIDER_ERROR_INSTANCE_TYPES_SCHEMA_DRIFT, field="envelope")
    if payload.get("success") is False:
        raise PhalaError("cli_failed")
    families = payload.get("result")
    if not isinstance(families, list):
        raise PhalaError(PROVIDER_ERROR_INSTANCE_TYPES_SCHEMA_DRIFT, field="result")

    seen: set[str] = set()
    parsed: list[dict[str, Any]] = []
    for family in families:
        for entry in parse_instance_type_family(family):
            if entry["name"] in seen:
                continue
            seen.add(entry["name"])
            parsed.append(entry)
            if len(parsed) >= MAX_INSTANCE_TYPE_ENTRIES:
                return parsed
    if not parsed:
        raise PhalaError(PROVIDER_ERROR_INSTANCE_TYPES_SCHEMA_DRIFT, field="items")
    return parsed


def parse_instance_type_family(family: Any) -> Iterator[dict[str, Any]]:
    """One `result[]` entry -> its parseable items, in provider order. A generator
    so the caller can bail at the entry cap without materializing a whole (possibly
    hostile) family's item list."""
    if not isinstance(family, dict) or not isinstance(family.get("items"), list):
        return
    family_name = family.get("name") if isinstance(family.get("name"), str) else None
    for item in family["items"]:
        entry = parse_instance_type_item(item, family_name)
        if entry is not None:
            yield entry


def parse_instance_type_item(item: Any, family_name: str | None) -> dict[str, Any] | None:
    """One `items[]` entry -> normalized dict, or None if the load-bearing `id` is unusable."""
    if not isinstance(item, dict):
        return None
    name = item.get("id")
    if not isinstance(name, str) or not INSTANCE_TYPE_NAME_RE.fullmatch(name):
        return None
    hourly_rate = instance_type_hourly_rate(item.get("hourly_rate"))
    return {
        "name": name,
        "family": item.get("family") if isinstance(item.get("family"), str) else family_name,
        "vcpu": instance_type_vcpu(item.get("vcpu")),
        "memory_gb": normalize_memory_gb(item.get("memory_mb")),
        "hourly_rate": hourly_rate,
        "currency": INSTANCE_TYPE_CURRENCY if hourly_rate is not None else None,
    }


def normalize_memory_gb(memory_mb: Any) -> int | float | None:
    """Provider-specific: Phala reports memory in MB, so convert to GB (rounded to 2
    decimals for display) and hand the result to the shared GB contract validator.
    Distinct from `instance_type_memory_gb`, which validates an already-GB value (the
    canonical stored form, re-checked on DB reload) -- one converts, one validates."""
    if isinstance(memory_mb, bool) or not isinstance(memory_mb, (int, float)):
        return None
    return instance_type_memory_gb(round(memory_mb / 1024, 2))


def json_object_from_text(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            payload, _end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise json.JSONDecodeError("no JSON object found", text, 0)


def first_string(
    payload: dict[str, Any],
    keys: tuple[str, ...],
    nested_keys: tuple[str, ...],
    *,
    required: bool = True,
) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    for nested_key in nested_keys:
        nested = payload.get(nested_key)
        if not isinstance(nested, dict):
            continue
        for key in keys:
            value = nested.get(key)
            if isinstance(value, str) and value:
                return value
    if required:
        raise PhalaError("invalid_response", field=keys[0])
    return ""


def gateway_host_from_payload(payload: dict[str, Any]) -> str:
    gateway_host = first_string(payload, ("gateway_host", "gatewayHost"), ("app", "cvm"), required=False)
    if gateway_host:
        return normalize_gateway_host(gateway_host)

    value = payload.get("gateway")
    if isinstance(value, str) and value:
        return normalize_gateway_host(value)
    if isinstance(value, dict):
        for key in ("base_domain", "baseDomain", "default_gateway_domain", "defaultGatewayDomain", "cname"):
            nested = value.get(key)
            if isinstance(nested, str) and nested:
                return normalize_gateway_host(nested)

    for nested_key in ("app", "cvm"):
        nested = payload.get(nested_key)
        if isinstance(nested, dict):
            try:
                return gateway_host_from_payload(nested)
            except PhalaError as exc:
                if exc.code != "invalid_response" or exc.field != "gateway_host":
                    raise

    raise PhalaError("invalid_response", field="gateway_host")


def normalize_gateway_host(gateway_host: str) -> str:
    return gateway_host.removeprefix("_.")


def normalize_status(raw_status: str) -> str:
    return PHALA_STATUS_MAP.get(raw_status.strip().lower(), "UNKNOWN")


def validate_managed_cvm_name(name: str) -> None:
    if not MANAGED_CVM_NAME_RE.fullmatch(name):
        raise PhalaError("invalid_name")


def validate_app_id(app_id: str) -> None:
    if not APP_ID_RE.fullmatch(app_id):
        raise PhalaError("invalid_response", field="app_id")


def update_identifier_from_info(payload: dict[str, Any]) -> str:
    vm_uuid = payload.get("vm_uuid")
    if isinstance(vm_uuid, str) and VM_UUID_RE.fullmatch(vm_uuid):
        return vm_uuid
    nested = payload.get("cvm")
    if isinstance(nested, dict):
        nested_vm_uuid = nested.get("vm_uuid")
        if isinstance(nested_vm_uuid, str) and VM_UUID_RE.fullmatch(nested_vm_uuid):
            return nested_vm_uuid
    return ""


def validate_gateway_host(gateway_host: str) -> None:
    if not DNS_HOST_RE.fullmatch(gateway_host):
        raise PhalaError("invalid_response", field="gateway_host")


def append_optional_arg(args: list[str], flag: str, value: str | None) -> None:
    if isinstance(value, str) and value.strip():
        args.extend([flag, value.strip()])


def managed_cvm_name(row: dict[str, Any]) -> str | None:
    for key in ("name", "cvm_name", "cvmName"):
        value = row.get(key)
        if isinstance(value, str) and value.startswith("umbra-v0-"):
            return value
    return None


def compile_redaction_patterns(raw_patterns: str) -> tuple[re.Pattern[str], ...]:
    patterns: list[re.Pattern[str]] = []
    for raw_pattern in raw_patterns.split(","):
        pattern = raw_pattern.strip()
        if pattern:
            patterns.append(re.compile(pattern))
    return tuple(patterns)


def scrub_output(output: str, api_token: str, patterns: tuple[re.Pattern[str], ...]) -> str:
    scrubbed = output.replace(api_token, "[redacted]") if api_token else output
    for secret in configured_sensitive_values():
        scrubbed = scrubbed.replace(secret, "[redacted]")
    for pattern in patterns:
        scrubbed = pattern.sub("[redacted]", scrubbed)
    scrubbed = SENSITIVE_OUTPUT_ENV_ASSIGNMENT_RE.sub(r"\1=[redacted]", scrubbed)
    scrubbed = SENSITIVE_OUTPUT_JSON_FIELD_RE.sub(r'\1"[redacted]"', scrubbed)
    return scrubbed


def configured_sensitive_values() -> tuple[str, ...]:
    values: list[str] = []
    for key, value in load_settings().raw.items():
        if value and len(value) >= 8 and SENSITIVE_OUTPUT_KEY_RE.search(key):
            values.append(value)
    return tuple(values)


def phala_subprocess_env(api_token: str) -> dict[str, str]:
    env = {key: os.environ[key] for key in SUBPROCESS_ENV_ALLOWLIST if os.environ.get(key)}
    env["PHALA_CLOUD_API_KEY"] = api_token
    return env


def staging_root() -> Path:
    dev_shm = Path("/dev/shm")
    if dev_shm.is_dir() and os.access(dev_shm, os.W_OK):
        return dev_shm
    return Path(tempfile.gettempdir())


def write_secret_file(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
    except Exception:
        with suppress(OSError):
            os.close(fd)
        raise
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        path.chmod(0o600)


def render_env_file(env: dict[str, str]) -> str:
    lines: list[str] = []
    for name, value in sorted(env.items()):
        if not ENV_NAME_RE.fullmatch(name):
            raise PhalaError("invalid_env_name")
        if "\n" in value or "\r" in value:
            raise PhalaError("invalid_env_value")
        lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


def secure_delete(path: Path) -> None:
    if not path.exists():
        return
    shred = shutil.which("shred")
    if shred:
        result = subprocess.run([shred, "-u", str(path)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return
    with suppress(FileNotFoundError):
        path.unlink()
