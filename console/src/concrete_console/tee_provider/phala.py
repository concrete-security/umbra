from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any

from concrete_console.config import load_settings
from concrete_console.readiness import DEFAULT_PHALA_CLI_PATH

APP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
CONCRETE_CVM_NAME_RE = re.compile(r"^concrete-v0-(?:cvm|sc)-[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
DNS_HOST_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
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
    redaction_patterns: tuple[re.Pattern[str], ...] = ()
    timeout_seconds: float = 300.0

    @classmethod
    def from_settings(cls, *, timeout_seconds: float | None = None) -> PhalaClient:
        raw = load_settings().raw
        api_token = raw.get("PHALA_API_TOKEN", "").strip()
        if not api_token:
            raise PhalaError("not_configured")
        patterns = compile_redaction_patterns(raw.get("PHALA_OUTPUT_REDACTION_PATTERNS", ""))
        return cls(
            cli_path=raw.get("PHALA_CLI_PATH", DEFAULT_PHALA_CLI_PATH).strip() or DEFAULT_PHALA_CLI_PATH,
            api_token=api_token,
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
    ) -> PhalaDeployResult:
        validate_concrete_cvm_name(name)
        async with staged_compose_and_env(compose_yaml=compose_yaml, env=env) as staged:
            args = [
                "deploy",
                "--name",
                name,
                "--compose",
                str(staged.compose_path),
                "-e",
                str(staged.env_path),
            ]
            append_optional_arg(args, "--instance-type", instance_type)
            append_optional_arg(args, "--region", region)
            args.extend(["--wait", "--json"])
            stdout = await self._run_text(args)
        return await self._deploy_result_from_stdout(stdout, fallback_lookup=name)

    async def update(self, *, app_id: str, compose_yaml: str, env: dict[str, str]) -> PhalaDeployResult:
        validate_app_id(app_id)
        async with staged_compose_and_env(compose_yaml=compose_yaml, env=env) as staged:
            stdout = await self._run_text(
                [
                    "deploy",
                    "--cvm-id",
                    app_id,
                    "--compose",
                    str(staged.compose_path),
                    "-e",
                    str(staged.env_path),
                    "--wait",
                    "--json",
                ]
            )
        return await self._deploy_result_from_stdout(stdout, fallback_lookup=app_id)

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
        return [row for row in rows if isinstance(row, dict) and concrete_cvm_name(row)]

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

    async def _run_json(self, args: list[str]) -> Any:
        stdout = await self._run_text(args)
        try:
            return json.loads(stdout or "{}")
        except json.JSONDecodeError as exc:
            raise PhalaError("invalid_json", output=scrub_output(stdout, self.api_token, self.redaction_patterns)) from exc

    async def _run_text(self, args: list[str]) -> str:
        process = await asyncio.create_subprocess_exec(
            self.cli_path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=phala_subprocess_env(self.api_token),
        )
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
        self._tmpdir = tempfile.TemporaryDirectory(prefix="concrete-phala-", dir=str(root))
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


def validate_concrete_cvm_name(name: str) -> None:
    if not CONCRETE_CVM_NAME_RE.fullmatch(name):
        raise PhalaError("invalid_name")


def validate_app_id(app_id: str) -> None:
    if not APP_ID_RE.fullmatch(app_id):
        raise PhalaError("invalid_response", field="app_id")


def validate_gateway_host(gateway_host: str) -> None:
    if not DNS_HOST_RE.fullmatch(gateway_host):
        raise PhalaError("invalid_response", field="gateway_host")


def append_optional_arg(args: list[str], flag: str, value: str | None) -> None:
    if isinstance(value, str) and value.strip():
        args.extend([flag, value.strip()])


def concrete_cvm_name(row: dict[str, Any]) -> str | None:
    for key in ("name", "cvm_name", "cvmName"):
        value = row.get(key)
        if isinstance(value, str) and value.startswith("concrete-v0-"):
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
    for pattern in patterns:
        scrubbed = pattern.sub("[redacted]", scrubbed)
    return scrubbed


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
