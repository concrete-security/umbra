from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any

from concrete_console.config import load_settings

DEFAULT_UV_BIN = "uv"
DNS_HOST_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
SUBPROCESS_ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "UV_PROJECT_ENVIRONMENT")


class ShadeError(RuntimeError):
    def __init__(self, code: str, *, output: str = "", field: str | None = None):
        super().__init__(code)
        self.code = code
        self.output = output
        self.field = field


@dataclass(frozen=True)
class ShadeBuildResult:
    compose_yaml: str
    stdout: str


@dataclass(frozen=True)
class ShadePolicyResult:
    policy: dict[str, Any]
    stdout: str


@dataclass(frozen=True)
class ShadeRenderResult:
    compose_yaml: str
    policy: dict[str, Any]
    build_stdout: str
    policy_stdout: str


@dataclass(frozen=True)
class ShadeClient:
    shade_dir: Path
    uv_bin: str = DEFAULT_UV_BIN
    timeout_seconds: float = 120.0

    @classmethod
    def from_settings(cls) -> ShadeClient:
        raw = load_settings().raw
        shade_dir = raw.get("SHADE_DIR", "").strip()
        if not shade_dir:
            raise ShadeError("not_configured")
        return cls(shade_dir=validate_shade_dir(Path(shade_dir)))

    async def build(self, *, shade_config_yaml: str, app_compose_yaml: str) -> ShadeBuildResult:
        validate_nonempty(shade_config_yaml, field="shade_config_yaml")
        validate_nonempty(app_compose_yaml, field="app_compose_yaml")
        async with staged_shade_build(shade_config_yaml=shade_config_yaml, app_compose_yaml=app_compose_yaml) as staged:
            stdout = await self._run(
                [
                    "run",
                    "--project",
                    str(validate_shade_dir(self.shade_dir)),
                    "shade",
                    "build",
                    "-c",
                    str(staged.shade_config_path),
                    "-f",
                    str(staged.app_compose_path),
                    "-o",
                    str(staged.output_compose_path),
                ]
            )
            compose_yaml = read_required_text(staged.output_compose_path, field="compose_yaml")
        return ShadeBuildResult(compose_yaml=compose_yaml, stdout=stdout)

    async def generate_policy(
        self,
        *,
        domain: str,
        deploy_compose_yaml: str,
        connect_host: str | None = None,
        allowed_tcb_status: tuple[str, ...] = ("UpToDate",),
    ) -> ShadePolicyResult:
        validate_hostname(domain)
        validate_nonempty(deploy_compose_yaml, field="deploy_compose_yaml")
        async with staged_policy_generation(deploy_compose_yaml=deploy_compose_yaml) as staged:
            args = [
                "run",
                "--project",
                str(validate_shade_dir(self.shade_dir)),
                "shade",
                "policy",
                "generate",
                "--domain",
                domain,
                "--compose",
                str(staged.deploy_compose_path),
                "--output",
                str(staged.policy_path),
            ]
            if allowed_tcb_status:
                args.extend(["--allowed-tcb-status", ",".join(allowed_tcb_status)])
            if connect_host:
                args.extend(["--connect-host", connect_host])
            stdout = await self._run(args)
            policy = read_required_json_object(staged.policy_path)
        return ShadePolicyResult(policy=policy, stdout=stdout)

    async def build_with_policy(
        self,
        *,
        shade_config_yaml: str,
        app_compose_yaml: str,
        domain: str,
        allowed_tcb_status: tuple[str, ...] = ("UpToDate",),
    ) -> ShadeRenderResult:
        build_result = await self.build(shade_config_yaml=shade_config_yaml, app_compose_yaml=app_compose_yaml)
        policy_result = await self.generate_policy(
            domain=domain,
            deploy_compose_yaml=build_result.compose_yaml,
            connect_host=None,
            allowed_tcb_status=allowed_tcb_status,
        )
        return ShadeRenderResult(
            compose_yaml=build_result.compose_yaml,
            policy=policy_result.policy,
            build_stdout=build_result.stdout,
            policy_stdout=policy_result.stdout,
        )

    async def _run(self, args: list[str]) -> str:
        process = await asyncio.create_subprocess_exec(
            self.uv_bin,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=shade_subprocess_env(),
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=self.timeout_seconds)
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.wait()
            raise ShadeError("cli_timeout") from exc
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        output = "\n".join(part for part in (stdout, stderr) if part)
        if process.returncode != 0:
            raise ShadeError("cli_failed", output=output)
        return stdout


@dataclass(frozen=True)
class StagedShadeBuild:
    directory: Path
    shade_config_path: Path
    app_compose_path: Path
    output_compose_path: Path


@dataclass(frozen=True)
class StagedPolicyGeneration:
    directory: Path
    deploy_compose_path: Path
    policy_path: Path


class staged_shade_build:
    def __init__(self, *, shade_config_yaml: str, app_compose_yaml: str):
        self.shade_config_yaml = shade_config_yaml
        self.app_compose_yaml = app_compose_yaml
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.files: StagedShadeBuild | None = None

    async def __aenter__(self) -> StagedShadeBuild:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="concrete-shade-")
        directory = Path(self._tmpdir.name)
        files = StagedShadeBuild(
            directory=directory,
            shade_config_path=directory / "shade.yml",
            app_compose_path=directory / "docker-compose.yml",
            output_compose_path=directory / "docker-compose.shade.yml",
        )
        write_private_file(files.shade_config_path, self.shade_config_yaml)
        write_private_file(files.app_compose_path, self.app_compose_yaml)
        self.files = files
        return files

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._tmpdir is not None:
            self._tmpdir.cleanup()


class staged_policy_generation:
    def __init__(self, *, deploy_compose_yaml: str):
        self.deploy_compose_yaml = deploy_compose_yaml
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.files: StagedPolicyGeneration | None = None

    async def __aenter__(self) -> StagedPolicyGeneration:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="concrete-shade-policy-")
        directory = Path(self._tmpdir.name)
        files = StagedPolicyGeneration(
            directory=directory,
            deploy_compose_path=directory / "docker-compose.shade.yml",
            policy_path=directory / "policy.json",
        )
        write_private_file(files.deploy_compose_path, self.deploy_compose_yaml)
        self.files = files
        return files

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._tmpdir is not None:
            self._tmpdir.cleanup()


def validate_shade_dir(path: Path) -> Path:
    if not path.is_dir():
        raise ShadeError("invalid_shade_dir", field="SHADE_DIR")
    return path


def validate_hostname(hostname: str) -> None:
    if not DNS_HOST_RE.fullmatch(hostname):
        raise ShadeError("invalid_hostname", field="domain")


def validate_nonempty(value: str, *, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ShadeError("invalid_input", field=field)


def write_private_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def read_required_text(path: Path, *, field: str) -> str:
    if not path.is_file():
        raise ShadeError("missing_output", field=field)
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        raise ShadeError("empty_output", field=field)
    return content


def read_required_json_object(path: Path) -> dict[str, Any]:
    content = read_required_text(path, field="policy")
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ShadeError("invalid_json", field="policy") from exc
    if not isinstance(payload, dict):
        raise ShadeError("invalid_policy", field="policy")
    return payload


def shade_subprocess_env() -> dict[str, str]:
    return {key: value for key in SUBPROCESS_ENV_ALLOWLIST if (value := os.environ.get(key))}
