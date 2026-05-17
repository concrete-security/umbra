from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import re
import shlex
from typing import Any

from concrete_console.config import load_settings
from concrete_console.resources import json_payload

ATLAS_VERIFIER_CMD_ENV = "ATLAS_VERIFIER_CMD"
ATTESTATION_ERROR_CODES = {
    "ATTESTATION_FETCH_FAILED",
    "ATTESTATION_QUOTE_INVALID",
    "ATTESTATION_IMAGE_MISMATCH",
    "ATTESTATION_RTMR_MISMATCH",
    "ATTESTATION_SESSION_BINDING_INVALID",
}
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
HEX96_RE = re.compile(r"^[0-9a-fA-F]{96}$")
IMAGE_MEASUREMENT_RE = HEX96_RE


@dataclass(frozen=True)
class AttestationReport:
    image_measurement: str
    rtmr3_digest: str


class AttestationVerifierUnavailable(RuntimeError):
    pass


class AttestationVerifierError(RuntimeError):
    def __init__(self, code: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.details = details or {}


class AtlasVerifierClient:
    def __init__(self, argv: list[str]) -> None:
        if not argv:
            raise AttestationVerifierUnavailable("ATLAS_VERIFIER_CMD is empty")
        self.argv = argv

    @classmethod
    def from_settings(cls) -> AtlasVerifierClient:
        command = load_settings().raw.get(ATLAS_VERIFIER_CMD_ENV, "").strip()
        if not command:
            raise AttestationVerifierUnavailable(f"{ATLAS_VERIFIER_CMD_ENV} is not configured")
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            raise AttestationVerifierError(
                "ATTESTATION_FETCH_FAILED",
                {"reason": "verifier_command_invalid"},
            ) from exc
        return cls(argv)

    async def verify(self, request: dict[str, Any], *, timeout_seconds: int) -> AttestationReport:
        payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            process = await asyncio.create_subprocess_exec(
                *self.argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise AttestationVerifierError(
                "ATTESTATION_FETCH_FAILED",
                {"reason": "verifier_unavailable", "errno": exc.errno},
            ) from exc
        try:
            stdout, _stderr = await asyncio.wait_for(process.communicate(payload), timeout=timeout_seconds)
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise AttestationVerifierError(
                "ATTESTATION_FETCH_FAILED",
                {"reason": "verifier_timeout"},
            ) from exc
        if process.returncode != 0:
            raise verifier_error_from_output(stdout)
        return parse_attestation_report(stdout)


async def verify_with_fetch_retries(
    verifier: AtlasVerifierClient,
    request: dict[str, Any],
    *,
    timeout_seconds: int,
    initial_delay_seconds: float = 5.0,
    max_delay_seconds: float = 20.0,
) -> AttestationReport:
    """Retry transient reachability failures while a freshly-provisioned CVM boots."""

    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(timeout_seconds, 0)
    delay = max(initial_delay_seconds, 0.0)
    max_delay = max(max_delay_seconds, 0.0)
    last_fetch_error: AttestationVerifierError | None = None

    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            if last_fetch_error is not None:
                raise last_fetch_error
            raise AttestationVerifierError("ATTESTATION_FETCH_FAILED", {"reason": "verifier_timeout"})
        try:
            attempt_timeout = max(1, min(timeout_seconds, int(remaining + 0.999)))
            return await verifier.verify(request, timeout_seconds=attempt_timeout)
        except AttestationVerifierError as exc:
            if exc.code != "ATTESTATION_FETCH_FAILED":
                raise
            last_fetch_error = exc
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise
            sleep_for = min(delay, remaining)
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            if max_delay > 0:
                delay = min(max_delay, delay * 2 if delay > 0 else max_delay)


def build_dev_cvm_attestation_request(snapshot: Any) -> dict[str, Any]:
    metadata = json_payload(_row_value(snapshot, "metadata") or {})
    if not isinstance(metadata, dict):
        metadata = {}
    policy_bundle = metadata.get("policy_bundle")
    if not isinstance(policy_bundle, dict):
        raise AttestationVerifierError(
            "ATTESTATION_QUOTE_INVALID",
            {"reason": "policy_bundle_missing"},
        )
    compose_template = policy_bundle.get("compose_template")
    rtmr3_binding = policy_bundle.get("rtmr3_binding")
    if not isinstance(compose_template, str) or not isinstance(rtmr3_binding, dict):
        raise AttestationVerifierError(
            "ATTESTATION_QUOTE_INVALID",
            {"reason": "policy_bundle_invalid"},
        )
    policy: dict[str, Any] = {
        "type": "dstack_tdx",
        "expected_image_measurement": _row_value(snapshot, "expected_image_measurement"),
        "app_compose": {"docker_compose_file": compose_template},
        "rtmr3_binding": rtmr3_binding,
    }
    expected_bootchain = policy_bundle.get("expected_bootchain")
    if isinstance(expected_bootchain, dict) and expected_bootchain:
        policy["expected_bootchain"] = expected_bootchain
    os_image_hash = policy_bundle.get("os_image_hash")
    if isinstance(os_image_hash, str) and os_image_hash:
        policy["os_image_hash"] = os_image_hash
    return {
        "kind": "dev_cvm",
        "fqdn": _row_value(snapshot, "fqdn"),
        **attestation_connect_host_payload(metadata),
        "policy": policy,
    }


def build_security_cvm_attestation_request(
    snapshot: Any,
    *,
    token_hashes: dict[str, str],
    console_url: str,
) -> dict[str, Any]:
    ingest_hash = token_hashes.get("INGEST")
    ca_export_hash = token_hashes.get("CA_EXPORT")
    if not isinstance(ingest_hash, str) or not HEX64_RE.fullmatch(ingest_hash):
        raise AttestationVerifierError(
            "ATTESTATION_QUOTE_INVALID",
            {"reason": "security_cvm_token_hash_missing", "purpose": "INGEST"},
        )
    if not isinstance(ca_export_hash, str) or not HEX64_RE.fullmatch(ca_export_hash):
        raise AttestationVerifierError(
            "ATTESTATION_QUOTE_INVALID",
            {"reason": "security_cvm_token_hash_missing", "purpose": "CA_EXPORT"},
        )
    return {
        "kind": "security_cvm",
        "fqdn": _row_value(snapshot, "fqdn"),
        **attestation_connect_host_payload(json_payload(_row_value_optional(snapshot, "metadata") or {})),
        "policy": {
            "type": "dstack_tdx",
            "expected_image_measurement": _row_value(snapshot, "expected_image_measurement"),
            "app_compose": {"docker_compose_file": _row_value(snapshot, "compose_config")},
            "rtmr3_binding": {
                "CONSOLE_URL": console_url,
                "entity_id": str(_row_value(snapshot, "entity_id")),
                "sc_id": str(_row_value(snapshot, "id")),
                "ingest_token_sha256": ingest_hash.lower(),
                "ca_export_token_sha256": ca_export_hash.lower(),
            },
        },
    }


def attestation_connect_host_payload(metadata: Any) -> dict[str, str]:
    if not isinstance(metadata, dict):
        return {}
    connect_host = metadata.get("passthrough_host") or metadata.get("connect_host")
    if not isinstance(connect_host, str) or not connect_host.strip():
        policy_bundle = metadata.get("policy_bundle")
        if isinstance(policy_bundle, dict):
            connect_host = policy_bundle.get("connect_host")
    if not isinstance(connect_host, str) or not connect_host.strip():
        return {}
    return {"connect_host": connect_host.strip()}


def verifier_error_from_output(stdout: bytes) -> AttestationVerifierError:
    try:
        payload = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return AttestationVerifierError("ATTESTATION_QUOTE_INVALID", {"reason": "verifier_failed"})
    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        return AttestationVerifierError("ATTESTATION_QUOTE_INVALID", {"reason": "verifier_failed"})
    code = error.get("code")
    if not isinstance(code, str) or code not in ATTESTATION_ERROR_CODES:
        code = "ATTESTATION_QUOTE_INVALID"
    details = error.get("details")
    return AttestationVerifierError(code, details if isinstance(details, dict) else {})


def parse_attestation_report(stdout: bytes) -> AttestationReport:
    try:
        payload = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationVerifierError("ATTESTATION_QUOTE_INVALID", {"reason": "malformed_verifier_output"}) from exc
    if not isinstance(payload, dict):
        raise AttestationVerifierError("ATTESTATION_QUOTE_INVALID", {"reason": "malformed_verifier_output"})
    image_measurement = payload.get("image_measurement")
    rtmr3_digest = payload.get("rtmr3_digest")
    if not isinstance(image_measurement, str) or not IMAGE_MEASUREMENT_RE.fullmatch(image_measurement):
        raise AttestationVerifierError(
            "ATTESTATION_QUOTE_INVALID",
            {"reason": "invalid_image_measurement"},
        )
    if not isinstance(rtmr3_digest, str) or not HEX96_RE.fullmatch(rtmr3_digest):
        raise AttestationVerifierError(
            "ATTESTATION_QUOTE_INVALID",
            {"reason": "invalid_rtmr3_digest"},
        )
    image_measurement = image_measurement.lower()
    rtmr3_digest = rtmr3_digest.lower()
    return AttestationReport(image_measurement=image_measurement, rtmr3_digest=rtmr3_digest)


def _row_value(row: Any, key: str) -> Any:
    if isinstance(row, dict):
        return row[key]
    return row[key]


def _row_value_optional(row: Any, key: str) -> Any:
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[key]
    except (KeyError, TypeError):
        return None
