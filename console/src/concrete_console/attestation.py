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
    per_attempt_timeout_seconds: int = 90,
) -> AttestationReport:
    """Retry transient reachability failures while a freshly-provisioned CVM boots.

    Each attempt is capped at `per_attempt_timeout_seconds` (NOT the full budget) so a
    single attempt that stalls — e.g. a TLS connect to a CVM whose nginx is mid HTTPS
    reload right after the leaf cert is issued — is killed and retried within the total
    `timeout_seconds` window, instead of burning the whole budget on one hung attempt."""

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
            attempt_timeout = max(1, min(per_attempt_timeout_seconds, timeout_seconds, int(remaining + 0.999)))
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


def _require_runtime_policy_fields(
    source: dict[str, Any], *, prefix: str
) -> tuple[dict[str, Any], str]:
    """Return ``(expected_bootchain, os_image_hash)`` from a launch/shade policy,
    raising ``ATTESTATION_QUOTE_INVALID`` if either is missing or empty.

    The single fail-closed floor shared by the Dev and SC request builders: both
    must carry the full runtime-verification fields, never a silent downgrade to a
    ``dev()`` policy. ``prefix`` namespaces the error reason (``dev_cvm`` /
    ``security_cvm``)."""
    expected_bootchain = source.get("expected_bootchain")
    if not isinstance(expected_bootchain, dict) or not expected_bootchain:
        raise AttestationVerifierError(
            "ATTESTATION_QUOTE_INVALID",
            {"reason": f"{prefix}_expected_bootchain_missing"},
        )
    os_image_hash = source.get("os_image_hash")
    if not isinstance(os_image_hash, str) or not os_image_hash:
        raise AttestationVerifierError(
            "ATTESTATION_QUOTE_INVALID",
            {"reason": f"{prefix}_os_image_hash_missing"},
        )
    return expected_bootchain, os_image_hash


def _dstack_tdx_request(
    kind: str,
    snapshot: Any,
    *,
    app_compose: dict[str, Any],
    expected_bootchain: dict[str, Any],
    os_image_hash: str,
    rtmr3_binding: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the verifier request the Dev and SC builders both emit: a full-runtime
    ``dstack_tdx`` policy (never ``dev()``) wrapped with the CVM kind + FQDN. The two builders
    differ only in how they source ``app_compose`` and ``rtmr3_binding``; everything else is
    this shared envelope."""
    return {
        "kind": kind,
        "fqdn": _row_value(snapshot, "fqdn"),
        "policy": {
            "type": "dstack_tdx",
            "expected_image_measurement": _row_value(snapshot, "expected_image_measurement"),
            "app_compose": app_compose,
            "expected_bootchain": expected_bootchain,
            "os_image_hash": os_image_hash,
            "rtmr3_binding": rtmr3_binding,
        },
    }


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
    # Same authoritative-app_compose extraction the SC builder uses (app_compose_json string
    # first, then the app_compose object), then overlay the launch compose_template as the
    # docker_compose_file. Falls back to a bare {docker_compose_file} only when the bundle
    # carries no app_compose at all.
    app_compose = _full_app_compose_from_shade_policy(policy_bundle) or {}
    app_compose["docker_compose_file"] = compose_template
    # FULL runtime verification — symmetric with the SC (build_security_cvm_attestation_request).
    # The Dev CVM is verified against its COMPLETE app_compose + expected_bootchain + os_image_hash
    # (dev-cvm.md §8.1/§9, the same checks the CLI already runs per-tunnel), never MRTD-only: the
    # MRTD is the shared dstack-guest base (DEV == SECURITY image measurement) and proves nothing
    # app-specific. The launch bundle always carries these (same shade source as the SC), so a
    # missing field is a hard fail here, never a silent downgrade to a dev() policy in the verifier.
    expected_bootchain, os_image_hash = _require_runtime_policy_fields(
        policy_bundle, prefix="dev_cvm"
    )
    return _dstack_tdx_request(
        "dev_cvm",
        snapshot,
        app_compose=app_compose,
        expected_bootchain=expected_bootchain,
        os_image_hash=os_image_hash,
        rtmr3_binding=rtmr3_binding,
    )


def _full_app_compose_from_shade_policy(shade_policy: dict[str, Any]) -> dict[str, Any] | None:
    """Return the authoritative, complete app_compose dict from a shade-generated policy.

    Prefer the compact ``app_compose_json`` string (hash-sensitive key order preserved)
    when present, otherwise the ``app_compose`` object. Returns None when neither yields a
    non-empty dict — callers MUST treat that as a hard failure (never fall back to a
    `dev()`-triggering bare policy)."""
    app_compose_json = shade_policy.get("app_compose_json")
    if isinstance(app_compose_json, str):
        parsed = json_payload(app_compose_json)
        if isinstance(parsed, dict) and parsed:
            return parsed
    candidate = shade_policy.get("app_compose")
    if isinstance(candidate, dict) and candidate:
        return dict(candidate)
    if isinstance(candidate, str):
        parsed = json_payload(candidate)
        if isinstance(parsed, dict) and parsed:
            return parsed
    return None


def build_security_cvm_attestation_request(
    snapshot: Any,
    *,
    token_hashes: dict[str, str],
    console_url: str,
    shade_policy: dict[str, Any],
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
    # FULL runtime verification — never `dev()` / `disable_runtime_verification`. The SC is
    # verified exactly like the Dev CVM: the shade-generated policy carries the AUTHORITATIVE,
    # COMPLETE app_compose + expected_bootchain + os_image_hash measured from the deployed
    # compose, so the atlas verifier runs compose-hash + bootchain + os-image + RTMR replay
    # against the quote. MRTD alone is the dstack-guest base measurement (shared by every CVM)
    # and proves nothing app-specific; it stays anchored to the row's expected_image_measurement.
    #
    # The 8bf96c0 regression was NOT "folding os_image_hash/expected_bootchain is wrong" — it was
    # folding them alongside an INCOMPLETE app_compose ({docker_compose_file} only), which changed
    # the reconstructed compose-hash → spurious app_compose_hash_mismatch. The fix is to send
    # shade's COMPLETE app_compose as-is (same source the Dev CVM forwarder verifies against in
    # prod), not to drop the runtime fields. See docs/specs/security-cvm.md §2.2.
    if not isinstance(shade_policy, dict):
        raise AttestationVerifierError(
            "ATTESTATION_QUOTE_INVALID",
            {"reason": "security_cvm_shade_policy_missing"},
        )
    app_compose = _full_app_compose_from_shade_policy(shade_policy)
    if app_compose is None:
        raise AttestationVerifierError(
            "ATTESTATION_QUOTE_INVALID",
            {"reason": "security_cvm_app_compose_missing"},
        )
    expected_bootchain, os_image_hash = _require_runtime_policy_fields(
        shade_policy, prefix="security_cvm"
    )
    return _dstack_tdx_request(
        "security_cvm",
        snapshot,
        app_compose=app_compose,
        expected_bootchain=expected_bootchain,
        os_image_hash=os_image_hash,
        rtmr3_binding={
            "CONSOLE_URL": console_url,
            "entity_id": str(_row_value(snapshot, "entity_id")),
            "sc_id": str(_row_value(snapshot, "id")),
            "ingest_token_sha256": ingest_hash.lower(),
            "ca_export_token_sha256": ca_export_hash.lower(),
        },
    )


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
    return row[key]
