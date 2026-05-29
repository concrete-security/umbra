from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
import time
from typing import Callable, Mapping

from concrete_security_cvm.control import ControlMap, DevCVMControlEntry
from concrete_security_cvm.policy import PolicyValidationError
from concrete_security_cvm.traffic import TrafficLogRecord


DLP_SCAN_BODY_LIMIT_BYTES = 10 * 1024 * 1024
DLP_SCAN_TIMEOUT_SECONDS = 0.050


class DLPScanTimeout(RuntimeError):
    pass


@dataclass(frozen=True)
class ProxyRequest:
    source_ip: str
    destination_ip: str
    scheme: str
    host: str
    port: int
    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes = b""
    timestamp: datetime | None = None


@dataclass(frozen=True)
class EnforcementResult:
    allowed: bool
    response_code: int | None
    reason: str
    cvm: DevCVMControlEntry | None
    upstream_headers: dict[str, str]
    traffic_log: TrafficLogRecord | None
    matched_policy_id: str | None = None
    proxy_token_hash_prefix: str | None = None


def proxy_token_hash_prefix(token: str, *, prefix_chars: int = 8) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:prefix_chars]


@dataclass(frozen=True)
class WebsocketFrameDecision:
    drop: bool
    ack_frame: bytes | None
    traffic_log: TrafficLogRecord | None
    matched_policy_id: str | None = None


def enforce_request(
    request: ProxyRequest,
    control_map: ControlMap,
    *,
    dlp_timeout_seconds: float = DLP_SCAN_TIMEOUT_SECONDS,
    dlp_now: Callable[[], float] = time.monotonic,
) -> EnforcementResult:
    headers = normalize_headers(request.headers)
    token = extract_proxy_bearer(headers)
    if token is None:
        return EnforcementResult(
            allowed=False,
            response_code=407,
            reason="proxy_auth_missing",
            cvm=None,
            upstream_headers={},
            traffic_log=None,
        )
    cvm = control_map.lookup_proxy_token(token)
    if cvm is None:
        return EnforcementResult(
            allowed=False,
            response_code=407,
            reason="proxy_auth_unknown",
            cvm=None,
            upstream_headers={},
            traffic_log=None,
            proxy_token_hash_prefix=proxy_token_hash_prefix(token),
        )

    return enforce_authenticated_request(
        request,
        cvm,
        dlp_timeout_seconds=dlp_timeout_seconds,
        dlp_now=dlp_now,
    )


def enforce_authenticated_request(
    request: ProxyRequest,
    cvm: DevCVMControlEntry,
    *,
    dlp_timeout_seconds: float = DLP_SCAN_TIMEOUT_SECONDS,
    dlp_now: Callable[[], float] = time.monotonic,
) -> EnforcementResult:
    headers = normalize_headers(request.headers)
    upstream_headers = strip_proxy_authorization(headers)
    decision = cvm.merged_policy.decide(
        scheme=request.scheme,
        host=request.host,
        port=request.port,
        method=request.method,
        path=request.path,
        body=request.body,
        headers=headers,
    )
    if not decision.allowed:
        return _blocked_result(request, cvm, upstream_headers, decision.reason, decision.rule_id)

    try:
        dlp_match = find_dlp_match(
            cvm.merged_policy.secret_patterns,
            upstream_headers,
            request.body,
            timeout_seconds=dlp_timeout_seconds,
            now=dlp_now,
        )
    except DLPScanTimeout:
        return _blocked_result(request, cvm, upstream_headers, "dlp_scan_timeout", None)
    if dlp_match is not None:
        return _blocked_result(request, cvm, upstream_headers, "dlp_secret_detected", dlp_match)

    try:
        injection_headers = cvm.merged_policy.render_injection_headers(
            scheme=request.scheme,
            host=request.host,
            port=request.port,
            method=request.method,
            path=request.path,
        )
    except PolicyValidationError:
        return _blocked_result(request, cvm, upstream_headers, "policy_secret_injection_conflict", None)
    upstream_headers.update(injection_headers)
    attributes: dict[str, str] = {}
    if decision.matched_rule is not None:
        attributes = decision.matched_rule.extract_traffic_log_attributes(request.body, headers)
    return EnforcementResult(
        allowed=True,
        response_code=None,
        reason="allowed",
        cvm=cvm,
        upstream_headers=upstream_headers,
        traffic_log=traffic_log_record(request, cvm, response_code=None, attributes=attributes),
        matched_policy_id=decision.rule_id,
    )


def enforce_connect_request(request: ProxyRequest, control_map: ControlMap) -> EnforcementResult:
    headers = normalize_headers(request.headers)
    token = extract_proxy_bearer(headers)
    if token is None:
        return EnforcementResult(
            allowed=False,
            response_code=407,
            reason="proxy_auth_missing",
            cvm=None,
            upstream_headers={},
            traffic_log=None,
        )
    cvm = control_map.lookup_proxy_token(token)
    if cvm is None:
        return EnforcementResult(
            allowed=False,
            response_code=407,
            reason="proxy_auth_unknown",
            cvm=None,
            upstream_headers={},
            traffic_log=None,
            proxy_token_hash_prefix=proxy_token_hash_prefix(token),
        )

    upstream_headers = strip_proxy_authorization(headers)
    decision = cvm.merged_policy.decide_tunnel(
        scheme=request.scheme,
        host=request.host,
        port=request.port,
    )
    if not decision.allowed:
        return _blocked_result(request, cvm, upstream_headers, decision.reason, decision.rule_id)
    return EnforcementResult(
        allowed=True,
        response_code=None,
        reason="allowed",
        cvm=cvm,
        upstream_headers=upstream_headers,
        traffic_log=traffic_log_record(request, cvm, response_code=200),
        matched_policy_id=decision.rule_id,
    )


def decide_inbound_websocket(
    request: ProxyRequest,
    content: bytes,
    cvm: DevCVMControlEntry,
) -> WebsocketFrameDecision | None:
    verdict = cvm.merged_policy.decide_inbound_websocket(
        scheme=request.scheme,
        host=request.host,
        port=request.port,
        content=content,
    )
    if verdict is None:
        return None
    if not verdict.drop:
        return WebsocketFrameDecision(drop=False, ack_frame=None, traffic_log=None, matched_policy_id=verdict.rule_id)
    return WebsocketFrameDecision(
        drop=True,
        ack_frame=verdict.ack_frame,
        traffic_log=traffic_log_record(request, cvm, response_code=None),
        matched_policy_id=verdict.rule_id,
    )


def extract_proxy_bearer(headers: Mapping[str, str]) -> str | None:
    raw = headers.get("proxy-authorization")
    if raw is None:
        return None
    match = re.fullmatch(r"Bearer ([^\s]+)", raw)
    if match is None:
        return None
    return match.group(1)


def strip_proxy_authorization(headers: Mapping[str, str]) -> dict[str, str]:
    return {name: value for name, value in headers.items() if name != "proxy-authorization"}


def normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        normalized[name.lower()] = value
    return normalized


def find_dlp_match(
    patterns: object,
    headers: Mapping[str, str],
    body: bytes,
    *,
    timeout_seconds: float = DLP_SCAN_TIMEOUT_SECONDS,
    now: Callable[[], float] = time.monotonic,
) -> str | None:
    header_blob = "\n".join(f"{name}: {value}" for name, value in sorted(headers.items()))
    body_text = body[:DLP_SCAN_BODY_LIMIT_BYTES].decode("utf-8", errors="ignore")
    deadline = now() + timeout_seconds
    for pattern in patterns:  # type: ignore[assignment]
        _raise_if_dlp_deadline_elapsed(now, deadline)
        if pattern.scan_headers and pattern.compiled.search(header_blob):
            return pattern.pattern_id
        _raise_if_dlp_deadline_elapsed(now, deadline)
        if pattern.scan_body and pattern.compiled.search(body_text):
            return pattern.pattern_id
        _raise_if_dlp_deadline_elapsed(now, deadline)
    return None


def traffic_log_record(
    request: ProxyRequest,
    cvm: DevCVMControlEntry,
    *,
    response_code: int | None,
    bytes_transferred: int = 0,
    attributes: Mapping[str, str] | None = None,
) -> TrafficLogRecord:
    return TrafficLogRecord(
        timestamp=request.timestamp or datetime.now(timezone.utc),
        cvm_id=cvm.cvm_id,
        source_ip=request.source_ip,
        destination_ip=request.destination_ip,
        destination_host=request.host,
        protocol=request.scheme,
        port=request.port,
        method=request.method.upper(),
        path=request.path,
        response_code=response_code,
        bytes_transferred=bytes_transferred,
        attributes=dict(attributes) if attributes else {},
    )


def _blocked_result(
    request: ProxyRequest,
    cvm: DevCVMControlEntry,
    upstream_headers: dict[str, str],
    reason: str,
    matched_policy_id: str | None,
) -> EnforcementResult:
    return EnforcementResult(
        allowed=False,
        response_code=403,
        reason=reason,
        cvm=cvm,
        upstream_headers=upstream_headers,
        traffic_log=traffic_log_record(request, cvm, response_code=403),
        matched_policy_id=matched_policy_id,
    )


def _raise_if_dlp_deadline_elapsed(now: Callable[[], float], deadline: float) -> None:
    if now() > deadline:
        raise DLPScanTimeout
