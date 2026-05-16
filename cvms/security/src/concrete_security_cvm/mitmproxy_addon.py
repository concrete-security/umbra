from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import logging
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from concrete_security_cvm.control_loop import ControlPlaneState
from concrete_security_cvm.enforcement import EnforcementResult, ProxyRequest, enforce_request
from concrete_security_cvm.traffic import TrafficLogEmitter, TrafficLogRecord


logger = logging.getLogger(__name__)


ResponseFactory = Callable[[int, bytes, Mapping[str, str]], Any]


class FlowTranslationError(ValueError):
    pass


class SecurityCVMProxyAddon:
    def __init__(
        self,
        *,
        control_state: ControlPlaneState,
        traffic_emitter: TrafficLogEmitter,
        response_factory: ResponseFactory | None = None,
    ) -> None:
        self.control_state = control_state
        self.traffic_emitter = traffic_emitter
        self.response_factory = response_factory or mitmproxy_response_factory

    def request(self, flow: Any) -> None:
        try:
            proxy_request = proxy_request_from_flow(flow)
        except FlowTranslationError as exc:
            flow.response = self.response_factory(
                400,
                b"Concrete Proxy: Malformed proxy request\n",
                {"Content-Type": "text/plain; charset=utf-8"},
            )
            logger.info("proxy_request_malformed", extra={"reason": str(exc)})
            return
        result = enforce_request(proxy_request, self.control_state.snapshot().control_map)
        if result.allowed:
            _replace_headers(flow.request.headers, result.upstream_headers)
            if result.traffic_log is not None:
                _metadata(flow)["concrete_traffic_log"] = result.traffic_log
            return
        self._reject(flow, result)

    def response(self, flow: Any) -> None:
        traffic_log = _metadata(flow).pop("concrete_traffic_log", None)
        if not isinstance(traffic_log, TrafficLogRecord):
            return
        response = getattr(flow, "response", None)
        if response is None:
            return
        status_code = int(getattr(response, "status_code", 0) or 0)
        self.traffic_emitter.enqueue(
            replace(
                traffic_log,
                response_code=status_code,
                bytes_transferred=_response_body_size(response),
            )
        )

    def error(self, flow: Any) -> None:
        traffic_log = _metadata(flow).pop("concrete_traffic_log", None)
        if not isinstance(traffic_log, TrafficLogRecord):
            return
        self.traffic_emitter.enqueue(replace(traffic_log, response_code=502, bytes_transferred=0))

    def _reject(self, flow: Any, result: EnforcementResult) -> None:
        if result.reason == "proxy_auth_unknown":
            logger.info("proxy_auth_unknown", extra={"cvm_id": None})
        if result.traffic_log is not None:
            self.traffic_emitter.enqueue(result.traffic_log)
        flow.response = self.response_factory(
            result.response_code or 403,
            _blocked_body(result.reason),
            {"Content-Type": "text/plain; charset=utf-8"},
        )


def proxy_request_from_flow(flow: Any) -> ProxyRequest:
    request = getattr(flow, "request", None)
    if request is None:
        raise FlowTranslationError("missing request")
    host = _required_str(getattr(request, "host", None), "host").lower().rstrip(".")
    method = _required_str(getattr(request, "method", None), "method").upper()
    scheme = _request_scheme(request, method)
    port = int(getattr(request, "port", 443 if scheme == "https" else 80))
    path = _path_without_query(getattr(request, "path", None))
    return ProxyRequest(
        source_ip=_connection_host(getattr(flow, "client_conn", None), fallback="unknown"),
        destination_ip=_connection_host(getattr(flow, "server_conn", None), fallback=host),
        scheme=scheme,
        host=host,
        port=port,
        method=method,
        path=path,
        headers=_headers_to_dict(getattr(request, "headers", {})),
        body=_request_body(request),
        timestamp=datetime.now(timezone.utc),
    )


def mitmproxy_response_factory(status_code: int, content: bytes, headers: Mapping[str, str]) -> Any:
    from mitmproxy import http

    return http.Response.make(status_code, content, dict(headers))


def _blocked_body(reason: str) -> bytes:
    messages = {
        "proxy_auth_missing": "Concrete Proxy: Proxy authentication required\n",
        "proxy_auth_unknown": "Concrete Proxy: Proxy authentication required\n",
        "blocked_destination": "Concrete Proxy: Destination blocked by policy\n",
        "destination_not_allowed": "Concrete Proxy: Destination not in allowed domains\n",
        "dlp_secret_detected": "Concrete Proxy: Blocked by DLP policy\n",
        "dlp_scan_timeout": "Concrete Proxy: Blocked by DLP scanner timeout\n",
        "policy_secret_injection_conflict": "Concrete Proxy: Secret injection conflict\n",
    }
    return messages.get(reason, "Concrete Proxy: Request blocked by policy\n").encode("utf-8")


def _request_scheme(request: Any, method: str) -> str:
    raw = getattr(request, "scheme", None)
    if isinstance(raw, str) and raw:
        return raw.lower()
    if method == "CONNECT":
        return "https"
    return "http"


def _headers_to_dict(headers: Any) -> dict[str, str]:
    if hasattr(headers, "items"):
        return {str(name): str(value) for name, value in headers.items()}
    return dict(headers)


def _replace_headers(headers: Any, values: Mapping[str, str]) -> None:
    headers.clear()
    for name, value in values.items():
        headers[name] = value


def _request_body(request: Any) -> bytes:
    for attr in ("raw_content", "content"):
        value = getattr(request, attr, None)
        if isinstance(value, bytes):
            return value
    return b""


def _response_body_size(response: Any) -> int:
    for attr in ("raw_content", "content"):
        value = getattr(response, attr, None)
        if isinstance(value, bytes):
            return len(value)
    return 0


def _path_without_query(path: Any) -> str:
    if not isinstance(path, str) or not path:
        return "/"
    parsed = urlsplit(path)
    return parsed.path or "/"


def _connection_host(connection: Any, *, fallback: str) -> str:
    for attr in ("ip_address", "address"):
        value = getattr(connection, attr, None)
        if isinstance(value, tuple) and value:
            return str(value[0])
        if isinstance(value, str) and value:
            return value
    return fallback


def _required_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise FlowTranslationError(f"missing {field}")
    return value


def _metadata(flow: Any) -> dict[str, Any]:
    metadata = getattr(flow, "metadata", None)
    if isinstance(metadata, dict):
        return metadata
    flow.metadata = {}
    return flow.metadata
