from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import logging
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from concrete_security_cvm.control_loop import ControlPlaneState
from concrete_security_cvm.enforcement import EnforcementResult, ProxyRequest, enforce_connect_request, enforce_request
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

    def http_connect(self, flow: Any) -> None:
        self._handle_proxy_flow(flow, connect_only=True)

    def request(self, flow: Any) -> None:
        self._handle_proxy_flow(flow, connect_only=False)

    def _handle_proxy_flow(self, flow: Any, *, connect_only: bool) -> None:
        if getattr(flow, "response", None) is not None:
            return
        request = getattr(flow, "request", None)
        raw_method = getattr(request, "method", None)
        if (
            not connect_only
            and isinstance(raw_method, str)
            and raw_method.upper() == "CONNECT"
            and _metadata(flow).get("concrete_connect_allowed") is True
        ):
            return
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
        if connect_only or proxy_request.method == "CONNECT":
            result = enforce_connect_request(proxy_request, self.control_state.snapshot().control_map)
        else:
            result = enforce_request(proxy_request, self.control_state.snapshot().control_map)
        if result.allowed:
            _replace_headers(flow.request.headers, result.upstream_headers)
            if result.traffic_log is not None:
                _metadata(flow)["concrete_traffic_log"] = result.traffic_log
            if connect_only or proxy_request.method == "CONNECT":
                _metadata(flow)["concrete_connect_allowed"] = True
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
    method = _required_str(getattr(request, "method", None), "method").upper()
    scheme = _request_scheme(request, method)
    host = _request_host(request, method).lower().rstrip(".")
    port = _request_port(request, method, scheme)
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


def _request_host(request: Any, method: str) -> str:
    for attr in ("host", "pretty_host"):
        value = getattr(request, attr, None)
        if isinstance(value, str) and value:
            return value
    if method == "CONNECT":
        host, _port = _split_connect_authority(_connect_authority(request))
        if host:
            return host
    raise FlowTranslationError("missing host")


def _request_port(request: Any, method: str, scheme: str) -> int:
    raw = getattr(request, "port", None)
    if isinstance(raw, int) and 1 <= raw <= 65535:
        return raw
    if method == "CONNECT":
        _host, port = _split_connect_authority(_connect_authority(request))
        if port is not None:
            return port
    return 443 if scheme == "https" else 80


def _connect_authority(request: Any) -> str:
    for attr in ("authority", "pretty_url", "url", "path"):
        value = getattr(request, attr, None)
        if isinstance(value, str) and value:
            return value
    raise FlowTranslationError("missing CONNECT authority")


def _split_connect_authority(value: str) -> tuple[str, int | None]:
    target = value
    if "://" in target:
        parsed = urlsplit(target)
        if parsed.hostname:
            return parsed.hostname, parsed.port
    target = target.lstrip("/")
    if not target or "/" in target:
        return "", None
    host, separator, port_text = target.rpartition(":")
    if separator and host and port_text.isdigit():
        port = int(port_text)
        if 1 <= port <= 65535:
            return host.strip("[]"), port
    return target, None


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
