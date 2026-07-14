from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import logging
import time
import zlib
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit
from uuid import UUID

from concrete_security_cvm.control_loop import ControlPlaneState
from concrete_security_cvm.enforcement import (
    DLP_SCAN_BODY_LIMIT_BYTES,
    EnforcementResult,
    ProxyRequest,
    decide_inbound_websocket,
    enforce_authenticated_request,
    enforce_connect_request,
    enforce_request,
)
from concrete_security_cvm.traffic import TrafficLogEmitter, TrafficLogRecord


logger = logging.getLogger(__name__)
CONNECT_IDENTITY_TTL_SECONDS = 3600
MAX_CONNECT_IDENTITIES = 4096
# mitmproxy retains every frame in `flow.websocket.messages` for the flow's lifetime, and the
# addon only ever needs the latest inbound frame (`messages[-1]`). Cap retention so a long-lived
# inbound WebSocket channel cannot grow RSS without bound and OOM the SC (tdx.small, no swap).
WS_MESSAGE_RETENTION = 8


ResponseFactory = Callable[[int, bytes, Mapping[str, str]], Any]
WebsocketInjector = Callable[[Any, bool, bytes], None]


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
        self.websocket_injector: WebsocketInjector = mitmproxy_websocket_injector
        self._connect_identities: dict[str, tuple[str, float]] = {}

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
        control_map = self.control_state.snapshot().control_map
        if connect_only or proxy_request.method == "CONNECT":
            result = enforce_connect_request(proxy_request, control_map)
        elif cvm := _connect_cvm(flow, control_map, self._connect_identities):
            result = enforce_authenticated_request(proxy_request, cvm)
        else:
            result = enforce_request(proxy_request, control_map)
        if result.allowed:
            metadata = _metadata(flow)
            if result.cvm is not None:
                metadata["concrete_cvm_id"] = str(result.cvm.cvm_id)
                metadata["concrete_websocket_governed"] = result.cvm.merged_policy.websocket_governed(
                    scheme=proxy_request.scheme,
                    host=proxy_request.host,
                    port=proxy_request.port,
                )
            _replace_headers(flow.request.headers, result.upstream_headers)
            if (connect_only or proxy_request.method == "CONNECT") and result.cvm is not None:
                if result.traffic_log is not None:
                    self.traffic_emitter.enqueue(result.traffic_log)
                metadata["concrete_connect_allowed"] = True
                if key := _client_connection_key(flow):
                    self._remember_connect_identity(key, result.cvm.cvm_id)
                return
            if result.traffic_log is not None:
                metadata["concrete_traffic_log"] = result.traffic_log
            return
        self._reject(flow, result)

    def websocket_message(self, flow: Any) -> None:
        # Bound retained frames first, on every call regardless of verdict, so passed/dropped/
        # injected frames cannot accumulate over the life of a long-lived WebSocket channel.
        _trim_websocket_messages(flow)
        message = _latest_websocket_message(flow)
        if message is None:
            return
        # Inbound only (server -> sandbox); a re-entrancy guard skips the ack
        # frames this hook itself injects.
        if getattr(message, "from_client", True) or getattr(message, "injected", False):
            return
        if _is_websocket_control_message(message):
            return
        content = _websocket_message_content(message) or b""
        metadata = _metadata(flow)
        was_governed = metadata.get("concrete_websocket_governed") is True
        flow_cvm_id = _flow_cvm_id(flow)
        control_map = self.control_state.snapshot().control_map
        cvm = _connect_cvm(flow, control_map, self._connect_identities)
        try:
            proxy_request = proxy_request_from_flow(flow)
        except FlowTranslationError:
            if was_governed:
                self._drop_websocket_frame(
                    flow,
                    message,
                    None,
                    cvm_id=flow_cvm_id,
                    reason="websocket_request_malformed",
                )
            return
        if cvm is None:
            if was_governed:
                self._drop_websocket_frame(
                    flow,
                    message,
                    proxy_request,
                    cvm_id=flow_cvm_id,
                    reason="websocket_cvm_unresolved",
                )
            return
        tunnel_decision = cvm.merged_policy.decide_tunnel(
            scheme=proxy_request.scheme,
            host=proxy_request.host,
            port=proxy_request.port,
        )
        if not tunnel_decision.allowed:
            self._drop_websocket_frame(
                flow,
                message,
                proxy_request,
                cvm_id=cvm.cvm_id,
                matched_policy_id=tunnel_decision.rule_id,
                reason=tunnel_decision.reason,
            )
            return
        current_governed = cvm.merged_policy.websocket_governed(
            scheme=proxy_request.scheme,
            host=proxy_request.host,
            port=proxy_request.port,
        )
        if not current_governed:
            if was_governed:
                self._drop_websocket_frame(
                    flow,
                    message,
                    proxy_request,
                    cvm_id=cvm.cvm_id,
                    reason="websocket_governance_removed",
                )
            return
        if getattr(message, "is_text", False) is not True:
            self._drop_websocket_frame(
                flow,
                message,
                proxy_request,
                cvm_id=cvm.cvm_id,
                reason="websocket_non_text_data",
            )
            return
        decision = decide_inbound_websocket(proxy_request, content, cvm)
        if decision is None:
            self._drop_websocket_frame(
                flow,
                message,
                proxy_request,
                cvm_id=cvm.cvm_id,
                reason="websocket_decision_missing",
            )
            return
        if not decision.drop:
            if decision.lifecycle:
                # Lifecycle (hello/disconnect) frames are delivered unfiltered
                # under the SC bound; emit a contents-free traffic log so the
                # bounded telemetry channel is auditable (cf. dropped frames).
                self.traffic_emitter.enqueue(
                    _websocket_traffic_log_record(proxy_request, cvm.cvm_id, decision="allowed")
                )
            return
        self._drop_websocket_frame(
            flow,
            message,
            proxy_request,
            cvm_id=cvm.cvm_id,
            matched_policy_id=decision.matched_policy_id,
            ack_frame=decision.ack_frame,
            reason="websocket_policy",
        )

    def client_disconnected(self, client_conn: Any) -> None:
        if key := _connection_key_from_connection(client_conn):
            self._connect_identities.pop(key, None)

    def _drop_websocket_frame(
        self,
        flow: Any,
        message: Any,
        request: ProxyRequest | None,
        *,
        cvm_id: UUID | None,
        matched_policy_id: str | None = None,
        ack_frame: bytes | None = None,
        reason: str,
    ) -> None:
        message.drop()
        if request is not None and cvm_id is not None:
            self.traffic_emitter.enqueue(
                _websocket_traffic_log_record(request, cvm_id, decision="websocket_frame_dropped")
            )
        if ack_frame is not None:
            self.websocket_injector(flow, False, ack_frame)
        logger.info(
            "websocket_frame_blocked",
            extra={
                "cvm_id": str(cvm_id) if cvm_id is not None else None,
                "matched_policy_id": matched_policy_id,
                "reason": reason,
            },
        )

    def _remember_connect_identity(self, key: str, cvm_id: UUID) -> None:
        now = time.monotonic()
        self._connect_identities[key] = (str(cvm_id), now)
        if len(self._connect_identities) <= MAX_CONNECT_IDENTITIES:
            return
        cutoff = now - CONNECT_IDENTITY_TTL_SECONDS
        stale_keys = [item_key for item_key, (_cvm_id, seen_at) in self._connect_identities.items() if seen_at < cutoff]
        for item_key in stale_keys:
            self._connect_identities.pop(item_key, None)
        if len(self._connect_identities) > MAX_CONNECT_IDENTITIES:
            self._connect_identities.clear()

    def responseheaders(self, flow: Any) -> None:
        # Stream the response body straight through instead of buffering the
        # whole thing in RAM. The SC's egress is dominated by large, long-lived
        # streaming responses (e.g. agent SSE), and buffering entire response
        # bodies is what drives the proxy into OOM. Requests are still fully
        # buffered (see request()/_request_body), so DLP request-body scanning
        # is unaffected. A counting callback keeps the traffic-log byte count
        # accurate even though response.content is not populated when streamed.
        response = getattr(flow, "response", None)
        if response is None:
            return
        metadata = _metadata(flow)
        metadata["concrete_streamed_bytes"] = 0

        def _count_streamed(chunk: bytes) -> bytes:
            metadata["concrete_streamed_bytes"] += len(chunk)
            return chunk

        response.stream = _count_streamed

    def response(self, flow: Any) -> None:
        metadata = _metadata(flow)
        traffic_log = metadata.pop("concrete_traffic_log", None)
        streamed_bytes = metadata.pop("concrete_streamed_bytes", None)
        if not isinstance(traffic_log, TrafficLogRecord):
            return
        response = getattr(flow, "response", None)
        if response is None:
            return
        status_code = int(getattr(response, "status_code", 0) or 0)
        # Streamed responses no longer populate response.content, so prefer the
        # byte count tallied by the stream callback; fall back to the buffered
        # body size for any response that was not streamed.
        if isinstance(streamed_bytes, int):
            bytes_transferred = streamed_bytes
        else:
            bytes_transferred = _response_body_size(response)
        self.traffic_emitter.enqueue(
            replace(
                traffic_log,
                response_code=status_code,
                bytes_transferred=bytes_transferred,
            )
        )

    def error(self, flow: Any) -> None:
        metadata = _metadata(flow)
        traffic_log = metadata.pop("concrete_traffic_log", None)
        metadata.pop("concrete_streamed_bytes", None)
        if not isinstance(traffic_log, TrafficLogRecord):
            return
        self.traffic_emitter.enqueue(replace(traffic_log, response_code=502, bytes_transferred=0))

    def _reject(self, flow: Any, result: EnforcementResult) -> None:
        if result.reason == "proxy_auth_unknown":
            logger.info(
                "proxy_auth_unknown",
                extra={
                    "cvm_id": None,
                    "proxy_token_hash_prefix": result.proxy_token_hash_prefix,
                },
            )
        elif result.reason == "policy_secret_injection_conflict":
            logger.info(
                "policy_secret_injection_conflict",
                extra={
                    "cvm_id": str(result.cvm.cvm_id) if result.cvm is not None else None,
                    "policy_version": result.cvm.policy_version if result.cvm is not None else None,
                },
            )
        if result.traffic_log is not None:
            self.traffic_emitter.enqueue(result.traffic_log)
        flow.response = self.response_factory(
            result.response_code or 403,
            _blocked_body(result),
            _blocked_headers(result),
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


def _websocket_traffic_log_record(request: ProxyRequest, cvm_id: UUID, *, decision: str) -> TrafficLogRecord:
    return TrafficLogRecord(
        timestamp=request.timestamp or datetime.now(timezone.utc),
        cvm_id=cvm_id,
        source_ip=request.source_ip,
        destination_ip=request.destination_ip,
        destination_host=request.host,
        protocol=request.scheme,
        port=request.port,
        method=request.method.upper(),
        path=request.path,
        response_code=None,
        bytes_transferred=0,
        attributes={},
        decision=decision,
    )


def mitmproxy_response_factory(status_code: int, content: bytes, headers: Mapping[str, str]) -> Any:
    from mitmproxy import http

    return http.Response.make(status_code, content, dict(headers))


def mitmproxy_websocket_injector(flow: Any, to_client: bool, message: bytes) -> None:
    from mitmproxy import ctx

    ctx.master.commands.call("inject.websocket", flow, to_client, message, True)


def _blocked_headers(result: EnforcementResult) -> dict[str, str]:
    headers = {"Content-Type": "text/plain; charset=utf-8"}
    if result.response_code == 403 and result.cvm is not None:
        headers.update(
            {
                "Proxy-Status": f"concrete-security-cvm; error={result.reason}",
                "X-Concrete-Blocked": "true",
                "X-Concrete-Block-Source": "profile",
                "X-Concrete-Block-Reason": result.reason,
                "X-Concrete-CVM-ID": str(result.cvm.cvm_id),
                "X-Concrete-Policy-Version": str(result.cvm.policy_version),
            }
        )
    return headers


def _blocked_body(result: EnforcementResult) -> bytes:
    auth_messages = {
        "proxy_auth_missing": "Concrete Proxy: Proxy authentication required\n",
        "proxy_auth_unknown": "Concrete Proxy: Proxy authentication required\n",
    }
    if result.reason in auth_messages:
        return auth_messages[result.reason].encode("utf-8")

    reason_messages = {
        "blocked_destination": "Reason: the destination is explicitly blocked.",
        "body_assertion_failed": "Reason: this endpoint is allowed only for specific request body values.",
        "destination_not_allowed": "Reason: this endpoint is not allowed.",
        "dlp_secret_detected": "Reason: profile DLP policy detected sensitive data.",
        "dlp_scan_timeout": "Reason: profile DLP scanning timed out.",
        "policy_secret_injection_conflict": "Reason: profile secret injection rules conflict.",
        "secret_injection_unfulfilled": (
            "Reason: a required secret injection has no usable credential for this CVM's owner "
            "(the referenced per-user secret is unminted, expired, or not bound to this host)."
        ),
    }
    body = "\n".join(
        [
            "Concrete network restriction: this request was blocked by the profile policy assigned to this Dev CVM.",
            reason_messages.get(result.reason, "Reason: profile policy blocked this request."),
            "This is a Concrete policy decision, not a network or server failure.",
            "",
        ]
    )
    return body.encode("utf-8")


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
    """Return the Content-Encoding-DECODED request body for inspection.

    `ProxyRequest.body` feeds DLP secret scanning, body assertions, and
    traffic-log attribute extraction — never request forwarding (mitmproxy
    forwards the original on-wire body untouched). Those inspectors must see the
    DECODED bytes: scanning the still-compressed `raw_content` lets a sandbox
    hide a secret behind `Content-Encoding: gzip` and slip it past DLP. When a
    declared content-coding cannot be decoded (unsupported codec, or a body that
    does not actually decompress) the SC fails CLOSED by raising
    FlowTranslationError, so the request is rejected rather than forwarded with
    an unreadable, unscanned body.
    """
    raw = _raw_request_body(request)
    encoding = _request_content_encoding(request)
    if encoding is None or not raw:
        return raw
    decoded = _decode_content_codings(raw, encoding, limit=DLP_SCAN_BODY_LIMIT_BYTES)
    if decoded is None:
        raise FlowTranslationError(f"undecodable content-encoding: {encoding!r}")
    return decoded


def _raw_request_body(request: Any) -> bytes:
    for attr in ("raw_content", "content"):
        value = getattr(request, attr, None)
        if isinstance(value, bytes):
            return value
    return b""


def _request_content_encoding(request: Any) -> str | None:
    raw = _header_value(getattr(request, "headers", None), "content-encoding")
    if raw is None:
        return None
    token = str(raw).strip()
    if not token or token.lower() == "identity":
        return None
    return token


def _header_value(headers: Any, name: str) -> str | None:
    # Real mitmproxy headers are case-insensitive; plain-dict test fakes are not,
    # so match case-insensitively over items().
    if headers is None:
        return None
    items = getattr(headers, "items", None)
    if callable(items):
        for key, value in items():
            if str(key).lower() == name:
                return str(value)
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter(name)
        if value is not None:
            return str(value)
    return None


def _decode_content_codings(raw: bytes, encoding: str, *, limit: int) -> bytes | None:
    # Content-Encoding lists codings in the order they were applied; undo them
    # right-to-left. Any unsupported coding fails the whole decode (caller fails
    # closed). Output is bounded to `limit` so a compression bomb cannot OOM the
    # SC; that matches the existing DLP scan-window truncation.
    codings = [token.strip().lower() for token in encoding.split(",") if token.strip()]
    decoded = raw
    for coding in reversed(codings):
        if coding == "identity":
            continue
        decoded = _inflate(decoded, coding, limit=limit)
        if decoded is None:
            return None
    return decoded


def _inflate(raw: bytes, coding: str, *, limit: int) -> bytes | None:
    if coding in ("gzip", "x-gzip"):
        wbits = 16 + zlib.MAX_WBITS
    elif coding == "deflate":
        wbits = zlib.MAX_WBITS
    else:
        # br / zstd / compress / unknown: the SC cannot inspect the plaintext,
        # so it must not forward it. Caller fails closed.
        return None
    decoded = _inflate_members(raw, wbits, limit)
    if decoded is None and coding == "deflate":
        # Some servers emit raw DEFLATE with no zlib header.
        decoded = _inflate_members(raw, -zlib.MAX_WBITS, limit)
    return decoded


def _inflate_members(raw: bytes, wbits: int, limit: int) -> bytes | None:
    # A Content-Encoding stream MAY be a concatenation of compressed members
    # (RFC 1952 §2.2 for gzip); conformant servers decode them ALL, so the SC
    # must too — otherwise a secret hidden in a later member is forwarded
    # unscanned (the destination reassembles it). Decode every member, bounded
    # to `limit`. Returns None to fail CLOSED when: a member is corrupt/
    # truncated, a member does not finish within the byte budget, OR the total
    # decoded output would exceed the budget (a body we cannot fully scan must
    # be rejected, not forwarded half-scanned).
    chunks: list[bytes] = []
    total = 0
    remaining = raw
    while remaining:
        decompressor = zlib.decompressobj(wbits)
        try:
            # +1 so an over-budget member yields a non-final result we can
            # detect (eof False) rather than silently truncating.
            out = decompressor.decompress(remaining, (limit - total) + 1)
        except zlib.error:
            return None
        if not decompressor.eof:
            return None
        chunks.append(out)
        total += len(out)
        if total > limit:
            return None
        remaining = decompressor.unused_data
    return b"".join(chunks)


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


def _latest_websocket_message(flow: Any) -> Any:
    websocket = getattr(flow, "websocket", None)
    messages = getattr(websocket, "messages", None)
    if not messages:
        return None
    return messages[-1]


def _trim_websocket_messages(flow: Any) -> None:
    websocket = getattr(flow, "websocket", None)
    messages = getattr(websocket, "messages", None)
    if messages is None:
        return
    excess = len(messages) - WS_MESSAGE_RETENTION
    if excess > 0:
        del messages[:excess]


def _is_websocket_control_message(message: Any) -> bool:
    for attr in ("opcode", "type"):
        raw = getattr(message, attr, None)
        opcode = _websocket_opcode_name(raw)
        if opcode in {"ping", "pong", "close"}:
            return True
    return False


def _websocket_opcode_name(raw: Any) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        value = raw
    else:
        name = getattr(raw, "name", None)
        value = name if isinstance(name, str) else str(raw)
    value = value.rsplit(".", 1)[-1].lower()
    return value or None


def _websocket_message_content(message: Any) -> bytes | None:
    content = getattr(message, "content", None)
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    return None


def _metadata(flow: Any) -> dict[str, Any]:
    metadata = getattr(flow, "metadata", None)
    if isinstance(metadata, dict):
        return metadata
    flow.metadata = {}
    return flow.metadata


def _connect_cvm(flow: Any, control_map: Any, identities: Mapping[str, tuple[str, float]]) -> Any:
    raw = _metadata(flow).get("concrete_cvm_id")
    if not isinstance(raw, str):
        key = _client_connection_key(flow)
        identity = identities.get(key) if key is not None else None
        if identity is not None and time.monotonic() - identity[1] <= CONNECT_IDENTITY_TTL_SECONDS:
            raw = identity[0]
    if not isinstance(raw, str):
        return None
    try:
        cvm_id = UUID(raw)
    except ValueError:
        return None
    return control_map.lookup_cvm_id(cvm_id)


def _flow_cvm_id(flow: Any) -> UUID | None:
    raw = _metadata(flow).get("concrete_cvm_id")
    if not isinstance(raw, str):
        return None
    try:
        return UUID(raw)
    except ValueError:
        return None


def _client_connection_key(flow: Any) -> str | None:
    return _connection_key_from_connection(getattr(flow, "client_conn", None))


def _connection_key_from_connection(connection: Any) -> str | None:
    if connection is None:
        return None
    for attr in ("address", "peername", "ip_address"):
        value = getattr(connection, attr, None)
        if isinstance(value, tuple) and len(value) >= 2:
            return f"{value[0]}:{value[1]}"
        if isinstance(value, str) and value:
            return value
    return f"id:{id(connection)}"
