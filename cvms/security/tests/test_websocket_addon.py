from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import time
import zlib
from typing import Mapping
from uuid import UUID

from umbra_security_cvm.control import ControlMap
from umbra_security_cvm.control_loop import ControlPlaneState
from umbra_security_cvm.mitmproxy_addon import CONNECT_IDENTITY_TTL_SECONDS, SecurityCVMProxyAddon
from umbra_security_cvm.traffic import TrafficLogClient, TrafficLogEmitter, TrafficLogQueue


CVM_ID = UUID("00000000-0000-4000-8000-000000000010")


@dataclass
class FakeResponse:
    status_code: int
    raw_content: bytes
    headers: Mapping[str, str]


@dataclass
class FakeConnection:
    address: tuple[str, int]
    ip_address: tuple[str, int] | None = None


@dataclass
class FakeWebSocketMessage:
    content: bytes
    from_client: bool = False
    injected: bool = False
    is_text: bool = True
    opcode: str | None = None
    dropped: bool = False

    @property
    def text(self) -> str:
        return self.content.decode("utf-8")

    def drop(self) -> None:
        self.dropped = True


@dataclass
class FakeWebSocketData:
    messages: list[FakeWebSocketMessage] = field(default_factory=list)


class FakeRequest:
    def __init__(self, *, host: str = "wss-primary.slack.com", port: int = 443) -> None:
        self.scheme = "https"
        self.host = host
        self.port = port
        self.method = "GET"
        self.path = "/link/?ticket=abc"
        self.authority = None
        self.pretty_url = None
        self.headers: dict[str, str] = {}
        self.raw_content = b""


class FakeFlow:
    def __init__(self, messages: list[FakeWebSocketMessage], *, metadata: dict[str, object] | None = None) -> None:
        self.request = FakeRequest()
        self.response: FakeResponse | None = None
        self.metadata: dict[str, object] = {"umbra_cvm_id": str(CVM_ID)} if metadata is None else metadata
        self.client_conn = FakeConnection(("10.0.0.5", 52344))
        self.server_conn = FakeConnection(("198.51.100.7", 443), ("198.51.100.7", 443))
        self.websocket = FakeWebSocketData(messages=messages)


def response_factory(status_code: int, content: bytes, headers: Mapping[str, str]) -> FakeResponse:
    return FakeResponse(status_code=status_code, raw_content=content, headers=headers)


def slack_policy() -> dict[str, object]:
    return {
        "allowed_destinations": [
            {
                "id": "slack-socket-mode",
                "scheme": "https",
                "host": "wss-primary.slack.com",
                "ports": [443],
                "methods": ["GET"],
                "path_prefixes": ["/"],
                "websocket_assertions": [
                    {
                        "direction": "inbound",
                        "when": {"/type": "events_api"},
                        "require": {
                            "/payload/event/channel": {"in": ["C0ALLOWED"]},
                            "/payload/event/user": {"in": ["U0ALLOWED"]},
                        },
                        "on_violation": "drop",
                        "on_drop_emit": {"envelope_id": "{/envelope_id}"},
                    }
                ],
            }
        ],
        "blocked_destinations": [],
        "secret_patterns": [],
        "secret_injections": [],
        "sandbox_env": [],
    }


def addon(policy: dict[str, object] | None = None) -> tuple[SecurityCVMProxyAddon, TrafficLogQueue, list[dict[str, object]]]:
    queue = TrafficLogQueue(max_entries=100, max_bytes=100_000)
    client = TrafficLogClient(console_url="https://console.example.com", ingest_token="ingest")
    emitter = TrafficLogEmitter(queue=queue, client=client)
    state = ControlPlaneState(
        control_map_for_policy(policy or slack_policy())
    )
    proxy_addon = SecurityCVMProxyAddon(
        control_state=state, traffic_emitter=emitter, response_factory=response_factory
    )
    injected: list[dict[str, object]] = []
    proxy_addon.websocket_injector = lambda flow, to_client, message: injected.append(
        {"flow": flow, "to_client": to_client, "message": message}
    )
    return proxy_addon, queue, injected


def control_map_for_policy(policy: dict[str, object]) -> ControlMap:
    return ControlMap.from_console_payload(
        {
            "entries": [
                {
                    "cvm_id": str(CVM_ID),
                    "fqdn": "cvm-abc.dev.example.com",
                    "proxy_token_hash": hashlib.sha256(b"proxy-token").hexdigest(),
                    "merged_policy": policy,
                    "policy_version": 3,
                    "updated_at": "2026-05-16T06:20:00Z",
                }
            ]
        }
    )


def events_api_message(*, channel: str = "C0ALLOWED", user: str = "U0ALLOWED") -> FakeWebSocketMessage:
    return FakeWebSocketMessage(
        content=json.dumps(
            {
                "envelope_id": "env-123",
                "type": "events_api",
                "payload": {"event": {"channel": channel, "user": user}},
            }
        ).encode("utf-8")
    )


def test_inbound_allowed_channel_not_dropped_no_ack_no_log() -> None:
    proxy_addon, queue, injected = addon()
    message = events_api_message()
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is False
    assert injected == []
    assert len(queue) == 0


def test_inbound_blocked_channel_drops_acks_and_logs_without_contents() -> None:
    proxy_addon, queue, injected = addon()
    message = events_api_message(channel="C0BLOCKED")
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is True
    assert len(injected) == 1
    assert injected[0]["to_client"] is False
    assert json.loads(injected[0]["message"]) == {"envelope_id": "env-123"}

    batch = queue.drain_batch()
    assert batch is not None
    assert len(batch.records) == 1
    log = batch.records[0]
    assert log.cvm_id == CVM_ID
    assert log.destination_host == "wss-primary.slack.com"
    assert log.protocol == "https"
    assert log.port == 443
    assert log.method == "GET"
    assert log.response_code is None
    payload = json.dumps(log.to_json())
    assert "C0BLOCKED" not in payload
    assert "env-123" not in payload


def test_inbound_blocked_sender_drops() -> None:
    proxy_addon, queue, injected = addon()
    message = events_api_message(user="U0OTHER")
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is True
    assert len(injected) == 1


def test_lifecycle_frame_passes_and_emits_contents_free_audit_log() -> None:
    proxy_addon, queue, injected = addon()
    message = FakeWebSocketMessage(
        content=json.dumps({"type": "hello", "num_connections": 1, "debug_info": {}}).encode("utf-8")
    )
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    # Delivered (not dropped, no ack injected), but the bounded telemetry
    # exemption is now AUDITED: one contents-free traffic log is emitted.
    assert message.dropped is False
    assert injected == []
    batch = queue.drain_batch()
    assert batch is not None
    assert len(batch.records) == 1
    log = batch.records[0]
    assert log.cvm_id == CVM_ID
    assert log.destination_host == "wss-primary.slack.com"
    assert log.method == "GET"
    assert log.response_code is None
    assert log.attributes == {}


def test_oversized_lifecycle_frame_drops_regardless_of_assertions() -> None:
    # WSIN-01 round-2: a hello frame whose total content exceeds the per-frame
    # budget is no longer exempt; it is dropped (not delivered) even though no
    # events_api assertion selects it.
    proxy_addon, queue, injected = addon()
    smuggle = {"type": "hello", "connection_info": {"note": "Z" * 5000}}
    message = FakeWebSocketMessage(content=json.dumps(smuggle).encode("utf-8"))
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is True
    assert len(queue) == 1


def test_lifecycle_frame_with_payload_fails_closed_when_assertions_govern_tunnel() -> None:
    proxy_addon, queue, injected = addon()
    message = FakeWebSocketMessage(content=json.dumps({"type": "hello", "payload": {"text": "hi"}}).encode("utf-8"))
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is True
    assert injected == []
    assert len(queue) == 1


def test_binary_non_json_frame_drops_when_assertions_govern_tunnel() -> None:
    proxy_addon, queue, injected = addon()
    message = FakeWebSocketMessage(content=b"\x00\x01\x02", is_text=False)
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is True
    assert injected == []
    assert len(queue) == 1


def test_binary_valid_json_frame_drops_when_assertions_govern_tunnel() -> None:
    proxy_addon, queue, injected = addon()
    message = events_api_message()
    message.is_text = False
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is True
    assert injected == []
    assert len(queue) == 1


def test_compressed_inbound_events_api_frame_fails_closed() -> None:
    proxy_addon, queue, injected = addon()
    compressed = zlib.compress(events_api_message(channel="C0BLOCKED", user="U0OTHER").content)
    message = FakeWebSocketMessage(content=compressed, is_text=False)
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is True
    assert injected == []
    assert len(queue) == 1


def test_unselected_inbound_frame_fails_closed_when_assertions_govern_tunnel() -> None:
    proxy_addon, queue, injected = addon()
    message = FakeWebSocketMessage(
        content=json.dumps({"type": "slash_commands", "payload": {"channel_id": "C0OTHER"}}).encode("utf-8")
    )
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is True
    assert injected == []
    assert len(queue) == 1


def test_websocket_control_opcode_passes_without_filtering() -> None:
    proxy_addon, queue, injected = addon()
    message = FakeWebSocketMessage(content=b"", is_text=False, opcode="ping")
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is False
    assert injected == []
    assert len(queue) == 0


def test_websocket_upgrade_persists_connect_identity_beyond_ttl() -> None:
    proxy_addon, queue, injected = addon()
    flow = FakeFlow([], metadata={})
    proxy_addon._connect_identities["10.0.0.5:52344"] = (str(CVM_ID), time.monotonic())

    proxy_addon.request(flow)

    assert flow.response is None
    assert flow.metadata["umbra_cvm_id"] == str(CVM_ID)
    assert flow.metadata["umbra_websocket_governed"] is True
    proxy_addon._connect_identities["10.0.0.5:52344"] = (
        str(CVM_ID),
        time.monotonic() - CONNECT_IDENTITY_TTL_SECONDS - 1,
    )
    message = events_api_message(channel="C0BLOCKED")
    flow.websocket.messages.append(message)

    proxy_addon.websocket_message(flow)

    assert message.dropped is True
    assert len(injected) == 1


def test_governed_websocket_drops_when_control_map_loses_cvm() -> None:
    proxy_addon, queue, injected = addon()
    flow = FakeFlow(
        [events_api_message()],
        metadata={"umbra_cvm_id": str(CVM_ID), "umbra_websocket_governed": True},
    )
    proxy_addon.control_state.replace(ControlMap.from_console_payload({"entries": []}))

    proxy_addon.websocket_message(flow)

    assert flow.websocket.messages[-1].dropped is True
    assert injected == []
    assert len(queue) == 1


def test_governed_websocket_drops_when_current_policy_removes_assertions() -> None:
    proxy_addon, queue, injected = addon()
    no_ws_policy = slack_policy()
    no_ws_policy["allowed_destinations"][0]["websocket_assertions"] = []
    flow = FakeFlow(
        [events_api_message()],
        metadata={"umbra_cvm_id": str(CVM_ID), "umbra_websocket_governed": True},
    )
    proxy_addon.control_state.replace(control_map_for_policy(no_ws_policy))

    proxy_addon.websocket_message(flow)

    assert flow.websocket.messages[-1].dropped is True
    assert injected == []
    assert len(queue) == 1


def test_outbound_from_client_message_untouched() -> None:
    proxy_addon, queue, injected = addon()
    message = events_api_message(channel="C0BLOCKED")
    message.from_client = True
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is False
    assert injected == []
    assert len(queue) == 0


def test_injected_ack_frame_not_refiltered() -> None:
    proxy_addon, queue, injected = addon()
    message = events_api_message(channel="C0BLOCKED")
    message.injected = True
    flow = FakeFlow([message])

    proxy_addon.websocket_message(flow)

    assert message.dropped is False
    assert injected == []
    assert len(queue) == 0


def test_inbound_websocket_messages_do_not_accumulate_unboundedly() -> None:
    # Regression for the SC OOM leak (introduced by 579bbad): mitmproxy appends every inbound
    # frame to flow.websocket.messages and retains them for the flow's lifetime. The SC addon
    # only ever needs the latest frame (`messages[-1]`), so it MUST bound that list — otherwise a
    # long-lived inbound WS channel (e.g. Slack Socket Mode) grows RSS without limit and OOMs the
    # SC (tdx.small, ~2 GB, no swap). This drives 1000 inbound frames through the addon and asserts
    # the retained list stays bounded. Without the trim, len(messages) == 1000 here.
    proxy_addon, queue, injected = addon()
    messages: list[FakeWebSocketMessage] = []
    flow = FakeFlow(messages)
    frames = 1000
    for _ in range(frames):
        messages.append(events_api_message())  # mitmproxy appends each inbound frame
        proxy_addon.websocket_message(flow)
    assert len(flow.websocket.messages) < 50, (
        f"flow.websocket.messages grew to {len(flow.websocket.messages)} after {frames} frames — "
        "unbounded WebSocket frame retention will OOM the Security CVM"
    )


def test_inbound_websocket_dropped_frames_do_not_accumulate() -> None:
    # Same leak, on the deny path: blocked frames are dropped and an ack is injected; mitmproxy
    # still retains every original frame (and, live, each injected ack) in flow.websocket.messages.
    # The retained list must stay bounded regardless of verdict.
    proxy_addon, queue, injected = addon()
    messages: list[FakeWebSocketMessage] = []
    flow = FakeFlow(messages)
    for _ in range(1000):
        messages.append(events_api_message(channel="C0BLOCKED"))
        proxy_addon.websocket_message(flow)
    assert len(flow.websocket.messages) < 50, len(flow.websocket.messages)


# --- Frame-type scope-edge coverage (the Slack read-only containment class) ---------------------
#
# A single `when: {"/type": "events_api"}` assertion that requires the FLAT
# /payload/event/{channel,user} pointers is BOTH:
#   - too aggressive: events_api subtypes that nest channel/user elsewhere (assistant_thread_*)
#     are selected but their require pointers are missing -> over-DROPPED (breaks the assistant pane);
#   - too narrow: slash_commands / interactive frames are a different envelope `type`, so they are
#     never selected -> pass UNFILTERED (escape channel/sender containment).
# The fix is profile-authoring: keep the generic events_api guard and ADD per-envelope-type guards
# that point `require` at each family's real channel/user pointers. Delivery is a cross-assertion
# UNION, so the specific guard delivers a frame the generic guard would have dropped.


def assistant_thread_started(*, channel: str = "C0ALLOWED", user: str = "U0ALLOWED") -> FakeWebSocketMessage:
    return FakeWebSocketMessage(
        content=json.dumps(
            {
                "envelope_id": "env-at",
                "type": "events_api",
                "payload": {"event": {"type": "assistant_thread_started",
                                      "assistant_thread": {"channel_id": channel, "user_id": user}}},
            }
        ).encode("utf-8")
    )


def slash_command(*, channel: str = "C0ALLOWED", user: str = "U0ALLOWED") -> FakeWebSocketMessage:
    return FakeWebSocketMessage(
        content=json.dumps(
            {"envelope_id": "env-sl", "type": "slash_commands",
             "payload": {"command": "/foo", "channel_id": channel, "user_id": user}}
        ).encode("utf-8")
    )


def interactive(*, channel: str = "C0ALLOWED", user: str = "U0ALLOWED") -> FakeWebSocketMessage:
    return FakeWebSocketMessage(
        content=json.dumps(
            {"envelope_id": "env-ix", "type": "interactive",
             "payload": {"channel": {"id": channel}, "user": {"id": user}}}
        ).encode("utf-8")
    )


def corrected_slack_policy() -> dict[str, object]:
    policy = slack_policy()
    policy["allowed_destinations"][0]["websocket_assertions"].extend(
        [
            {
                "direction": "inbound",
                "when": {"/type": "events_api", "/payload/event/type": "assistant_thread_started"},
                "require": {
                    "/payload/event/assistant_thread/channel_id": {"in": ["C0ALLOWED"]},
                    "/payload/event/assistant_thread/user_id": {"in": ["U0ALLOWED"]},
                },
                "on_violation": "drop",
            },
            {
                "direction": "inbound",
                "when": {"/type": "slash_commands"},
                "require": {"/payload/channel_id": {"in": ["C0ALLOWED"]},
                            "/payload/user_id": {"in": ["U0ALLOWED"]}},
                "on_violation": "drop",
            },
            {
                "direction": "inbound",
                "when": {"/type": "interactive"},
                "require": {"/payload/channel/id": {"in": ["C0ALLOWED"]},
                            "/payload/user/id": {"in": ["U0ALLOWED"]}},
                "on_violation": "drop",
            },
        ]
    )
    return policy


def test_single_events_api_guard_overdrops_assistant_thread_and_drops_unselected_frames() -> None:
    # Baseline documenting the profile-authoring bug the corrected policy fixes.
    proxy_addon, queue, injected = addon(slack_policy())
    at = assistant_thread_started()
    proxy_addon.websocket_message(FakeFlow([at]))
    assert at.dropped is True  # assistant pane frame WRONGLY dropped (require paths missing)
    sl = slash_command(channel="C0OTHER", user="U0OTHER")
    proxy_addon.websocket_message(FakeFlow([sl]))
    assert sl.dropped is True  # unselected frames now fail closed instead of leaking


def test_corrected_policy_delivers_assistant_thread_and_contains_slash_interactive() -> None:
    proxy_addon, queue, injected = addon(corrected_slack_policy())

    # app_mention still filtered correctly by the generic guard.
    allowed = events_api_message()
    proxy_addon.websocket_message(FakeFlow([allowed]))
    assert allowed.dropped is False

    # assistant_thread_started in the allowed DM/channel is now DELIVERED (was dropped).
    at_ok = assistant_thread_started()
    proxy_addon.websocket_message(FakeFlow([at_ok]))
    assert at_ok.dropped is False

    # assistant_thread_started in a non-allowed channel is dropped.
    at_bad = assistant_thread_started(channel="C0OTHER")
    proxy_addon.websocket_message(FakeFlow([at_bad]))
    assert at_bad.dropped is True

    # slash + interactive are now under channel/sender containment.
    for off in (slash_command(channel="C0OTHER", user="U0OTHER"), interactive(user="U0OTHER")):
        proxy_addon.websocket_message(FakeFlow([off]))
        assert off.dropped is True
    for ok in (slash_command(), interactive()):
        proxy_addon.websocket_message(FakeFlow([ok]))
        assert ok.dropped is False
