import asyncio
import hashlib

from umbra_security_cvm.control import ControlMap, PollResult
from umbra_security_cvm.control_loop import ControlPlaneState, poll_control_plane_once, run_control_plane_poll_loop


def payload(token: bytes, etag: str) -> ControlMap:
    return ControlMap.from_console_payload(
        {
            "entries": [
                {
                    "cvm_id": "00000000-0000-4000-8000-000000000010",
                    "fqdn": "cvm-abc.dev.example.com",
                    "proxy_token_hash": hashlib.sha256(token).hexdigest(),
                    "merged_policy": {
                        "allowed_destinations": [],
                        "blocked_destinations": [],
                        "secret_patterns": [],
                        "secret_injections": [],
                        "sandbox_env": [],
                    },
                    "policy_version": 1,
                    "updated_at": "2026-05-16T06:00:00Z",
                }
            ]
        },
        etag=etag,
    )


class FakeClient:
    def __init__(self, results: list[PollResult | Exception]) -> None:
        self.results = results
        self.etags: list[str | None] = []

    async def poll_once(self, *, etag: str | None = None) -> PollResult:
        self.etags.append(etag)
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def test_poll_control_plane_once_swaps_on_200_and_keeps_map_on_304() -> None:
    state = ControlPlaneState()
    client = FakeClient(
        [
            PollResult(control_map=payload(b"proxy-token", '"next"'), etag='"next"', not_modified=False),
            PollResult(control_map=None, etag='"next"', not_modified=True),
        ]
    )

    assert asyncio.run(poll_control_plane_once(client, state)) is True
    assert state.snapshot().control_map.lookup_proxy_token("proxy-token") is not None
    assert asyncio.run(poll_control_plane_once(client, state)) is False
    assert state.snapshot().control_map.lookup_proxy_token("proxy-token") is not None
    assert client.etags == [None, '"next"']


def test_poll_loop_applies_jittered_sleep_between_iterations() -> None:
    state = ControlPlaneState()
    client = FakeClient(
        [
            PollResult(control_map=payload(b"one", '"one"'), etag='"one"', not_modified=False),
            PollResult(control_map=payload(b"two", '"two"'), etag='"two"', not_modified=False),
        ]
    )
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    asyncio.run(
        run_control_plane_poll_loop(
            client,  # type: ignore[arg-type]
            state,
            interval_seconds=5.0,
            jitter_seconds=1.0,
            sleep=fake_sleep,
            random_uniform=lambda low, high: high,
            max_iterations=2,
        )
    )

    assert sleeps == [6.0]
    assert state.snapshot().control_map.lookup_proxy_token("two") is not None


def test_poll_loop_keeps_running_after_transient_poll_failure() -> None:
    state = ControlPlaneState()
    client = FakeClient(
        [
            RuntimeError("console unavailable"),
            PollResult(control_map=payload(b"recovered", '"recovered"'), etag='"recovered"', not_modified=False),
        ]
    )
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    asyncio.run(
        run_control_plane_poll_loop(
            client,  # type: ignore[arg-type]
            state,
            interval_seconds=5.0,
            jitter_seconds=0.0,
            sleep=fake_sleep,
            random_uniform=lambda low, high: 0.0,
            max_iterations=2,
        )
    )

    assert sleeps == [5.0]
    assert state.snapshot().control_map.lookup_proxy_token("recovered") is not None
