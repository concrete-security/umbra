from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import asyncio
import random
from typing import Awaitable, Callable

from concrete_security_cvm.control import ControlMap, SCControlClient


@dataclass(frozen=True)
class ControlPlaneSnapshot:
    control_map: ControlMap
    updated_at: datetime


class ControlPlaneState:
    def __init__(self, initial: ControlMap | None = None) -> None:
        self._snapshot = ControlPlaneSnapshot(
            control_map=initial or ControlMap.from_console_payload({"entries": []}),
            updated_at=datetime.now(timezone.utc),
        )

    def snapshot(self) -> ControlPlaneSnapshot:
        return self._snapshot

    def replace(self, control_map: ControlMap) -> None:
        self._snapshot = ControlPlaneSnapshot(control_map=control_map, updated_at=datetime.now(timezone.utc))


async def poll_control_plane_once(client: SCControlClient, state: ControlPlaneState) -> bool:
    result = await client.poll_once(etag=state.snapshot().control_map.etag)
    if result.not_modified or result.control_map is None:
        return False
    state.replace(result.control_map)
    return True


async def run_control_plane_poll_loop(
    client: SCControlClient,
    state: ControlPlaneState,
    *,
    interval_seconds: float = 5.0,
    jitter_seconds: float = 1.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    random_uniform: Callable[[float, float], float] = random.uniform,
    max_iterations: int | None = None,
) -> None:
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")
    if jitter_seconds < 0:
        raise ValueError("jitter_seconds must be non-negative")
    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        await poll_control_plane_once(client, state)
        iterations += 1
        if max_iterations is not None and iterations >= max_iterations:
            break
        delay = interval_seconds + random_uniform(-jitter_seconds, jitter_seconds)
        await sleep(max(0.0, delay))
