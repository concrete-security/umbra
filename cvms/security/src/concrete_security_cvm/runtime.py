from __future__ import annotations

from dataclasses import dataclass, field
import asyncio
from collections.abc import MutableMapping
import logging
import os
from threading import Thread
from typing import Awaitable, Callable, Mapping

from concrete_security_cvm.binding import BootBinding, REQUIRED_ENV
from concrete_security_cvm.ca import InMemoryRootCA, generate_root_ca
from concrete_security_cvm.control import SCControlClient
from concrete_security_cvm.control_loop import ControlPlaneState, run_control_plane_poll_loop
from concrete_security_cvm.management_http import serve_management_http
from concrete_security_cvm.traffic import (
    TrafficLogClient,
    TrafficLogEmitter,
    TrafficLogQueue,
    run_traffic_log_emitter_loop,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SecurityCVMRuntimeConfig:
    console_url: str
    entity_id: str
    sc_id: str
    ingest_token: str = field(repr=False)
    ca_export_token: str = field(repr=False)
    management_host: str = "0.0.0.0"
    management_port: int = 8081
    control_interval_seconds: float = 5.0
    control_jitter_seconds: float = 1.0
    traffic_flush_interval_seconds: float = 1.0

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | MutableMapping[str, str],
        *,
        consume_secrets: bool = False,
    ) -> SecurityCVMRuntimeConfig:
        missing = [name for name in REQUIRED_ENV if not env.get(name)]
        if missing:
            raise ValueError(f"missing Security CVM boot env: {', '.join(missing)}")
        config = cls(
            console_url=env["CONSOLE_URL"],
            entity_id=env["ENTITY_ID"],
            sc_id=env["SC_ID"],
            ingest_token=env["CONSOLE_INGEST_TOKEN"],
            ca_export_token=env["CA_EXPORT_TOKEN"],
            management_host=env.get("SC_MANAGEMENT_HOST", "0.0.0.0"),
            management_port=_parse_port(env.get("SC_MANAGEMENT_PORT", "8081")),
            control_interval_seconds=_parse_positive_float(
                env.get("SC_CONTROL_INTERVAL_SECONDS", "5.0"),
                "SC_CONTROL_INTERVAL_SECONDS",
            ),
            control_jitter_seconds=_parse_non_negative_float(
                env.get("SC_CONTROL_JITTER_SECONDS", "1.0"),
                "SC_CONTROL_JITTER_SECONDS",
            ),
            traffic_flush_interval_seconds=_parse_positive_float(
                env.get("SC_TRAFFIC_FLUSH_INTERVAL_SECONDS", "1.0"),
                "SC_TRAFFIC_FLUSH_INTERVAL_SECONDS",
            ),
        )
        if consume_secrets and isinstance(env, MutableMapping):
            env.pop("CONSOLE_INGEST_TOKEN", None)
            env.pop("CA_EXPORT_TOKEN", None)
        return config

    def boot_binding(self) -> BootBinding:
        return BootBinding.from_plaintexts(
            console_url=self.console_url,
            entity_id=self.entity_id,
            sc_id=self.sc_id,
            ingest_token=self.ingest_token,
            ca_export_token=self.ca_export_token,
        )


@dataclass
class SecurityCVMRuntime:
    config: SecurityCVMRuntimeConfig
    ca: InMemoryRootCA
    control_state: ControlPlaneState
    traffic_emitter: TrafficLogEmitter
    control_client: SCControlClient = field(repr=False)

    @classmethod
    def build(cls, config: SecurityCVMRuntimeConfig) -> SecurityCVMRuntime:
        ca = generate_root_ca()
        control_state = ControlPlaneState()
        control_client = SCControlClient(console_url=config.console_url, ingest_token=config.ingest_token)
        traffic_client = TrafficLogClient(console_url=config.console_url, ingest_token=config.ingest_token)
        traffic_emitter = TrafficLogEmitter(
            queue=TrafficLogQueue(),
            client=traffic_client,
            flush_interval_seconds=config.traffic_flush_interval_seconds,
        )
        return cls(
            config=config,
            ca=ca,
            control_state=control_state,
            traffic_emitter=traffic_emitter,
            control_client=control_client,
        )

    def start_management_thread(self) -> Thread:
        thread = Thread(
            target=serve_management_http,
            kwargs={
                "ca": self.ca,
                "ca_export_token": self.config.ca_export_token,
                "host": self.config.management_host,
                "port": self.config.management_port,
            },
            daemon=True,
            name="security-cvm-management-http",
        )
        thread.start()
        return thread

    async def run_background_loops(
        self,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        await asyncio.gather(
            run_control_plane_poll_loop(
                self.control_client,
                self.control_state,
                interval_seconds=self.config.control_interval_seconds,
                jitter_seconds=self.config.control_jitter_seconds,
                sleep=sleep,
            ),
            run_traffic_log_emitter_loop(self.traffic_emitter, sleep=sleep),
        )


def main() -> None:
    logging.basicConfig(level=os.environ.get("SC_LOG_LEVEL", "INFO"))
    config = SecurityCVMRuntimeConfig.from_env(os.environ, consume_secrets=True)
    binding = config.boot_binding()
    logger.info(
        "security_cvm_boot_binding_ready",
        extra={
            "entity_id": binding.entity_id,
            "sc_id": binding.sc_id,
            "rtmr3_digest": binding.rtmr3_digest(),
        },
    )
    runtime = SecurityCVMRuntime.build(config)
    runtime.start_management_thread()
    asyncio.run(runtime.run_background_loops())


def _parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError("SC_MANAGEMENT_PORT must be an integer") from exc
    if port <= 0 or port > 65535:
        raise ValueError("SC_MANAGEMENT_PORT must be 1..65535")
    return port


def _parse_positive_float(raw: str, name: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _parse_non_negative_float(raw: str, name: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


if __name__ == "__main__":
    main()
