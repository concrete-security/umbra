from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Mapping

from concrete_security_cvm.ca import write_mitmproxy_ca_files
from concrete_security_cvm.mitmproxy_addon import ResponseFactory, SecurityCVMProxyAddon
from concrete_security_cvm.runtime import SecurityCVMRuntime, SecurityCVMRuntimeConfig


MITMPROXY_SCRIPT_ENV = "CONCRETE_SECURITY_CVM_MITMPROXY_SCRIPT"
DEFAULT_MITMPROXY_CONFDIR = "/tmp/mitmproxy"
DEFAULT_MITMPROXY_HOST = "0.0.0.0"
DEFAULT_MITMPROXY_PORT = "8080"


class SecurityCVMMitmproxyRuntime(SecurityCVMProxyAddon):
    def __init__(self, *, runtime: SecurityCVMRuntime, response_factory: ResponseFactory | None = None) -> None:
        super().__init__(
            control_state=runtime.control_state,
            traffic_emitter=runtime.traffic_emitter,
            response_factory=response_factory,
        )
        self.runtime = runtime
        self._management_thread: Any = None
        self._background_task: asyncio.Task[None] | None = None

    async def running(self) -> None:
        self._management_thread = self.runtime.start_management_thread()
        self._background_task = asyncio.create_task(self.runtime.run_background_loops())

    def done(self) -> None:
        if self._background_task is not None:
            self._background_task.cancel()


def build_runtime_addon_from_env(
    env: Mapping[str, str] | None = None,
    *,
    response_factory: ResponseFactory | None = None,
) -> SecurityCVMMitmproxyRuntime:
    source = os.environ if env is None else env
    config = SecurityCVMRuntimeConfig.from_env(source, consume_secrets=source is os.environ)
    runtime = SecurityCVMRuntime.build(config)
    confdir = Path(source.get("SC_MITMPROXY_CONFDIR", DEFAULT_MITMPROXY_CONFDIR))
    write_mitmproxy_ca_files(runtime.ca, confdir)
    return SecurityCVMMitmproxyRuntime(runtime=runtime, response_factory=response_factory)


def mitmdump_args(*, script_path: str | None = None, env: Mapping[str, str] | None = None) -> list[str]:
    source = os.environ if env is None else env
    confdir = source.get("SC_MITMPROXY_CONFDIR", DEFAULT_MITMPROXY_CONFDIR)
    host = source.get("SC_MITMPROXY_HOST", DEFAULT_MITMPROXY_HOST)
    port = source.get("SC_MITMPROXY_PORT", DEFAULT_MITMPROXY_PORT)
    return [
        "mitmdump",
        "--mode",
        "regular",
        "--listen-host",
        host,
        "--listen-port",
        port,
        "--set",
        f"confdir={confdir}",
        "--set",
        "ssl_insecure=false",
        "--set",
        "flow_detail=0",
        "-s",
        script_path or str(Path(__file__).resolve()),
    ]


def main() -> None:
    os.environ[MITMPROXY_SCRIPT_ENV] = "1"
    os.execvp("mitmdump", mitmdump_args())


addons = [build_runtime_addon_from_env()] if os.environ.get(MITMPROXY_SCRIPT_ENV) == "1" else []


if __name__ == "__main__":
    main()
