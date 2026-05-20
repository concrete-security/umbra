"""TEE provider adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class CvmProviderError(RuntimeError):
    def __init__(self, code: str, *, provider: str = "unknown", output: str = ""):
        super().__init__(code)
        self.code = code
        self.provider = provider
        self.output = output


@dataclass(frozen=True)
class CvmProviderDeploymentResult:
    deployment_id: str
    gateway_host: str
    status: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class CvmProvider:
    provider: str
    client: Any

    @classmethod
    def from_settings(cls, *, timeout_seconds: float | None = None) -> CvmProvider:
        from concrete_console.tee_provider.phala import PhalaClient, PhalaError

        try:
            client = PhalaClient.from_settings(timeout_seconds=timeout_seconds)
        except PhalaError as exc:
            raise CvmProviderError(exc.code, provider="phala", output=exc.output) from exc
        return cls(provider="phala", client=client)

    async def deploy(
        self,
        *,
        name: str,
        compose_yaml: str,
        env: dict[str, str],
        instance_type: str | None = None,
        region: str | None = None,
    ) -> CvmProviderDeploymentResult:
        return self._result(
            await self._call(
                "deploy",
                name=name,
                compose_yaml=compose_yaml,
                env=env,
                instance_type=instance_type,
                region=region,
            )
        )

    async def update_deployment(
        self,
        *,
        deployment_id: str,
        compose_yaml: str,
        env: dict[str, str],
    ) -> CvmProviderDeploymentResult:
        return self._result(
            await self._call(
                "update",
                app_id=deployment_id,
                compose_yaml=compose_yaml,
                env=env,
            )
        )

    async def status(self, deployment_id: str) -> str:
        return await self._call("status", deployment_id)

    async def deployment_compose_sha256(self, deployment_id: str) -> str:
        return await self._call("compose_file_sha256", deployment_id)

    async def start(self, deployment_id: str) -> None:
        await self._call("start", deployment_id)

    async def stop(self, deployment_id: str) -> None:
        await self._call("stop", deployment_id)

    async def delete(self, deployment_id: str) -> None:
        await self._call("delete", deployment_id)

    async def _call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        from concrete_console.tee_provider.phala import PhalaError

        try:
            return await getattr(self.client, method)(*args, **kwargs)
        except PhalaError as exc:
            raise CvmProviderError(exc.code, provider=self.provider, output=exc.output) from exc

    def _result(self, result: Any) -> CvmProviderDeploymentResult:
        return CvmProviderDeploymentResult(
            deployment_id=result.app_id,
            gateway_host=result.gateway_host,
            status=result.status,
            raw=getattr(result, "raw", {}),
        )


def cvm_provider_from_settings(*, timeout_seconds: float | None = None) -> CvmProvider:
    return CvmProvider.from_settings(timeout_seconds=timeout_seconds)
