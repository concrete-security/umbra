"""TEE provider adapters."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import math
import re
from typing import Any

# Error codes that cross the adapter boundary: raised by provider adapters,
# classified by consumers (e.g. the instance-type catalog). Single authorship
# so a rename cannot silently break the string comparison on the other side.
PROVIDER_ERROR_NOT_CONFIGURED = "not_configured"
PROVIDER_ERROR_INSTANCE_TYPES_SCHEMA_DRIFT = "instance_types_schema_drift"

# Instance-type catalog contract values shared by the adapter parser and the
# catalog service (defense in depth re-checks the same rules on DB loads).
# The 64-char cap mirrors the launch request-body bound (routes.py CVMCreate).
INSTANCE_TYPE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# Hard bound on parsed catalog entries; a genuine catalog is ~10 items, so the
# cap only bites on a hostile/broken payload (the service logs when it does).
MAX_INSTANCE_TYPE_ENTRIES = 512
# Hard bound on the decoded instance-types response size (a real catalog is a few
# KB); trips only on a hostile/broken response, before json.loads builds the tree.
MAX_INSTANCE_TYPES_RESPONSE_BYTES = 5 * 1024 * 1024


# -- instance-type field validators (the single validation authority) ----------
#
# One home for the numeric field contract, shared by BOTH the provider parser and
# the catalog's DB reload -- so a value the provider would reject can never slip in
# via a tampered/legacy DB row (defense in depth, exactly like INSTANCE_TYPE_NAME_RE
# above guards the name on both paths). Each returns the canonical value or None; a
# None never crashes a caller, it just drops that one field.


def instance_type_vcpu(value: Any) -> int | None:
    """vcpu contract: a positive integer. bools (an int subclass) are rejected."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def instance_type_memory_gb(value: Any) -> int | float | None:
    """memory_gb contract: a positive, finite number of GB, int when whole. Validates
    the GB value both after the provider's MB->GB conversion and on DB reload; the
    MB->GB conversion (and display rounding) stays in the provider parser upstream."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        return None
    return int(value) if float(value).is_integer() else value


def instance_type_hourly_rate(value: Any) -> float | None:
    """hourly_rate contract: a non-negative, finite number. Numeric strings are
    accepted (the provider sometimes sends them; the DB stores plain floats)."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        rate = Decimal(str(value).strip())
    except InvalidOperation:
        return None
    if not rate.is_finite() or rate < 0:
        return None
    # A large-but-finite Decimal (e.g. "1e400") passes is_finite() yet overflows
    # float() to inf; re-check so a non-finite float never reaches the catalog
    # (it would break the endpoint's JSON serialization).
    rate_f = float(rate)
    return rate_f if math.isfinite(rate_f) else None


class CvmProviderError(RuntimeError):
    def __init__(self, code: str, *, provider: str = "unknown", output: str = "", field: str | None = None):
        super().__init__(code)
        self.code = code
        self.provider = provider
        self.output = output
        self.field = field


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
        from umbra_console.tee_provider.phala import PhalaClient, PhalaError

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
        disk_size_gb: int | None = None,
    ) -> CvmProviderDeploymentResult:
        return self._result(
            await self._call(
                "deploy",
                name=name,
                compose_yaml=compose_yaml,
                env=env,
                instance_type=instance_type,
                region=region,
                disk_size_gb=disk_size_gb,
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

    async def list_instance_types(self) -> list[dict[str, Any]]:
        return await self._call("list_instance_types")

    async def deployment_compose_sha256(self, deployment_id: str) -> str:
        return await self._call("compose_file_sha256", deployment_id)

    async def start(self, deployment_id: str) -> None:
        await self._call("start", deployment_id)

    async def stop(self, deployment_id: str) -> None:
        await self._call("stop", deployment_id)

    async def delete(self, deployment_id: str) -> None:
        await self._call("delete", deployment_id)

    async def _call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        from umbra_console.tee_provider.phala import PhalaError

        try:
            return await getattr(self.client, method)(*args, **kwargs)
        except PhalaError as exc:
            raise CvmProviderError(exc.code, provider=self.provider, output=exc.output, field=exc.field) from exc

    def _result(self, result: Any) -> CvmProviderDeploymentResult:
        return CvmProviderDeploymentResult(
            deployment_id=result.app_id,
            gateway_host=result.gateway_host,
            status=result.status,
            raw=getattr(result, "raw", {}),
        )


def cvm_provider_from_settings(*, timeout_seconds: float | None = None) -> CvmProvider:
    return CvmProvider.from_settings(timeout_seconds=timeout_seconds)
