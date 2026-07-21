"""Instance-type catalog: last-known-good cache of the provider's launchable machine types.

Lifecycle:
- virgin boot: memory and DB are seeded with the built-in bootstrap snapshot
  immediately, then a background provider fetch replaces both on success; the boot
  never waits on the provider.
- warm boot: load the persisted catalog immediately (source becomes "database",
  `fetched_at` untouched), then refresh asynchronously without blocking startup.
- steady state: the reconciliation pass calls `spawn_refresh_if_due()` (non-blocking,
  due-gated); success schedules the next refresh at +24h (+ jitter), failure walks
  the retry ladder.
- reads (`GET /instance-types`, launch validation) are memory-only and never call
  the provider inline; an explicit `?refresh=true` does one bounded inline fetch,
  and a stale non-refresh read additionally kicks a due-gated background refresh
  via `spawn_refresh_if_due` (the same entry point the reconciliation pass uses).

The in-memory catalog is an immutable value object replaced atomically only after
a successful fetch + parse; failures only attach `last_refresh_error`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import json
import random
from typing import Any

from concrete_console.audit_anchor import as_utc, parse_iso_z
from concrete_console.db import get_pool
from concrete_console.log_config import logger
from concrete_console.resources import json_payload, timestamp
from concrete_console.tee_provider import (
    INSTANCE_TYPE_NAME_RE,
    MAX_INSTANCE_TYPE_ENTRIES,
    PROVIDER_ERROR_INSTANCE_TYPES_SCHEMA_DRIFT,
    PROVIDER_ERROR_NOT_CONFIGURED,
    CvmProvider,
    CvmProviderError,
    instance_type_hourly_rate,
    instance_type_memory_gb,
    instance_type_vcpu,
)

log = logger()

RETRY_LADDER_SECONDS = (300, 600, 3600, 21600, 43200, 86400)  # 5m 10m 1h 6h 12h 24h
REFRESH_INTERVAL_SECONDS = 86400
REFRESH_JITTER_MAX_SECONDS = 7200
# Derived so a healthy catalog can never be reported stale: the next scheduled
# refresh lands at most interval + max jitter after the last one, plus 1h grace.
STALE_AFTER_SECONDS = REFRESH_INTERVAL_SECONDS + REFRESH_JITTER_MAX_SECONDS + 3600  # 27h
BACKGROUND_FETCH_TIMEOUT_SECONDS = 60.0
INLINE_REFRESH_TIMEOUT_SECONDS = 30.0

# Refresh reasons; REASON_MANUAL is behavior-bearing (manual failures never
# advance the retry ladder), the others are telemetry labels.
REASON_BOOT = "boot"
REASON_SCHEDULER = "scheduler"
REASON_STALE_READ = "stale_read"
REASON_MANUAL = "manual"

SOURCE_PROVIDER = "provider"
SOURCE_DATABASE = "database"
SOURCE_BOOTSTRAP_FALLBACK = "bootstrap_fallback"

ERROR_KIND_PROVIDER_UNREACHABLE = "provider_unreachable"
ERROR_KIND_SCHEMA_DRIFT = "schema_drift"

DESCRIPTIVE_FIELDS = ("family", "vcpu", "memory_gb", "hourly_rate")

CATALOG_ROW_ID = 1


def is_instance_type_launchable(*, family: str | None) -> bool:
    # GPU types stay catalogued and visible but are not launchable yet: there is
    # no measured GPU dstack image, so a launch would fail attestation. Normalize
    # the label so "GPU"/"gpu " can't slip past the check. An unknown/absent family
    # stays launchable ON PURPOSE: making it non-launchable would turn a benign
    # provider family-rename into an entity-wide launch outage, whereas a
    # mislabelled GPU that slips through is caught by attestation (a wasted
    # provisioning cycle, not un-attested execution). Generalize to a capability
    # map only once per-instance-type measured images actually exist.
    return (family or "").strip().lower() != "gpu"


@dataclass(frozen=True)
class RefreshError:
    kind: str  # "provider_unreachable" | "schema_drift"
    field: str | None  # schema_drift locus: "envelope" | "result" | "items"
    at: datetime

    def payload(self) -> dict[str, Any]:
        return {"kind": self.kind, "field": self.field, "at": isoformat(self.at)}

    @classmethod
    def from_payload(cls, raw: Any) -> RefreshError | None:
        if not isinstance(raw, dict):
            return None
        kind = raw.get("kind")
        at = parse_timestamp(raw.get("at"))
        if kind not in (ERROR_KIND_PROVIDER_UNREACHABLE, ERROR_KIND_SCHEMA_DRIFT) or at is None:
            return None
        field = raw.get("field")
        return cls(kind=kind, field=field if isinstance(field, str) else None, at=at)


@dataclass(frozen=True)
class InstanceType:
    name: str
    family: str | None
    vcpu: int | None
    memory_gb: int | float | None
    hourly_rate: float | None
    currency: str | None

    @property
    def launchable(self) -> bool:
        return is_instance_type_launchable(family=self.family)

    def payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "family": self.family,
            "vcpu": self.vcpu,
            "memory_gb": self.memory_gb,
            "hourly_rate": self.hourly_rate,
            "currency": self.currency,
            "launchable": self.launchable,
        }

    @classmethod
    def from_payload(cls, raw: Any) -> InstanceType | None:
        # Every field is validated through the same authority the provider parser
        # uses (name regex + instance_type_* numeric contract), so a tampered or
        # legacy DB row cannot smuggle an out-of-spec name OR an out-of-range number
        # (zero/negative vcpu or memory, negative price) into the in-memory catalog.
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            return None
        if not INSTANCE_TYPE_NAME_RE.fullmatch(raw["name"]):
            return None
        hourly_rate = instance_type_hourly_rate(raw.get("hourly_rate"))
        return cls(
            name=raw["name"],
            family=string_or_none(raw.get("family")),
            vcpu=instance_type_vcpu(raw.get("vcpu")),
            memory_gb=instance_type_memory_gb(raw.get("memory_gb")),
            hourly_rate=hourly_rate,
            # Spec §3.6a: currency is null whenever hourly_rate is. The provider parse
            # path enforces this coupling; re-enforce it on reload too, so a tampered or
            # legacy row can't serve a currency without a price.
            currency=string_or_none(raw.get("currency")) if hourly_rate is not None else None,
        )


@dataclass(frozen=True)
class InstanceTypeCatalog:
    instance_types: tuple[InstanceType, ...]
    fetched_at: datetime | None
    source: str  # "provider" | "database" | "bootstrap_fallback"
    last_refresh_error: RefreshError | None

    def is_stale(self, now: datetime) -> bool:
        if self.fetched_at is None:
            return True
        return (now - self.fetched_at).total_seconds() > STALE_AFTER_SECONDS

    def names(self) -> frozenset[str]:
        return frozenset(entry.name for entry in self.instance_types)

    def launchable_names(self) -> frozenset[str]:
        return frozenset(entry.name for entry in self.instance_types if entry.launchable)

    def field_miss_counts(self) -> dict[str, int]:
        """Machine-readable drift report: per expected descriptive field, how many
        entries failed to parse it (absent, renamed, or an invalid value all
        normalize to None). Empty dict == every expected field has a valid value
        on every entry, so tests/monitoring can assert it empty. The single source
        for both the wire payload and the operator WARNING log; human wording is
        left to consumers (the CLI renders the sentence)."""
        return {
            field: miss
            for field in DESCRIPTIVE_FIELDS
            if (miss := sum(1 for entry in self.instance_types if getattr(entry, field) is None))
        }

    def catalog_metadata(self, *, now: datetime, refresh_in_progress: bool) -> dict[str, Any]:
        return {
            "source": self.source,
            "fetched_at": isoformat(self.fetched_at),
            "stale": self.is_stale(now),
            "refresh_in_progress": refresh_in_progress,
            "last_refresh_error": self.last_refresh_error.payload() if self.last_refresh_error else None,
            "field_miss_counts": self.field_miss_counts(),
        }

    def payload(self, *, now: datetime, refresh_in_progress: bool, default_name: str | None) -> dict[str, Any]:
        return {
            "instance_types": [
                # Gate `default` on launchability (same rule the launch validates):
                # a non-launchable type is never marked default, so the listing can't
                # advertise a default the launch would reject ("default, not supported").
                {**entry.payload(), "default": entry.name == default_name and entry.launchable}
                for entry in self.instance_types
            ],
            "catalog": self.catalog_metadata(now=now, refresh_in_progress=refresh_in_progress),
        }


def bootstrap_fallback_catalog() -> InstanceTypeCatalog:
    """The provider adapter's authoring-time snapshot, seeded on a virgin database
    and served until the first successful provider fetch; announced as such via
    source="bootstrap_fallback" / fetched_at=None (always stale)."""
    # Deferred import: phala pulls in readiness -> scheduler, which imports this
    # module back at load time (the established pattern for adapter access).
    from concrete_console.tee_provider.phala import BOOTSTRAP_INSTANCE_TYPES

    return InstanceTypeCatalog(
        instance_types=tuple(
            entry for raw in BOOTSTRAP_INSTANCE_TYPES if (entry := InstanceType.from_payload(raw)) is not None
        ),
        fetched_at=None,
        source=SOURCE_BOOTSTRAP_FALLBACK,
        last_refresh_error=None,
    )


class InstanceTypeCatalogService:
    """Runtime state around the catalog: single-flight refresh, retry ladder, persistence."""

    def __init__(self) -> None:
        self._catalog = bootstrap_fallback_catalog()
        self._refresh_in_progress = False
        self._next_attempt_at: datetime | None = None
        self._retry_attempt = 0
        self._boot_task: asyncio.Task[None] | None = None
        self._background_tasks: set[asyncio.Task[bool]] = set()

    # -- memory-only reads (endpoint + launch validation) ----------------------

    def snapshot(self) -> InstanceTypeCatalog:
        return self._catalog

    def refresh_in_progress(self) -> bool:
        # A spawned-but-not-yet-started background task counts: from the caller's
        # perspective a refresh IS underway the moment it is scheduled.
        return self._refresh_in_progress or any(not task.done() for task in self._background_tasks)

    # -- lifecycle --------------------------------------------------------------

    async def initialize(self) -> None:
        """Boot path; never waits on the provider.

        Warm boot (DB row present): serve the persisted catalog immediately.
        Virgin boot (row genuinely ABSENT): seed memory AND the DB with the
        bootstrap fallback right away. A FAILED or unusable DB read/parse is NOT a
        virgin boot: memory serves the bootstrap temporarily but nothing is
        persisted, so a transient outage can never clobber the stored
        last-known-good row. All paths then refresh in the background.

        The read AND the parse both run under the guard below: "a bad DB state must
        not block boot" is a boundary invariant, so it must not depend on any helper
        staying non-throwing forever.
        """
        row = None
        loaded = None
        virgin = False
        try:
            row = await load_catalog_row()
            virgin = row is None
            if row is not None:
                loaded = catalog_from_db_row(row)
        except Exception as exc:  # noqa: BLE001 - a broken DB read/parse must not block boot
            log.error("instance_types_db_load_failed", error_type=type(exc).__name__)
        if row is not None:
            if loaded is not None:
                self._catalog = loaded
            else:
                log.error("instance_types_db_row_invalid")
        if virgin:
            await self._persist_current("boot_seed")
        self._boot_task = asyncio.create_task(self._boot_refresh(virgin=virgin), name="instance-types-boot-refresh")

    async def shutdown(self) -> None:
        tasks = [task for task in (self._boot_task, *self._background_tasks) if task is not None]
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def _boot_refresh(self, *, virgin: bool) -> None:
        refreshed = await self.refresh(reason=REASON_BOOT)
        if not refreshed and virgin:
            # Keep the persisted bootstrap row honest: it now carries the boot
            # failure, so the next boot knows the provider has never been reached.
            await self._persist_current("boot_failure")

    # -- refresh machinery --------------------------------------------------------

    def spawn_refresh_if_due(self, *, reason: str) -> bool:
        """The one background-refresh entry point (scheduler tick and stale reads
        alike): due-gated by the retry ladder, single-flight, and non-blocking —
        the fetch runs as a tracked task so a slow provider can never stall the
        caller. Returns True when a refresh is running or was just spawned."""
        if self.refresh_in_progress():
            return True
        if self._next_attempt_at is not None and utcnow() < self._next_attempt_at:
            return False
        task = asyncio.create_task(self.refresh(reason=reason), name=f"instance-types-{reason}-refresh")
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return True

    async def refresh(self, *, reason: str, timeout_seconds: float = BACKGROUND_FETCH_TIMEOUT_SECONDS) -> bool:
        """Fetch + parse + atomic swap + persist. Returns True on success.
        Failure only attaches `last_refresh_error` and advances the retry ladder."""
        if self._refresh_in_progress:
            return False
        self._refresh_in_progress = True
        try:
            now = utcnow()
            try:
                provider = CvmProvider.from_settings(timeout_seconds=timeout_seconds)
                raw_types = await provider.list_instance_types()
            except CvmProviderError as exc:
                self._record_failure(exc, now=now, reason=reason)
                return False
            catalog = catalog_from_provider_types(raw_types, fetched_at=now)
            self._catalog = catalog
            self._retry_attempt = 0
            self._schedule_daily(now)
            if len(raw_types) >= MAX_INSTANCE_TYPE_ENTRIES:
                log.warning("instance_types_truncated", count=len(raw_types))
            warn_on_field_drift(catalog)
            await self._persist_current(reason)
            log.info(
                "instance_types_refreshed",
                reason=reason,
                count=len(catalog.instance_types),
                next_attempt_at=isoformat(self._next_attempt_at),
            )
            return True
        finally:
            self._refresh_in_progress = False

    async def _persist_current(self, reason: str) -> None:
        try:
            await persist_catalog(self._catalog)
        except Exception as exc:  # noqa: BLE001 - memory stays authoritative; retried next cycle
            log.error("instance_types_db_persist_failed", reason=reason, error_type=type(exc).__name__)

    def _record_failure(self, exc: CvmProviderError, *, now: datetime, reason: str) -> None:
        """Attach the failure to the served catalog, then apply one of three
        rescheduling policies derived from (error code, reason):

        - `not_configured`  -> daily cadence, WARNING (a missing provider token is
          a configuration state, not an outage; retrying cannot help);
        - manual `?refresh=true` -> record only (a user retrying during a short
          blip must not push the next SCHEDULED refresh a day out);
        - scheduled/stale/boot -> walk the retry ladder, ERROR.
        """
        kind = (
            ERROR_KIND_SCHEMA_DRIFT
            if exc.code == PROVIDER_ERROR_INSTANCE_TYPES_SCHEMA_DRIFT
            else ERROR_KIND_PROVIDER_UNREACHABLE
        )
        self._catalog = replace(self._catalog, last_refresh_error=RefreshError(kind=kind, field=exc.field, at=now))
        if exc.code == PROVIDER_ERROR_NOT_CONFIGURED:
            if reason != REASON_MANUAL:
                # Settle at the daily cadence and clear the ladder: this is a config
                # state, not an outage, so a later real outage must restart backoff
                # at the first rung rather than resume a stale count.
                self._retry_attempt = 0
                self._schedule_daily(now)
            log.warning(
                "instance_types_provider_not_configured",
                reason=reason,
                next_attempt_at=isoformat(self._next_attempt_at),
            )
            return
        if reason == REASON_MANUAL:
            log.error("instance_types_fetch_failed", reason=reason, error_code=exc.code, field=exc.field)
            return
        self._retry_attempt += 1
        ladder_index = min(self._retry_attempt - 1, len(RETRY_LADDER_SECONDS) - 1)
        if ladder_index == len(RETRY_LADDER_SECONDS) - 1:
            # Ladder exhausted: settle into the daily cadence (always in the
            # future, so a long outage cannot degenerate into a hot loop).
            self._schedule_daily(now)
        else:
            self._next_attempt_at = now + timedelta(seconds=RETRY_LADDER_SECONDS[ladder_index])
        event = "instance_types_schema_drift" if kind == ERROR_KIND_SCHEMA_DRIFT else "instance_types_fetch_failed"
        log.error(
            event,
            reason=reason,
            error_code=exc.code,
            field=exc.field,
            retry_attempt=self._retry_attempt,
            next_attempt_at=isoformat(self._next_attempt_at),
        )

    def _schedule_daily(self, now: datetime) -> None:
        self._next_attempt_at = now + timedelta(seconds=REFRESH_INTERVAL_SECONDS + refresh_jitter_seconds())


def warn_on_field_drift(catalog: InstanceTypeCatalog) -> None:
    """A fetch that parses but loses descriptive fields is early drift: warn the operator."""
    missing = catalog.field_miss_counts()
    if missing:
        log.warning("instance_types_field_drift", missing_fields=missing, count=len(catalog.instance_types))


def refresh_jitter_seconds() -> float:
    return random.uniform(0, REFRESH_JITTER_MAX_SECONDS)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime | None) -> str | None:
    """None-tolerant wire timestamp; delegates to the shared Z-suffixed helper."""
    return timestamp(value) if value is not None else None


def parse_timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        return as_utc(parse_iso_z(raw))
    except ValueError:
        return None


def string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


# -- persistence -----------------------------------------------------------------


async def load_catalog_row() -> Any:
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchrow(
            "SELECT payload, fetched_at, source, last_refresh_error FROM instance_type_catalog WHERE id = $1",
            CATALOG_ROW_ID,
        )


def catalog_from_provider_types(raw_types: list[dict[str, Any]], *, fetched_at: datetime) -> InstanceTypeCatalog:
    """Build a fresh provider catalog from the adapter's normalized dicts. Pure
    construction; the sibling of `catalog_from_db_row` for the refresh path."""
    return InstanceTypeCatalog(
        instance_types=tuple(entry for raw in raw_types if (entry := InstanceType.from_payload(raw)) is not None),
        fetched_at=fetched_at,
        source=SOURCE_PROVIDER,
        last_refresh_error=None,
    )


def _json_or_none(value: Any) -> Any:
    """Tolerant decode of a stored catalog column. A row whose JSON is corrupt (a
    legacy/tampered value that `json.loads` chokes on) must make the catalog
    UNUSABLE -- so boot falls back to the in-memory bootstrap and persists nothing
    -- never crash startup. `json_payload` raises on malformed JSON; here that is
    just another unusable-row signal, exactly like a non-list payload below."""
    try:
        return json_payload(value)
    except (ValueError, TypeError):
        return None


def catalog_from_db_row(row: Any) -> InstanceTypeCatalog | None:
    entries = _json_or_none(row["payload"])
    if not isinstance(entries, list):
        return None
    instance_types = tuple(entry for raw in entries if (entry := InstanceType.from_payload(raw)) is not None)
    if not instance_types:
        return None
    # We write this row ourselves from validated objects, so a drop here should
    # not happen in normal operation -- a tampered row, a legacy row from before a
    # stricter parser, or a payload()/from_payload bug. Keep it as last-known-good
    # (better than discarding the catalog) but surface the loss.
    if len(instance_types) < len(entries):
        log.warning("instance_types_db_row_partial", parsed=len(instance_types), stored=len(entries))
    error_payload = _json_or_none(row["last_refresh_error"])
    # A restart does not rejuvenate the data: the label flips to "database" while
    # `fetched_at` keeps the original provider fetch time. A persisted bootstrap
    # fallback keeps its label so nobody mistakes it for provider data.
    stored_source = row["source"]
    return InstanceTypeCatalog(
        instance_types=instance_types,
        fetched_at=row["fetched_at"],
        source=SOURCE_BOOTSTRAP_FALLBACK if stored_source == SOURCE_BOOTSTRAP_FALLBACK else SOURCE_DATABASE,
        last_refresh_error=RefreshError.from_payload(error_payload),
    )


async def persist_catalog(catalog: InstanceTypeCatalog) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        # The WHERE guard makes the upsert monotonic in freshness: a bootstrap
        # payload (fetched_at NULL) can never overwrite a dated provider row, and
        # an older fetch can never overwrite a newer one — so a stalled write
        # losing a last-writer-wins race cannot clobber the last-known-good row.
        await conn.execute(
            """
            INSERT INTO instance_type_catalog (id, payload, fetched_at, source, last_refresh_error, updated_at)
            VALUES ($1, $2::jsonb, $3, $4, $5::jsonb, now())
            ON CONFLICT (id) DO UPDATE SET
                payload = EXCLUDED.payload,
                fetched_at = EXCLUDED.fetched_at,
                source = EXCLUDED.source,
                last_refresh_error = EXCLUDED.last_refresh_error,
                updated_at = now()
            WHERE instance_type_catalog.fetched_at IS NULL
               OR (EXCLUDED.fetched_at IS NOT NULL AND EXCLUDED.fetched_at >= instance_type_catalog.fetched_at)
            """,
            CATALOG_ROW_ID,
            json.dumps([entry.payload() for entry in catalog.instance_types]),
            catalog.fetched_at,
            catalog.source,
            json.dumps(catalog.last_refresh_error.payload()) if catalog.last_refresh_error else None,
        )


_service: InstanceTypeCatalogService | None = None


def catalog_service() -> InstanceTypeCatalogService:
    global _service
    if _service is None:
        _service = InstanceTypeCatalogService()
    return _service
