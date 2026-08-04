"""Instance-type catalog service: lifecycle, retry ladder, persistence semantics."""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

import umbra_console.instance_types as instance_types
import umbra_console.tee_provider.phala as phala
from umbra_console.instance_types import (
    ERROR_KIND_PROVIDER_UNREACHABLE,
    ERROR_KIND_SCHEMA_DRIFT,
    REFRESH_INTERVAL_SECONDS,
    RETRY_LADDER_SECONDS,
    InstanceType,
    InstanceTypeCatalog,
    InstanceTypeCatalogService,
    RefreshError,
    bootstrap_fallback_catalog,
    catalog_from_db_row,
    catalog_from_provider_types,
)
from umbra_console.tee_provider import (
    instance_type_hourly_rate,
    instance_type_vcpu,
)
from umbra_console.tee_provider.phala import (
    PhalaError,
    instance_types_from_payload,
    normalize_memory_gb,
)

from conftest import FakePhalaClient, PROVIDER_TYPES, not_configured, schema_drift, unreachable


BOOTSTRAP_NAMES = bootstrap_fallback_catalog().names()


def run(awaitable):
    """Run an async service method to completion from a sync test (one event loop)."""
    return asyncio.run(awaitable)


def utcnow() -> datetime:
    """Timezone-aware UTC now — matches the aware datetimes the service compares against."""
    return datetime.now(timezone.utc)


def stub_async(monkeypatch, target, name, *, returns):
    """Replace the async function `target.name` with one that returns `returns`,
    for the duration of the test. E.g. stub the DB loader to simulate a virgin boot:
    stub_async(monkeypatch, instance_types, "load_catalog_row", returns=None)."""

    async def _stub(*args, **kwargs):
        return returns

    monkeypatch.setattr(target, name, _stub)


@pytest.fixture()
def service(monkeypatch) -> InstanceTypeCatalogService:
    """A fresh `InstanceTypeCatalogService` with the provider faked and persistence
    captured in memory. A `FakePhalaClient` is installed behind the real
    `PhalaClient.from_settings`, so the real `CvmProvider` wraps it — the provider
    layer runs for real. Script provider outcomes via
    `service.phala.instance_types_outcomes`; inspect writes via `service.persisted`.
    No DB and no network are touched."""
    fake = FakePhalaClient()
    monkeypatch.setattr(
        "umbra_console.tee_provider.phala.PhalaClient.from_settings",
        classmethod(lambda cls, *, timeout_seconds=None: fake),
    )

    persisted: list[InstanceTypeCatalog] = []

    async def fake_persist(catalog):
        persisted.append(catalog)

    monkeypatch.setattr(instance_types, "persist_catalog", fake_persist)
    svc = InstanceTypeCatalogService()
    svc.persisted = persisted
    svc.phala = fake
    return svc


# -- boot lifecycle -----------------------------------------------------------


def test_boot_virgin_success(monkeypatch, service) -> None:
    """When the database is empty, the service immediately serves and persists the
    bootstrap catalog, then replaces it with provider data once the background
    refresh succeeds."""

    # Arrange: empty DB (load returns None -> virgin boot) and a provider that
    # will answer the first refresh with these types.
    stub_async(monkeypatch, instance_types, "load_catalog_row", returns=None)
    service.phala.instance_types_outcomes = [PROVIDER_TYPES]

    async def scenario():
        # Act: boot. initialize() loads the (empty) DB, sees a virgin boot, serves +
        # persists the bootstrap catalog, and kicks off a background provider refresh.
        await service.initialize()

        # Before that refresh finishes, callers already see the bootstrap catalog.
        assert service.persisted[0].source == "bootstrap_fallback"
        assert service.snapshot().source == "bootstrap_fallback"

        # Wait for the background refresh, which fetches real data and replaces it.
        await service._boot_task
        return service.snapshot()

    catalog = run(scenario())

    # Assert: the provider catalog has replaced the bootstrap one, error-free...
    assert catalog.source == "provider"
    assert catalog.names() == {"tdx.small", "tdx.large"}
    assert catalog.last_refresh_error is None
    # ...and it's the last thing written to the DB.
    assert service.persisted[-1].source == "provider"


def test_boot_virgin_failure(monkeypatch, service) -> None:
    """When the database is empty AND the first provider refresh fails, the service
    keeps serving the bootstrap catalog, records the error, and starts the retry
    ladder (next attempt ~5 minutes out)."""

    stub_async(monkeypatch, instance_types, "load_catalog_row", returns=None)

    # Configure the fake provider so the first refresh fails (provider unreachable)
    # instead of returning a catalog.
    service.phala.instance_types_outcomes = [unreachable()]

    async def scenario():
        # Boot the service: it serves + persists the bootstrap catalog, then starts
        # the background refresh (_boot_task) — which will fail here.
        await service.initialize()

        # Wait for the failing background refresh to finish.
        await service._boot_task

        # Return the final catalog after the failed refresh.
        return service.snapshot()

    catalog = run(scenario())

    # The refresh failed, so the bootstrap catalog is still what callers get.
    assert catalog.source == "bootstrap_fallback"
    assert catalog.names() == BOOTSTRAP_NAMES
    # A bootstrap catalog has no fetch time, so it always counts as stale.
    assert catalog.fetched_at is None and catalog.is_stale(utcnow())

    # The failure is recorded on the catalog as a provider-unreachable error.
    assert catalog.last_refresh_error.kind == ERROR_KIND_PROVIDER_UNREACHABLE
    assert [c.source for c in service.persisted] == ["bootstrap_fallback", "bootstrap_fallback"]
    assert service.persisted[-1].last_refresh_error is not None

    # The retry ladder has started: one attempt made, next one ~5 minutes out.
    assert service._retry_attempt == 1
    delay = (service._next_attempt_at - utcnow()).total_seconds()
    assert 290 < delay <= RETRY_LADDER_SECONDS[0]


def test_boot_warm(monkeypatch, service) -> None:
    """Warm boot: the database already holds a catalog.
    The service serves that DB copy immediately (source "database") without rejuvenating
    its fetched_at,  then starts a background refresh.
    In this test, the warm-up refresh fails, so the persisted catalog is kept, the failure is
    recorded, and nothing new is written."""


    # Simulate the DB returning an outdated catalog fetched 3 days ago.
    original_fetch = utcnow() - timedelta(days=3)

    stub_async(
        monkeypatch,
        instance_types,
        "load_catalog_row",
        returns={
            "payload": [entry | {} for entry in PROVIDER_TYPES], # Copy
            "fetched_at": original_fetch,
            "source": "provider",
            "last_refresh_error": None,
        },
    )

    # Simulate the provider being unavailable during the background refresh.
    service.phala.instance_types_outcomes = [unreachable()]

    async def scenario():
        # Boot the service.
        #
        # initialize():
        #   1. loads the catalog from the DB
        #   2. immediately serves it to callers
        #   3. starts a background refresh (_boot_task)
        await service.initialize()

        # Before the background (_boot_task) refresh completes, callers should still see the
        # persisted DB catalog:
        # source becomes "database" and fetched_at keeps its original (old) value.
        loaded = service.snapshot()
        assert loaded.source == "database"
        assert loaded.fetched_at == original_fetch

        # Wait for the failing background refresh to finish.
        await service._boot_task
        return service.snapshot()

    catalog = run(scenario())

    # Since the provider refresh failed, the previously persisted catalog is still served
    assert catalog.source == "database"
    # The original fetch timestamp is preserved, so the catalog remains stale.
    assert catalog.fetched_at == original_fetch
    assert catalog.is_stale(utcnow())

    # The provider failure is attached to the served catalog.
    assert catalog.last_refresh_error.kind == ERROR_KIND_PROVIDER_UNREACHABLE

    # A failed warm boot never overwrites the last-known-good catalog in the DB.
    assert service.persisted == []


# -- scheduler + retry ladder ---------------------------------------------------


def test_refresh_resets_ladder_success(service) -> None:
    """A successful refresh should clear retry state after a previous failure."""

    # First refresh fails (steps onto the ladder), the second succeeds.
    service.phala.instance_types_outcomes = [unreachable(), PROVIDER_TYPES]

    async def scenario():
        # Failure #1 -> retry counter on rung 1.
        await service.refresh(reason="test")
        assert service._retry_attempt == 1
        # Success -> should reset everything.
        await service.refresh(reason="test")

    run(scenario())

    # Retry state is cleared.
    assert service._retry_attempt == 0
    assert service.snapshot().last_refresh_error is None

    # Scheduling returns to daily cadence (+ jitter).
    delay = (service._next_attempt_at - utcnow()).total_seconds()
    assert REFRESH_INTERVAL_SECONDS - 60 < delay <= REFRESH_INTERVAL_SECONDS + 7200


def test_refresh_single_flight(service) -> None:
    """Only one refresh ever runs at a time. While one is in flight, a second inline
    refresh is refused and a scheduler tick reports "already covered" without starting
    a duplicate -- and the in-progress flag is released once the refresh ends."""

    started = asyncio.Event()
    call_count = {"n": 0}

    # A provider call that hangs, so the first refresh stays "in flight".
    async def hang():
        call_count["n"] += 1
        started.set()
        await asyncio.Event().wait()

    service.phala.list_instance_types = hang

    async def scenario():
        # Start one refresh and wait until it's actually running.
        first = asyncio.create_task(service.refresh(reason="manual"))
        await started.wait()

        # A second inline refresh backs off (False) without touching the provider.
        assert await service.refresh(reason="manual") is False
        assert call_count["n"] == 1

        # A scheduler tick reports it as covered (True) but spawns no extra task.
        assert service.spawn_refresh_if_due(reason="scheduler") is True
        assert service._background_tasks == set()

        # Cancel the hanging refresh; the flag must be released in its finally block.
        first.cancel()
        try:
            await first
        except asyncio.CancelledError:
            pass
        assert service._refresh_in_progress is False

    run(scenario())


# -- kinds & error payloads -----------------------------------------------------


@pytest.mark.parametrize(
    ("provider_error", "expected_kind", "expected_field"),
    [
        (unreachable(), ERROR_KIND_PROVIDER_UNREACHABLE, None),  # outage -> no field
        (schema_drift(field="result"), ERROR_KIND_SCHEMA_DRIFT, "result"),  # bad shape -> locus
    ],
    ids=["unreachable", "schema_drift"],
)
def test_refresh_kinds_failure(service, provider_error, expected_kind, expected_field) -> None:
    """Each provider failure is recorded on the catalog as a typed error: an outage
    becomes provider_unreachable (no field), a bad response becomes schema_drift with
    the offending field, so callers can tell "Phala is down" from "Phala changed"."""

    service.phala.instance_types_outcomes = [provider_error]

    run(service.refresh(reason="test"))

    error = service.snapshot().last_refresh_error
    assert error.kind == expected_kind
    assert error.field == expected_field


# -- persistence round-trip -----------------------------------------------------


@pytest.mark.parametrize(
    ("row", "expected_error_kind"),
    [
        # A good bootstrap row rebuilds, keeping its source and its saved error.
        (
            {
                "payload": [e.payload() for e in bootstrap_fallback_catalog().instance_types],
                "fetched_at": None,
                "source": "bootstrap_fallback",
                "last_refresh_error": RefreshError(ERROR_KIND_PROVIDER_UNREACHABLE, None, utcnow()).payload(),
            },
            ERROR_KIND_PROVIDER_UNREACHABLE,
        ),
        # Rows with nothing usable rebuild to None, not an empty catalog.
        ({"payload": "{}", "fetched_at": None, "source": "provider", "last_refresh_error": None}, None),
        ({"payload": [], "fetched_at": None, "source": "provider", "last_refresh_error": None}, None),
        ({"payload": [{"nom": "x"}], "fetched_at": None, "source": "provider", "last_refresh_error": None}, None),
        # A tampered/stale row can't smuggle an out-of-spec name into the catalog: the
        # name bound is re-checked on load, exactly like the provider parser does.
        ({"payload": [{"name": "x" * 70}], "fetched_at": None, "source": "provider", "last_refresh_error": None}, None),
        (
            {"payload": [{"name": "tdx\x1b.evil"}], "fetched_at": None, "source": "provider", "last_refresh_error": None},
            None,
        ),
        # A corrupt JSON string in the payload column (legacy/tampered row) is an
        # unusable row, not a crash: it rebuilds to None like any other unusable row
        # so boot falls back to the bootstrap. Regression for the bare-json.loads bug.
        ({"payload": "not json{", "fetched_at": None, "source": "provider", "last_refresh_error": None}, None),
    ],
    ids=[
        "bootstrap_ok",
        "not_a_list",
        "empty",
        "no_valid_name",
        "name_too_long",
        "name_bad_charset",
        "payload_bad_json",
    ],
)
def test_catalog_from_db_row(row, expected_error_kind) -> None:
    """Rebuilds a catalog from a saved database row.

    A good row keeps its source and turns the stored error back into a real error.
    A row with nothing usable -- including one whose name violates the format bound --
    rebuilds to None (so boot treats it as an unusable DB, and a tampered row can't
    smuggle an out-of-spec name into the in-memory catalog).
    """
    catalog = catalog_from_db_row(row)

    if expected_error_kind is None:
        assert catalog is None
    else:
        assert catalog.source == "bootstrap_fallback"
        assert catalog.last_refresh_error.kind == expected_error_kind


def test_catalog_from_db_row_out_of_range_failure() -> None:
    """DB reload enforces the same numeric bounds as the provider parser (shared
    instance_type_* validators): a tampered/legacy row's zero/negative vcpu, zero/
    negative memory, or negative price all drop to None instead of being smuggled in."""
    row = {
        "payload": [
            {
                "name": "tdx.small",
                "family": "cpu",
                "vcpu": 0,  # zero/negative -> not a real cpu count
                "memory_gb": -8,  # zero/negative memory
                "hourly_rate": -1.5,  # negative price
                "currency": "USD",
            }
        ],
        "fetched_at": utcnow(),
        "source": "provider",
        "last_refresh_error": None,
    }

    catalog = catalog_from_db_row(row)

    # The name is valid, so the entry still builds -- but every out-of-range field is
    # rejected (None), matching exactly what the provider normalizer would have done.
    assert catalog is not None
    entry = catalog.instance_types[0]
    assert (entry.vcpu, entry.memory_gb, entry.hourly_rate) == (None, None, None)


@pytest.mark.parametrize(
    ("hourly_rate", "currency", "expected_currency"),
    [
        (0.058, "USD", "USD"),  # priced -> stored currency kept
        (None, "USD", None),  # priceless -> currency forced null (tampered/legacy row)
    ],
    ids=["priced", "priceless"],
)
def test_from_payload_currency_coupled_to_rate(hourly_rate, currency, expected_currency) -> None:
    """Spec §3.6a: currency is null whenever hourly_rate is. from_payload re-enforces the
    coupling on DB reload (like the provider path), so a tampered/legacy row can't serve a
    currency without a price."""
    entry = InstanceType.from_payload(
        {
            "name": "tdx.small",
            "family": "cpu",
            "vcpu": 1,
            "memory_gb": 2,
            "hourly_rate": hourly_rate,
            "currency": currency,
        }
    )

    assert entry is not None
    assert entry.hourly_rate == hourly_rate
    assert entry.currency == expected_currency


def test_catalog_from_db_row_bad_error_json_success() -> None:
    """A corrupt JSON string in the (non-load-bearing) last_refresh_error column must
    not discard an otherwise-good catalog: the error degrades to None and the catalog
    still rebuilds. Regression for the bare-json.loads bug on the error column."""
    row = {
        "payload": [e.payload() for e in bootstrap_fallback_catalog().instance_types],
        "fetched_at": None,
        "source": "provider",
        "last_refresh_error": "oops{not json",
    }

    catalog = catalog_from_db_row(row)

    assert catalog is not None
    assert catalog.names() == BOOTSTRAP_NAMES
    assert catalog.last_refresh_error is None


# -- payload shape ----------------------------------------------------------------


def test_payload_shape() -> None:
    """The wire payload the API returns carries everything the CLI needs to render the
    catalog: per-type default and launchable flags (GPU listed but not launchable), a
    null price passed through as-is, and a metadata block with source, staleness, an
    in-progress marker, and the last error."""

    now = utcnow()
    # A catalog with a default CPU type, a CPU type missing its price, a GPU type,
    # fetched 28h ago (past the 27h stale bound) with a recorded schema-drift error.
    catalog = InstanceTypeCatalog(
        instance_types=(
            InstanceType(name="tdx.small", family="cpu", vcpu=1, memory_gb=2, hourly_rate=0.058, currency="USD"),
            InstanceType(name="tdx.large", family="cpu", vcpu=4, memory_gb=8, hourly_rate=None, currency=None),
            InstanceType(name="h200.small", family="gpu", vcpu=24, memory_gb=192, hourly_rate=4.8, currency="USD"),
        ),
        fetched_at=now - timedelta(hours=28),
        source="database",
        last_refresh_error=RefreshError(kind=ERROR_KIND_SCHEMA_DRIFT, field="items", at=now),
    )

    payload = catalog.payload(now=now, refresh_in_progress=True, default_name="tdx.small")

    # Per-type flags: only the named default is default; a missing price stays null.
    assert payload["instance_types"][0]["default"] is True
    assert payload["instance_types"][1]["default"] is False
    assert payload["instance_types"][1]["hourly_rate"] is None
    # GPU is catalogued and listed, but not launchable; CPU types are launchable.
    assert payload["instance_types"][0]["launchable"] is True
    assert payload["instance_types"][2]["launchable"] is False
    assert catalog.launchable_names() == frozenset({"tdx.small", "tdx.large"})

    # Metadata block mirrors the service state (source, staleness, refresh, error).
    meta = payload["catalog"]
    assert meta["source"] == "database"
    assert meta["stale"] is True  # 28h > 27h threshold
    assert meta["refresh_in_progress"] is True
    assert meta["last_refresh_error"]["kind"] == ERROR_KIND_SCHEMA_DRIFT
    assert meta["last_refresh_error"]["field"] == "items"


@pytest.mark.parametrize(
    ("instance", "expected_default"),
    [
        (InstanceType("tdx.small", "cpu", 1, 2, 0.058, "USD"), True),  # launchable -> honored
        (InstanceType("h200.small", "gpu", 24, 192, 4.8, "USD"), False),  # non-launchable -> suppressed
    ],
    ids=["launchable", "non_launchable"],
)
def test_payload_default_gated_by_launchable(instance, expected_default) -> None:
    """`default` is gated on the same launchability rule the launch validates: the
    configured default is marked only when it is launchable, so the listing never
    advertises a default (e.g. a GPU) that the launch would reject."""
    now = utcnow()
    catalog = InstanceTypeCatalog(
        instance_types=(instance,), fetched_at=now, source="provider", last_refresh_error=None
    )

    marked = catalog.payload(now=now, refresh_in_progress=False, default_name=instance.name)["instance_types"][0]

    assert marked["default"] is expected_default


@pytest.mark.parametrize(
    ("age", "expected_stale"),
    [
        (timedelta(hours=26, minutes=30), False),  # interval + max jitter, still inside the 1h grace
        (timedelta(seconds=instance_types.STALE_AFTER_SECONDS), False),  # exactly at the bound: fresh
        (timedelta(seconds=instance_types.STALE_AFTER_SECONDS + 1), True),  # 1s past the bound
        (timedelta(hours=48), True),  # well past
        (None, True),  # never fetched -> always stale
    ],
    ids=["within_grace", "at_bound", "one_second_past", "well_past", "never_fetched"],
)
def test_staleness_boundary(age, expected_stale) -> None:
    """A catalog is "stale" once it's older than the 27h bound (daily interval + max
    jitter + 1h grace). Checked right around the boundary: at the bound it's still
    fresh, one second past it flips to stale, and a never-fetched catalog is always
    stale."""
    now = utcnow()
    fetched_at = None if age is None else now - age
    catalog = InstanceTypeCatalog(
        instance_types=(InstanceType("tdx.small", "cpu", 1, 2, 0.058, "USD"),),
        fetched_at=fetched_at,
        source="provider",
        last_refresh_error=None,
    )
    assert catalog.is_stale(now) is expected_stale


# -- boot/DB-failure semantics, ladder gating, task tracking ----------------------


@pytest.mark.parametrize("db_state", ["read_raises", "invalid_row", "malformed_payload"])
def test_boot_db_unusable_failure(monkeypatch, service, db_state) -> None:
    """An unusable DB is not the same as an empty one. Whether the read RAISES, returns
    a row we can't parse, or returns a row whose payload JSON is corrupt, the service
    falls back to the in-memory bootstrap so callers aren't blocked -- but it persists
    NOTHING, so the stored last-known-good row is never clobbered (it may be fine and
    just momentarily unreadable)."""

    # Arrange: make the DB unusable in the ways it can be.
    if db_state == "read_raises":
        # The read blows up (connection down, etc.).
        async def load(*args, **kwargs):
            raise RuntimeError("db down")

        monkeypatch.setattr(instance_types, "load_catalog_row", load)
    elif db_state == "invalid_row":
        # The read succeeds but the row can't build a catalog (empty payload).
        stub_async(
            monkeypatch,
            instance_types,
            "load_catalog_row",
            returns={"payload": [], "fetched_at": utcnow(), "source": "provider", "last_refresh_error": None},
        )
    else:
        # The read succeeds but the payload column holds a corrupt JSON string:
        # this must NOT crash boot (regression for the bare-json.loads bug).
        stub_async(
            monkeypatch,
            instance_types,
            "load_catalog_row",
            returns={"payload": "not json{", "fetched_at": utcnow(), "source": "provider", "last_refresh_error": None},
        )

    # The background refresh also fails, so nothing external rescues us either.
    service.phala.instance_types_outcomes = [unreachable()]

    async def scenario():
        await service.initialize()
        await service._boot_task

    run(scenario())

    # Callers get the in-memory bootstrap (not "database")...
    assert service.snapshot().source == "bootstrap_fallback"
    # ...and nothing is written: the unusable row is preserved, never overwritten.
    assert service.persisted == []


def test_boot_db_parse_raises_failure(monkeypatch, service) -> None:
    """Boundary invariant, independent of any helper's contract: even if the parse
    itself RAISES (a future regression in catalog_from_db_row), boot must not crash --
    it falls back to the in-memory bootstrap and persists nothing. The read and the
    parse both run under initialize()'s guard, so the invariant can't silently come to
    depend on catalog_from_db_row staying non-throwing."""

    stub_async(
        monkeypatch,
        instance_types,
        "load_catalog_row",
        returns={"payload": [], "fetched_at": utcnow(), "source": "provider", "last_refresh_error": None},
    )

    def boom(row):
        raise RuntimeError("parse regression")

    monkeypatch.setattr(instance_types, "catalog_from_db_row", boom)
    service.phala.instance_types_outcomes = [unreachable()]

    async def scenario():
        await service.initialize()  # must not raise
        await service._boot_task

    run(scenario())

    assert service.snapshot().source == "bootstrap_fallback"
    assert service.persisted == []


def test_refresh_manual_failure_no_ladder(service) -> None:
    """A user hitting `?refresh=true` can't disturb the background schedule. Manual
    refreshes still record errors, but they never advance the retry ladder nor move the
    next scheduled attempt -- so repeated manual retries can't starve or reset it."""

    # Arrange: one scheduled failure (arms the ladder), plus six more for manual tries.
    service.phala.instance_types_outcomes = [unreachable() for _ in range(7)]

    async def scenario():
        # A scheduled failure moves the ladder to step 1 and sets the next attempt.
        await service.refresh(reason="scheduler")
        scheduled_next = service._next_attempt_at

        # Six failing manual refreshes on top of it.
        for _ in range(6):
            await service.refresh(reason="manual")
        return scheduled_next

    scheduled_next = run(scenario())

    # The ladder and the scheduled attempt are exactly where the scheduler left them...
    assert service._retry_attempt == 1
    assert service._next_attempt_at == scheduled_next
    # ...but the manual failures were still recorded.
    assert service.snapshot().last_refresh_error is not None


def test_refresh_not_configured(service) -> None:
    """A missing provider token is a config problem, not an outage, so it must not walk
    the retry ladder: retrying every 5 minutes wouldn't help. The service records the
    error but stays on the normal daily cadence."""

    # Arrange: the provider is not configured (no token).
    service.phala.instance_types_outcomes = [not_configured()]

    run(service.refresh(reason="scheduler"))

    # No ladder step: the retry counter stays at 0 and the next attempt is ~24h out.
    assert service._retry_attempt == 0
    delay = (service._next_attempt_at - utcnow()).total_seconds()
    assert delay > REFRESH_INTERVAL_SECONDS - 60
    # The error is still recorded for callers to see.
    assert service.snapshot().last_refresh_error.kind == ERROR_KIND_PROVIDER_UNREACHABLE


def test_refresh_shutdown_cancels(service) -> None:
    """Shutdown must not hang on an in-flight refresh: it cancels any background fetch
    still running, so app teardown is clean even mid-refresh."""

    started = asyncio.Event()

    # A provider call that never returns on its own -> only cancellation ends it.
    async def hang():
        started.set()
        await asyncio.Event().wait()

    service.phala.list_instance_types = hang

    async def scenario():
        # Start a background refresh and wait until it's actually running.
        assert service.spawn_refresh_if_due(reason="stale_read") is True
        await started.wait()

        # Shutdown cancels it: no task is left running.
        await service.shutdown()
        assert service._background_tasks == set() or all(t.cancelled() for t in service._background_tasks)

    run(scenario())


def test_refresh_spawn_if_due(service) -> None:
    """spawn_refresh_if_due() starts a background fetch only when an attempt is due.

    It starts at most one. Once the catalog is fresh it starts nothing -- whatever the
    reason (a scheduler tick or a stale read), so callers can't hammer the provider.
    """
    service.phala.instance_types_outcomes = [PROVIDER_TYPES, PROVIDER_TYPES]

    async def scenario():
        # Due (fresh boot): starts exactly one fetch; wait for it to land.
        assert service.spawn_refresh_if_due(reason="scheduler") is True
        assert len(service._background_tasks) == 1
        await next(iter(service._background_tasks.copy()))
        assert service.snapshot().source == "provider"

        # Fresh now (next attempt ~24h out): not due, so a stale read starts nothing.
        assert service.spawn_refresh_if_due(reason="stale_read") is False
        assert service._background_tasks == set()

        # Force it due again: it starts a fetch regardless of the reason.
        service._next_attempt_at = utcnow() - timedelta(seconds=1)
        assert service.spawn_refresh_if_due(reason="stale_read") is True
        assert len(service._background_tasks) == 1
        await next(iter(service._background_tasks.copy()))

    run(scenario())


# -- mutation-resistance pins (round-4 audit) ---------------------------------------


def test_persist_catalog_freshness_guard(monkeypatch) -> None:
    """The SQL write itself refuses to go backwards: its ON CONFLICT clause blocks a
    bootstrap (undated) payload from overwriting a real dated row, and an older fetch
    from overwriting a newer one. The service tests can't see this (they mock
    persist_catalog), so we assert the guard is literally present in the SQL."""

    executed = []

    class FakeConn:
        async def execute(self, sql, *args):
            executed.append((sql, args))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class FakePool:
        def acquire(self):
            return FakeConn()

    async def fake_pool():
        return FakePool()

    monkeypatch.setattr(instance_types, "get_pool", fake_pool)

    run(instance_types.persist_catalog(bootstrap_fallback_catalog()))

    sql, args = executed[0]
    # The two halves of the guard, plus the bootstrap row we asked it to write.
    assert "instance_type_catalog.fetched_at IS NULL" in sql
    assert "EXCLUDED.fetched_at >= instance_type_catalog.fetched_at" in sql
    assert args[0] == instance_types.CATALOG_ROW_ID
    assert args[2] is None  # bootstrap fetched_at
    assert args[3] == "bootstrap_fallback"


def test_refresh_ladder_rungs(service) -> None:
    """A run of failures walks the FULL retry ladder, then plateaus at the daily cadence.
    Each consecutive failure schedules the next attempt at the matching ladder rung
    (rung i ~= RETRY_LADDER_SECONDS[i]). Once the ladder is exhausted every further
    failure stays at the daily cadence, so the service never busy-loops on an outage."""

    # A few more failures than the ladder is long, to observe the plateau past its end.
    overshoot = 3
    service.phala.instance_types_outcomes = [
        unreachable() for _ in range(len(RETRY_LADDER_SECONDS) + overshoot)
    ]

    async def scenario():
        delays = []
        for _ in range(len(RETRY_LADDER_SECONDS) + overshoot):
            service._next_attempt_at = None  # force the attempt "due"
            before = utcnow()
            await service.refresh(reason="scheduler")
            delays.append((service._next_attempt_at - before).total_seconds())
        return delays

    delays = run(scenario())

    # Rungs 0..last-1 each land just above their ladder value (jitter only lengthens it).
    for i in range(len(RETRY_LADDER_SECONDS) - 1):
        rung = RETRY_LADDER_SECONDS[i]
        assert rung - 1 < delays[i] < rung + 5, f"rung {i}: {delays[i]} vs {rung}"

    # The terminal rung and every attempt past it settle at the daily cadence (+ jitter).
    for delay in delays[len(RETRY_LADDER_SECONDS) - 1 :]:
        assert delay > REFRESH_INTERVAL_SECONDS - 60


# -- field_miss_counts drift report ------------------------------------------------


@pytest.mark.parametrize(
    ("types", "expected_counts"),
    [
        # All fields present -> no misses.
        (
            (
                InstanceType("tdx.small", "cpu", vcpu=1, memory_gb=2, hourly_rate=0.058, currency="USD"),
                InstanceType("tdx.large", "cpu", vcpu=4, memory_gb=8, hourly_rate=0.232, currency="USD"),
            ),
            {},
        ),
        # A renamed/absent field or a bad value surfaces as None post-parse and is
        # counted per field: here 1 missing vcpu and 2 missing memory_gb.
        (
            (
                InstanceType("tdx.small", "cpu", vcpu=1, memory_gb=None, hourly_rate=0.058, currency="USD"),
                InstanceType("tdx.large", "cpu", vcpu=None, memory_gb=None, hourly_rate=0.232, currency="USD"),
            ),
            {"vcpu": 1, "memory_gb": 2},
        ),
    ],
    ids=["all_present", "some_missing"],
)
def test_field_miss_counts(types, expected_counts) -> None:
    """field_miss_counts() tallies how many entries are missing each field -- a drift
    signal for when the provider renames or drops a field. The metadata block carries
    that same machine dict verbatim (no human wording)."""

    catalog = InstanceTypeCatalog(
        instance_types=types, fetched_at=utcnow(), source="provider", last_refresh_error=None
    )

    assert catalog.field_miss_counts() == expected_counts
    metadata = catalog.catalog_metadata(now=utcnow(), refresh_in_progress=False)
    assert metadata["field_miss_counts"] == expected_counts


def test_field_miss_counts_bootstrap() -> None:
    """The built-in bootstrap snapshot must itself be drift-free, so an empty
    field_miss_counts on it is a meaningful "all good" baseline."""
    assert bootstrap_fallback_catalog().field_miss_counts() == {}


# A well-formed item; each drift case below breaks exactly one field of it.
_GOOD_ITEM = {"id": "tdx.small", "family": "cpu", "vcpu": 2, "memory_mb": 2048, "hourly_rate": 0.1}


@pytest.mark.parametrize(
    ("item", "drift_field"),
    [
        # Phala RENAMES a field: our key goes missing, so the value drops to None.
        ({**_GOOD_ITEM, "vcpu": None, "cpu_count": 2}, "vcpu"),
        ({**_GOOD_ITEM, "memory_mb": None, "memory_size": 2048}, "memory_gb"),
        ({**_GOOD_ITEM, "hourly_rate": None, "price": 0.1}, "hourly_rate"),
        # Phala KEEPS the field but sends a value we can't trust: also drops to None.
        ({**_GOOD_ITEM, "memory_mb": "lots"}, "memory_gb"),
    ],
    ids=["renamed_vcpu", "renamed_memory", "renamed_rate", "bad_value"],
)
def test_parse_surfaces_drift(item, drift_field) -> None:
    """Parsing never crashes on provider drift, but it must SIGNAL it.

    Whether Phala renames a field (our key goes missing) or sends a non-conforming
    value, that field drops to None and field_miss_counts flags exactly it -- the
    drift signal an operator sees in the endpoint metadata. The other fields, still
    valid, are not flagged.
    """
    parsed = instance_types_from_payload({"success": True, "result": [{"name": "cpu", "items": [item]}]})
    catalog = catalog_from_provider_types(parsed, fetched_at=utcnow())

    assert catalog.field_miss_counts() == {drift_field: 1}


# -- instance-type field validators (shared contract) ---------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, 1),  # smallest valid
        (64, 64),  # large valid
        (0, None),  # zero is not a real cpu count
        (-2, None),  # negative
        (2.5, None),  # not an integer
        ("4", None),  # numeric string, not an int
        (True, None),  # bool is an int in Python, but not a real value
        (None, None),  # absent
    ],
    ids=["one", "large", "zero", "negative", "float", "string", "bool", "none"],
)
def test_instance_type_vcpu(value, expected) -> None:
    """vcpu keeps only positive integers; everything else becomes None."""
    assert instance_type_vcpu(value) == expected


@pytest.mark.parametrize(
    ("memory_mb", "expected_gb"),
    [
        (2048, 2),  # exact multiple -> int GB
        (196608, 192),  # large exact multiple
        (1536, 1.5),  # non-integer -> kept as float
        (1500, 1.46),  # rounded to 2 decimals
        (0, None),  # zero
        (-1024, None),  # negative
        ("lots", None),  # not a number
        (True, None),  # bool
        (float("inf"), None),  # non-finite
        (float("nan"), None),  # non-finite
    ],
    ids=["exact", "large", "half", "rounded", "zero", "negative", "string", "bool", "inf", "nan"],
)
def test_normalize_memory_gb(memory_mb, expected_gb) -> None:
    """Phala reports MB; we expose GB (mb / 1024). Whole values stay int, others round
    to 2 decimals, and anything not a positive finite number becomes None."""
    assert normalize_memory_gb(memory_mb) == expected_gb


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.058, 0.058),  # float
        (0, 0.0),  # zero is allowed
        (2, 2.0),  # int -> float
        ("0.116", 0.116),  # numeric string is accepted
        (-1, None),  # negative
        (True, None),  # bool
        ("abc", None),  # not a number
        ("Infinity", None),  # parses as Decimal but is not finite
        (float("nan"), None),  # non-finite
        ("1e400", None),  # finite Decimal, but float() overflows it to inf -> 2nd guard
        (None, None),  # absent / wrong type
    ],
    ids=["float", "zero", "int", "string", "negative", "bool", "text", "inf_string", "nan", "finite_overflow", "none"],
)
def test_instance_type_hourly_rate(value, expected) -> None:
    """hourly_rate accepts non-negative finite numbers (including numeric strings);
    everything else becomes None."""
    assert instance_type_hourly_rate(value) == expected


# -- provider parser: tolerant parse of `phala instance-types --json` -----------

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_instance_types_fixture() -> dict:
    return json.loads((FIXTURES_DIR / "phala_instance_types.json").read_text())


def test_parse_success() -> None:
    """The happy path on a real captured `phala instance-types --json` response: every
    family is flattened into a normalized list, order preserved, CPU and GPU families
    tagged, each entry carrying the canonical keys."""

    parsed = instance_types_from_payload(load_instance_types_fixture())

    # All families are flattened into one list, in order.
    assert len(parsed) == 10
    names = [entry["name"] for entry in parsed]
    assert names[:3] == ["tdx.small", "tdx.medium", "tdx.large"]

    # Every entry has exactly the six canonical keys (no raw Phala keys leak through).
    for entry in parsed:
        assert set(entry) == {"name", "family", "vcpu", "memory_gb", "hourly_rate", "currency"}

    # A few full entries across both families -- and the MB->GB conversion
    # (2048/4096/8192 MB -> 2/4/8 GB) is applied.
    by_name = {entry["name"]: entry for entry in parsed}
    assert by_name["tdx.small"] == {
        "name": "tdx.small", "family": "cpu", "vcpu": 1, "memory_gb": 2, "hourly_rate": 0.058, "currency": "USD"
    }
    assert (by_name["tdx.medium"]["vcpu"], by_name["tdx.medium"]["memory_gb"]) == (2, 4)
    assert (by_name["tdx.large"]["vcpu"], by_name["tdx.large"]["memory_gb"]) == (4, 8)
    assert by_name["h200.small"]["family"] == "gpu"
    assert by_name["h200.small"]["memory_gb"] == 192


def test_parse_degrades_fields() -> None:
    """The parser is tolerant: if the provider renames a field, breaks its type, drops a
    price, or adds a new field, the entry still parses -- the unknown/broken fields just
    become None and additive fields are ignored. It never raises on a usable entry."""

    payload = {
        "success": True,
        "result": [
            {
                "name": "cpu",
                "items": [
                    {
                        "id": "tdx.small",
                        "cpu_count": 1,  # "vcpu" renamed
                        "memory_mb": "lots",  # type broken
                        "hourly_rate": None,  # price withdrawn
                        "brand_new_field": {"x": 1},  # additive change: ignored
                    }
                ],
            }
        ],
    }

    parsed = instance_types_from_payload(payload)

    assert parsed == [
        {
            "name": "tdx.small",
            "family": "cpu",
            "vcpu": None,
            "memory_gb": None,
            "hourly_rate": None,
            # No price -> no currency.
            "currency": None,
        }
    ]


def test_parse_drops_and_dedupes() -> None:
    """Entries with an unusable name are dropped and duplicate names are collapsed
    (first one wins). Only the one valid entry survives all the junk -- over-long names,
    control bytes, non-string ids, and non-dict items are all discarded."""

    payload = {
        "success": True,
        "result": [
            {
                "name": "cpu",
                "items": [
                    {"id": "tdx.small", "vcpu": 1},
                    {"id": "tdx.small", "vcpu": 99},  # duplicate: first wins
                    {"id": "x" * 70},  # over the 64-char bound (mirrors the launch body cap)
                    {"id": "tdx\x1b[31m.evil"},  # control bytes
                    {"id": True},  # not a string
                    "not-a-dict",
                ],
            }
        ],
    }

    parsed = instance_types_from_payload(payload)

    # Only the first "tdx.small" survives, keeping its own vcpu (not the duplicate's 99).
    assert [entry["name"] for entry in parsed] == ["tdx.small"]
    assert parsed[0]["vcpu"] == 1


@pytest.mark.parametrize(
    ("payload", "expected_field"),
    [
        ([1, 2], "envelope"),  # top-level isn't the expected object
        ({"success": True, "data": []}, "result"),  # "result" key missing
        ({"success": True, "result": [{"name": "cpu", "items": [{"uid": "tdx.small"}]}]}, "items"),  # no valid item
        ({"success": True, "result": []}, "items"),  # zero families -> zero items
    ],
)
def test_parse_schema_drift(payload, expected_field) -> None:
    """When the shape is so wrong that NOTHING usable comes out (vs. a single tolerable
    bad field), the parser raises schema_drift and names the offending location, so an
    operator can see what part of Phala's response changed."""

    with pytest.raises(PhalaError) as exc:
        instance_types_from_payload(payload)

    assert exc.value.code == "instance_types_schema_drift"
    assert exc.value.field == expected_field


def test_parse_cli_failed() -> None:
    """A response that explicitly reports failure (`success: false`) is surfaced as
    cli_failed -- the provider told us it failed, that's not schema drift."""

    with pytest.raises(PhalaError) as exc:
        instance_types_from_payload({"success": False, "result": []})

    assert exc.value.code == "cli_failed"


def test_parse_name_bound() -> None:
    """Names are bounded at 64 chars (the same cap the launch request body enforces):
    exactly 64 is kept, 65 is dropped. Pinning the exact edge guards against an
    off-by-one that would let the catalog and the launch validator disagree."""

    at_bound = "a" + "b" * 63  # 64 chars: kept
    over_bound = "a" + "b" * 64  # 65 chars: dropped
    payload = {
        "success": True,
        "result": [{"name": "cpu", "items": [{"id": at_bound}, {"id": over_bound}]}],
    }

    parsed = instance_types_from_payload(payload)

    assert [entry["name"] for entry in parsed] == [at_bound]


def test_parse_caps_flood(monkeypatch) -> None:
    """A hostile family with far more items than the cap is capped AND consumed lazily:
    given 3x the cap, exactly the cap is kept and the per-item parser runs only up to
    the cap -- so the generator bails at the cap instead of materializing the whole
    family (the call count would be 3x the cap if it scanned everything)."""

    from umbra_console.tee_provider import MAX_INSTANCE_TYPE_ENTRIES

    calls = {"n": 0}
    real_parse_item = phala.parse_instance_type_item

    def counting_parse_item(item, family_name):
        calls["n"] += 1
        return real_parse_item(item, family_name)

    monkeypatch.setattr(phala, "parse_instance_type_item", counting_parse_item)

    payload = {
        "success": True,
        "result": [
            {"name": "cpu", "items": [{"id": f"tdx.evil{i}"} for i in range(MAX_INSTANCE_TYPE_ENTRIES * 3)]}
        ],
    }

    parsed = instance_types_from_payload(payload)

    assert len(parsed) == MAX_INSTANCE_TYPE_ENTRIES
    assert calls["n"] == MAX_INSTANCE_TYPE_ENTRIES  # bailed at the cap; never scanned all 3x items


# -- provider contract: the fake and (when reachable) the live Phala ------------

CANONICAL_KEYS = {"name", "family", "vcpu", "memory_gb", "hourly_rate", "currency"}


def test_list_instance_types_contract(phala_client) -> None:
    """A read-only contract the fake and the live provider must both satisfy. The
    'real' run happens when PHALA_API_TOKEN (env or repo-root .env) and the phala CLI
    are present; otherwise only the fake runs.

    1. We get a non-empty response.
    2. Every entry has exactly the canonical field NAMES (a renamed field would be
       missing here).
    3. The important attributes (name, family, vcpu, memory_gb) each hold a VALID
       value -- not None, right type and range (a renamed field would be None). The
       price is NOT asserted here: Phala may legitimately leave it undetermined, so it
       can be null even on a healthy catalog. Such a null price is still counted as a
       descriptive miss by field_miss_counts -- an accepted false positive (we keep
       tracking the price), not truly ignored.
    """
    parsed = run(phala_client.list_instance_types())

    # 1. A non-empty list came back.
    assert isinstance(parsed, list) and parsed

    for entry in parsed:
        # 2. Exactly the canonical keys -- no missing/renamed field, no extra key.
        assert set(entry) == CANONICAL_KEYS

        # 3. Important attributes carry a valid value.
        assert isinstance(entry["name"], str) and entry["name"]
        assert isinstance(entry["family"], str) and entry["family"]  # "cpu" / "gpu"
        assert isinstance(entry["vcpu"], int) and entry["vcpu"] > 0
        assert isinstance(entry["memory_gb"], (int, float)) and entry["memory_gb"] > 0
