import asyncio
import base64
import hashlib
import json
from types import SimpleNamespace
from uuid import UUID

from concrete_console import attestation
from concrete_console import scheduler


class FakeConn:
    def __init__(self, *, fetch_rows=None, fetchrow_row=None, execute_result="UPDATE 1"):
        self.fetch_rows = fetch_rows or []
        self.fetchrow_row = fetchrow_row
        self.execute_result = execute_result
        self.fetch_calls: list[tuple[str, tuple[object, ...]]] = []
        self.fetchrow_calls: list[tuple[str, tuple[object, ...]]] = []
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetch(self, query, *args):
        self.fetch_calls.append((query, args))
        return self.fetch_rows

    async def fetchrow(self, query, *args):
        self.fetchrow_calls.append((query, args))
        return self.fetchrow_row

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return self.execute_result

    def transaction(self):
        return AsyncContext()


def operation_row(**overrides):
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000030"),
        "kind": "cvm.launch",
        "status": "pending",
        "progress_step": "persist_stub",
        "progress_percent": 10,
    }
    row.update(overrides)
    return row


def test_pending_operation_start_progress_advances_known_sagas() -> None:
    assert scheduler.pending_operation_start_progress(
        "cvm.launch",
        progress_step="persist_stub",
        progress_percent=10,
    ) == ("phala_deploy", 20)
    assert scheduler.pending_operation_start_progress(
        "security_cvm.provision",
        progress_step="persist_tokens_and_stub",
        progress_percent=10,
    ) == ("phala_deploy", 20)
    assert scheduler.pending_operation_start_progress(
        "cvm.terminate",
        progress_step="queued",
        progress_percent=0,
    ) == ("phala_terminate", 25)


def test_pending_operation_start_progress_ignores_unknown_kind() -> None:
    assert (
        scheduler.pending_operation_start_progress(
            "unknown.kind",
            progress_step="queued",
            progress_percent=0,
        )
        is None
    )


def test_claim_active_operations_uses_skip_locked() -> None:
    conn = FakeConn(fetch_rows=[operation_row()])

    rows = asyncio.run(scheduler.claim_active_operations(conn, batch_size=7))

    assert rows == [operation_row()]
    query, args = conn.fetch_calls[0]
    assert "FOR UPDATE SKIP LOCKED" in query
    assert "updated_at < now() - INTERVAL '30 seconds'" in query
    assert args == (7,)


def test_advance_claimed_operation_marks_pending_row_running() -> None:
    conn = FakeConn()

    advanced = asyncio.run(scheduler.advance_claimed_operation(conn, operation_row()))

    assert advanced is True
    query, args = conn.execute_calls[0]
    assert "SET status = 'running'" in query
    assert args == (
        UUID("00000000-0000-4000-8000-000000000030"),
        "phala_deploy",
        20,
    )


def test_advance_claimed_operation_leaves_running_row_unchanged() -> None:
    conn = FakeConn()

    advanced = asyncio.run(scheduler.advance_claimed_operation(conn, operation_row(status="running")))

    assert advanced is False
    assert conn.execute_calls == []


def test_executable_running_operation_recognizes_terminate_step() -> None:
    assert scheduler.executable_running_operation(
        operation_row(kind="cvm.terminate", status="running", progress_step="phala_terminate")
    )
    assert scheduler.executable_running_operation(
        operation_row(kind="cvm.launch", status="running", progress_step="phala_deploy")
    )
    assert scheduler.executable_running_operation(
        operation_row(kind="cvm.launch", status="running", progress_step="cf_txt_create")
    )
    assert scheduler.executable_running_operation(
        operation_row(kind="cvm.launch", status="running", progress_step="cf_cname_create")
    )
    assert scheduler.executable_running_operation(
        operation_row(kind="cvm.launch", status="running", progress_step="verify_attestation")
    )
    assert scheduler.executable_running_operation(
        operation_row(kind="cvm.launch", status="running", progress_step="await_sc_pull")
    )
    assert scheduler.executable_running_operation(
        operation_row(kind="cvm.launch", status="running", progress_step="policy_push")
    )
    assert scheduler.executable_running_operation(
        operation_row(kind="cvm.launch", status="running", progress_step="finalise")
    )
    assert scheduler.executable_running_operation(
        operation_row(kind="security_cvm.provision", status="running", progress_step="phala_deploy")
    )
    assert scheduler.executable_running_operation(
        operation_row(kind="security_cvm.provision", status="running", progress_step="fetch_ca")
    )
    assert scheduler.executable_running_operation(
        operation_row(kind="audit.export", status="running", progress_step="materialize")
    )


def test_pending_operation_start_is_executable_for_live_sagas() -> None:
    assert scheduler.pending_operation_start_is_executable(operation_row(kind="cvm.launch"))
    assert scheduler.pending_operation_start_is_executable(
        operation_row(kind="security_cvm.provision", progress_step="persist_tokens_and_stub")
    )
    assert scheduler.pending_operation_start_is_executable(operation_row(kind="cvm.terminate", progress_step="queued"))
    assert scheduler.pending_operation_start_is_executable(
        operation_row(kind="audit.export", progress_step="queued", progress_percent=0)
    )


def test_lease_running_operation_updates_executable_row() -> None:
    conn = FakeConn()

    leased = asyncio.run(
        scheduler.lease_running_operation(
            conn,
            operation_row(kind="cvm.terminate", status="running", progress_step="phala_terminate"),
        )
    )

    assert leased is True
    query, args = conn.execute_calls[0]
    assert "SET updated_at = now()" in query
    assert args == (UUID("00000000-0000-4000-8000-000000000030"),)


def test_run_operation_scheduler_pass_executes_newly_started_pending_row(monkeypatch) -> None:
    conn = FakeConn(fetch_rows=[operation_row()])
    executed: list[object] = []

    async def fake_get_pool():
        return LaunchFakePool(conn)

    async def fake_execute_running_operation(operation_id):
        executed.append(operation_id)
        return True

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)
    monkeypatch.setattr(scheduler, "execute_running_operation", fake_execute_running_operation)

    claimed = asyncio.run(scheduler.run_operation_scheduler_pass(batch_size=1))

    assert claimed == ["00000000-0000-4000-8000-000000000030"]
    assert executed == [UUID("00000000-0000-4000-8000-000000000030")]


def test_execute_running_operation_dispatches_audit_export(monkeypatch) -> None:
    operation_id = UUID("00000000-0000-4000-8000-000000000030")
    conn = FakeConn(
        fetchrow_row=operation_row(
            id=operation_id,
            kind="audit.export",
            status="running",
            progress_step="materialize",
        )
    )
    executed: list[object] = []

    async def fake_get_pool():
        return LaunchFakePool(conn)

    async def fake_execute_audit_export_operation(dispatched_operation_id):
        executed.append(dispatched_operation_id)

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)
    monkeypatch.setattr(scheduler, "execute_audit_export_operation", fake_execute_audit_export_operation)

    assert asyncio.run(scheduler.execute_running_operation(operation_id)) is True
    assert executed == [operation_id]


def audit_event_row(**overrides):
    now = scheduler.datetime.now(scheduler.timezone.utc)
    row = {
        "seq": 1,
        "id": UUID("00000000-0000-4000-8000-000000000071"),
        "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
        "actor_id": UUID("00000000-0000-4000-8000-000000000020"),
        "actor_email": "dev@example.com",
        "action": "USER_REGISTERED",
        "target_type": "user",
        "target_id": "00000000-0000-4000-8000-000000000020",
        "before": None,
        "after": {"email": "dev@example.com"},
        "ip_address": None,
        "description": "user registered",
        "request_id": "req-1",
        "timestamp": now,
        "prev_hash": "0" * 64,
        "row_hash": "1" * 64,
    }
    row.update(overrides)
    return row


class AuditExportConn:
    def __init__(self, *, issued_exists: bool = False):
        self.operation_id = UUID("00000000-0000-4000-8000-000000000030")
        self.entity_id = UUID("00000000-0000-4000-8000-000000000001")
        self.actor_id = UUID("00000000-0000-4000-8000-000000000020")
        self.issued_exists = issued_exists
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []
        self.fetchval_calls: list[tuple[str, tuple[object, ...]]] = []
        self.audit_calls: list[dict[str, object]] = []

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, query, *args):
        assert "JOIN audit_export_requests" in query
        return {
            "id": self.operation_id,
            "actor_id": self.actor_id,
            "actor_email": "dev@example.com",
            "entity_id": self.entity_id,
            "filters": {"format": "ndjson", "action": "USER_REGISTERED"},
        }

    async def fetch(self, query, *args):
        assert "FROM audit_events" in query
        assert "action = $2" in query
        assert args == (self.entity_id, "USER_REGISTERED", scheduler.AUDIT_EXPORT_ROW_CAP + 1)
        return [audit_event_row(entity_id=self.entity_id, actor_id=self.actor_id)]

    async def fetchval(self, query, *args):
        self.fetchval_calls.append((query, args))
        assert "AUDIT_EXPORT_ISSUED" in query
        assert args == (str(self.operation_id),)
        return 1 if self.issued_exists else None

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


def test_execute_audit_export_operation_materializes_artifact_and_result(monkeypatch) -> None:
    conn = AuditExportConn()
    written: list[tuple[str, str, object]] = []

    async def fake_get_pool():
        return LaunchFakePool(conn)

    async def fake_write_artifact(bucket_uri, object_key, artifact):
        written.append((bucket_uri, object_key, artifact))
        return f"file:///tmp/{object_key}"

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setenv("AUDIT_EXPORT_BUCKET", "file:///tmp/concrete-audit-exports")
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.com")
    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)
    monkeypatch.setattr(scheduler, "write_audit_export_artifact", fake_write_artifact)
    monkeypatch.setattr(scheduler, "insert_audit_event", fake_insert_audit_event)

    asyncio.run(scheduler.execute_audit_export_operation(conn.operation_id))

    assert written[0][0] == "file:///tmp/concrete-audit-exports"
    assert written[0][1] == "audit-exports/00000000-0000-4000-8000-000000000030.ndjson"
    assert written[0][2].row_count == 1
    assert conn.audit_calls[0]["action"] == "AUDIT_EXPORT_ISSUED"
    operation_updates = [args for query, args in conn.execute_calls if "UPDATE operations" in query]
    assert len(operation_updates) == 1
    result = json.loads(operation_updates[0][1])
    assert result["download_url"].startswith("https://console.example.com/api/v1/audit/exports/")
    assert result["content_type"] == "application/x-ndjson"
    assert result["row_count"] == 1
    artifact_writes = [query for query, _args in conn.execute_calls if "INSERT INTO audit_export_artifacts" in query]
    assert "ON CONFLICT (operation_id) DO UPDATE" in artifact_writes[0]


def test_execute_audit_export_operation_reuses_existing_object_after_retry(monkeypatch, tmp_path) -> None:
    conn = AuditExportConn(issued_exists=True)
    attempted_artifacts: list[object] = []
    read_uris: list[str] = []

    async def fake_get_pool():
        return LaunchFakePool(conn)

    async def fake_write_artifact(_bucket_uri, _object_key, artifact):
        attempted_artifacts.append(artifact)
        raise scheduler.AuditExportStorageError("already exists")

    async def fake_read_artifact(_bucket_uri, storage_uri):
        read_uris.append(storage_uri)
        return attempted_artifacts[0].content

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setenv("AUDIT_EXPORT_BUCKET", tmp_path.as_uri())
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.com")
    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)
    monkeypatch.setattr(scheduler, "write_audit_export_artifact", fake_write_artifact)
    monkeypatch.setattr(scheduler, "read_audit_export_artifact", fake_read_artifact)
    monkeypatch.setattr(scheduler, "insert_audit_event", fake_insert_audit_event)

    asyncio.run(scheduler.execute_audit_export_operation(conn.operation_id))

    assert read_uris[0].endswith("/audit-exports/00000000-0000-4000-8000-000000000030.ndjson")
    assert conn.audit_calls == []
    operation_updates = [args for query, args in conn.execute_calls if "UPDATE operations" in query]
    assert len(operation_updates) == 1
    result = json.loads(operation_updates[0][1])
    assert result["sha256"] == attempted_artifacts[0].sha256


def test_execute_operation_step_with_logging_records_elapsed(monkeypatch) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    class FakeLog:
        def info(self, event: str, **kwargs) -> None:
            events.append((event, kwargs))

        def error(self, event: str, **kwargs) -> None:
            events.append((event, kwargs))

    async def handler() -> None:
        return None

    monkeypatch.setattr(scheduler, "log", FakeLog())

    asyncio.run(
        scheduler.execute_operation_step_with_logging(
            UUID("00000000-0000-4000-8000-000000000030"),
            kind="cvm.launch",
            step="phala_deploy",
            handler=handler,
        )
    )

    assert events[0] == (
        "operation_scheduler_step_started",
        {
            "operation_id": "00000000-0000-4000-8000-000000000030",
            "kind": "cvm.launch",
            "step": "phala_deploy",
        },
    )
    assert events[1][0] == "operation_scheduler_step_finished"
    assert events[1][1]["operation_id"] == "00000000-0000-4000-8000-000000000030"
    assert events[1][1]["kind"] == "cvm.launch"
    assert events[1][1]["step"] == "phala_deploy"
    assert isinstance(events[1][1]["elapsed_ms"], int)


def test_execute_operation_step_with_logging_records_failure(monkeypatch) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    class FakeLog:
        def info(self, event: str, **kwargs) -> None:
            events.append((event, kwargs))

        def error(self, event: str, **kwargs) -> None:
            events.append((event, kwargs))

    async def handler() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(scheduler, "log", FakeLog())

    try:
        asyncio.run(
            scheduler.execute_operation_step_with_logging(
                UUID("00000000-0000-4000-8000-000000000030"),
                kind="security_cvm.provision",
                step="verify_attestation",
                handler=handler,
            )
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected RuntimeError")

    assert [event for event, _kwargs in events] == [
        "operation_scheduler_step_started",
        "operation_scheduler_step_failed",
    ]
    assert events[1][1]["operation_id"] == "00000000-0000-4000-8000-000000000030"
    assert events[1][1]["kind"] == "security_cvm.provision"
    assert events[1][1]["step"] == "verify_attestation"
    assert events[1][1]["error_type"] == "RuntimeError"
    assert isinstance(events[1][1]["elapsed_ms"], int)


def test_provider_app_id_parses_json_metadata() -> None:
    assert scheduler.provider_app_id({"app_id": "app-123"}) == "app-123"
    assert scheduler.provider_app_id('{"app_id": "app-123"}') == "app-123"
    assert scheduler.provider_app_id({}) is None


def security_atls_policy(**overrides):
    policy = {
        "type": "dstack_tdx",
        "allowed_tcb_status": ["UpToDate"],
        "app_compose": {"docker_compose_file": "services:\n  mitmproxy:\n    image: example/sc@sha256:abc\n"},
        "expected_bootchain": {"mrtd": "b" * 64, "rtmr0": "0" * 64, "rtmr1": "1" * 64, "rtmr2": "2" * 64},
        "os_image_hash": "b" * 64,
    }
    policy.update(overrides)
    return policy


def launch_snapshot(**overrides):
    now = scheduler.datetime.now(scheduler.timezone.utc)
    row = {
        "cvm_id": UUID("00000000-0000-4000-8000-000000000031"),
        "fqdn": "cvm-abc.dev.example.com",
        "instance_type": "tdx.small",
        "region": "FR-PARIS-1",
        "compose_config": "services:\n  user-sandbox:\n    image: example/dev@sha256:abc\n",
        "expected_image_measurement": "a" * 64,
        "security_cvm_fqdn": "sc-abc.sc.example.com",
        "security_cvm_proxy_port": 8080,
        "security_cvm_ca_cert_pem": "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
        "security_cvm_metadata": {"atls_policy": security_atls_policy()},
        "security_cvm_expected_image_measurement": "b" * 64,
        "security_cvm_image_measurement": "b" * 64,
        "security_cvm_rtmr3_digest": "c" * 96,
        "security_cvm_last_policy_pull_at": None,
        "security_cvm_last_policy_pull_etag": None,
        "proxy_token_created_at": now,
    }
    row.update(overrides)
    return row


def decode_env(value: str) -> str:
    return base64.b64decode(value.encode("ascii")).decode("utf-8")


def cvm_resource_row(**overrides):
    now = scheduler.datetime.now(scheduler.timezone.utc)
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000031"),
        "owner_id": UUID("00000000-0000-4000-8000-000000000020"),
        "owner_email": "dev@example.com",
        "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
        "state": "RUNNING",
        "instance_type": "tdx.small",
        "region": "FR-PARIS-1",
        "fqdn": "cvm-abc.dev.example.com",
        "expected_image_measurement": "a" * 64,
        "image_measurement": "a" * 64,
        "rtmr3_digest": "d" * 96,
        "attestation_verified_at": now,
        "error_reason": None,
        "policy_version": 1,
        "created_at": now,
        "updated_at": now,
        "profiles": [{"id": UUID("00000000-0000-4000-8000-000000000050"), "name": "Default"}],
        "ssh_keys": [{"id": UUID("00000000-0000-4000-8000-000000000060"), "label": "laptop"}],
    }
    row.update(overrides)
    return row


def security_cvm_snapshot(**overrides):
    now = scheduler.datetime.now(scheduler.timezone.utc)
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000041"),
        "operation_id": UUID("00000000-0000-4000-8000-000000000030"),
        "actor_id": UUID("00000000-0000-4000-8000-000000000020"),
        "actor_email": "admin@example.com",
        "operation_updated_at": now,
        "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
        "state": "PROVISIONING",
        "fqdn": "sc-abc.sc.example.com",
        "instance_type": "tdx.small",
        "region": "FR-PARIS-1",
        "metadata": {},
        "compose_config": "services:\n  mitmproxy:\n    image: example/sc@sha256:abc\n",
        "txt_dns_record_id": None,
        "cname_dns_record_id": None,
        "proxy_port": 8080,
        "ca_cert_pem": None,
        "ingest_token_plaintext": "ingest-plaintext",
        "ingest_token_stashed_at": now,
        "ca_export_token_plaintext": "ca-export-plaintext",
        "ca_export_token_stashed_at": now,
        "expected_image_measurement": "b" * 64,
        "image_measurement": None,
        "rtmr3_digest": None,
        "attestation_verified_at": None,
        "policy_version": 0,
    }
    row.update(overrides)
    return row


def security_cvm_resource_row(**overrides):
    now = scheduler.datetime.now(scheduler.timezone.utc)
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000041"),
        "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
        "state": "RUNNING",
        "fqdn": "sc-abc.sc.example.com",
        "instance_type": "tdx.small",
        "region": "FR-PARIS-1",
        "error_reason": None,
        "policy_version": 0,
        "expected_image_measurement": "b" * 64,
        "image_measurement": "b" * 64,
        "rtmr3_digest": "d" * 96,
        "attestation_verified_at": now,
        "created_at": now,
        "updated_at": now,
    }
    row.update(overrides)
    return row


def test_build_cvm_launch_env_binds_runtime_material() -> None:
    env, binding = scheduler.build_cvm_launch_env(
        launch_snapshot(),
        public_keys=["ssh-ed25519 zzz label-z", "ssh-ed25519 aaa label-a"],
        profile_rows=[
            {"policy": {"sandbox_env": {"ZED": "last", "AWS_ACCESS_KEY_ID": "concrete-proxy-injected"}}}
        ],
        proxy_token="proxy-plaintext",
    )

    authorized_keys = "ssh-ed25519 aaa label-a\nssh-ed25519 zzz label-z\n"
    ca_cert = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"
    assert env["SECURITY_CVM_FQDN"] == "sc-abc.sc.example.com"
    assert env["SECURITY_CVM_PROXY_PORT"] == "8080"
    assert env["SECURITY_CVM_PROXY_TOKEN"] == "proxy-plaintext"
    assert decode_env(env["AUTHORIZED_SSH_KEYS_B64"]) == authorized_keys
    assert decode_env(env["SANDBOX_ENV_PLACEHOLDERS_B64"]) == "AWS_ACCESS_KEY_ID=concrete-proxy-injected\nZED=last\n"
    assert decode_env(env["SECURITY_CVM_CA_CERT_B64"]) == ca_cert
    assert json.loads(decode_env(env["SECURITY_CVM_ATLS_POLICY_B64"])) == security_atls_policy()
    assert binding == {
        "cvm_id": "00000000-0000-4000-8000-000000000031",
        "security_cvm_fqdn": "sc-abc.sc.example.com",
        "security_cvm_proxy_port": 8080,
        "security_cvm_proxy_token_sha256": hashlib.sha256(b"proxy-plaintext").hexdigest(),
        "security_cvm_ca_cert_sha256": hashlib.sha256(ca_cert.encode("utf-8")).hexdigest(),
        "authorised_ssh_keys_sha256": hashlib.sha256(authorized_keys.encode("utf-8")).hexdigest(),
    }


def test_build_cvm_policy_bundle_uses_shade_policy_and_binding() -> None:
    binding = {"cvm_id": "00000000-0000-4000-8000-000000000031"}
    bundle = scheduler.build_cvm_policy_bundle(
        launch_snapshot(),
        shade_policy={
            "policy_template_version": "dev-v1",
            "app_compose": {"docker_compose_file": "services: {}\n"},
            "expected_bootchain": {"mrtd": "d" * 64},
            "os_image_hash": "e" * 64,
        },
        rtmr3_binding=binding,
    )

    assert bundle["cvm_id"] == "00000000-0000-4000-8000-000000000031"
    assert bundle["policy_template_version"] == "dev-v1"
    assert bundle["compose_template"] == "services: {}\n"
    assert bundle["expected_bootchain"] == {"mrtd": "d" * 64}
    assert bundle["os_image_hash"] == "e" * 64
    assert bundle["rtmr3_binding"] == binding
    assert bundle["security_cvm_fqdn"] == "sc-abc.sc.example.com"
    assert bundle["issued_at"].endswith("Z")


def test_cvm_launch_provider_name_is_concrete_scoped() -> None:
    assert (
        scheduler.cvm_launch_provider_name(UUID("00000000-0000-4000-8000-123456789abc"))
        == "concrete-v0-cvm-0000000000004000"
    )


def test_render_dev_cvm_shade_config_routes_tunnel_websocket() -> None:
    shade = scheduler.render_dev_cvm_shade_config(launch_snapshot(), name="concrete-v0-cvm-test")

    assert "name: concrete-v0-cvm-test" in shade
    assert "domain: cvm-abc.dev.example.com" in shade
    assert "instance_type: tdx.small" in shade
    assert "region: FR-PARIS-1" in shade
    assert "dev-tunnel:" in shade
    assert "path: /concrete/tunnel" in shade
    assert "websocket: true" in shade


def test_security_cvm_provider_name_is_concrete_scoped() -> None:
    assert (
        scheduler.security_cvm_provider_name(UUID("00000000-0000-4000-8000-123456789abc"))
        == "concrete-v0-sc-0000000000004000"
    )


class AsyncContext:
    def __init__(self, value=None):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, exc_type, exc, tb):
        return None


class LaunchFakeConn:
    def __init__(self, **snapshot_overrides):
        self.snapshot_overrides = snapshot_overrides
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, query, *args):
        if "SELECT target_id" in query and "FROM operations" in query:
            return {"target_id": UUID("00000000-0000-4000-8000-000000000031")}
        assert "FROM operations o" in query
        row = launch_snapshot(
            operation_id=UUID("00000000-0000-4000-8000-000000000030"),
            actor_id=UUID("00000000-0000-4000-8000-000000000020"),
            actor_email="dev@example.com",
            entity_id=UUID("00000000-0000-4000-8000-000000000001"),
            state="PROVISIONING",
            metadata={},
            txt_dns_record_id=None,
            cname_dns_record_id=None,
            security_cvm_id=UUID("00000000-0000-4000-8000-000000000041"),
            **self.snapshot_overrides,
        )
        return row

    async def fetch(self, query, *args):
        if "FROM cvm_ssh_keys" in query:
            return [{"public_key": "ssh-ed25519 aaa label-a"}]
        if "FROM cvm_profiles" in query:
            return [{"profile_id": UUID("00000000-0000-4000-8000-000000000050"), "policy": {}}]
        raise AssertionError(f"unexpected fetch query: {query}")

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


class LaunchFakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return AsyncContext(self.conn)


class SecurityProvisionFakeConn:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []
        self.audit_calls: list[dict[str, object]] = []

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, query, *args):
        if "FROM operations o" in query and "JOIN security_cvms sc" in query:
            return self.snapshot
        if "FROM security_cvms" in query and "WHERE id = $1" in query:
            return security_cvm_resource_row()
        return None

    async def fetch(self, query, *args):
        if "FROM service_principal_tokens" in query:
            return [
                {"purpose": "INGEST", "token_hash": "b" * 64},
                {"purpose": "CA_EXPORT", "token_hash": "c" * 64},
            ]
        return []

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


def test_build_security_cvm_provision_env_uses_stashed_plaintexts(monkeypatch) -> None:
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.com")
    env = scheduler.build_security_cvm_provision_env(security_cvm_snapshot())

    assert env == {
        "CONSOLE_URL": "https://console.example.com",
        "ENTITY_ID": "00000000-0000-4000-8000-000000000001",
        "SC_ID": "00000000-0000-4000-8000-000000000041",
        "SECURITY_CVM_FQDN": "sc-abc.sc.example.com",
        "CONSOLE_INGEST_TOKEN": "ingest-plaintext",
        "CA_EXPORT_TOKEN": "ca-export-plaintext",
    }


def test_security_cvm_token_stash_expires_after_one_hour() -> None:
    now = scheduler.datetime.now(scheduler.timezone.utc)

    assert scheduler.security_cvm_token_stash_available(
        security_cvm_snapshot(
            ingest_token_stashed_at=now - scheduler.timedelta(seconds=3599),
            ca_export_token_stashed_at=now - scheduler.timedelta(seconds=3599),
        )
    )
    assert not scheduler.security_cvm_token_stash_available(
        security_cvm_snapshot(
            ingest_token_stashed_at=now - scheduler.timedelta(seconds=3601),
            ca_export_token_stashed_at=now - scheduler.timedelta(seconds=3601),
        )
    )


def test_execute_security_cvm_phala_deploy_materializes_env_and_metadata(monkeypatch) -> None:
    conn = SecurityProvisionFakeConn(security_cvm_snapshot())
    captured: dict[str, object] = {}

    async def fake_get_pool():
        return LaunchFakePool(conn)

    class FakeShadeClient:
        @classmethod
        def from_settings(cls):
            return cls()

        async def build_with_policy(self, *, shade_config_yaml, app_compose_yaml, domain):
            captured["shade_config_yaml"] = shade_config_yaml
            captured["app_compose_yaml"] = app_compose_yaml
            captured["domain"] = domain
            return SimpleNamespace(
                compose_yaml="services:\n  generated:\n    image: example\n",
                policy=security_atls_policy(app_compose={"docker_compose_file": app_compose_yaml}),
            )

    class FakePhalaClient:
        @classmethod
        def from_settings(cls):
            return cls()

        async def deploy(self, *, name, compose_yaml, env):
            captured["name"] = name
            captured["compose_yaml"] = compose_yaml
            captured["env"] = dict(env)
            return SimpleNamespace(app_id="sc-app-123", gateway_host="gateway.example.com", status="RUNNING")

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setenv("CONSOLE_URL", "https://console.example.com")
    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)
    monkeypatch.setattr("concrete_console.shade_provider.shade.ShadeClient", FakeShadeClient)
    monkeypatch.setattr("concrete_console.tee_provider.phala.PhalaClient", FakePhalaClient)
    monkeypatch.setattr(scheduler, "insert_audit_event", fake_insert_audit_event)

    asyncio.run(scheduler.execute_security_cvm_phala_deploy_operation(UUID("00000000-0000-4000-8000-000000000030")))

    env = captured["env"]
    assert isinstance(env, dict)
    assert captured["name"] == "concrete-v0-sc-0000000000004000"
    assert "domain: sc-abc.sc.example.com" in str(captured["shade_config_yaml"])
    assert captured["domain"] == "sc-abc.sc.example.com"
    assert env["CONSOLE_INGEST_TOKEN"] == "ingest-plaintext"
    assert env["CA_EXPORT_TOKEN"] == "ca-export-plaintext"
    metadata_calls = [args for query, args in conn.execute_calls if "UPDATE security_cvms" in query and "metadata" in query]
    metadata = json.loads(metadata_calls[0][1])
    assert metadata["app_id"] == "sc-app-123"
    assert metadata["atls_policy"]["type"] == "dstack_tdx"
    assert metadata["atls_policy"]["app_compose"]["docker_compose_file"] == security_cvm_snapshot()["compose_config"]
    assert conn.audit_calls[0]["action"] == "SECURITY_CVM_PROVISIONING_STARTED"
    progress_calls = [args for query, args in conn.execute_calls if "progress_step = $2" in query]
    assert progress_calls[-1] == (UUID("00000000-0000-4000-8000-000000000030"), "cf_txt_create", 40)


def test_execute_security_cvm_finalise_scrubs_stash_and_materializes_result(monkeypatch) -> None:
    conn = SecurityProvisionFakeConn(
        security_cvm_snapshot(
            ca_cert_pem="-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
            image_measurement="b" * 64,
            rtmr3_digest="d" * 96,
            attestation_verified_at=scheduler.datetime.now(scheduler.timezone.utc),
        )
    )

    async def fake_get_pool():
        return LaunchFakePool(conn)

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)
    monkeypatch.setattr(scheduler, "insert_audit_event", fake_insert_audit_event)

    asyncio.run(scheduler.execute_security_cvm_finalise_operation(UUID("00000000-0000-4000-8000-000000000030")))

    scrub_updates = [query for query, _args in conn.execute_calls if "ingest_token_plaintext = NULL" in query]
    assert scrub_updates
    operation_updates = [args for query, args in conn.execute_calls if "UPDATE operations" in query and "status = 'succeeded'" in query]
    result = json.loads(operation_updates[0][1])
    assert result["ingest_token"] == "ingest-plaintext"
    assert result["ca_export_token"] == "ca-export-plaintext"
    assert result["security_cvm"]["state"] == "RUNNING"
    assert conn.audit_calls[0]["action"] == "SECURITY_CVM_PROVISIONED"


def test_execute_cvm_launch_phala_deploy_persists_hash_only(monkeypatch) -> None:
    conn = LaunchFakeConn()
    captured: dict[str, object] = {}

    async def fake_get_pool():
        return LaunchFakePool(conn)

    class FakeShadeClient:
        @classmethod
        def from_settings(cls):
            return cls()

        async def build_with_policy(self, *, shade_config_yaml, app_compose_yaml, domain):
            captured["shade_config_yaml"] = shade_config_yaml
            captured["app_compose_yaml"] = app_compose_yaml
            captured["domain"] = domain
            return SimpleNamespace(
                compose_yaml="services:\n  app:\n    image: generated\n",
                policy={
                    "policy_template_version": "dev-v1",
                    "app_compose": {"docker_compose_file": app_compose_yaml},
                    "expected_bootchain": {"mrtd": "d" * 64},
                    "os_image_hash": "e" * 64,
                },
            )

    class FakePhalaClient:
        @classmethod
        def from_settings(cls):
            return cls()

        async def deploy(self, *, name, compose_yaml, env):
            captured["name"] = name
            captured["compose_yaml"] = compose_yaml
            captured["env"] = dict(env)
            return SimpleNamespace(app_id="app-123", gateway_host="gateway.example.com", status="RUNNING")

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)
    monkeypatch.setattr("concrete_console.shade_provider.shade.ShadeClient", FakeShadeClient)
    monkeypatch.setattr("concrete_console.tee_provider.phala.PhalaClient", FakePhalaClient)

    asyncio.run(scheduler.execute_cvm_launch_phala_deploy_operation(UUID("00000000-0000-4000-8000-000000000030")))

    env = captured["env"]
    assert isinstance(env, dict)
    assert captured["name"] == "concrete-v0-cvm-0000000000004000"
    assert env["SECURITY_CVM_PROXY_TOKEN"]
    proxy_token_hash = hashlib.sha256(env["SECURITY_CVM_PROXY_TOKEN"].encode("utf-8")).hexdigest()
    assert captured["domain"] == "cvm-abc.dev.example.com"
    assert any("UPDATE service_principal_tokens" in query for query, _args in conn.execute_calls)
    insert_calls = [args for query, args in conn.execute_calls if "INSERT INTO service_principal_tokens" in query]
    assert insert_calls == [(UUID("00000000-0000-4000-8000-000000000031"), proxy_token_hash)]
    metadata_calls = [args for query, args in conn.execute_calls if "UPDATE cvms" in query and "metadata" in query]
    assert len(metadata_calls) == 1
    metadata = json.loads(metadata_calls[0][1])
    assert metadata["app_id"] == "app-123"
    assert metadata["gateway_host"] == "gateway.example.com"
    assert metadata["policy_bundle"]["rtmr3_binding"]["security_cvm_proxy_token_sha256"] == proxy_token_hash
    progress_calls = [args for query, args in conn.execute_calls if "progress_step = 'cf_txt_create'" in query]
    assert progress_calls == [
        (
            UUID("00000000-0000-4000-8000-000000000030"),
            UUID("00000000-0000-4000-8000-000000000031"),
            40,
        )
    ]


def test_execute_cvm_launch_phala_deploy_requires_security_cvm_atls_policy(monkeypatch) -> None:
    conn = LaunchFakeConn(security_cvm_metadata={})

    async def fake_get_pool():
        return LaunchFakePool(conn)

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)

    asyncio.run(scheduler.execute_cvm_launch_phala_deploy_operation(UUID("00000000-0000-4000-8000-000000000030")))

    operation_updates = [args for query, args in conn.execute_calls if "UPDATE operations" in query and "status = 'failed'" in query]
    error = json.loads(operation_updates[0][1])
    assert error == {
        "code": "SECURITY_CVM_ATLS_POLICY_UNAVAILABLE",
        "details": {"component": "security_cvm_atls_policy"},
    }


class AttestationGateConn:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetchrow(self, query, *args):
        if "FROM operations o" in query:
            return self.snapshot
        return None

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


class AttestationPersistConn:
    def __init__(self):
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []
        self.audit_calls: list[dict[str, object]] = []

    def transaction(self):
        return AsyncContext()

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


class ReconcileAttestationConn:
    def __init__(self, *, security_rows=None, dev_rows=None, token_rows=None):
        self.security_rows = security_rows or []
        self.dev_rows = dev_rows or []
        self.token_rows = token_rows or []
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []
        self.audit_calls: list[dict[str, object]] = []

    def transaction(self):
        return AsyncContext()

    async def fetch(self, query, *args):
        if "FROM security_cvms sc" in query:
            return self.security_rows
        if "FROM cvms c" in query:
            return self.dev_rows
        if "FROM service_principal_tokens" in query:
            return self.token_rows
        raise AssertionError(f"unexpected fetch query: {query}")

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


class OrphanDnsConn:
    def __init__(self):
        self.dev_rows = [
            {
                "id": UUID("00000000-0000-4000-8000-000000000031"),
                "txt_dns_record_id": "dev-txt",
                "cname_dns_record_id": "dev-cname",
            }
        ]
        self.security_rows = [
            {
                "id": UUID("00000000-0000-4000-8000-000000000041"),
                "txt_dns_record_id": "sc-txt",
                "cname_dns_record_id": None,
            }
        ]
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    def transaction(self):
        return AsyncContext()

    async def fetch(self, query, *args):
        if "FROM cvms" in query:
            return self.dev_rows
        if "FROM security_cvms" in query:
            return self.security_rows
        raise AssertionError(f"unexpected fetch query: {query}")

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


class MaintenancePruneConn:
    def __init__(self):
        self.execute_calls: list[str] = []

    async def execute(self, query, *args):
        self.execute_calls.append(query)
        if "revoked_tokens" in query:
            return "DELETE 2"
        if "idempotency_keys" in query:
            return "DELETE 0"
        if "loopback_auth_pending" in query:
            return "DELETE 4"
        if "device_flow_pending" in query:
            return "DELETE 1"
        if "operations" in query:
            return "DELETE 3"
        raise AssertionError(f"unexpected execute query: {query}")


class ProviderDriftConn:
    def __init__(self, *, dev_rows=None, security_rows=None, execute_result="UPDATE 1"):
        self.dev_rows = dev_rows or []
        self.security_rows = security_rows or []
        self.execute_result = execute_result
        self.fetch_calls: list[str] = []
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []
        self.audit_calls: list[dict[str, object]] = []

    def transaction(self):
        return AsyncContext()

    async def fetch(self, query, *args):
        self.fetch_calls.append(query)
        if "FROM cvms c" in query:
            return self.dev_rows
        if "FROM security_cvms sc" in query:
            return self.security_rows
        raise AssertionError(f"unexpected fetch query: {query}")

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return self.execute_result


def test_reconcile_dev_cvm_provider_drift_marks_failed(monkeypatch) -> None:
    cvm_id = UUID("00000000-0000-4000-8000-000000000031")
    conn = ProviderDriftConn(
        dev_rows=[
            {
                "id": cvm_id,
                "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
                "state": "RUNNING",
                "metadata": {"app_id": "app-123"},
                "error_reason": None,
            }
        ]
    )
    status_calls: list[str] = []

    class FakePhalaClient:
        @classmethod
        def from_settings(cls, *, timeout_seconds=None):
            assert timeout_seconds == 30.0
            return cls()

        async def status(self, app_id):
            status_calls.append(app_id)
            return "FAILED"

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setattr("concrete_console.tee_provider.phala.PhalaClient", FakePhalaClient)
    monkeypatch.setattr(scheduler, "insert_audit_event", fake_insert_audit_event)

    advanced = asyncio.run(scheduler.reconcile_dev_cvm_provider_drift(conn))

    assert advanced == [str(cvm_id)]
    assert status_calls == ["app-123"]
    assert "FOR UPDATE SKIP LOCKED" in conn.fetch_calls[0]
    assert "o.status IN ('pending', 'running')" in conn.fetch_calls[0]
    update_calls = [args for query, args in conn.execute_calls if "UPDATE cvms" in query]
    assert update_calls == [(cvm_id, "FAILED", "PHALA_OBSERVED_FAILED")]
    assert conn.audit_calls[0]["actor_email"] == "reconciler@concrete.system"
    assert conn.audit_calls[0]["action"] == "CVM_FAILED"
    assert conn.audit_calls[0]["after"]["error_reason"] == "PHALA_OBSERVED_FAILED"
    assert conn.audit_calls[0]["after"]["source"] == "reconciler"


def test_reconcile_security_cvm_provider_drift_marks_stopped(monkeypatch) -> None:
    security_cvm_id = UUID("00000000-0000-4000-8000-000000000041")
    conn = ProviderDriftConn(
        security_rows=[
            {
                "id": security_cvm_id,
                "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
                "state": "RUNNING",
                "metadata": {"app_id": "sc-app-123"},
                "error_reason": None,
            }
        ]
    )

    class FakePhalaClient:
        @classmethod
        def from_settings(cls, *, timeout_seconds=None):
            assert timeout_seconds == 30.0
            return cls()

        async def status(self, app_id):
            assert app_id == "sc-app-123"
            return "STOPPED"

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setattr("concrete_console.tee_provider.phala.PhalaClient", FakePhalaClient)
    monkeypatch.setattr(scheduler, "insert_audit_event", fake_insert_audit_event)

    advanced = asyncio.run(scheduler.reconcile_security_cvm_provider_drift(conn))

    assert advanced == [str(security_cvm_id)]
    assert "FOR UPDATE SKIP LOCKED" in conn.fetch_calls[0]
    update_calls = [args for query, args in conn.execute_calls if "UPDATE security_cvms" in query]
    assert update_calls == [(security_cvm_id, "STOPPED", None)]
    assert conn.audit_calls[0]["action"] == "SECURITY_CVM_STOPPED"
    assert conn.audit_calls[0]["target_type"] == "security_cvm"
    assert conn.audit_calls[0]["after"] == {
        "state": "STOPPED",
        "provider_status": "STOPPED",
        "source": "reconciler",
    }


def test_execute_cvm_launch_attestation_gate_waits_for_real_verifier(monkeypatch) -> None:
    snapshot = launch_snapshot(
        operation_updated_at=scheduler.datetime.now(scheduler.timezone.utc),
        actor_id=UUID("00000000-0000-4000-8000-000000000020"),
        actor_email="dev@example.com",
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
        state="PROVISIONING",
        metadata={},
        txt_dns_record_id="txt-1",
        cname_dns_record_id="cname-1",
        image_measurement=None,
        rtmr3_digest=None,
        attestation_verified_at=None,
        policy_version=0,
        security_cvm_id=UUID("00000000-0000-4000-8000-000000000041"),
    )
    conn = AttestationGateConn(snapshot)

    async def fake_get_pool():
        return LaunchFakePool(conn)

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)

    asyncio.run(scheduler.execute_cvm_launch_attestation_gate_operation(UUID("00000000-0000-4000-8000-000000000030")))

    assert conn.execute_calls == []


def test_execute_cvm_launch_attestation_gate_advances_after_columns_exist(monkeypatch) -> None:
    snapshot = launch_snapshot(
        operation_updated_at=scheduler.datetime.now(scheduler.timezone.utc),
        actor_id=UUID("00000000-0000-4000-8000-000000000020"),
        actor_email="dev@example.com",
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
        state="PROVISIONING",
        metadata={},
        txt_dns_record_id="txt-1",
        cname_dns_record_id="cname-1",
        image_measurement="a" * 64,
        rtmr3_digest="d" * 96,
        attestation_verified_at=scheduler.datetime.now(scheduler.timezone.utc),
        policy_version=0,
        security_cvm_id=UUID("00000000-0000-4000-8000-000000000041"),
    )
    conn = AttestationGateConn(snapshot)

    async def fake_get_pool():
        return LaunchFakePool(conn)

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)

    asyncio.run(scheduler.execute_cvm_launch_attestation_gate_operation(UUID("00000000-0000-4000-8000-000000000030")))

    assert len(conn.execute_calls) == 1
    query, args = conn.execute_calls[0]
    assert "progress_step = $2" in query
    assert args == (UUID("00000000-0000-4000-8000-000000000030"), "await_sc_pull", 70)


def test_run_cvm_launch_attestation_verifier_persists_report_and_audit(monkeypatch) -> None:
    policy_bundle = {
        "compose_template": "services: {}\n",
        "expected_bootchain": {"mrtd": "d" * 64},
        "os_image_hash": "e" * 64,
        "rtmr3_binding": {"cvm_id": "00000000-0000-4000-8000-000000000031"},
    }
    snapshot = launch_snapshot(
        operation_updated_at=scheduler.datetime.now(scheduler.timezone.utc),
        actor_id=UUID("00000000-0000-4000-8000-000000000020"),
        actor_email="dev@example.com",
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
        state="PROVISIONING",
        metadata={"policy_bundle": policy_bundle},
        image_measurement=None,
        rtmr3_digest=None,
        attestation_verified_at=None,
        policy_version=0,
        security_cvm_id=UUID("00000000-0000-4000-8000-000000000041"),
    )
    conn = AttestationPersistConn()
    captured_request: dict[str, object] = {}

    async def fake_get_pool():
        return LaunchFakePool(conn)

    class FakeVerifier:
        async def verify(self, request, *, timeout_seconds):
            captured_request.update(request)
            assert timeout_seconds == 180
            return attestation.AttestationReport(image_measurement="a" * 64, rtmr3_digest="d" * 96)

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)
    monkeypatch.setattr(attestation.AtlasVerifierClient, "from_settings", classmethod(lambda cls: FakeVerifier()))
    monkeypatch.setattr(scheduler, "insert_audit_event", fake_insert_audit_event)

    handled = asyncio.run(
        scheduler.run_cvm_launch_attestation_verifier(UUID("00000000-0000-4000-8000-000000000030"), snapshot)
    )

    assert handled is True
    assert captured_request["kind"] == "dev_cvm"
    cvm_updates = [args for query, args in conn.execute_calls if "UPDATE cvms" in query]
    assert cvm_updates[0][:3] == (
        UUID("00000000-0000-4000-8000-000000000031"),
        "a" * 64,
        "d" * 96,
    )
    assert conn.audit_calls[0]["action"] == "CVM_ATTESTATION_VERIFIED"
    assert conn.audit_calls[0]["after"]["source"] == "launch"
    operation_updates = [args for query, args in conn.execute_calls if "UPDATE operations" in query]
    assert operation_updates == [(UUID("00000000-0000-4000-8000-000000000030"), "await_sc_pull", 70)]


def test_reconcile_security_cvm_attestation_refresh_persists_success(monkeypatch) -> None:
    security_cvm_id = UUID("00000000-0000-4000-8000-000000000041")
    conn = ReconcileAttestationConn(
        security_rows=[
            {
                "id": security_cvm_id,
                "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
                "fqdn": "sc.example.com",
                "compose_config": "services: {}\n",
                "expected_image_measurement": "a" * 64,
                "image_measurement": None,
                "rtmr3_digest": None,
                "attestation_verified_at": None,
                "error_reason": None,
            }
        ],
        token_rows=[
            {"purpose": "INGEST", "token_hash": "b" * 64},
            {"purpose": "CA_EXPORT", "token_hash": "c" * 64},
        ],
    )
    captured_request: dict[str, object] = {}

    class FakeVerifier:
        async def verify(self, request, *, timeout_seconds):
            captured_request.update(request)
            assert timeout_seconds == 30
            return attestation.AttestationReport(image_measurement="a" * 64, rtmr3_digest="d" * 96)

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setenv("CONSOLE_URL", "https://console.example.com")
    monkeypatch.setattr(attestation.AtlasVerifierClient, "from_settings", classmethod(lambda cls: FakeVerifier()))
    monkeypatch.setattr(scheduler, "insert_audit_event", fake_insert_audit_event)

    advanced = asyncio.run(scheduler.reconcile_security_cvm_attestations(conn))

    assert advanced == [str(security_cvm_id)]
    assert captured_request["kind"] == "security_cvm"
    assert captured_request["policy"]["rtmr3_binding"]["CONSOLE_URL"] == "https://console.example.com"
    security_updates = [args for query, args in conn.execute_calls if "UPDATE security_cvms" in query]
    assert security_updates[0][:3] == (security_cvm_id, "a" * 64, "d" * 96)
    assert conn.audit_calls[0]["action"] == "SECURITY_CVM_ATTESTATION_VERIFIED"
    assert conn.audit_calls[0]["after"]["source"] == "reconciler"


def test_reconcile_dev_cvm_attestation_refresh_records_drift(monkeypatch) -> None:
    cvm_id = UUID("00000000-0000-4000-8000-000000000031")
    policy_bundle = {
        "compose_template": "services: {}\n",
        "expected_bootchain": {"mrtd": "d" * 64},
        "os_image_hash": "e" * 64,
        "rtmr3_binding": {"cvm_id": str(cvm_id)},
    }
    conn = ReconcileAttestationConn(
        dev_rows=[
            {
                "cvm_id": cvm_id,
                "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
                "fqdn": "cvm.example.com",
                "metadata": {"policy_bundle": policy_bundle},
                "expected_image_measurement": "a" * 64,
                "image_measurement": "a" * 64,
                "rtmr3_digest": "d" * 96,
                "attestation_verified_at": scheduler.datetime.now(scheduler.timezone.utc)
                - scheduler.timedelta(seconds=90_000),
                "error_reason": None,
            }
        ]
    )

    class FakeVerifier:
        async def verify(self, request, *, timeout_seconds):
            assert request["kind"] == "dev_cvm"
            return attestation.AttestationReport(image_measurement="e" * 64, rtmr3_digest="f" * 96)

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setattr(attestation.AtlasVerifierClient, "from_settings", classmethod(lambda cls: FakeVerifier()))
    monkeypatch.setattr(scheduler, "insert_audit_event", fake_insert_audit_event)

    advanced = asyncio.run(scheduler.reconcile_dev_cvm_attestations(conn))

    assert advanced == [str(cvm_id)]
    drift_updates = [args for query, args in conn.execute_calls if "SET error_reason = 'ATTESTATION_DRIFT'" in query]
    assert drift_updates == [(cvm_id,)]
    assert conn.audit_calls[0]["action"] == "CVM_ATTESTATION_DRIFT"
    assert conn.audit_calls[0]["after"]["drift_kind"] == "both"


def test_cleanup_orphan_dns_records_uses_component_zones(monkeypatch) -> None:
    conn = OrphanDnsConn()
    calls: list[tuple[str, str]] = []

    class FakeCloudflareClient:
        def __init__(self, zone_id_key: str):
            self.zone_id_key = zone_id_key

        async def delete_record(self, record_id: str) -> None:
            calls.append((self.zone_id_key, record_id))

    monkeypatch.setattr(
        "concrete_console.dns_provider.cloudflare.CloudflareClient.from_settings",
        classmethod(lambda cls, *, zone_id_key="CLOUDFLARE_ZONE_ID": FakeCloudflareClient(zone_id_key)),
    )

    cleaned = asyncio.run(scheduler.cleanup_orphan_dns_records(conn))

    assert cleaned == [
        "cvm:00000000-0000-4000-8000-000000000031:txt_dns_record_id",
        "cvm:00000000-0000-4000-8000-000000000031:cname_dns_record_id",
        "security_cvm:00000000-0000-4000-8000-000000000041:txt_dns_record_id",
    ]
    assert calls == [
        ("CLOUDFLARE_ZONE_ID", "dev-txt"),
        ("CLOUDFLARE_ZONE_ID", "dev-cname"),
        ("SECURITY_CVM_ZONE_ID", "sc-txt"),
    ]
    assert len(conn.execute_calls) == 3
    assert all("SET " in query and "= NULL" in query for query, _args in conn.execute_calls)


def test_prune_expired_reconciler_rows_uses_one_day_grace() -> None:
    conn = MaintenancePruneConn()

    cleaned = asyncio.run(scheduler.prune_expired_reconciler_rows(conn))

    assert cleaned == ["maintenance:revoked_tokens:2"]
    assert [query for query in conn.execute_calls if "INTERVAL '1 day'" in query]
    assert all("FOR UPDATE SKIP LOCKED" in query for query in conn.execute_calls)
    assert any("DELETE FROM revoked_tokens" in query for query in conn.execute_calls)
    assert any("DELETE FROM idempotency_keys" in query for query in conn.execute_calls)
    assert not any("DELETE FROM device_flow_pending" in query for query in conn.execute_calls)
    assert scheduler.deleted_row_count("DELETE 12") == 12
    assert scheduler.deleted_row_count("UPDATE 12") == 0


def test_prune_expired_auth_flow_rows_uses_now_cutoff_and_skip_locked() -> None:
    conn = MaintenancePruneConn()

    cleaned = asyncio.run(scheduler.prune_expired_auth_flow_rows(conn))

    assert cleaned == ["maintenance:loopback_auth_pending:4", "maintenance:device_flow_pending:1"]
    assert len(conn.execute_calls) == 2
    assert all("expires_at < now()" in query for query in conn.execute_calls)
    assert all("INTERVAL '1 day'" not in query for query in conn.execute_calls)
    assert all("FOR UPDATE SKIP LOCKED" in query for query in conn.execute_calls)


def test_prune_expired_operations_uses_skip_locked_without_grace() -> None:
    conn = MaintenancePruneConn()

    count = asyncio.run(scheduler.prune_expired_operations(conn))

    assert count == 3
    query = conn.execute_calls[0]
    assert "FROM operations" in query
    assert "expires_at IS NOT NULL" in query
    assert "expires_at < now()" in query
    assert "INTERVAL '1 day'" not in query
    assert "FOR UPDATE SKIP LOCKED" in query


def test_execute_cvm_launch_await_sc_pull_advances_after_observation(monkeypatch) -> None:
    token_created_at = scheduler.datetime.now(scheduler.timezone.utc) - scheduler.timedelta(seconds=5)
    snapshot = launch_snapshot(
        operation_updated_at=scheduler.datetime.now(scheduler.timezone.utc),
        actor_id=UUID("00000000-0000-4000-8000-000000000020"),
        actor_email="dev@example.com",
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
        state="PROVISIONING",
        metadata={},
        policy_version=0,
        security_cvm_id=UUID("00000000-0000-4000-8000-000000000041"),
        proxy_token_created_at=token_created_at,
        security_cvm_last_policy_pull_at=token_created_at + scheduler.timedelta(seconds=1),
        security_cvm_last_policy_pull_etag='"abc"',
    )
    conn = AttestationGateConn(snapshot)

    async def fake_get_pool():
        return LaunchFakePool(conn)

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)

    asyncio.run(scheduler.execute_cvm_launch_await_sc_pull_operation(UUID("00000000-0000-4000-8000-000000000030")))

    assert len(conn.execute_calls) == 1
    query, args = conn.execute_calls[0]
    assert "progress_step = $2" in query
    assert args == (UUID("00000000-0000-4000-8000-000000000030"), "policy_push", 80)


def test_execute_cvm_launch_await_sc_pull_waits_before_timeout(monkeypatch) -> None:
    token_created_at = scheduler.datetime.now(scheduler.timezone.utc)
    snapshot = launch_snapshot(
        operation_updated_at=token_created_at,
        actor_id=UUID("00000000-0000-4000-8000-000000000020"),
        actor_email="dev@example.com",
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
        state="PROVISIONING",
        metadata={},
        policy_version=0,
        security_cvm_id=UUID("00000000-0000-4000-8000-000000000041"),
        proxy_token_created_at=token_created_at,
        security_cvm_last_policy_pull_at=None,
    )
    conn = AttestationGateConn(snapshot)

    async def fake_get_pool():
        return LaunchFakePool(conn)

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)

    asyncio.run(scheduler.execute_cvm_launch_await_sc_pull_operation(UUID("00000000-0000-4000-8000-000000000030")))

    assert conn.execute_calls == []


def test_execute_cvm_launch_await_sc_pull_falls_forward_after_timeout(monkeypatch) -> None:
    token_created_at = scheduler.datetime.now(scheduler.timezone.utc) - scheduler.timedelta(seconds=20)
    snapshot = launch_snapshot(
        operation_updated_at=token_created_at,
        actor_id=UUID("00000000-0000-4000-8000-000000000020"),
        actor_email="dev@example.com",
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
        state="PROVISIONING",
        metadata={},
        policy_version=0,
        security_cvm_id=UUID("00000000-0000-4000-8000-000000000041"),
        proxy_token_created_at=token_created_at,
        security_cvm_last_policy_pull_at=token_created_at - scheduler.timedelta(seconds=1),
    )
    conn = AttestationGateConn(snapshot)

    async def fake_get_pool():
        return LaunchFakePool(conn)

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)

    asyncio.run(scheduler.execute_cvm_launch_await_sc_pull_operation(UUID("00000000-0000-4000-8000-000000000030")))

    assert len(conn.execute_calls) == 1
    query, args = conn.execute_calls[0]
    assert "progress_step = $2" in query
    assert args == (UUID("00000000-0000-4000-8000-000000000030"), "policy_push", 80)


class FinaliseConn:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []
        self.audit_calls: list[dict[str, object]] = []

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, query, *args):
        if "FROM operations o" in query:
            return self.snapshot
        if "FROM cvms c" in query and "JOIN users owner" in query:
            return cvm_resource_row()
        return None

    async def fetch(self, query, *args):
        if "ep.name AS profile_name" in query:
            return [{"profile_id": UUID("00000000-0000-4000-8000-000000000050"), "profile_name": "Default"}]
        return []

    async def fetchval(self, query, *args):
        if "SELECT policy_version" in query:
            return 1
        return None

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


def test_execute_cvm_launch_finalise_materializes_result_and_audit(monkeypatch) -> None:
    policy_bundle = {
        "cvm_id": "00000000-0000-4000-8000-000000000031",
        "rtmr3_binding": {"cvm_id": "00000000-0000-4000-8000-000000000031"},
    }
    snapshot = launch_snapshot(
        operation_updated_at=scheduler.datetime.now(scheduler.timezone.utc),
        actor_id=UUID("00000000-0000-4000-8000-000000000020"),
        actor_email="dev@example.com",
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
        state="PROVISIONING",
        metadata={"policy_bundle": policy_bundle},
        txt_dns_record_id="txt-1",
        cname_dns_record_id="cname-1",
        image_measurement="a" * 64,
        rtmr3_digest="d" * 96,
        attestation_verified_at=scheduler.datetime.now(scheduler.timezone.utc),
        policy_version=1,
        security_cvm_id=UUID("00000000-0000-4000-8000-000000000041"),
    )
    conn = FinaliseConn(snapshot)

    async def fake_get_pool():
        return LaunchFakePool(conn)

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setattr(scheduler, "get_pool", fake_get_pool)
    monkeypatch.setattr(scheduler, "insert_audit_event", fake_insert_audit_event)

    asyncio.run(scheduler.execute_cvm_launch_finalise_operation(UUID("00000000-0000-4000-8000-000000000030")))

    assert [call["action"] for call in conn.audit_calls] == [
        "CVM_LAUNCHED",
        "SUBDOMAIN_PROVISIONED",
        "CVM_PROFILE_ATTACHED",
    ]
    operation_updates = [args for query, args in conn.execute_calls if "UPDATE operations" in query]
    assert len(operation_updates) == 1
    result = json.loads(operation_updates[0][1])
    assert result["cvm"]["state"] == "RUNNING"
    assert result["policy_bundle"] == policy_bundle
