import asyncio
import base64
import hashlib
import json
from types import SimpleNamespace
from uuid import UUID

from concrete_console import scheduler


class FakeConn:
    def __init__(self, *, fetch_rows=None, execute_result="UPDATE 1"):
        self.fetch_rows = fetch_rows or []
        self.execute_result = execute_result
        self.fetch_calls: list[tuple[str, tuple[object, ...]]] = []
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetch(self, query, *args):
        self.fetch_calls.append((query, args))
        return self.fetch_rows

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return self.execute_result


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


def test_provider_app_id_parses_json_metadata() -> None:
    assert scheduler.provider_app_id({"app_id": "app-123"}) == "app-123"
    assert scheduler.provider_app_id('{"app_id": "app-123"}') == "app-123"
    assert scheduler.provider_app_id({}) is None


def launch_snapshot(**overrides):
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
        "security_cvm_expected_image_measurement": "b" * 64,
        "security_cvm_image_measurement": "b" * 64,
        "security_cvm_rtmr3_digest": "c" * 96,
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
    assert json.loads(decode_env(env["SECURITY_CVM_ATLS_POLICY_B64"]))["fqdn"] == "sc-abc.sc.example.com"
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


class AsyncContext:
    def __init__(self, value=None):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, exc_type, exc, tb):
        return None


class LaunchFakeConn:
    def __init__(self):
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, query, *args):
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
