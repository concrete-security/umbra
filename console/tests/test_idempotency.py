from concrete_console.idempotency import advisory_lock_key, entity_launch_lock_key, request_body_sha256


def test_request_body_sha256_hashes_raw_body() -> None:
    assert request_body_sha256(b'{"user_id":null}') != request_body_sha256(b'{"user_id": null}')


def test_advisory_lock_key_is_deterministic_signed_bigint() -> None:
    key = advisory_lock_key(
        credential_id="00000000-0000-4000-8000-000000000001",
        idempotency_key="session-revoke-smoke",
        route="POST /api/v1/admin/sessions/revoke",
    )

    assert key == advisory_lock_key(
        credential_id="00000000-0000-4000-8000-000000000001",
        idempotency_key="session-revoke-smoke",
        route="POST /api/v1/admin/sessions/revoke",
    )
    assert -(2**63) <= key < 2**63


def test_entity_launch_lock_key_is_deterministic_signed_bigint() -> None:
    entity_id = "00000000-0000-4000-8000-0000000000ee"
    key = entity_launch_lock_key(entity_id)

    assert key == entity_launch_lock_key(entity_id)
    assert entity_launch_lock_key(entity_id) != entity_launch_lock_key("00000000-0000-4000-8000-0000000000ef")
    assert -(2**63) <= key < 2**63


def test_entity_launch_lock_key_does_not_collide_with_idempotency_lock() -> None:
    # Distinct namespaces: the per-entity launch lock and an idempotency lock
    # derived from the same UUID must not share a lock id.
    entity_id = "00000000-0000-4000-8000-0000000000ee"
    assert entity_launch_lock_key(entity_id) != advisory_lock_key(
        credential_id=entity_id, idempotency_key="", route=""
    )
