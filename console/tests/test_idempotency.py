from concrete_console.idempotency import advisory_lock_key, request_body_sha256


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
