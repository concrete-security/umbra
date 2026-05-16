from concrete_security_cvm.ca import generate_root_ca
from concrete_security_cvm.management import handle_ca_pem_request, parse_bearer


def test_parse_bearer_accepts_single_bearer_token() -> None:
    assert parse_bearer("Bearer abc123") == "abc123"
    assert parse_bearer(None) is None
    assert parse_bearer("Basic abc123") is None
    assert parse_bearer("Bearer") is None
    assert parse_bearer("Bearer abc 123") is None
    assert parse_bearer("Bearer  abc123") is None


def test_ca_pem_request_returns_public_ca_on_matching_bearer() -> None:
    ca = generate_root_ca()

    response = handle_ca_pem_request(
        headers={"authorization": "Bearer export-token"},
        ca=ca,
        ca_export_token="export-token",
    )

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/x-pem-file"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.body == ca.ca_pem
    assert b"PRIVATE KEY" not in response.body


def test_ca_pem_request_rejects_missing_malformed_or_wrong_bearer() -> None:
    ca = generate_root_ca()

    for headers in ({}, {"authorization": "Bearer wrong"}, {"authorization": "Basic export-token"}):
        response = handle_ca_pem_request(headers=headers, ca=ca, ca_export_token="export-token")
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.body == b""
