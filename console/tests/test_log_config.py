from concrete_console.log_config import redact_log_values


def test_redaction_preserves_request_id() -> None:
    event = redact_log_values(
        None,
        "info",
        {
            "event": "request_completed",
            "request_id": "00000000-0000-4000-8000-000000000001",
            "authorization": "Bearer secret-token",
        },
    )

    assert event["request_id"] == "00000000-0000-4000-8000-000000000001"
    assert event["authorization"] == "<redacted>"
