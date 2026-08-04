import json
import logging
import re

from umbra_console.log_config import redact_log_values
from umbra_console.metrics import prometheus_text


class NamedLogger:
    def __init__(self, name: str) -> None:
        self.name = name


def test_redaction_preserves_request_id() -> None:
    event = redact_log_values(
        NamedLogger("test.redaction.preserve"),
        "info",
        {
            "event": "request_completed",
            "request_id": "00000000-0000-4000-8000-000000000001",
            "authorization": "Bearer secret-token",
        },
    )

    assert event["request_id"] == "00000000-0000-4000-8000-000000000001"
    assert event["authorization"] == "<redacted>"


def test_redaction_covers_spec_denied_keys() -> None:
    event = redact_log_values(
        NamedLogger("test.redaction.keys"),
        "info",
        {
            "event": "request_completed",
            "before": {"email": "admin@example.com"},
            "after": {"email": "admin@example.com"},
            "compose_config": "services: {}",
            "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nsecret\n-----END CERTIFICATE-----",
            "ingest_token_plaintext": "ingest",
            "ca_export_token_plaintext": "ca-export",
            "nested": {"device_code": "device-code"},
        },
    )

    assert event["before"] == "<redacted>"
    assert event["after"] == "<redacted>"
    assert event["compose_config"] == "<redacted>"
    assert event["ca_cert_pem"] == "<redacted>"
    assert event["ingest_token_plaintext"] == "<redacted>"
    assert event["ca_export_token_plaintext"] == "<redacted>"
    assert event["nested"]["device_code"] == "<redacted>"


def test_redaction_uses_configured_secret_values(monkeypatch) -> None:
    source = "test.redaction.configured"
    before = _metric_value(source)
    monkeypatch.setenv("GOOGLE_OIDC_CLIENT_SECRET", "configured-secret-value")

    event = redact_log_values(
        NamedLogger(source),
        "info",
        {"event": "upstream_error", "message": "provider echoed configured-secret-value"},
    )

    assert event["message"] == "<redacted>"
    assert _metric_value(source) == before + 1


def test_redaction_emits_alarm_log(caplog) -> None:
    with caplog.at_level(logging.ERROR, logger="umbra_console.redaction"):
        redact_log_values(
            NamedLogger("test.redaction.alarm"),
            "info",
            {"event": "request_completed", "authorization": "Bearer secret-token"},
        )

    payloads = [json.loads(record.message) for record in caplog.records]
    assert {
        "event": "redacted_value_in_log",
        "level": "error",
        "key": "authorization",
        "source": "test.redaction.alarm",
    } in payloads


def _metric_value(source: str) -> int:
    match = re.search(
        rf'umbra_console_redacted_value_in_log_total\{{source="{re.escape(source)}"\}} (\d+)',
        prometheus_text(),
    )
    return int(match.group(1)) if match else 0
