from __future__ import annotations

from collections import defaultdict
from threading import Lock
from time import perf_counter
from typing import DefaultDict

REQUEST_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)

_lock = Lock()
_requests_total: DefaultDict[tuple[str, str, str], int] = defaultdict(int)
_duration_sum: DefaultDict[tuple[str, str, str], float] = defaultdict(float)
_duration_count: DefaultDict[tuple[str, str, str], int] = defaultdict(int)
_duration_buckets: DefaultDict[tuple[str, str, str, float], int] = defaultdict(int)
_redacted_values_total: DefaultDict[str, int] = defaultdict(int)
_audit_chain_verification_failures_total = 0


def monotonic_seconds() -> float:
    return perf_counter()


def observe_request(*, route: str, method: str, status: int, duration_seconds: float) -> None:
    labels = (route, method, str(status))
    with _lock:
        _requests_total[labels] += 1
        _duration_sum[labels] += duration_seconds
        _duration_count[labels] += 1
        for bucket in REQUEST_BUCKETS:
            if duration_seconds <= bucket:
                _duration_buckets[(*labels, bucket)] += 1


def observe_redacted_value_in_log(*, source: str) -> None:
    with _lock:
        _redacted_values_total[source] += 1


def observe_audit_chain_verification_failure() -> None:
    global _audit_chain_verification_failures_total
    with _lock:
        _audit_chain_verification_failures_total += 1


def prometheus_text() -> str:
    lines: list[str] = []
    _emit_request_metrics(lines)
    _emit_redaction_metrics(lines)
    _emit_audit_metrics(lines)
    _emit_zero_placeholders(lines)
    return "\n".join(lines) + "\n"


def _emit_request_metrics(lines: list[str]) -> None:
    lines.append("# HELP umbra_console_requests_total Total Console HTTP requests.")
    lines.append("# TYPE umbra_console_requests_total counter")
    with _lock:
        request_items = sorted(_requests_total.items())
        duration_items = sorted(_duration_count.items())
        bucket_items = dict(_duration_buckets)
        sum_items = dict(_duration_sum)
    for (route, method, status), value in request_items:
        lines.append(
            f'umbra_console_requests_total{{route="{_label(route)}",method="{method}",status="{status}"}} {value}'
        )

    lines.append("# HELP umbra_console_request_duration_seconds Console HTTP request duration.")
    lines.append("# TYPE umbra_console_request_duration_seconds histogram")
    for route, method, status in (labels for labels, _ in duration_items):
        cumulative = 0
        for bucket in REQUEST_BUCKETS:
            cumulative = bucket_items.get((route, method, status, bucket), cumulative)
            lines.append(
                "umbra_console_request_duration_seconds_bucket"
                f'{{route="{_label(route)}",method="{method}",status="{status}",le="{bucket:g}"}} {cumulative}'
            )
        count = _duration_count[(route, method, status)]
        total = sum_items[(route, method, status)]
        lines.append(
            "umbra_console_request_duration_seconds_bucket"
            f'{{route="{_label(route)}",method="{method}",status="{status}",le="+Inf"}} {count}'
        )
        lines.append(
            f'umbra_console_request_duration_seconds_count{{route="{_label(route)}",method="{method}",status="{status}"}} {count}'
        )
        lines.append(
            f'umbra_console_request_duration_seconds_sum{{route="{_label(route)}",method="{method}",status="{status}"}} {total:.9f}'
        )


def _emit_redaction_metrics(lines: list[str]) -> None:
    lines.append("# HELP umbra_console_redacted_value_in_log_total Secret values caught by log redaction.")
    lines.append("# TYPE umbra_console_redacted_value_in_log_total counter")
    with _lock:
        items = sorted(_redacted_values_total.items())
    if not items:
        lines.append('umbra_console_redacted_value_in_log_total{source=""} 0')
        return
    for source, value in items:
        lines.append(f'umbra_console_redacted_value_in_log_total{{source="{_label(source)}"}} {value}')


def _emit_audit_metrics(lines: list[str]) -> None:
    lines.append(
        "# HELP umbra_console_audit_chain_verification_failures_total "
        "Failed full audit-chain verification attempts."
    )
    lines.append("# TYPE umbra_console_audit_chain_verification_failures_total counter")
    with _lock:
        failures = _audit_chain_verification_failures_total
    lines.append(f"umbra_console_audit_chain_verification_failures_total {failures}")


def _emit_zero_placeholders(lines: list[str]) -> None:
    placeholders = [
        ("umbra_console_rate_limit_drops_total", "counter", 'route="",dimension=""'),
        ("umbra_console_jwt_verification_duration_seconds_count", "counter", ""),
        ("umbra_console_jwt_revocation_lookup_duration_seconds_count", "counter", ""),
        ("umbra_console_operation_duration_seconds_count", "counter", 'kind="",terminal_status=""'),
        ("umbra_console_operations_inflight", "gauge", 'kind=""'),
        ("umbra_console_saga_step_duration_seconds_count", "counter", 'kind="",step=""'),
        ("umbra_console_external_call_duration_seconds_count", "counter", 'adapter="",op="",outcome=""'),
        ("umbra_console_audit_chain_seq", "gauge", ""),
        ("umbra_console_audit_anchor_age_seconds", "gauge", ""),
        ("umbra_console_auth_refresh_reuse_detected_total", "counter", ""),
        ("umbra_console_traffic_logs_ingested_total", "counter", 'principal_id=""'),
        ("umbra_console_traffic_log_resolution_rate", "gauge", ""),
    ]
    for name, metric_type, labels in placeholders:
        lines.append(f"# TYPE {name} {metric_type}")
        suffix = f"{{{labels}}}" if labels else ""
        lines.append(f"{name}{suffix} 0")


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
