from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping
from urllib.parse import parse_qs, unquote

import re2


TOP_LEVEL_FIELDS = {
    "allowed_destinations",
    "blocked_destinations",
    "secret_patterns",
    "secret_injections",
    "sandbox_env",
}
DESTINATION_FIELDS = {
    "id",
    "scheme",
    "host",
    "ports",
    "methods",
    "path_prefixes",
    "body_assertions",
    "traffic_log_attributes",
}
DESTINATION_EXTENSION_FIELDS = {"body_assertions", "traffic_log_attributes"}
DESTINATION_MATCH_FIELDS = {"scheme", "host", "ports", "methods", "path_prefixes"}
SECRET_PATTERN_FIELDS = {"id", "name", "pattern", "scan_headers", "scan_body"}
SECRET_INJECTION_FIELDS = {"id", "match", "type", "header", "value", "value_template"}
SANDBOX_ENV_FIELDS = {"name", "value"}
BODY_ASSERTION_FIELDS = {"kind", "field", "allow_values"}
TRAFFIC_LOG_ATTRIBUTE_FIELDS = {"name", "kind", "field"}
BODY_ASSERTION_KINDS = {"form", "json"}

ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HEADER_RE = re.compile(r"^[a-z][a-z0-9-]{0,126}$")
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
POINTER_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
TRAFFIC_LOG_ATTRIBUTE_NAME_RE = re.compile(r"^[a-z_]{1,32}$")
PATH_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
PATH_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
PATH_AMBIGUOUS_ESCAPE_RE = re.compile(r"%(?:2[eEfF]|5[cC])")
HOP_BY_HOP_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

MAX_BODY_ASSERTION_BYTES = 1 * 1024 * 1024
MAX_BODY_ASSERTION_JSON_DEPTH = 32
MAX_BODY_ASSERTION_JSON_KEYS = 1024
MAX_BODY_ASSERTION_JSON_ARRAY = 1024
MAX_BODY_ASSERTIONS_PER_RULE = 16
MAX_TRAFFIC_LOG_ATTRIBUTES_PER_RULE = 4
MAX_POINTER_SEGMENTS_JSON = 4
MAX_ALLOW_VALUES = 256
MAX_ALLOW_VALUE_LEN = 256
MAX_TRAFFIC_LOG_ATTRIBUTE_VALUE_CHARS = 256


class _Missing:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<_MISSING>"


_MISSING: Any = _Missing()


@dataclass(frozen=True)
class PolicyError:
    field: str
    type: str
    message: str


class PolicyValidationError(ValueError):
    def __init__(self, errors: list[PolicyError]) -> None:
        self.errors = errors
        super().__init__("; ".join(f"{error.field}: {error.message}" for error in errors))


@dataclass(frozen=True)
class BodyAssertion:
    kind: str
    field: tuple[str, ...]
    allow_values: frozenset[str]

    def evaluate(self, body: bytes, headers: Mapping[str, str]) -> bool:
        value = _extract_scalar(self.kind, self.field, body, headers)
        if value is _MISSING:
            return False
        return _scalar_to_str(value) in self.allow_values


@dataclass(frozen=True)
class TrafficLogAttribute:
    name: str
    kind: str
    field: tuple[str, ...]

    def extract(self, body: bytes, headers: Mapping[str, str]) -> str | None:
        value = _extract_scalar(self.kind, self.field, body, headers)
        if value is _MISSING:
            return None
        return _scalar_to_str(value)[:MAX_TRAFFIC_LOG_ATTRIBUTE_VALUE_CHARS]


@dataclass(frozen=True)
class DestinationRule:
    rule_id: str | None
    scheme: str
    host: str
    ports: tuple[int, ...]
    methods: tuple[str, ...]
    path_prefixes: tuple[str, ...]
    body_assertions: tuple[BodyAssertion, ...] = ()
    traffic_log_attributes: tuple[TrafficLogAttribute, ...] = ()

    def matches(self, *, scheme: str, host: str, port: int, method: str, path: str) -> bool:
        return (
            self.scheme == scheme.lower()
            and self._host_matches(host.lower().rstrip("."))
            and port in self.ports
            and method.upper() in self.methods
            and _path_matches_prefixes(path, self.path_prefixes)
        )

    def matches_tunnel(self, *, scheme: str, host: str, port: int) -> bool:
        return self.scheme == scheme.lower() and self._host_matches(host.lower().rstrip(".")) and port in self.ports

    def _host_matches(self, host: str) -> bool:
        if self.host.startswith("*."):
            suffix = self.host[2:]
            return host.endswith(f".{suffix}") and host != suffix
        return host == self.host

    def body_assertions_pass(self, body: bytes, headers: Mapping[str, str]) -> bool:
        return all(assertion.evaluate(body, headers) for assertion in self.body_assertions)

    def extract_traffic_log_attributes(self, body: bytes, headers: Mapping[str, str]) -> dict[str, str]:
        attributes: dict[str, str] = {}
        for attribute in self.traffic_log_attributes:
            value = attribute.extract(body, headers)
            if value is not None:
                attributes[attribute.name] = value
        return attributes


@dataclass(frozen=True)
class SecretPattern:
    pattern_id: str
    name: str
    pattern: str
    scan_headers: bool
    scan_body: bool
    compiled: Any


@dataclass(frozen=True)
class SecretInjection:
    injection_id: str
    match: DestinationRule
    header: str
    value: str
    value_template: str

    def rendered_value(self) -> str:
        return self.value_template.replace("${secret}", self.value)


@dataclass(frozen=True)
class SandboxEnvPlaceholder:
    name: str
    value: str


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    rule_id: str | None = None
    matched_rule: DestinationRule | None = None


@dataclass(frozen=True)
class EffectivePolicy:
    allowed_destinations: tuple[DestinationRule, ...]
    blocked_destinations: tuple[DestinationRule, ...]
    secret_patterns: tuple[SecretPattern, ...]
    secret_injections: tuple[SecretInjection, ...]
    sandbox_env: tuple[SandboxEnvPlaceholder, ...]

    @classmethod
    def deny_all(cls) -> EffectivePolicy:
        return cls(
            allowed_destinations=(),
            blocked_destinations=(),
            secret_patterns=(),
            secret_injections=(),
            sandbox_env=(),
        )

    def decide(
        self,
        *,
        scheme: str,
        host: str,
        port: int,
        method: str,
        path: str,
        body: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> PolicyDecision:
        request = {
            "scheme": scheme,
            "host": host,
            "port": port,
            "method": method,
            "path": path or "/",
        }
        for rule in self.blocked_destinations:
            if rule.matches(**request):
                return PolicyDecision(False, "blocked_destination", rule.rule_id)
        for rule in self.allowed_destinations:
            if not rule.matches(**request):
                continue
            if rule.body_assertions and not rule.body_assertions_pass(body, headers or {}):
                continue
            return PolicyDecision(True, "allowed_destination", rule.rule_id, matched_rule=rule)
        return PolicyDecision(False, "destination_not_allowed")

    def decide_tunnel(self, *, scheme: str, host: str, port: int) -> PolicyDecision:
        request = {
            "scheme": scheme,
            "host": host,
            "port": port,
        }
        for rule in self.blocked_destinations:
            if rule.matches_tunnel(**request):
                return PolicyDecision(False, "blocked_destination", rule.rule_id)
        for rule in self.allowed_destinations:
            if rule.matches_tunnel(**request):
                return PolicyDecision(True, "allowed_destination", rule.rule_id, matched_rule=rule)
        return PolicyDecision(False, "destination_not_allowed")

    def render_injection_headers(
        self,
        *,
        scheme: str,
        host: str,
        port: int,
        method: str,
        path: str,
    ) -> dict[str, str]:
        rendered: dict[str, str] = {}
        ids_by_header: dict[str, str] = {}
        request = {
            "scheme": scheme,
            "host": host,
            "port": port,
            "method": method,
            "path": path or "/",
        }
        for injection in self.secret_injections:
            if not injection.match.matches(**request):
                continue
            value = injection.rendered_value()
            existing = rendered.get(injection.header)
            if existing is not None and existing != value:
                raise PolicyValidationError(
                    [
                        PolicyError(
                            field=f"secret_injections.{injection.injection_id}.header",
                            type="secret_injection_conflict",
                            message=f"conflicts with {ids_by_header[injection.header]}",
                        )
                    ]
                )
            rendered[injection.header] = value
            ids_by_header[injection.header] = injection.injection_id
        return rendered


def parse_effective_policy(raw: Any) -> EffectivePolicy:
    errors: list[PolicyError] = []
    if not isinstance(raw, dict):
        raise PolicyValidationError([PolicyError("policy", "object_required", "policy must be an object")])
    _reject_unknown_fields(raw, TOP_LEVEL_FIELDS, "policy", errors)
    if errors:
        raise PolicyValidationError(errors)
    allowed = _parse_destination_rules(
        raw.get("allowed_destinations", []),
        "allowed_destinations",
        errors,
        allow_extensions=True,
    )
    blocked = _parse_destination_rules(
        raw.get("blocked_destinations", []),
        "blocked_destinations",
        errors,
        allow_extensions=False,
    )
    patterns = _parse_secret_patterns(raw.get("secret_patterns", []), errors)
    injections = _parse_secret_injections(raw.get("secret_injections", []), errors)
    sandbox_env = _parse_sandbox_env(raw.get("sandbox_env", []), errors)
    if errors:
        raise PolicyValidationError(errors)
    return EffectivePolicy(
        allowed_destinations=tuple(allowed),
        blocked_destinations=tuple(blocked),
        secret_patterns=tuple(patterns),
        secret_injections=tuple(injections),
        sandbox_env=tuple(sandbox_env),
    )


def _parse_destination_rules(
    raw: Any,
    field: str,
    errors: list[PolicyError],
    *,
    allow_extensions: bool,
) -> list[DestinationRule]:
    if not isinstance(raw, list):
        errors.append(PolicyError(field, "array_required", "destination rules must be an array"))
        return []
    return [
        rule
        for index, item in enumerate(raw)
        if (
            rule := _parse_destination_rule(
                item,
                f"{field}.{index}",
                errors,
                require_id=True,
                allow_extensions=allow_extensions,
            )
        )
        is not None
    ]


def _parse_destination_rule(
    raw: Any,
    field: str,
    errors: list[PolicyError],
    *,
    require_id: bool,
    allow_extensions: bool = False,
) -> DestinationRule | None:
    if not isinstance(raw, dict):
        errors.append(PolicyError(field, "object_required", "destination rule must be an object"))
        return None
    base_fields = DESTINATION_FIELDS if require_id else DESTINATION_MATCH_FIELDS
    allowed_fields = base_fields if allow_extensions else (base_fields - DESTINATION_EXTENSION_FIELDS)
    _reject_unknown_fields(raw, allowed_fields, field, errors)
    rule_id = raw.get("id")
    if require_id:
        if not isinstance(rule_id, str) or not ID_RE.fullmatch(rule_id):
            errors.append(PolicyError(f"{field}.id", "invalid_id", "id must be 1..100 chars [A-Za-z0-9._:-]"))
    elif "id" in raw:
        errors.append(PolicyError(f"{field}.id", "forbidden_field", "match rules must not include id"))
        rule_id = None
    scheme = raw.get("scheme")
    host = raw.get("host")
    if scheme not in {"http", "https"}:
        errors.append(PolicyError(f"{field}.scheme", "invalid_scheme", "scheme must be http or https"))
        scheme = "https"
    if not isinstance(host, str) or not _valid_policy_host(host):
        errors.append(PolicyError(f"{field}.host", "invalid_host", "host must be lower-case DNS or leading wildcard"))
        host = ""
    ports = _parse_ports(raw.get("ports"), scheme, f"{field}.ports", errors)
    methods = _parse_methods(raw.get("methods"), f"{field}.methods", errors)
    path_prefixes = _parse_path_prefixes(raw.get("path_prefixes"), f"{field}.path_prefixes", errors)
    body_assertions: list[BodyAssertion] = []
    traffic_log_attributes: list[TrafficLogAttribute] = []
    if allow_extensions:
        body_assertions = _parse_body_assertions(
            raw.get("body_assertions", []),
            f"{field}.body_assertions",
            errors,
        )
        traffic_log_attributes = _parse_traffic_log_attributes(
            raw.get("traffic_log_attributes", []),
            f"{field}.traffic_log_attributes",
            errors,
        )
    if not host or not methods or not path_prefixes:
        return None
    return DestinationRule(
        rule_id=rule_id if isinstance(rule_id, str) else None,
        scheme=scheme,
        host=host,
        ports=tuple(ports),
        methods=tuple(methods),
        path_prefixes=tuple(path_prefixes),
        body_assertions=tuple(body_assertions),
        traffic_log_attributes=tuple(traffic_log_attributes),
    )


def _parse_body_assertions(
    raw: Any,
    field: str,
    errors: list[PolicyError],
) -> list[BodyAssertion]:
    if raw is None or raw == []:
        return []
    if not isinstance(raw, list):
        errors.append(PolicyError(field, "array_required", "body_assertions must be an array"))
        return []
    if len(raw) > MAX_BODY_ASSERTIONS_PER_RULE:
        errors.append(
            PolicyError(
                field,
                "too_many",
                f"body_assertions must contain at most {MAX_BODY_ASSERTIONS_PER_RULE} entries",
            )
        )
        return []
    assertions: list[BodyAssertion] = []
    for index, item in enumerate(raw):
        item_field = f"{field}.{index}"
        if not isinstance(item, dict):
            errors.append(PolicyError(item_field, "object_required", "body assertion must be an object"))
            continue
        _reject_unknown_fields(item, BODY_ASSERTION_FIELDS, item_field, errors)
        kind = item.get("kind")
        if kind not in BODY_ASSERTION_KINDS:
            errors.append(PolicyError(f"{item_field}.kind", "invalid_kind", "kind must be form or json"))
            continue
        segments = _parse_pointer_field(item.get("field"), kind, f"{item_field}.field", errors)
        if segments is None:
            continue
        allow_values = _parse_allow_values(item.get("allow_values"), f"{item_field}.allow_values", errors)
        if allow_values is None:
            continue
        assertions.append(BodyAssertion(kind=kind, field=segments, allow_values=frozenset(allow_values)))
    return assertions


def _parse_traffic_log_attributes(
    raw: Any,
    field: str,
    errors: list[PolicyError],
) -> list[TrafficLogAttribute]:
    if raw is None or raw == []:
        return []
    if not isinstance(raw, list):
        errors.append(PolicyError(field, "array_required", "traffic_log_attributes must be an array"))
        return []
    if len(raw) > MAX_TRAFFIC_LOG_ATTRIBUTES_PER_RULE:
        errors.append(
            PolicyError(
                field,
                "too_many",
                f"traffic_log_attributes must contain at most {MAX_TRAFFIC_LOG_ATTRIBUTES_PER_RULE} entries",
            )
        )
        return []
    seen_names: set[str] = set()
    attributes: list[TrafficLogAttribute] = []
    for index, item in enumerate(raw):
        item_field = f"{field}.{index}"
        if not isinstance(item, dict):
            errors.append(PolicyError(item_field, "object_required", "traffic_log_attribute must be an object"))
            continue
        _reject_unknown_fields(item, TRAFFIC_LOG_ATTRIBUTE_FIELDS, item_field, errors)
        name = item.get("name")
        if not isinstance(name, str) or not TRAFFIC_LOG_ATTRIBUTE_NAME_RE.fullmatch(name):
            errors.append(
                PolicyError(f"{item_field}.name", "invalid_name", "name must be 1..32 chars [a-z_]")
            )
            continue
        if name in seen_names:
            errors.append(
                PolicyError(f"{item_field}.name", "duplicate_name", f"name {name!r} already used in this rule")
            )
            continue
        kind = item.get("kind")
        if kind not in BODY_ASSERTION_KINDS:
            errors.append(PolicyError(f"{item_field}.kind", "invalid_kind", "kind must be form or json"))
            continue
        segments = _parse_pointer_field(item.get("field"), kind, f"{item_field}.field", errors)
        if segments is None:
            continue
        seen_names.add(name)
        attributes.append(TrafficLogAttribute(name=name, kind=kind, field=segments))
    return attributes


def _parse_pointer_field(
    raw: Any,
    kind: str,
    field: str,
    errors: list[PolicyError],
) -> tuple[str, ...] | None:
    if not isinstance(raw, str):
        errors.append(PolicyError(field, "invalid_field", "field must be a string"))
        return None
    if not raw.startswith("/"):
        errors.append(PolicyError(field, "invalid_field", "field must start with '/'"))
        return None
    segments_raw = raw[1:].split("/")
    if not segments_raw or any(not segment for segment in segments_raw):
        errors.append(PolicyError(field, "invalid_field", "field segments must be non-empty"))
        return None
    max_segments = 1 if kind == "form" else MAX_POINTER_SEGMENTS_JSON
    if len(segments_raw) > max_segments:
        errors.append(
            PolicyError(
                field,
                "invalid_field",
                f"field must have at most {max_segments} segments for kind={kind}",
            )
        )
        return None
    for segment in segments_raw:
        if not POINTER_SEGMENT_RE.fullmatch(segment):
            errors.append(
                PolicyError(field, "invalid_field", "field segments must be 1..64 chars from [A-Za-z0-9_.-]")
            )
            return None
    return tuple(segments_raw)


def _parse_allow_values(
    raw: Any,
    field: str,
    errors: list[PolicyError],
) -> list[str] | None:
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_ALLOW_VALUES:
        errors.append(
            PolicyError(
                field,
                "invalid_allow_values",
                f"allow_values must contain 1..{MAX_ALLOW_VALUES} strings",
            )
        )
        return None
    values: list[str] = []
    for index, value in enumerate(raw):
        if not isinstance(value, str) or not 1 <= len(value) <= MAX_ALLOW_VALUE_LEN:
            errors.append(
                PolicyError(
                    f"{field}.{index}",
                    "invalid_allow_value",
                    f"allow_value must be 1..{MAX_ALLOW_VALUE_LEN} chars",
                )
            )
            return None
        values.append(value)
    return values


def _parse_secret_patterns(raw: Any, errors: list[PolicyError]) -> list[SecretPattern]:
    if not isinstance(raw, list):
        errors.append(PolicyError("secret_patterns", "array_required", "secret_patterns must be an array"))
        return []
    patterns: list[SecretPattern] = []
    for index, item in enumerate(raw):
        field = f"secret_patterns.{index}"
        if not isinstance(item, dict):
            errors.append(PolicyError(field, "object_required", "secret pattern must be an object"))
            continue
        _reject_unknown_fields(item, SECRET_PATTERN_FIELDS, field, errors)
        pattern_id = item.get("id")
        name = item.get("name")
        pattern = item.get("pattern")
        scan_headers = item.get("scan_headers")
        scan_body = item.get("scan_body")
        if not isinstance(pattern_id, str) or not ID_RE.fullmatch(pattern_id):
            errors.append(PolicyError(f"{field}.id", "invalid_id", "id must be 1..100 chars [A-Za-z0-9._:-]"))
            continue
        if not isinstance(name, str) or len(name) > 100:
            errors.append(PolicyError(f"{field}.name", "invalid_name", "name must be a string <=100 chars"))
            continue
        if not isinstance(pattern, str) or not pattern or len(pattern) > 4096:
            errors.append(PolicyError(f"{field}.pattern", "invalid_pattern", "pattern must be 1..4096 chars"))
            continue
        if not isinstance(scan_headers, bool) or not isinstance(scan_body, bool):
            errors.append(PolicyError(field, "invalid_scan_flags", "scan flags must be booleans"))
            continue
        try:
            compiled = re2.compile(pattern)
        except Exception as exc:
            errors.append(PolicyError(f"{field}.pattern", "invalid_regex", str(exc)))
            continue
        patterns.append(SecretPattern(pattern_id, name, pattern, scan_headers, scan_body, compiled))
    return patterns


def _parse_secret_injections(raw: Any, errors: list[PolicyError]) -> list[SecretInjection]:
    if not isinstance(raw, list):
        errors.append(PolicyError("secret_injections", "array_required", "secret_injections must be an array"))
        return []
    injections: list[SecretInjection] = []
    for index, item in enumerate(raw):
        field = f"secret_injections.{index}"
        if not isinstance(item, dict):
            errors.append(PolicyError(field, "object_required", "secret injection must be an object"))
            continue
        _reject_unknown_fields(item, SECRET_INJECTION_FIELDS, field, errors)
        injection_id = item.get("id")
        injection_type = item.get("type")
        header = item.get("header")
        value = item.get("value")
        template = item.get("value_template")
        if not isinstance(injection_id, str) or not ID_RE.fullmatch(injection_id):
            errors.append(PolicyError(f"{field}.id", "invalid_id", "id must be 1..100 chars [A-Za-z0-9._:-]"))
            continue
        if injection_type != "request_header":
            errors.append(PolicyError(f"{field}.type", "invalid_type", "only request_header is supported"))
            continue
        match = _parse_destination_rule(
            item.get("match"),
            f"{field}.match",
            errors,
            require_id=False,
            allow_extensions=False,
        )
        if not isinstance(header, str) or not HEADER_RE.fullmatch(header) or header in HOP_BY_HOP_HEADERS:
            errors.append(PolicyError(f"{field}.header", "invalid_header", "header must be lower-case and injectable"))
            continue
        if not isinstance(value, str):
            errors.append(PolicyError(f"{field}.value", "string_required", "value must be a string"))
            continue
        if not isinstance(template, str) or template.count("${secret}") != 1:
            errors.append(
                PolicyError(f"{field}.value_template", "invalid_template", "template must contain ${secret} once")
            )
            continue
        if len(template.replace("${secret}", value)) > 8192:
            errors.append(PolicyError(f"{field}.value_template", "rendered_value_too_long", "rendered value too long"))
            continue
        if match is not None:
            injections.append(SecretInjection(injection_id, match, header, value, template))
    return injections


def _parse_sandbox_env(raw: Any, errors: list[PolicyError]) -> list[SandboxEnvPlaceholder]:
    if not isinstance(raw, list):
        errors.append(PolicyError("sandbox_env", "array_required", "sandbox_env must be an array"))
        return []
    placeholders: list[SandboxEnvPlaceholder] = []
    for index, item in enumerate(raw):
        field = f"sandbox_env.{index}"
        if not isinstance(item, dict):
            errors.append(PolicyError(field, "object_required", "sandbox_env item must be an object"))
            continue
        _reject_unknown_fields(item, SANDBOX_ENV_FIELDS, field, errors)
        name = item.get("name")
        value = item.get("value")
        if not isinstance(name, str) or not ENV_NAME_RE.fullmatch(name):
            errors.append(PolicyError(f"{field}.name", "invalid_name", "name must be a POSIX env name"))
            continue
        if not isinstance(value, str):
            errors.append(PolicyError(f"{field}.value", "string_required", "value must be a string"))
            continue
        placeholders.append(SandboxEnvPlaceholder(name, value))
    return placeholders


def _parse_ports(raw: Any, scheme: str, field: str, errors: list[PolicyError]) -> list[int]:
    if raw is None:
        return [443 if scheme == "https" else 80]
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        errors.append(PolicyError(field, "invalid_ports", "ports must contain 1..16 integers"))
        return []
    ports: list[int] = []
    for index, port in enumerate(raw):
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            errors.append(PolicyError(f"{field}.{index}", "invalid_port", "port must be 1..65535"))
            continue
        ports.append(port)
    return ports


def _parse_methods(raw: Any, field: str, errors: list[PolicyError]) -> list[str]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        errors.append(PolicyError(field, "invalid_methods", "methods must contain 1..16 uppercase methods"))
        return []
    methods: list[str] = []
    for index, method in enumerate(raw):
        if not isinstance(method, str) or not method or method != method.upper() or len(method) > 20:
            errors.append(PolicyError(f"{field}.{index}", "invalid_method", "method must be uppercase"))
            continue
        methods.append(method)
    return methods


def _parse_path_prefixes(raw: Any, field: str, errors: list[PolicyError]) -> list[str]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= 32:
        errors.append(PolicyError(field, "invalid_path_prefixes", "path_prefixes must contain 1..32 values"))
        return []
    prefixes: list[str] = []
    for index, prefix in enumerate(raw):
        if not isinstance(prefix, str) or not _valid_policy_path(prefix):
            errors.append(
                PolicyError(
                    f"{field}.{index}",
                    "invalid_path_prefix",
                    "path prefix must be an absolute unambiguous origin path",
                )
            )
            continue
        prefixes.append(prefix)
    return prefixes


def _reject_unknown_fields(raw: dict[str, Any], allowed: set[str], field: str, errors: list[PolicyError]) -> None:
    for key in sorted(set(raw) - allowed):
        errors.append(PolicyError(f"{field}.{key}", "unknown_field", "field is not part of the Security CVM schema"))


def _valid_policy_host(host: str) -> bool:
    if host != host.lower() or host.endswith(".") or len(host) > 253:
        return False
    if host.startswith("*."):
        suffix = host[2:]
        return "." in suffix and _valid_dns_name(suffix)
    return _valid_dns_name(host)


def _valid_dns_name(host: str) -> bool:
    labels = host.split(".")
    return len(labels) >= 2 and all(DNS_LABEL_RE.fullmatch(label) for label in labels)


def valid_proxy_token_hash(value: str) -> bool:
    return bool(HEX_SHA256_RE.fullmatch(value))


def _extract_scalar(kind: str, field: tuple[str, ...], body: bytes, headers: Mapping[str, str]) -> Any:
    if not body or len(body) > MAX_BODY_ASSERTION_BYTES:
        return _MISSING
    if not _content_type_matches(kind, headers):
        return _MISSING
    if kind == "form":
        if len(field) != 1:
            return _MISSING
        parsed = _parse_form_body(body)
        if parsed is _MISSING:
            return _MISSING
        return parsed.get(field[0], _MISSING)
    if kind == "json":
        parsed = _parse_json_body(body)
        if parsed is _MISSING:
            return _MISSING
        return _walk_json_pointer(parsed, field)
    return _MISSING


def _content_type_matches(kind: str, headers: Mapping[str, str]) -> bool:
    content_type = ""
    for name, value in headers.items():
        if name.lower() == "content-type":
            content_type = value
            break
    media_type = content_type.split(";", 1)[0].strip().lower()
    if kind == "form":
        return media_type == "application/x-www-form-urlencoded"
    if kind == "json":
        return media_type == "application/json"
    return False


def _path_matches_prefixes(path: str, prefixes: tuple[str, ...]) -> bool:
    return _valid_policy_path(path) and any(path.startswith(prefix) for prefix in prefixes)


def _valid_policy_path(path: str) -> bool:
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    if PATH_CONTROL_RE.search(path) or "\\" in path or "?" in path or "#" in path:
        return False
    if PATH_BAD_PERCENT_RE.search(path) or PATH_AMBIGUOUS_ESCAPE_RE.search(path):
        return False
    decoded = unquote(path)
    if not decoded.startswith("/") or "\\" in decoded or PATH_CONTROL_RE.search(decoded):
        return False
    if decoded != "/" and "//" in decoded:
        return False
    segments = decoded.split("/")
    for index, segment in enumerate(segments[1:], start=1):
        if segment in {".", ".."}:
            return False
        if segment == "" and index != len(segments) - 1:
            return False
    return True


def _parse_form_body(body: bytes) -> dict[str, str] | Any:
    try:
        decoded = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _MISSING
    try:
        parsed = parse_qs(decoded, strict_parsing=True, keep_blank_values=True)
    except ValueError:
        return _MISSING
    result: dict[str, str] = {}
    for key, values in parsed.items():
        if len(values) != 1:
            continue
        result[key] = values[0]
    return result


def _parse_json_body(body: bytes) -> Any:
    try:
        decoded = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _MISSING
    try:
        value = json.loads(decoded)
    except json.JSONDecodeError:
        return _MISSING
    if not _validate_json_bounds(value, depth=0):
        return _MISSING
    return value


def _validate_json_bounds(value: Any, *, depth: int) -> bool:
    if depth > MAX_BODY_ASSERTION_JSON_DEPTH:
        return False
    if isinstance(value, dict):
        if len(value) > MAX_BODY_ASSERTION_JSON_KEYS:
            return False
        for v in value.values():
            if not _validate_json_bounds(v, depth=depth + 1):
                return False
    elif isinstance(value, list):
        if len(value) > MAX_BODY_ASSERTION_JSON_ARRAY:
            return False
        for v in value:
            if not _validate_json_bounds(v, depth=depth + 1):
                return False
    return True


def _walk_json_pointer(value: Any, segments: tuple[str, ...]) -> Any:
    cursor: Any = value
    for segment in segments:
        if isinstance(cursor, dict):
            if segment not in cursor:
                return _MISSING
            cursor = cursor[segment]
        elif isinstance(cursor, list):
            try:
                index = int(segment)
            except ValueError:
                return _MISSING
            if index < 0 or index >= len(cursor):
                return _MISSING
            cursor = cursor[index]
        else:
            return _MISSING
    if isinstance(cursor, bool):
        return cursor
    if isinstance(cursor, (str, int, float)):
        return cursor
    return _MISSING


def _scalar_to_str(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
