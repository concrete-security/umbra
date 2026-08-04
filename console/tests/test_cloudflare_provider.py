import asyncio
import json

import httpx
import pytest

from umbra_console.dns_provider.cloudflare import (
    CLOUDFLARE_API_BASE,
    CloudflareClient,
    CloudflareError,
    dstack_txt_name,
    gateway_cname_content,
    record_create_payload,
)


def run(awaitable):
    return asyncio.run(awaitable)


def json_response(payload: dict, *, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, json=payload)


def test_dstack_txt_and_gateway_cname_shapes() -> None:
    assert dstack_txt_name("cvm-abc.dev.example.com") == "_dstack-app-address.cvm-abc.dev.example.com"
    assert gateway_cname_content("gateway.example.com") == "_.gateway.example.com"


def test_record_create_payload_sets_ttl_and_cname_proxy_mode() -> None:
    assert record_create_payload(record_type="TXT", name="name.example.com", content="app:443") == {
        "type": "TXT",
        "name": "name.example.com",
        "content": "app:443",
        "ttl": 1,
    }
    assert record_create_payload(record_type="CNAME", name="name.example.com", content="_.gateway.example.com") == {
        "type": "CNAME",
        "name": "name.example.com",
        "content": "_.gateway.example.com",
        "ttl": 1,
        "proxied": False,
    }


def test_ensure_dstack_txt_reuses_matching_record() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer cf-token"
        return json_response(
            {
                "success": True,
                "result": [
                    {
                        "id": "txt-record",
                        "type": "TXT",
                        "name": "_dstack-app-address.cvm.example.com",
                        "content": "app-123:443",
                    }
                ],
            }
        )

    client = CloudflareClient(api_token="cf-token", zone_id="zone", transport=httpx.MockTransport(handler))

    record_id = run(client.ensure_dstack_txt(fqdn="cvm.example.com", app_id="app-123"))

    assert record_id == "txt-record"
    assert [request.method for request in requests] == ["GET"]
    assert requests[0].url.params["name"] == "_dstack-app-address.cvm.example.com"
    assert requests[0].url.params["type"] == "TXT"


def test_ensure_gateway_cname_creates_unproxied_record() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return json_response({"success": True, "result": []})
        assert request.method == "POST"
        body = json.loads(request.content)
        assert body == {
            "type": "CNAME",
            "name": "cvm.example.com",
            "content": "_.gateway.example.com",
            "ttl": 1,
            "proxied": False,
        }
        return json_response(
            {
                "success": True,
                "result": {
                    "id": "cname-record",
                    "type": "CNAME",
                    "name": "cvm.example.com",
                    "content": "_.gateway.example.com",
                },
            }
        )

    client = CloudflareClient(api_token="cf-token", zone_id="zone", transport=httpx.MockTransport(handler))

    record_id = run(client.ensure_gateway_cname(fqdn="cvm.example.com", gateway_host="gateway.example.com"))

    assert record_id == "cname-record"
    assert [request.method for request in requests] == ["GET", "POST"]


def test_ensure_record_refuses_conflicting_existing_record() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            {
                "success": True,
                "result": [
                    {
                        "id": "txt-record",
                        "type": "TXT",
                        "name": "_dstack-app-address.cvm.example.com",
                        "content": "other:443",
                    }
                ],
            }
        )

    client = CloudflareClient(api_token="cf-token", zone_id="zone", transport=httpx.MockTransport(handler))

    with pytest.raises(CloudflareError) as exc:
        run(client.ensure_dstack_txt(fqdn="cvm.example.com", app_id="app-123"))

    assert exc.value.code == "record_conflict"


def test_delete_record_tolerates_404() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return json_response({"success": False, "errors": [{"code": 1001}]}, status_code=404)

    client = CloudflareClient(api_token="cf-token", zone_id="zone", transport=httpx.MockTransport(handler))

    run(client.delete_record("record-id"))

    assert seen == [f"{CLOUDFLARE_API_BASE}zones/zone/dns_records/record-id"]


def test_api_error_captures_status_and_cloudflare_codes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"success": False, "errors": [{"code": 9109}]}, status_code=403)

    client = CloudflareClient(api_token="cf-token", zone_id="zone", transport=httpx.MockTransport(handler))

    with pytest.raises(CloudflareError) as exc:
        run(client.find_records(name="cvm.example.com", record_type="CNAME"))

    assert exc.value.code == "api_error"
    assert exc.value.http_status == 403
    assert exc.value.cloudflare_codes == (9109,)


def test_invalid_response_shape_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"success": True, "result": [{"id": "", "type": "TXT", "name": "x", "content": "y"}]})

    client = CloudflareClient(api_token="cf-token", zone_id="zone", transport=httpx.MockTransport(handler))

    with pytest.raises(CloudflareError) as exc:
        run(client.find_records(name="cvm.example.com", record_type="TXT"))

    assert exc.value.code == "invalid_response"
    assert exc.value.field == "id"


def test_from_settings_requires_token_and_zone(monkeypatch) -> None:
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "zone")

    with pytest.raises(CloudflareError) as exc:
        CloudflareClient.from_settings()

    assert exc.value.code == "not_configured"


def test_from_settings_rejects_api_base_override_without_debug_gate(monkeypatch) -> None:
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-token")
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "zone")
    monkeypatch.setenv("CLOUDFLARE_API_BASE", "https://cloudflare.invalid/client/v4/")
    monkeypatch.setenv("OIDC_OVERRIDES_ALLOWED", "false")

    with pytest.raises(CloudflareError) as exc:
        CloudflareClient.from_settings()

    assert exc.value.code == "override_not_allowed"


def test_from_settings_accepts_security_zone(monkeypatch) -> None:
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-token")
    monkeypatch.setenv("SECURITY_CVM_ZONE_ID", "security-zone")
    monkeypatch.delenv("CLOUDFLARE_API_BASE", raising=False)

    client = CloudflareClient.from_settings(zone_id_key="SECURITY_CVM_ZONE_ID")

    assert client.api_token == "cf-token"
    assert client.zone_id == "security-zone"
