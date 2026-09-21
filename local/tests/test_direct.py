import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from umbra_local import direct
from umbra_local.state import LocalError


@pytest.mark.parametrize("header", [
    b"GET http://example.com/ HTTP/1.1\r\nProxy-Authorization: Bearer guest\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nproxy-authorization: Bearer guest\r\nProxy-Authorization: Bearer guest2\r\n\r\n",
])
def test_guest_cannot_supply_proxy_identity_success(header):
    """Host replaces every guest bearer before the attested upstream sees it."""
    encoded, _, _ = direct.proxy_header(header, "host-token")
    assert b"guest" not in encoded and encoded.count(b"Proxy-Authorization:") == 1


@pytest.mark.parametrize("header", [
    b"GET http://example.com/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
    b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nContent-Length: 2\r\n\r\n",
    b"GET http://example.com/ HTTP/1.1\r\n Bad: header\r\n\r\n",
    b"GET /local HTTP/1.1\r\n\r\n",
])
def test_ambiguous_proxy_framing_failure(header):
    """Ambiguous framing cannot smuggle requests around host authentication."""
    with pytest.raises(LocalError):
        direct.proxy_header(header, "host-token")


def test_plain_http_one_request_success():
    """The broker sends the exact body length and asks SC to close the response."""
    encoded, connect, length = direct.proxy_header(b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 12\r\nConnection: keep-alive\r\n\r\n", "host-token")
    assert (connect, length, b"Connection: close" in encoded) == (False, 12, True)


def test_expired_host_lease_failure():
    """No transport subprocess is opened after host authorization has expired."""
    broker = direct.DirectBroker({}, "/tmp")
    broker.lease = {"expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}
    with pytest.raises(LocalError, match="expired"):
        asyncio.run(broker.open())
