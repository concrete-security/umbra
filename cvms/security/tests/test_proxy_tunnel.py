from __future__ import annotations

import asyncio

from concrete_security_cvm.proxy_tunnel import ProxyTunnelConfig, handle_client


async def fake_mitmproxy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    request = await reader.readuntil(b"\r\n\r\n")
    assert b"CONNECT example.com:443 HTTP/1.1" in request
    assert b"Proxy-Authorization: Bearer proxy-token\r\n" in request
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    payload = await reader.readexactly(5)
    writer.write(payload.upper())
    await writer.drain()
    writer.close()
    await writer.wait_closed()


def test_proxy_tunnel_upgrades_then_bridges_raw_proxy_bytes() -> None:
    asyncio.run(_proxy_tunnel_upgrades_then_bridges_raw_proxy_bytes())


async def _proxy_tunnel_upgrades_then_bridges_raw_proxy_bytes() -> None:
    upstream = await asyncio.start_server(fake_mitmproxy, "127.0.0.1", 0)
    upstream_port = upstream.sockets[0].getsockname()[1]
    config = ProxyTunnelConfig(upstream_host="127.0.0.1", upstream_port=upstream_port)
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, config), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    writer.write(
        b"GET /concrete/proxy HTTP/1.1\r\n"
        b"Host: sc.example.com\r\n"
        b"Connection: Upgrade\r\n"
        b"Upgrade: concrete-proxy\r\n"
        b"\r\n"
        b"CONNECT example.com:443 HTTP/1.1\r\n"
        b"Host: example.com:443\r\n"
        b"Proxy-Authorization: Bearer proxy-token\r\n"
        b"\r\n"
        b"hello"
    )
    await writer.drain()

    upgrade = await reader.readuntil(b"\r\n\r\n")
    assert b"101 Switching Protocols" in upgrade
    response = await reader.readuntil(b"\r\n\r\n")
    assert b"200 Connection Established" in response
    assert await reader.readexactly(5) == b"HELLO"

    writer.close()
    await writer.wait_closed()
    server.close()
    await server.wait_closed()
    upstream.close()
    await upstream.wait_closed()


def test_proxy_tunnel_rejects_plain_request_without_upgrade() -> None:
    asyncio.run(_proxy_tunnel_rejects_plain_request_without_upgrade())


async def _proxy_tunnel_rejects_plain_request_without_upgrade() -> None:
    config = ProxyTunnelConfig(upstream_host="127.0.0.1", upstream_port=9)
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, config), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    writer.write(b"GET /concrete/proxy HTTP/1.1\r\nHost: sc.example.com\r\n\r\n")
    await writer.drain()

    response = await reader.read()
    assert b"426 Upgrade Required" in response

    writer.close()
    await writer.wait_closed()
    server.close()
    await server.wait_closed()
