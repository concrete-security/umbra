import asyncio
import base64
import importlib.util
import os
import sys
from pathlib import Path


def load_tunnel_module():
    path = Path(__file__).resolve().parents[1] / "user-sandbox" / "concrete-dev-tunnel.py"
    spec = importlib.util.spec_from_file_location("concrete_dev_tunnel", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def echo_server(reader, writer):
    data = await reader.read(5)
    writer.write(data.upper())
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def read_server_frame(reader):
    first, second = await reader.readexactly(2)
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(await reader.readexactly(2), "big")
    elif length == 127:
        length = int.from_bytes(await reader.readexactly(8), "big")
    return first & 0x0F, await reader.readexactly(length)


def masked_binary(payload: bytes) -> bytes:
    mask = b"abcd"
    return bytes([0x82, 0x80 | len(payload)]) + mask + bytes(
        byte ^ mask[index % 4] for index, byte in enumerate(payload)
    )


async def smoke():
    tunnel_module = load_tunnel_module()
    ssh = await asyncio.start_server(echo_server, "127.0.0.1", 0)
    ssh_port = ssh.sockets[0].getsockname()[1]
    config = tunnel_module.TunnelConfig("127.0.0.1", 0, "127.0.0.1", ssh_port, "/concrete/tunnel")
    tunnel = await asyncio.start_server(lambda r, w: tunnel_module.handle_client(r, w, config), "127.0.0.1", 0)
    tunnel_port = tunnel.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", tunnel_port)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    writer.write(
        (
            "GET /concrete/tunnel HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        + masked_binary(b"hello")
    )
    await writer.drain()
    response = await reader.readuntil(b"\r\n\r\n")
    assert b"101 Switching Protocols" in response
    opcode, payload = await read_server_frame(reader)
    assert opcode == 2
    assert payload == b"HELLO"
    writer.close()
    await writer.wait_closed()
    tunnel.close()
    await tunnel.wait_closed()
    ssh.close()
    await ssh.wait_closed()


if __name__ == "__main__":
    asyncio.run(smoke())
