import asyncio
import base64
import importlib.util
import json
import os
import stat
import sys
import tempfile
from pathlib import Path


def load_forwarder_module():
    path = Path(__file__).resolve().parents[1] / "user-sandbox" / "concrete-dev-egress-forwarder.py"
    spec = importlib.util.spec_from_file_location("concrete_dev_egress_forwarder", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def fake_security_cvm(reader, writer):
    request = await reader.readuntil(b"\r\n\r\n")
    assert b"CONNECT example.com:443 HTTP/1.1" in request
    assert b"Proxy-Authorization: Bearer real-proxy-token\r\n" in request
    assert b"sandbox-provided-token" not in request
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    data = await reader.read(5)
    writer.write(data.upper())
    await writer.drain()
    writer.close()
    await writer.wait_closed()


def write_fake_connect_helper(directory: Path, relay_port: int) -> Path:
    helper = directory / "fake-atls-connect.py"
    helper.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import asyncio",
                "import json",
                "import sys",
                f"TARGET_PORT = {relay_port}",
                "",
                "async def pipe(reader, writer):",
                "    try:",
                "        while True:",
                "            data = await reader.read(65536)",
                "            if not data:",
                "                break",
                "            writer.write(data)",
                "            await writer.drain()",
                "    finally:",
                "        writer.close()",
                "        await writer.wait_closed()",
                "",
                "async def handle(local_reader, local_writer):",
                "    remote_reader, remote_writer = await asyncio.open_connection('127.0.0.1', TARGET_PORT)",
                "    await asyncio.gather(pipe(local_reader, remote_writer), pipe(remote_reader, local_writer))",
                "",
                "async def main():",
                "    request = json.loads(sys.stdin.readline())",
                "    assert request['fqdn'] == 'sc.example.com'",
                "    assert request['port'] == 443",
                "    assert request['policy_path']",
                "    assert request['ca_cert_path']",
                "    server = await asyncio.start_server(handle, '127.0.0.1', 0)",
                "    port = server.sockets[0].getsockname()[1]",
                "    print(json.dumps({'host': '127.0.0.1', 'port': port}), flush=True)",
                "    async with server:",
                "        await server.serve_forever()",
                "",
                "try:",
                "    asyncio.run(main())",
                "except KeyboardInterrupt:",
                "    pass",
                "",
            ]
        )
    )
    helper.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return helper


def set_forwarder_env(helper: Path) -> None:
    os.environ["SECURITY_CVM_FQDN"] = "sc.example.com"
    os.environ["SECURITY_CVM_PROXY_PORT"] = "8080"
    os.environ["SECURITY_CVM_PROXY_TOKEN"] = "real-proxy-token"
    os.environ["SECURITY_CVM_CA_CERT_B64"] = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nMIIB\n").decode("ascii")
    os.environ["SECURITY_CVM_ATLS_POLICY_B64"] = base64.b64encode(json.dumps({"type": "dstack_tdx"}).encode()).decode(
        "ascii"
    )
    os.environ["DEV_EGRESS_ATLS_CONNECT_CMD"] = str(helper)


async def smoke():
    forwarder = load_forwarder_module()
    security_cvm = await asyncio.start_server(fake_security_cvm, "127.0.0.1", 0)
    relay_port = security_cvm.sockets[0].getsockname()[1]
    with tempfile.TemporaryDirectory() as temp:
        helper = write_fake_connect_helper(Path(temp), relay_port)
        runtime_dir = Path(temp) / "run"
        set_forwarder_env(helper)
        config = forwarder.load_config(runtime_dir)
        server = await asyncio.start_server(lambda r, w: forwarder.handle_client(r, w, config), "127.0.0.1", 0)
        forwarder_port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", forwarder_port)
        writer.write(
            b"CONNECT example.com:443 HTTP/1.1\r\n"
            b"Host: example.com:443\r\n"
            b"Proxy-Authorization: Bearer sandbox-provided-token\r\n"
            b"\r\n"
            b"hello"
        )
        await writer.drain()
        response = await reader.readuntil(b"\r\n\r\n")
        assert b"200 Connection Established" in response
        assert await reader.readexactly(5) == b"HELLO"
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()
    security_cvm.close()
    await security_cvm.wait_closed()


if __name__ == "__main__":
    asyncio.run(smoke())
