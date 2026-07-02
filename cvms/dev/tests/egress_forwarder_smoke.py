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
    upgrade = await reader.readuntil(b"\r\n\r\n")
    assert b"GET /concrete/proxy HTTP/1.1" in upgrade
    assert b"Host: sc.example.com" in upgrade
    assert b"Upgrade: concrete-proxy\r\n" in upgrade
    assert b"Proxy-Authorization" not in upgrade
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: concrete-proxy\r\nConnection: Upgrade\r\n\r\n")
    await writer.drain()
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


async def fake_security_cvm_http(reader, writer):
    upgrade = await reader.readuntil(b"\r\n\r\n")
    assert b"GET /concrete/proxy HTTP/1.1" in upgrade
    assert b"Proxy-Authorization" not in upgrade
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: concrete-proxy\r\nConnection: Upgrade\r\n\r\n")
    await writer.drain()

    request = await reader.readuntil(b"\r\n\r\n")
    assert b"GET http://archive.ubuntu.com/ubuntu/dists/noble/InRelease HTTP/1.1" in request
    assert b"Proxy-Authorization: Bearer real-proxy-token\r\n" in request
    assert b"Connection: close\r\n" in request
    assert b"noble-updates" not in request

    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    await writer.drain()
    try:
        extra = await asyncio.wait_for(reader.read(1), timeout=0.1)
    except asyncio.TimeoutError:
        extra = b""
    assert extra == b""

    writer.close()
    await writer.wait_closed()


async def fake_security_cvm_blocked_connect(reader, writer):
    upgrade = await reader.readuntil(b"\r\n\r\n")
    assert b"GET /concrete/proxy HTTP/1.1" in upgrade
    assert b"Proxy-Authorization" not in upgrade
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: concrete-proxy\r\nConnection: Upgrade\r\n\r\n")
    await writer.drain()

    request = await reader.readuntil(b"\r\n\r\n")
    assert b"CONNECT blocked.example.com:443 HTTP/1.1" in request
    assert b"Proxy-Authorization: Bearer real-proxy-token\r\n" in request

    body = (
        b"Concrete network restriction: this request was blocked by the profile policy assigned "
        b"to this Dev CVM.\nThis is a Concrete policy decision, not a network or server failure.\n"
    )
    writer.write(
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"X-Concrete-Blocked: true\r\n"
        b"Content-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )
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


def write_refresh_only_fake_connect_helper(directory: Path, relay_port: int) -> Path:
    helper = directory / "fake-atls-connect-refresh.py"
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
                "    with open(request['policy_path'], 'r', encoding='utf-8') as policy_file:",
                "        policy = json.load(policy_file)",
                "    if policy.get('refresh') is not True:",
                "        print('primary policy rejected by fake helper', file=sys.stderr)",
                "        return 1",
                "    server = await asyncio.start_server(handle, '127.0.0.1', 0)",
                "    port = server.sockets[0].getsockname()[1]",
                "    print(json.dumps({'host': '127.0.0.1', 'port': port}), flush=True)",
                "    async with server:",
                "        await server.serve_forever()",
                "",
                "try:",
                "    raise SystemExit(asyncio.run(main()))",
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
    os.environ["DEV_CVM_CONTROL_TOKEN"] = "real-dev-control-token"
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

    security_cvm_refresh = await asyncio.start_server(fake_security_cvm, "127.0.0.1", 0)
    relay_port = security_cvm_refresh.sockets[0].getsockname()[1]
    with tempfile.TemporaryDirectory() as temp:
        temp_path = Path(temp)
        helper = write_refresh_only_fake_connect_helper(temp_path, relay_port)
        refresh_policy_path = temp_path / "refreshed-policy.json"
        refresh_policy_path.write_text(json.dumps({"type": "dstack_tdx", "refresh": True}), encoding="utf-8")
        runtime_dir = temp_path / "run"
        set_forwarder_env(helper)
        config = forwarder.load_config(runtime_dir)

        original_fetch = forwarder.fetch_refreshed_atls_policy

        refresh_fetches = 0

        def fake_fetch_refreshed_atls_policy(_config):
            nonlocal refresh_fetches
            refresh_fetches += 1
            _config.atls_policy_refresh_path.write_text(
                refresh_policy_path.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            return forwarder.RefreshedAtlsPolicy(
                policy_path=_config.atls_policy_refresh_path,
            )

        forwarder.fetch_refreshed_atls_policy = fake_fetch_refreshed_atls_policy
        try:
            server = await asyncio.start_server(lambda r, w: forwarder.handle_client(r, w, config), "127.0.0.1", 0)
            forwarder_port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", forwarder_port)
            writer.write(
                b"CONNECT example.com:443 HTTP/1.1\r\n"
                b"Host: example.com:443\r\n"
                b"\r\n"
                b"hello"
            )
            await writer.drain()
            response = await reader.readuntil(b"\r\n\r\n")
            assert b"200 Connection Established" in response
            assert await reader.readexactly(5) == b"HELLO"
            writer.close()
            await writer.wait_closed()
            reader, writer = await asyncio.open_connection("127.0.0.1", forwarder_port)
            writer.write(
                b"CONNECT example.com:443 HTTP/1.1\r\n"
                b"Host: example.com:443\r\n"
                b"\r\n"
                b"hello"
            )
            await writer.drain()
            response = await reader.readuntil(b"\r\n\r\n")
            assert b"200 Connection Established" in response
            assert await reader.readexactly(5) == b"HELLO"
            assert refresh_fetches == 1
            writer.close()
            await writer.wait_closed()
            server.close()
            await server.wait_closed()
        finally:
            forwarder.fetch_refreshed_atls_policy = original_fetch
    security_cvm_refresh.close()
    await security_cvm_refresh.wait_closed()

    security_cvm_blocked = await asyncio.start_server(fake_security_cvm_blocked_connect, "127.0.0.1", 0)
    relay_port = security_cvm_blocked.sockets[0].getsockname()[1]
    with tempfile.TemporaryDirectory() as temp:
        helper = write_fake_connect_helper(Path(temp), relay_port)
        runtime_dir = Path(temp) / "run"
        set_forwarder_env(helper)
        config = forwarder.load_config(runtime_dir)
        server = await asyncio.start_server(lambda r, w: forwarder.handle_client(r, w, config), "127.0.0.1", 0)
        forwarder_port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", forwarder_port)
        writer.write(
            b"CONNECT blocked.example.com:443 HTTP/1.1\r\n"
            b"Host: blocked.example.com:443\r\n"
            b"\r\n"
        )
        await writer.drain()
        response = await reader.read()
        assert b"HTTP/1.1 403 Forbidden" in response
        assert b"X-Concrete-Blocked: true" in response
        assert b"Concrete network restriction" in response
        assert b"profile policy assigned to this Dev CVM" in response
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()
    security_cvm_blocked.close()
    await security_cvm_blocked.wait_closed()

    security_cvm_http = await asyncio.start_server(fake_security_cvm_http, "127.0.0.1", 0)
    relay_port = security_cvm_http.sockets[0].getsockname()[1]
    with tempfile.TemporaryDirectory() as temp:
        helper = write_fake_connect_helper(Path(temp), relay_port)
        runtime_dir = Path(temp) / "run"
        set_forwarder_env(helper)
        config = forwarder.load_config(runtime_dir)
        server = await asyncio.start_server(lambda r, w: forwarder.handle_client(r, w, config), "127.0.0.1", 0)
        forwarder_port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", forwarder_port)
        writer.write(
            b"GET http://archive.ubuntu.com/ubuntu/dists/noble/InRelease HTTP/1.1\r\n"
            b"Host: archive.ubuntu.com\r\n"
            b"\r\n"
            b"GET http://archive.ubuntu.com/ubuntu/dists/noble-updates/InRelease HTTP/1.1\r\n"
            b"Host: archive.ubuntu.com\r\n"
            b"\r\n"
        )
        await writer.drain()
        response = await reader.read()
        assert b"HTTP/1.1 200 OK" in response
        assert response.count(b"HTTP/1.1") == 1
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()
    security_cvm_http.close()
    await security_cvm_http.wait_closed()


def ca_distribution_smoke():
    import hashlib
    from types import SimpleNamespace

    forwarder = load_forwarder_module()

    pem = "-----BEGIN CERTIFICATE-----\nMIIBexampleCA\n-----END CERTIFICATE-----\n"
    sha = hashlib.sha256(pem.encode("utf-8")).hexdigest()

    # extract_validated_ca: happy path returns the PEM.
    assert (
        forwarder.extract_validated_ca(
            {"security_cvm_fqdn": "sc.example.com", "ca_cert_pem": pem, "ca_cert_sha256": sha},
            "sc.example.com",
        )
        == pem
    )
    # Rejects a CA bound to a different SC FQDN.
    assert (
        forwarder.extract_validated_ca(
            {"security_cvm_fqdn": "evil.example.com", "ca_cert_pem": pem, "ca_cert_sha256": sha},
            "sc.example.com",
        )
        is None
    )
    # Rejects a self-inconsistent digest.
    assert (
        forwarder.extract_validated_ca(
            {"security_cvm_fqdn": "sc.example.com", "ca_cert_pem": pem, "ca_cert_sha256": "0" * 64},
            "sc.example.com",
        )
        is None
    )
    # Rejects a non-certificate payload and a non-dict payload.
    assert (
        forwarder.extract_validated_ca(
            {"security_cvm_fqdn": "sc.example.com", "ca_cert_pem": "nope", "ca_cert_sha256": sha},
            "sc.example.com",
        )
        is None
    )
    assert forwarder.extract_validated_ca("nope", "sc.example.com") is None

    # write_ca_distribution: atomic publish, change detection, world-readable mode.
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "shared" / "security-cvm-ca.pem"
        config = SimpleNamespace(ca_distribution_path=path)
        assert forwarder.write_ca_distribution(config, pem) is True
        assert path.read_text(encoding="utf-8") == pem
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert forwarder.write_ca_distribution(config, pem) is False  # unchanged → no rewrite
        rotated = "-----BEGIN CERTIFICATE-----\nMIIBrotatedCA\n-----END CERTIFICATE-----\n"
        assert forwarder.write_ca_distribution(config, rotated) is True
        assert path.read_text(encoding="utf-8") == rotated

    print("ca_distribution_smoke: OK")


if __name__ == "__main__":
    ca_distribution_smoke()
    asyncio.run(smoke())
