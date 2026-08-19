import asyncio
import base64
import importlib.util
import json
import os
import stat
import sys
import tempfile
import time
from pathlib import Path


def load_forwarder_module():
    path = Path(__file__).resolve().parents[1] / "user-sandbox" / "umbra-dev-egress-forwarder.py"
    spec = importlib.util.spec_from_file_location("umbra_dev_egress_forwarder", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def fake_security_cvm(reader, writer):
    upgrade = await reader.readuntil(b"\r\n\r\n")
    assert b"GET /umbra/proxy HTTP/1.1" in upgrade
    assert b"Host: sc.example.com" in upgrade
    assert b"Upgrade: umbra-proxy\r\n" in upgrade
    assert b"Proxy-Authorization" not in upgrade
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: umbra-proxy\r\nConnection: Upgrade\r\n\r\n")
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
    assert b"GET /umbra/proxy HTTP/1.1" in upgrade
    assert b"Proxy-Authorization" not in upgrade
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: umbra-proxy\r\nConnection: Upgrade\r\n\r\n")
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
    assert b"GET /umbra/proxy HTTP/1.1" in upgrade
    assert b"Proxy-Authorization" not in upgrade
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: umbra-proxy\r\nConnection: Upgrade\r\n\r\n")
    await writer.drain()

    request = await reader.readuntil(b"\r\n\r\n")
    assert b"CONNECT blocked.example.com:443 HTTP/1.1" in request
    assert b"Proxy-Authorization: Bearer real-proxy-token\r\n" in request

    body = (
        b"Umbra network restriction: this request was blocked by the profile policy assigned "
        b"to this Dev CVM.\nThis is an Umbra policy decision, not a network or server failure.\n"
    )
    writer.write(
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"X-Umbra-Blocked: true\r\n"
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
    os.environ["CONSOLE_URL"] = "https://console.example.com"
    os.environ["DEV_EGRESS_ATLS_CONNECT_CMD"] = str(helper)


def install_test_policy(forwarder, config):
    policy = {
        "type": "dstack_tdx",
        "expected_bootchain": {"mrtd": "a" * 96},
        "app_compose": {"docker_compose_file": "services: {}\n"},
        "os_image_hash": "b" * 64,
    }
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    forwarder.write_private_file(config.atls_policy_path, payload, 0o444)
    return policy


async def smoke():
    forwarder = load_forwarder_module()
    security_cvm = await asyncio.start_server(fake_security_cvm, "127.0.0.1", 0)
    relay_port = security_cvm.sockets[0].getsockname()[1]
    with tempfile.TemporaryDirectory() as temp:
        helper = write_fake_connect_helper(Path(temp), relay_port)
        runtime_dir = Path(temp) / "run"
        set_forwarder_env(helper)
        config = forwarder.load_config(runtime_dir)
        policy_fetches = 0
        original_fetch = forwarder.fetch_refreshed_atls_policy

        def fake_initial_policy_fetch(_config, *, force=False):
            nonlocal policy_fetches
            assert force is True
            policy_fetches += 1
            install_test_policy(forwarder, _config)
            return forwarder.RefreshedAtlsPolicy(policy_path=_config.atls_policy_path)

        forwarder.fetch_refreshed_atls_policy = fake_initial_policy_fetch
        try:
            server = await asyncio.start_server(lambda r, w: forwarder.handle_client(r, w, config), "127.0.0.1", 0)
            assert config.atls_policy_path.exists() is False
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
            assert policy_fetches == 1
            writer.close()
            await writer.wait_closed()
            server.close()
            await server.wait_closed()
        finally:
            forwarder.fetch_refreshed_atls_policy = original_fetch
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
        install_test_policy(forwarder, config)

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
        install_test_policy(forwarder, config)
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
        assert b"X-Umbra-Blocked: true" in response
        assert b"Umbra network restriction" in response
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
        install_test_policy(forwarder, config)
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

    # Startup may bind without policy material (the measurement path has no
    # authenticated Console identity), but it must not fetch or open upstream.
    from types import SimpleNamespace

    with tempfile.TemporaryDirectory() as temp:
        temp_path = Path(temp)
        config = SimpleNamespace(
            atls_policy_path=temp_path / "run" / "security-cvm.atls-policy.json",
            listen_host="127.0.0.1",
            listen_port=3128,
        )
        events = []

        class FakeServer:
            sockets = []

            async def __aenter__(self):
                return self

            async def __aexit__(self, _exc_type, _exc, _traceback):
                return None

            async def serve_forever(self):
                events.append("serve")

        async def fake_start_server(_handler, _host, _port):
            assert config.atls_policy_path.exists() is False
            events.append("listen")
            return FakeServer()

        async def fake_ca_distribution_loop(_config):
            return None

        originals = (
            forwarder.load_config,
            forwarder.seed_ca_distribution,
            forwarder.ca_distribution_loop,
            forwarder.asyncio.start_server,
        )
        forwarder.load_config = lambda: config
        forwarder.seed_ca_distribution = lambda _config: events.append("seed-ca")
        forwarder.ca_distribution_loop = fake_ca_distribution_loop
        forwarder.asyncio.start_server = fake_start_server
        try:
            await forwarder.main()
        finally:
            (
                forwarder.load_config,
                forwarder.seed_ca_distribution,
                forwarder.ca_distribution_loop,
                forwarder.asyncio.start_server,
            ) = originals
        assert events == ["seed-ca", "listen", "serve"]

    # Concurrent first requests share one authenticated fetch flight.
    with tempfile.TemporaryDirectory() as temp:
        temp_path = Path(temp)
        config = SimpleNamespace(
            console_url="https://console.example.com",
            atls_policy_path=temp_path / "run" / "security-cvm.atls-policy.json",
            atls_policy_refresh_path=temp_path / "run" / "security-cvm.atls-policy.refresh.json",
            atls_policy_fetch_lock=asyncio.Lock(),
        )
        fetches = 0

        def delayed_policy_fetch(_config, *, force=False):
            nonlocal fetches
            assert force is True
            fetches += 1
            time.sleep(0.05)
            install_test_policy(forwarder, _config)
            return forwarder.RefreshedAtlsPolicy(policy_path=_config.atls_policy_path)

        original_fetch = forwarder.fetch_refreshed_atls_policy
        forwarder.fetch_refreshed_atls_policy = delayed_policy_fetch
        try:
            await asyncio.gather(forwarder.ensure_atls_policy(config), forwarder.ensure_atls_policy(config))
        finally:
            forwarder.fetch_refreshed_atls_policy = original_fetch
        assert fetches == 1

    # A rejected control response returns 502 and never reaches atls-connect or
    # the Security CVM, while the listener remains available for later retries.
    with tempfile.TemporaryDirectory() as temp:
        temp_path = Path(temp)
        config = SimpleNamespace(
            console_url="https://console.example.com",
            atls_policy_path=temp_path / "run" / "security-cvm.atls-policy.json",
            atls_policy_refresh_path=temp_path / "run" / "security-cvm.atls-policy.refresh.json",
            atls_policy_fetch_lock=asyncio.Lock(),
        )
        upstream_calls = 0

        async def forbidden_upstream(_config):
            nonlocal upstream_calls
            upstream_calls += 1
            raise AssertionError("upstream must not open without an authenticated policy")

        original_fetch = forwarder.fetch_refreshed_atls_policy
        original_upstream = forwarder.open_verified_upstream
        original_attempts = forwarder.ATLS_POLICY_FETCH_MAX_ATTEMPTS
        forwarder.fetch_refreshed_atls_policy = lambda _config, *, force=False: None
        forwarder.open_verified_upstream = forbidden_upstream
        forwarder.ATLS_POLICY_FETCH_MAX_ATTEMPTS = 1
        try:
            server = await asyncio.start_server(lambda r, w: forwarder.handle_client(r, w, config), "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            await writer.drain()
            response = await reader.read()
            assert b"502 Bad Gateway" in response
            assert b"egress forwarder failed closed" in response
            assert upstream_calls == 0
            writer.close()
            await writer.wait_closed()
            server.close()
            await server.wait_closed()
        finally:
            forwarder.fetch_refreshed_atls_policy = original_fetch
            forwarder.open_verified_upstream = original_upstream
            forwarder.ATLS_POLICY_FETCH_MAX_ATTEMPTS = original_attempts


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

    # The first boot seeds launch-bound CA + metadata without clobbering a
    # persisted authenticated rotation when the forwarder restarts.
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "shared" / "security-cvm-ca.pem"
        binding_path = Path(temp) / "shared" / "security-cvm-ca.json"
        launch_path = Path(temp) / "run" / "security-cvm-ca.pem"
        launch_path.parent.mkdir(parents=True)
        launch_path.write_text(pem, encoding="utf-8")
        config = SimpleNamespace(
            security_cvm_fqdn="sc.example.com",
            ca_cert_path=launch_path,
            ca_distribution_path=path,
            ca_distribution_binding_path=binding_path,
        )

        forwarder.seed_ca_distribution(config)
        assert path.read_text(encoding="utf-8") == pem
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        assert binding == {
            "security_cvm_fqdn": "sc.example.com",
            "ca_cert_sha256": sha,
            "launch_ca_cert_sha256": sha,
        }
        assert stat.S_IMODE(binding_path.stat().st_mode) == 0o444
        assert forwarder.read_ca_distribution(config) == ("valid", pem.encode("utf-8"))

        assert forwarder.write_ca_distribution(config, pem) is False  # unchanged → no rewrite
        rotated = "-----BEGIN CERTIFICATE-----\nMIIBrotatedCA\n-----END CERTIFICATE-----\n"
        assert forwarder.write_ca_distribution(config, rotated) is True
        assert path.read_text(encoding="utf-8") == rotated
        forwarder.seed_ca_distribution(config)
        assert path.read_text(encoding="utf-8") == rotated  # restart must not roll back to launch CA

        # A refreshed aTLS policy is bound to the latest CA accepted through
        # the authenticated runtime path, not forever to the launch CA.
        policy = {
            "type": "dstack_tdx",
            "expected_bootchain": {"mrtd": "a" * 96},
            "app_compose": {"docker_compose_file": "services: {}\n"},
            "os_image_hash": "b" * 64,
        }
        payload = json.dumps(
            {
                "security_cvm_fqdn": "sc.example.com",
                "ca_cert_sha256": hashlib.sha256(rotated.encode("utf-8")).hexdigest(),
                "atls_policy": policy,
            }
        ).encode("utf-8")

        class FakeResponse:
            status = 200

            @staticmethod
            def read(_limit):
                return payload

        class FakeConnection:
            def __init__(self, host, port, timeout):
                assert (host, port, timeout) == ("console.example.com", 443, 5)

            def request(self, method, request_path, headers):
                assert (method, request_path) == ("GET", "/internal/dev-control/security-cvm-atls-policy")
                assert headers["Authorization"] == "Bearer dev-control-token"

            @staticmethod
            def getresponse():
                return FakeResponse()

            @staticmethod
            def close():
                pass

        refresh_config = SimpleNamespace(
            console_url="https://console.example.com",
            dev_control_token="dev-control-token",
            security_cvm_fqdn="sc.example.com",
            ca_cert_path=launch_path,
            ca_distribution_path=path,
            ca_distribution_binding_path=binding_path,
            atls_policy_path=Path(temp) / "run" / "security-cvm.atls-policy.json",
            atls_policy_refresh_path=Path(temp) / "run" / "security-cvm.atls-policy.refresh.json",
        )
        original_connection = forwarder.http.client.HTTPSConnection
        forwarder.http.client.HTTPSConnection = FakeConnection
        try:
            bootstrapped = forwarder.fetch_refreshed_atls_policy(refresh_config, force=True)
            assert bootstrapped is not None
            assert bootstrapped.policy_path == refresh_config.atls_policy_path
            assert json.loads(bootstrapped.policy_path.read_text(encoding="utf-8")) == policy

            refreshed = forwarder.fetch_refreshed_atls_policy(refresh_config)
            assert refreshed is not None
            assert json.loads(refreshed.policy_path.read_text(encoding="utf-8")) == policy

            # Disabled and incomplete control-plane documents are never installed.
            payload = json.dumps(
                {
                    "security_cvm_fqdn": "sc.example.com",
                    "ca_cert_sha256": hashlib.sha256(rotated.encode("utf-8")).hexdigest(),
                    "atls_policy": {**policy, "disable_runtime_verification": True},
                }
            ).encode("utf-8")
            assert forwarder.fetch_refreshed_atls_policy(refresh_config, force=True) is None
            payload = json.dumps(
                {
                    "security_cvm_fqdn": "sc.example.com",
                    "ca_cert_sha256": hashlib.sha256(rotated.encode("utf-8")).hexdigest(),
                    "atls_policy": {"type": "dstack_tdx"},
                }
            ).encode("utf-8")
            assert forwarder.fetch_refreshed_atls_policy(refresh_config, force=True) is None

            # A candidate that does not match the most recently accepted CA
            # remains fail-closed.
            payload = json.dumps(
                {
                    "security_cvm_fqdn": "sc.example.com",
                    "ca_cert_sha256": hashlib.sha256(rotated.encode("utf-8")).hexdigest(),
                    "atls_policy": policy,
                }
            ).encode("utf-8")
            assert forwarder.write_ca_distribution(config, pem) is True
            assert forwarder.fetch_refreshed_atls_policy(refresh_config) is None
        finally:
            forwarder.http.client.HTTPSConnection = original_connection

        # Partial/corrupt persisted state is never replaced from immutable
        # launch material. Only a fresh authenticated CA response (represented
        # by write_ca_distribution) may repair it.
        path.unlink()
        path.write_bytes(b"not a certificate")
        forwarder.seed_ca_distribution(config)
        assert path.read_bytes() == b"not a certificate"
        assert forwarder.read_ca_distribution(config) == ("invalid", None)
        assert forwarder.write_ca_distribution(config, rotated) is True
        assert forwarder.read_ca_distribution(config) == ("valid", rotated.encode("utf-8"))

        class UnreadablePath:
            @staticmethod
            def lstat():
                raise PermissionError("denied")

        unreadable_config = SimpleNamespace(
            ca_distribution_path=UnreadablePath(),
            ca_distribution_binding_path=UnreadablePath(),
        )
        assert forwarder.read_ca_distribution(unreadable_config) == ("invalid", None)

        # A full update that changes launch CA but retains the SC FQDN is a new
        # binding, not an ordinary restart. Rebase instead of re-trusting the
        # persisted CA from the previous launch baseline.
        updated_launch_pem = "-----BEGIN CERTIFICATE-----\nMIIBupdatedLaunchCA\n-----END CERTIFICATE-----\n"
        updated_launch_path = Path(temp) / "run" / "security-cvm-updated-launch-ca.pem"
        updated_launch_path.write_text(updated_launch_pem, encoding="utf-8")
        updated_config = SimpleNamespace(
            security_cvm_fqdn="sc.example.com",
            ca_cert_path=updated_launch_path,
            ca_distribution_path=path,
            ca_distribution_binding_path=binding_path,
        )
        assert forwarder.read_ca_distribution(updated_config) == ("foreign", None)
        forwarder.seed_ca_distribution(updated_config)
        assert forwarder.read_ca_distribution(updated_config) == (
            "valid",
            updated_launch_pem.encode("utf-8"),
        )

        # A full CVM update may keep the named volume while changing the
        # launch-bound SC FQDN. A valid foreign sidecar is not trusted; current
        # attested launch material replaces it for the new binding.
        next_pem = "-----BEGIN CERTIFICATE-----\nMIIBnextCA\n-----END CERTIFICATE-----\n"
        next_launch_path = Path(temp) / "run" / "security-cvm-next-ca.pem"
        next_launch_path.write_text(next_pem, encoding="utf-8")
        next_config = SimpleNamespace(
            security_cvm_fqdn="sc-next.example.com",
            ca_cert_path=next_launch_path,
            ca_distribution_path=path,
            ca_distribution_binding_path=binding_path,
        )
        assert forwarder.read_ca_distribution(next_config) == ("foreign", None)
        forwarder.seed_ca_distribution(next_config)
        assert forwarder.read_ca_distribution(next_config) == ("valid", next_pem.encode("utf-8"))

    print("ca_distribution_smoke: OK")


if __name__ == "__main__":
    ca_distribution_smoke()
    asyncio.run(smoke())
