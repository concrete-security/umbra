#!/usr/bin/env python3
"""Exercise the real nested Docker/runc path inside a fresh Sysbox sandbox."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time


MARKER = "umbra-nested-docker-sysbox-ok"
# Reviewed published application digests, not caller-supplied version overrides.
# containerd and runc may report their otherwise exact versions with a leading v.
RELEASE_INNER_VERSIONS = {
    "ghcr.io/concrete-security/umbra-dev-cvm@sha256:8ceb3590898d28f7ee54bc06b46ad4487473988c24719bee6ab69bd80c2fb0f9": {
        "Engine": "29.9.2", "containerd": "2.4.2", "runc": "1.5.2", "docker-init": "0.19.0",
    },
    "ghcr.io/concrete-security/umbra-dev-cvm@sha256:c2f103331848d534783625888fa3920453d2848deeeef92dfcb1903a7589a0ba": {
        "Engine": "29.7.1", "containerd": "2.2.6", "runc": "1.3.6", "docker-init": "0.19.0",
    },
}
BRIDGE_PROBE = (
    'command -v timeout >/dev/null && command -v bash >/dev/null || exit 8; '
    'probe() { timeout 3 bash -c \'exec 3<>/dev/tcp/$1/$2\' bash "$1" "$2"; }; '
    'probe "$3" "$4" || exit 8; '
    'status=0; probe "$1" "$2" || status=$?; '
    'probe "$3" "$4" || exit 8; '
    f'case $status in 1|124) printf {MARKER};; *) exit 9;; esac'
)


def run(args: list[str], *, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr[-4000:]}")
    return result


def check_result(result: subprocess.CompletedProcess, expected: str) -> None:
    """An unrelated setup/runtime error must never pass the known-failure control."""
    if expected == "success":
        if result.returncode != 0 or result.stdout != MARKER:
            raise RuntimeError(f"nested container did not succeed: {result.stderr[-4000:]}")
    elif expected == "unsafe-procfs":
        parts = (
            "runc create failed", "unsafe procfs detected", "openat2",
            "/proc/./sys/net/ipv4/ip_unprivileged_port_start", "invalid cross-device link",
        )
        if result.returncode != 125 or result.stdout or not all(part in result.stderr for part in parts):
            raise RuntimeError(f"baseline did not reproduce the procfs failure: {result.stderr[-4000:]}")
    else:
        raise ValueError("unknown nested test expectation")


def root_mapping(value: str) -> int:
    """Namespace root must map to an unprivileged ID on the runner host."""
    mappings = [tuple(map(int, line.split())) for line in value.splitlines()]
    roots = [host for inner, host, count in mappings if inner == 0 and count > 0]
    if len(roots) != 1 or roots[0] == 0:
        raise RuntimeError("Sysbox root is not mapped to an unprivileged host ID")
    return roots[0]


def stream_image(sandbox: str, image: str) -> None:
    # No archive file or socket bind mount enters the sandbox. Both ends must succeed.
    export = subprocess.Popen(["docker", "image", "save", image], stdout=subprocess.PIPE)
    try:
        consumer = subprocess.run(
            ["docker", "exec", "-i", "--user", "dev", sandbox, "docker", "image", "load"],
            stdin=export.stdout, capture_output=True, text=True, timeout=180, check=False,
        )
        export.stdout.close()
        if export.wait(timeout=30) != 0 or consumer.returncode != 0:
            raise RuntimeError("could not stream the pinned image into the sandbox Docker daemon")
    finally:
        if export.poll() is None:
            export.kill()
            export.wait()
        if export.stdout:
            export.stdout.close()


def verify(args: argparse.Namespace) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", args.sandbox):
        raise ValueError("expected a full sandbox container ID")
    if not re.fullmatch(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}", args.image):
        raise ValueError("nested image must be digest-pinned")
    ipaddress.IPv4Address(args.origin)
    ipaddress.IPv4Address(args.control)
    endpoint = run(["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"])
    if endpoint.stdout.strip() != "unix:///var/run/docker.sock" or os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock") != "unix:///var/run/docker.sock":
        raise RuntimeError("refuse non-local Docker daemon")
    sandbox = json.loads(run(["docker", "inspect", args.sandbox]).stdout)[0]
    dev_reference = os.environ["DEV_CVM_COMPOSE_SMOKE_IMAGE"]
    if dev_reference not in RELEASE_INNER_VERSIONS:
        raise RuntimeError("unreviewed Dev release image")
    expected_versions = RELEASE_INNER_VERSIONS[dev_reference]
    selected = json.loads(run(["docker", "image", "inspect", dev_reference]).stdout)[0]
    if sandbox["Image"] != selected["Id"] or dev_reference not in selected.get("RepoDigests", []):
        raise RuntimeError("sandbox is not running the selected Dev release image")
    host = sandbox["HostConfig"]
    if host["Runtime"] != "sysbox-runc" or host["Privileged"] or host["PidMode"] == "host" or host["IpcMode"] == "host":
        raise RuntimeError("unexpected sandbox isolation")
    if host.get("UsernsMode") or host.get("SecurityOpt"):
        raise RuntimeError("sandbox overrides Sysbox user namespace or security policy")
    networks = sandbox["NetworkSettings"]["Networks"]
    if len(networks) != 1:
        raise RuntimeError("sandbox must have exactly one internal network")
    network = json.loads(run(["docker", "network", "inspect", next(iter(networks))]).stdout)[0]
    if network["Internal"] is not True:
        raise RuntimeError("sandbox network is not internal")
    if any(mount["Type"] != "volume" and not (mount["Type"] == "tmpfs" and mount["Destination"] == "/run") for mount in sandbox["Mounts"]):
        raise RuntimeError("sandbox has an unexpected host bind mount")
    pid = sandbox["State"]["Pid"]
    mappings = {}
    for name in ("uid_map", "gid_map"):
        # Read the actual init process mapping from the HOST procfs, not Sysbox's view.
        value = run(["sudo", "cat", f"/proc/{pid}/{name}"]).stdout
        mappings[name] = root_mapping(value)
    if run(["docker", "exec", "--user", "dev", args.sandbox, "id", "-u"]).stdout.strip() != "1001":
        raise RuntimeError("default developer identity changed")

    inner = ["docker", "exec", "--user", "dev", args.sandbox, "docker"]
    for _ in range(60):
        if run([*inner, "info"], check=False, timeout=10).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("nested Docker daemon never became ready; baseline is inconclusive")
    version = json.loads(run([*inner, "version", "--format", "{{json .Server}}"] ).stdout)
    components = {item["Name"]: item["Version"] for item in version["Components"]}
    normalized = {
        name: value.removeprefix("v") if name in ("containerd", "runc") else value
        for name, value in components.items()
    }
    if (len(components) != len(version["Components"])
            or version["Version"] != expected_versions["Engine"]
            or normalized != expected_versions):
        raise RuntimeError(f"unexpected release inner runtime versions: {components}")
    image = json.loads(run(["docker", "image", "inspect", args.image]).stdout)[0]
    if args.image not in image.get("RepoDigests", []) or image["Os"] != "linux" or image["Architecture"] != "amd64":
        raise RuntimeError("nested fixture is not the selected linux/amd64 image")
    stream_image(args.sandbox, args.image)
    loaded = json.loads(run([*inner, "image", "inspect", image["Id"]]).stdout)[0]
    if loaded["Id"] != image["Id"]:
        raise RuntimeError("inner Docker loaded a different fixture image")

    results = []
    for network_mode in ("none", "bridge"):
        name = f"umbra-sysbox-smoke-{network_mode}"
        command = [*inner, "run", "--rm", "--pull=never", "--name", name,
                   f"--network={network_mode}", "--read-only", "--cap-drop=ALL",
                   "--security-opt=no-new-privileges", "--pids-limit=32", "--memory=64m",
                   "--entrypoint=/bin/sh", image["Id"], "-c", f"printf {MARKER}"]
        result = run(command, check=False, timeout=60)
        try:
            check_result(result, args.expect)
        finally:
            # docker --rm should remove failed creates too; remove only our named fixture.
            run([*inner, "rm", "-f", name], check=False)
        results.append({"network": network_mode, "exit_code": result.returncode, "expected": args.expect, "stderr": result.stderr[-4000:]})
    if args.expect == "success":
        # The origin is reachable from the uplink control, but must not be reachable
        # from a fresh nested bridge container even without proxy variables.
        command = [*inner, "run", "--rm", "--pull=never", "--network=bridge", "--read-only",
                   "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=32",
                   "--memory=64m", "--entrypoint=/bin/bash", image["Id"], "-c",
                   BRIDGE_PROBE, "bash", args.origin, "18080", args.control, "3128"]
        check_result(run(command, check=False, timeout=30), "success")
    return {
        "status": "expected-outcome", "expectation": args.expect,
        "dev_image": dev_reference, "dev_image_id": sandbox["Image"], "nested_image": args.image, "nested_image_id": image["Id"],
        "inner_versions": components, "host_root_mapping": mappings, "probes": results,
        "nested_bridge_direct_egress_denied": args.expect == "success",
        "not_exercised": ["TDX attestation", "dstack boot", "KMS key continuity", "user data migration"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expect", choices=("success", "unsafe-procfs"), required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--control", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists():
        raise RuntimeError("refuse to overwrite an earlier test receipt")
    result = verify(args)
    with args.receipt.open("x", encoding="utf-8") as receipt:
        json.dump(result, receipt, indent=2)
        receipt.write("\n")


if __name__ == "__main__":
    main()
