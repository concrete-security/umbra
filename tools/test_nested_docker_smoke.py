"""Prevent unrelated failures from certifying the Sysbox compatibility fix."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import shutil
import socket

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / 'cvms/dev/tests/nested_docker_smoke.py'
SPEC = importlib.util.spec_from_file_location('nested_docker_smoke', SCRIPT)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)
ERROR = (
    'failed to create task: runc create failed: open sysctl '
    'net.ipv4.ip_unprivileged_port_start file: unsafe procfs detected: '
    'openat2 /proc/./sys/net/ipv4/ip_unprivileged_port_start: invalid cross-device link'
)


def test_exact_procfs_baseline_success():
    """The observed nested runc failure qualifies the negative control."""
    smoke.check_result(subprocess.CompletedProcess([], 125, '', ERROR), 'unsafe-procfs')


@pytest.mark.parametrize('code,stdout,stderr', [
    (0, smoke.MARKER, ''),
    (125, '', 'Cannot connect to the Docker daemon'),
    (125, '', 'OCI runtime create failed: mount through procfd: operation not permitted'),
    (124, '', ERROR),
    (125, 'unexpected output', ERROR),
    (125, '', ERROR.replace('net/ipv4/ip_unprivileged_port_start', 'vm/mmap_min_addr')),
    (125, '', ERROR.replace('invalid cross-device link', 'permission denied')),
])
def test_unrelated_baseline_result_failure(code, stdout, stderr):
    """Setup errors, different sysctls and successful baselines are inconclusive."""
    with pytest.raises(RuntimeError, match='did not reproduce'):
        smoke.check_result(subprocess.CompletedProcess([], code, stdout, stderr), 'unsafe-procfs')


@pytest.mark.parametrize('code,stdout', [(125, ''), (0, ''), (1, smoke.MARKER)])
def test_incomplete_candidate_result_failure(code, stdout):
    """A candidate passes only when the new container actually runs its command."""
    with pytest.raises(RuntimeError, match='did not succeed'):
        smoke.check_result(subprocess.CompletedProcess([], code, stdout, ERROR), 'success')


def test_candidate_marker_success():
    """A real successful command is the candidate's positive control."""
    smoke.check_result(subprocess.CompletedProcess([], 0, smoke.MARKER, ''), 'success')


@pytest.mark.parametrize('mapping', ['', '0 0 4294967295', '1 100000 65535', '0 100000 0'])
def test_unmapped_or_host_root_failure(mapping):
    """The host mapping must not give namespace root the host's root identity."""
    with pytest.raises(RuntimeError):
        smoke.root_mapping(mapping)


def test_host_root_remapping_success():
    """A nonzero host mapping establishes the required Sysbox user namespace."""
    assert smoke.root_mapping('         0     100000      65536\n') == 100000


@pytest.mark.skipif(not shutil.which("timeout"), reason="GNU timeout is required for the runner probe")
@pytest.mark.parametrize('control_listens,origin_listens,expected_code', [
    (True, False, 0), (False, False, 8), (True, True, 9),
], ids=['blocked-egress', 'broken-control', 'reachable-origin'])
def test_bridge_tcp_probe_controls_success(control_listens, origin_listens, expected_code):
    """The actual shell probe accepts a denial only between working TCP controls."""
    with socket.socket() as control, socket.socket() as origin:
        control.bind(('127.0.0.1', 0))
        origin.bind(('127.0.0.1', 0))
        if control_listens:
            control.listen(8)
        if origin_listens:
            origin.listen(8)
        result = subprocess.run([
            'bash', '-c', smoke.BRIDGE_PROBE, 'bash',
            '127.0.0.1', str(origin.getsockname()[1]),
            '127.0.0.1', str(control.getsockname()[1]),
        ], capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == expected_code
    assert result.stdout == (smoke.MARKER if expected_code == 0 else '')
