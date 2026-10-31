"""Prevent unrelated failures from certifying the Sysbox compatibility fix."""
from __future__ import annotations

import argparse
import importlib.util
import json
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
RELEASES = [
    (
        'ghcr.io/concrete-security/umbra-dev-cvm@sha256:8ceb3590898d28f7ee54bc06b46ad4487473988c24719bee6ab69bd80c2fb0f9',
        {'Engine': '29.9.2', 'containerd': 'v2.4.2', 'runc': '1.5.2', 'docker-init': '0.19.0'},
    ),
    (
        'ghcr.io/concrete-security/umbra-dev-cvm@sha256:c2f103331848d534783625888fa3920453d2848deeeef92dfcb1903a7589a0ba',
        {'Engine': '29.7.1', 'containerd': 'v2.2.6', 'runc': '1.3.6', 'docker-init': '0.19.0'},
    ),
]


def runtime_version(components):
    return {
        'Version': components['Engine'],
        'Components': [{'Name': name, 'Version': value} for name, value in components.items()],
    }


@pytest.fixture
def runtime_probe(monkeypatch):
    """Run the actual verifier against deterministic Docker command responses."""
    calls = []

    def invoke(reference, version, expected='success'):
        args = argparse.Namespace(sandbox='a' * 64, image='ubuntu@sha256:' + 'b' * 64,
                                  expect=expected, origin='192.0.2.1', control='192.0.2.2')
        dev_id, nested_id = 'sha256:' + 'c' * 64, 'sha256:' + 'd' * 64
        inner = ['docker', 'exec', '--user', 'dev', args.sandbox, 'docker']

        def respond(command, **_kwargs):
            calls.append(command)
            value = ''
            if command[:3] == ['docker', 'context', 'inspect']:
                value = 'unix:///var/run/docker.sock'
            elif command == ['docker', 'inspect', args.sandbox]:
                value = [{
                    'Image': dev_id,
                    'HostConfig': {'Runtime': 'sysbox-runc', 'Privileged': False, 'PidMode': '', 'IpcMode': ''},
                    'NetworkSettings': {'Networks': {'internal': {}}},
                    'Mounts': [{'Type': 'volume'}], 'State': {'Pid': 123},
                }]
            elif command == ['docker', 'image', 'inspect', reference]:
                value = [{'Id': dev_id, 'RepoDigests': [reference]}]
            elif command == ['docker', 'network', 'inspect', 'internal']:
                value = [{'Internal': True}]
            elif command in (['sudo', 'cat', '/proc/123/uid_map'], ['sudo', 'cat', '/proc/123/gid_map']):
                value = '0 100000 65536'
            elif command == ['docker', 'exec', '--user', 'dev', args.sandbox, 'id', '-u']:
                value = '1001'
            elif command == [*inner, 'info']:
                pass
            elif command == [*inner, 'version', '--format', '{{json .Server}}']:
                value = version
            elif command == ['docker', 'image', 'inspect', args.image]:
                value = [{'Id': nested_id, 'RepoDigests': [args.image], 'Os': 'linux', 'Architecture': 'amd64'}]
            elif command == [*inner, 'image', 'inspect', nested_id]:
                value = [{'Id': nested_id}]
            elif command[:len(inner) + 1] == [*inner, 'run']:
                if expected == 'unsafe-procfs':
                    return subprocess.CompletedProcess(command, 125, '', ERROR)
                value = smoke.MARKER
            elif command[:len(inner) + 1] == [*inner, 'rm']:
                pass
            else:
                raise AssertionError(f'unexpected command: {command}')
            return subprocess.CompletedProcess(command, 0, value if isinstance(value, str) else json.dumps(value), '')

        monkeypatch.setenv('DEV_CVM_COMPOSE_SMOKE_IMAGE', reference)
        monkeypatch.setenv('DOCKER_HOST', 'unix:///var/run/docker.sock')
        monkeypatch.setattr(smoke, 'run', respond)
        monkeypatch.setattr(smoke, 'stream_image', lambda *_args: calls.append(['stream-image']))
        return smoke.verify(args)

    return invoke, calls


@pytest.mark.parametrize('reference,components', RELEASES, ids=['current-release', 'migration-baseline'])
@pytest.mark.parametrize('expected', ['success', 'unsafe-procfs'])
def test_digest_bound_runtime_reaches_probes_success(runtime_probe, reference, components, expected):
    """Each approved image reaches the existing runtime probes with its own exact tuple."""
    invoke, _calls = runtime_probe
    receipt = invoke(reference, runtime_version(components), expected)
    assert receipt['dev_image'] == reference
    assert receipt['inner_versions'] == components
    assert [(row['network'], row['expected']) for row in receipt['probes']] == [
        ('none', expected), ('bridge', expected),
    ]
    assert receipt['nested_bridge_direct_egress_denied'] == (expected == 'success')


@pytest.mark.parametrize('selected,reported', [(0, 1), (1, 0)])
def test_other_release_runtime_tuple_failure(runtime_probe, selected, reported):
    """An approved tuple cannot certify the other approved application digest."""
    invoke, calls = runtime_probe
    with pytest.raises(RuntimeError, match='unexpected release inner runtime versions'):
        invoke(RELEASES[selected][0], runtime_version(RELEASES[reported][1]))
    assert ['stream-image'] not in calls


@pytest.mark.parametrize('reference', [
    'ghcr.io/concrete-security/umbra-dev-cvm@sha256:' + 'e' * 64,
    'ghcr.io/concrete-security/umbra-dev-cvm:latest',
    RELEASES[0][0].replace('concrete-security', 'unreviewed-owner'),
])
def test_unreviewed_application_image_failure(runtime_probe, reference):
    """A familiar runtime tuple never qualifies an unknown image or mutable tag."""
    invoke, calls = runtime_probe
    with pytest.raises(RuntimeError, match='unreviewed Dev release image'):
        invoke(reference, runtime_version(RELEASES[0][1]))
    assert ['stream-image'] not in calls


@pytest.mark.parametrize('reference,components', RELEASES, ids=['current-release', 'migration-baseline'])
@pytest.mark.parametrize('field', ['Version', 'Engine', 'containerd', 'runc', 'docker-init', 'missing', 'duplicate', 'extra'])
def test_runtime_tuple_drift_failure(runtime_probe, reference, components, field):
    """All components and the Engine summary must agree without missing or duplicate names."""
    invoke, calls = runtime_probe
    version = runtime_version(components)
    if field == 'Version':
        version['Version'] = '0.0.0'
    elif field == 'missing':
        version['Components'].pop()
    elif field == 'duplicate':
        version['Components'].append(version['Components'][0].copy())
    elif field == 'extra':
        version['Components'].append({'Name': 'unreviewed', 'Version': '0.0.0'})
    else:
        next(row for row in version['Components'] if row['Name'] == field)['Version'] = '0.0.0'
    with pytest.raises(RuntimeError, match='unexpected release inner runtime versions'):
        invoke(reference, version)
    assert ['stream-image'] not in calls


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
