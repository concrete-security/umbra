"""Exercise the actual cold-handover collector and qualified artifact packager offline."""

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import textwrap
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'cvms/dev/tests/compose_smoke.sh').read_text()
COLLECTOR = SOURCE.split('cat > "$smoke_tmpdir/handover-state.py" <<\'PY\'\n', 1)[1].split('\nPY\n', 1)[0]
WORKFLOW = (ROOT / '.github/workflows/sysbox-compatibility.yml').read_text()
PACKAGE_STEP = WORKFLOW.split('      - name: Package the successfully qualified candidate and provenance\n', 1)[1]
PACKAGE = textwrap.dedent(PACKAGE_STEP.split('        run: |\n', 1)[1].split('      - name: Retain the successfully qualified candidate\n', 1)[0]).split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
COMPARISON = (ROOT / 'ops/verify/sysbox-compatibility.sh').read_text().split('python3 - "$receipt_dir" <<\'PY\'\n', 1)[1].split('\nPY', 1)[0]
IMAGE = 'sha256:' + 'e' * 64
ROOTFILE = '/usr/local/share/umbra-sysbox-handover'

class Handover(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sysbox-handover-offline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.receipts = self.root / 'receipts'
        self.receipts.mkdir()
        self.baseline = self.root / 'baseline.json'
        self.baseline.write_text(json.dumps({'nested_image_id': IMAGE}))
        self.owners = {}
        self.calls = []
        self.image = IMAGE
        self.save_error = None
        self.expectation = 'preserved'
        self.rows = []
        for i, service in enumerate(('user-sandbox', 'dev-egress-forwarder', 'dev-tunnel', 'smoke-origin')):
            self.rows.append({'Id': str(i + 1) * 64, 'Image': 'sha256:' + 'd' * 64,
                'Config': {'Labels': {'com.docker.compose.service': service}},
                'State': {'Status': 'running', 'Pid': 123 + i, 'Health': {'Status': 'healthy'}},
                'HostConfig': {'Runtime': 'sysbox-runc' if i == 0 else 'runc'},
                'Mounts': [{'Type': 'volume', 'Name': 'test-' + name, 'Destination': path, 'RW': True}
                    for name, path in (('home', '/home/dev'), ('workspaces', '/home/dev/workspaces'), ('docker', '/var/lib/docker'))] if i == 0 else []})
    def actual_inner(self, code, phase, expectation):
        real_open, real_fstat = os.open, os.fstat
        descriptors = {}
        def mapped_open(path, flags, mode=0o777):
            mapped = self.root / 'files' / path.lstrip('/')
            mapped.parent.mkdir(parents=True, exist_ok=True)
            fd = real_open(mapped, flags, mode)
            descriptors[fd] = path
            return fd
        def owner(fd, uid, gid):
            self.owners[descriptors[fd]] = (uid, gid)
        def observed_stat(fd):
            values = list(real_fstat(fd))
            if descriptors[fd] in self.owners:
                values[4], values[5] = self.owners[descriptors[fd]]
            return os.stat_result(values)
        out = io.StringIO()
        with patch.object(sys, 'argv', ['-', phase, expectation]), patch('os.open', mapped_open), patch('os.fchown', owner), patch('os.fstat', observed_stat), redirect_stdout(out):
            exec(compile(code, 'actual-inner', 'exec'), {})
        return out.getvalue()
    def run_fake(self, args, **kwargs):
        self.calls.append(args)
        if args[:3] == ['docker', 'ps', '-aq']:
            value = '\n'.join(r['Id'] for r in self.rows)
        elif args[:2] == ['docker', 'inspect']:
            value = json.dumps(self.rows)
        elif args[:2] == ['sudo', 'cat']:
            value = '12 11 0:42 / / rw - overlay overlay rw,upperdir=' + (f"/var/lib/sysbox/rootfs/{self.rows[0]['Id']}/overlay2/diff" if self.expectation == 'rootfs-loss' else '/var/lib/docker/overlay2/owned/diff') + '\n'
        elif 'input' in kwargs:
            value = self.actual_inner(kwargs['input'], args[-2], args[-1])
        elif args[-1] == 'info':
            value = ''
        elif args[-3:-1] == ['image', 'inspect']:
            value = json.dumps([{'Id': self.image}])
        elif args[-3:-1] == ['image', 'save']:
            assert kwargs == {'stdout': subprocess.DEVNULL, 'stderr': subprocess.PIPE, 'timeout': 120, 'check': True}
            if self.save_error: raise self.save_error
            value = ''
        else:
            raise AssertionError(args)
        return subprocess.CompletedProcess(args, 0, value, '')
    def collect(self, phase):
        with patch.object(sys, 'argv', ['-', phase, 'test', str(self.receipts), str(self.baseline), self.expectation]), patch('subprocess.run', self.run_fake):
            exec(compile(COLLECTOR, 'actual-collector', 'exec'), {})
    def baseline_first(self):
        self.collect('before')
        self.calls.clear()
    def test_preserved_state_success(self):
        """preserved state success."""
        self.baseline_first()
        self.collect('after')
        self.assertEqual(json.loads((self.receipts / 'before.json').read_text())['fixtures'], json.loads((self.receipts / 'after.json').read_text())['fixtures'])
    def test_missing_rootfs_failure(self):
        """missing rootfs failure."""
        self.baseline_first()
        (self.root / 'files' / ROOTFILE.lstrip('/')).unlink()
        with self.assertRaises(FileNotFoundError): self.collect('after')
        self.assertTrue((self.receipts / 'init-root-after.txt').exists())
        self.assertFalse(any(args[-1] == 'info' for args in self.calls))
    def test_content_loss_failure(self):
        """content loss failure."""
        self.baseline_first()
        (self.root / 'files' / ROOTFILE.lstrip('/')).write_text('lost')
        with self.assertRaisesRegex(SystemExit, 'fixture changed'): self.collect('after')
    def test_owner_loss_failure(self):
        """owner loss failure."""
        self.baseline_first()
        self.owners[ROOTFILE] = (1001, 1001)
        with self.assertRaisesRegex(SystemExit, 'fixture changed'): self.collect('after')
    def test_mode_loss_failure(self):
        """mode loss failure."""
        self.baseline_first()
        (self.root / 'files' / ROOTFILE.lstrip('/')).chmod(0o644)
        with self.assertRaisesRegex(SystemExit, 'fixture changed'): self.collect('after')
    def test_symlink_failure(self):
        """symlink failure."""
        self.baseline_first()
        path = self.root / 'files' / ROOTFILE.lstrip('/')
        path.unlink()
        path.symlink_to(self.baseline)
        with self.assertRaises(OSError): self.collect('after')
    def test_recreated_container_failure(self):
        """recreated container failure."""
        self.baseline_first()
        self.rows[0]['Id'] = 'f' * 64
        with self.assertRaisesRegex(SystemExit, 'recreated'): self.collect('after')
        self.assertFalse(any('exec' in args for args in self.calls))
    def test_changed_volume_failure(self):
        """changed volume failure."""
        self.baseline_first()
        self.rows[0]['Mounts'][0]['Name'] = 'replacement'
        with self.assertRaisesRegex(SystemExit, 'recreated'): self.collect('after')
    def test_root_marker_on_volume_failure(self):
        """root marker on volume failure."""
        self.rows[0]['Mounts'].append({'Type': 'volume', 'Name': 'bad', 'Destination': '/usr/local', 'RW': True})
        with self.assertRaisesRegex(SystemExit, 'outside every'): self.collect('before')
    def test_lost_inner_image_failure(self):
        """lost inner image failure."""
        self.baseline_first()
        self.image = 'sha256:' + 'f' * 64
        with self.assertRaisesRegex(SystemExit, 'lost the previously'): self.collect('after')

    def test_readable_content_both_phases_success(self):
        """readable content both phases success."""
        self.collect('before')
        self.collect('after')
        self.assertEqual(sum(args[-3:-1] == ['image', 'save'] for args in self.calls), 2)
        for phase in ('before', 'after'):
            self.assertIs(json.loads((self.receipts / (phase + '.json')).read_text())['inner_image_content_readable'], True)
    def test_missing_content_despite_metadata_failure(self):
        """missing content despite metadata failure."""
        self.baseline_first()
        self.save_error = subprocess.CalledProcessError(1, 'image save')
        with self.assertRaises(subprocess.CalledProcessError): self.collect('after')
        self.assertFalse((self.receipts / 'after.json').exists())
    def test_content_read_timeout_failure(self):
        """content read timeout failure."""
        self.baseline_first()
        self.save_error = subprocess.TimeoutExpired('image save', 120)
        with self.assertRaises(subprocess.TimeoutExpired): self.collect('after')
        self.assertFalse((self.receipts / 'after.json').exists())

    def test_unhealthy_service_failure(self):
        """unhealthy service failure."""
        self.baseline_first()
        self.rows[1]['State']['Health']['Status'] = 'unhealthy'
        with self.assertRaisesRegex(SystemExit, 'service failed'): self.collect('after')
        self.assertFalse((self.receipts / 'after.json').exists())
    def test_health_timeout_failure(self):
        """health timeout failure."""
        self.baseline_first()
        self.rows[1]['State']['Health']['Status'] = 'starting'
        with patch('time.monotonic', side_effect=[0, 601]), self.assertRaisesRegex(SystemExit, 'within 600'): self.collect('after')
        self.assertFalse((self.receipts / 'after.json').exists())
    def test_waits_for_health_success(self):
        """waits for health success."""
        self.baseline_first()
        self.rows[1]['State']['Health']['Status'] = 'starting'
        def healthy(_): self.rows[1]['State']['Health']['Status'] = 'healthy'
        with patch('time.sleep', healthy): self.collect('after')
        self.assertTrue((self.receipts / 'after.json').exists())

    def test_exact_clone_loss_control_success(self):
        """exact clone loss control success."""
        self.expectation = 'rootfs-loss'
        self.baseline_first()
        (self.root / 'files' / ROOTFILE.lstrip('/')).unlink()
        self.collect('after')
        after = json.loads((self.receipts / 'after.json').read_text())
        self.assertTrue(after['fixtures'][ROOTFILE]['missing'])
        self.assertTrue(after['inner_image_content_readable'])
        self.assertEqual(sum(record.get('missing', False) for record in after['fixtures'].values()), 1)

    def test_clone_loss_control_requires_loss_failure(self):
        """clone loss control requires loss failure."""
        self.expectation = 'rootfs-loss'
        self.baseline_first()
        with self.assertRaisesRegex(SystemExit, 'exactly the expected'):
            self.collect('after')

    def test_clone_loss_control_rejects_volume_loss_failure(self):
        """clone loss control rejects volume loss failure."""
        self.expectation = 'rootfs-loss'
        self.baseline_first()
        for path in (ROOTFILE, '/home/dev/.umbra-sysbox-handover'):
            (self.root / 'files' / path.lstrip('/')).unlink()
        with self.assertRaises(FileNotFoundError):
            self.collect('after')

    def test_clone_loss_control_rejects_corrupt_rootfs_failure(self):
        """clone loss control rejects corrupt rootfs failure."""
        self.expectation = 'rootfs-loss'
        self.baseline_first()
        (self.root / 'files' / ROOTFILE.lstrip('/')).write_text('corrupt')
        with self.assertRaisesRegex(SystemExit, 'fixture changed'):
            self.collect('after')

    def test_clone_loss_control_requires_image_content_failure(self):
        """clone loss control requires image content failure."""
        self.expectation = 'rootfs-loss'
        self.baseline_first()
        (self.root / 'files' / ROOTFILE.lstrip('/')).unlink()
        self.save_error = subprocess.CalledProcessError(1, 'image save')
        with self.assertRaises(subprocess.CalledProcessError):
            self.collect('after')

    def test_wrong_cloning_backing_failure(self):
        """wrong cloning backing failure."""
        self.baseline_first()
        self.expectation = 'rootfs-loss'
        original = self.run_fake
        def wrong_backing(args, **kwargs):
            if args[:2] == ['sudo', 'cat']:
                return subprocess.CompletedProcess(args, 0, '12 11 0:42 / / rw - overlay overlay rw,upperdir=/var/lib/docker/owned/diff\n', '')
            return original(args, **kwargs)
        with patch('subprocess.run', wrong_backing), self.assertRaisesRegex(SystemExit, 'backing'):
            with patch.object(sys, 'argv', ['-', 'after', 'test', str(self.receipts), str(self.baseline), self.expectation]):
                exec(compile(COLLECTOR, 'actual-collector', 'exec'), {})

class Comparison(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sysbox-comparison-offline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for phase in ('0.6.7', '0.7.1', 'default-clone'):
            (self.root / f'compose-{phase}.txt').write_text('passed\n')
        common = {'dev_image_id': IMAGE, 'nested_image': IMAGE, 'nested_image_id': IMAGE,
                  'inner_versions': {'Docker': 'fixture'}, 'expectation': 'success',
                  'nested_bridge_direct_egress_denied': True, 'not_exercised': ['dstack boot']}
        self.receipts = {
            'nested-0.6.7.json': {**common, 'expectation': 'unsafe-procfs', 'nested_bridge_direct_egress_denied': False},
            'nested-0.7.1.json': dict(common),
            'default-clone/handover/handover.json': {'status': 'passed', 'rootfs_outcome': 'rootfs-loss'},
            'default-clone/handover/nested-candidate.json': dict(common),
            'no-rootfs-cloning/handover/handover.json': {'status': 'passed', 'rootfs_outcome': 'preserved'},
            'no-rootfs-cloning/handover/nested-candidate.json': dict(common),
        }

    def compare(self):
        for name, value in self.receipts.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))
        with patch.object(sys, 'argv', ['-', str(self.root)]), patch.dict(os.environ, {'UMBRA_SYSBOX_CANDIDATE_VERSION': '0.7.1+umbra.1'}), redirect_stdout(io.StringIO()):
            exec(compile(COMPARISON, 'actual-comparison', 'exec'), {})

    def test_distinct_qualification_arms_success(self):
        """Only the fresh no-clone configuration receives preservation qualification."""
        self.compare()
        result = json.loads((self.root / 'comparison.json').read_text())
        self.assertFalse(result['migrates_already_cloned_rootfs'])
        self.assertIn('--disable-rootfs-cloning', result['manager_flags'])

    def test_changed_runtime_inputs_failure(self):
        """The comparison rejects an image mismatch between qualification arms."""
        self.receipts['nested-0.7.1.json']['nested_image_id'] = 'changed'
        with self.assertRaisesRegex(SystemExit, 'input changed'):
            self.compare()

    def test_unexpected_control_outcome_failure(self):
        """A missing exact clone-loss control cannot qualify preservation."""
        self.receipts['default-clone/handover/handover.json']['rootfs_outcome'] = 'preserved'
        with self.assertRaisesRegex(SystemExit, 'distinct rootfs outcomes'):
            self.compare()

    def test_no_clone_data_loss_failure(self):
        """Loss in the preservation arm remains a failing qualification."""
        self.receipts['no-rootfs-cloning/handover/handover.json']['rootfs_outcome'] = 'rootfs-loss'
        with self.assertRaisesRegex(SystemExit, 'distinct rootfs outcomes'):
            self.compare()

    def test_missing_control_egress_enforcement_failure(self):
        """The loss control still needs candidate bridge-egress enforcement."""
        self.receipts['default-clone/handover/nested-candidate.json']['nested_bridge_direct_egress_denied'] = False
        with self.assertRaisesRegex(SystemExit, 'egress enforcement'):
            self.compare()

class Packaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sysbox-package-offline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.inputs = ['ops/verify/sysbox-build/binaries.expected.sha256', 'ops/verify/sysbox-build/Dockerfile']
        for name in self.inputs + ['.github/workflows/sysbox-compatibility.yml', 'ops/verify/sysbox-compatibility.sh', 'cvms/dev/tests/compose_smoke.sh', 'cvms/dev/tests/nested_docker_smoke.py', 'tools/test_nested_docker_smoke.py', 'tools/test_sysbox_handover.py']:
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture source\n')
        self.candidate = self.root / 'sysbox-candidate'; self.candidate.mkdir()
        self.security = self.root / 'sysbox-security'; self.security.mkdir()
        self.runtime = self.root / 'sysbox-compatibility'; self.runtime.mkdir()
        lines = []
        for name in ('sysbox-runc', 'sysbox-fs', 'sysbox-mgr'):
            data = ('ELF fixture ' + name).encode()
            (self.candidate / name).write_bytes(data)
            lines.append(hashlib.sha256(data).hexdigest() + '  ' + name + '\n')
        manifest = ''.join(lines)
        (self.repo / self.inputs[0]).write_text(manifest)
        (self.security / 'binaries.sha256').write_text(manifest)
        for name in ['vulnerabilities.json', 'device-filter-tests.txt']:
            (self.security / name).write_text('{}\n')
        for name in ['nested-0.6.7.json', 'nested-0.7.1.json', 'manager-0.6.7.txt', 'manager-0.7.1-no-rootfs-cloning.txt',
                     *[arm + '/handover/' + path for arm in ('default-clone', 'no-rootfs-cloning')
                       for path in ('before.json', 'after.json', 'handover.json', 'nested-candidate.json')],
                     'default-clone/handover/expected-rootfs-loss.txt']:
            path = self.runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{}\n')
        self.comparison = {'status': 'passed', 'cold_handover': {'status': 'passed', 'rootfs_outcome': 'preserved', 'not_exercised': ['dstack boot']},
            'default_clone_loss_control': {'status': 'passed', 'rootfs_outcome': 'rootfs-loss'},
            'migrates_already_cloned_rootfs': False,
            'manager_flags': ['--data-root', '/var/lib/sysbox', '--disable-ovfs-on-idmapped-mount', '--disable-rootfs-cloning']}
    def package(self):
        (self.runtime / 'comparison.json').write_text(json.dumps(self.comparison))
        env = {name: 'test' for name in ['GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_EVENT_NAME', 'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA', 'DEV_CVM_COMPOSE_SMOKE_IMAGE', 'UMBRA_NESTED_TEST_IMAGE']}
        env['RUNNER_TEMP'] = str(self.root)
        def git(args, **kwargs):
            return '\n'.join(self.inputs) if args[1] == 'ls-files' else 'a' * 40 + '\n'
        old = Path.cwd()
        try:
            os.chdir(self.repo)
            with patch.dict(os.environ, env), patch('subprocess.check_output', git):
                exec(compile(PACKAGE, 'actual-packaging', 'exec'), {})
        finally:
            os.chdir(old)
    def test_exact_bytes_and_modes_success(self):
        """exact bytes and modes success."""
        self.package()
        out = self.root / 'sysbox-qualified-candidate'
        with tarfile.open(out / 'sysbox-candidate.tar.gz') as archive:
            self.assertEqual(len(archive.getmembers()), 3)
            for member in archive.getmembers():
                self.assertEqual(member.mode, 0o755)
                self.assertEqual(archive.extractfile(member).read(), (self.candidate / member.name).read_bytes())
        self.assertLess((out / 'qualification.json').stat().st_size, 32768)
    def test_changed_scanned_bytes_failure(self):
        """changed scanned bytes failure."""
        (self.candidate / 'sysbox-runc').write_text('changed')
        with self.assertRaisesRegex(SystemExit, 'changed after'): self.package()
        self.assertFalse((self.root / 'sysbox-qualified-candidate').exists())
    def test_missing_scan_binary_failure(self):
        """missing scan binary failure."""
        (self.security / 'binaries.sha256').write_text('a  sysbox-runc\n')
        with self.assertRaisesRegex(SystemExit, 'invalid candidate checksum'): self.package()
    def test_failed_handover_failure(self):
        """failed handover failure."""
        self.comparison['cold_handover']['status'] = 'failed'
        with self.assertRaisesRegex(SystemExit, 'no successful'): self.package()
    def test_symlink_binary_failure(self):
        """symlink binary failure."""
        path = self.candidate / 'sysbox-runc'; path.unlink(); path.symlink_to(self.security / 'binaries.sha256')
        with self.assertRaisesRegex(SystemExit, 'invalid or oversized'): self.package()

    def test_wrong_configuration_failure(self):
        """wrong configuration failure."""
        self.comparison['manager_flags'].remove('--disable-rootfs-cloning')
        with self.assertRaisesRegex(SystemExit, 'declared fresh'):
            self.package()

    def test_unqualified_clone_control_failure(self):
        """unqualified clone control failure."""
        self.comparison['default_clone_loss_control']['status'] = 'failed'
        with self.assertRaisesRegex(SystemExit, 'declared fresh'):
            self.package()

    def test_existing_clone_migration_claim_failure(self):
        """existing clone migration claim failure."""
        self.comparison['migrates_already_cloned_rootfs'] = True
        with self.assertRaisesRegex(SystemExit, 'declared fresh'):
            self.package()

if __name__ == '__main__':
    unittest.main()
