#!/usr/bin/env python3
"""Repackage only the pinned, unpublished 0.1.0 distribution; never rebuild binaries."""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
BUILDER = 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--verifier', required=True)
    parser.add_argument('--packaging-commit', required=True)
    args = parser.parse_args()
    require(bool(re.fullmatch('[0-9a-f]{40}', args.packaging_commit)), 'invalid packaging commit')
    pins = json.loads((HERE / 'recover-0.1.0-inputs.json').read_text())
    original = {}
    paths = {}
    for name, checksum in pins['assets'].items():
        matches = list(args.inputs.rglob(name))
        require(len(matches) == 1, f'expected exactly one input: {name}')
        paths[name] = matches[0]
        original[name] = matches[0].read_bytes()
        require(digest(original[name]) == checksum, f'original digest mismatch: {name}')
    provenance_name = 'umbra-cli.intoto.jsonl'
    subprocess.run([
        args.verifier, 'verify-artifact',
        *[str(paths[name]) for name in original if name != provenance_name],
        '--provenance-path', str(paths[provenance_name]),
        '--source-uri', 'github.com/concrete-security/umbra',
        '--source-branch', 'main', '--build-workflow-input', 'dry_run=false',
        '--builder-id', BUILDER,
    ], check=True)
    envelope = json.loads(original[provenance_name])['dsseEnvelope']
    statement = json.loads(base64.b64decode(envelope['payload']))
    invocation = statement['predicate']['invocation']
    require(invocation['configSource']['digest']['sha1'] == pins['source_commit'], 'wrong binary source commit')
    require(invocation['environment']['github_run_id'] == str(pins['source_run']), 'wrong original run')
    require(invocation['configSource']['entryPoint'] == '.github/workflows/publish-cli.yml', 'wrong original workflow')
    subjects = {item['name']: item['digest']['sha256'] for item in statement['subject']}
    manifest = dict((line.split('  ', 1)[1], line.split('  ', 1)[0])
                    for line in original['SHA256SUMS'].decode().splitlines())
    require(manifest['umbra-cli-0.1.0.crate'] == pins['crate_checksum'], 'wrong crate checksum')
    require(subjects['umbra-cli-0.1.0.crate'] == pins['crate_checksum'], 'wrong signed crate checksum')
    archive_name = 'umbra-cli-release-tree.tar.gz'
    kept = []
    removed = set()
    binary_hashes = {}
    with tarfile.open(fileobj=io.BytesIO(original[archive_name]), mode='r:gz') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            if name in {'skills', 'skills/umbra-cli', 'skills/umbra-cli/SKILL.md'}:
                removed.add(name)
                continue
            require(member.isdir() or member.isfile(), 'link or special entry in original archive')
            data = archive.extractfile(member).read() if member.isfile() else None
            kept.append((member, data))
            if name.startswith('0.1.0/') and name.endswith('/umbra'):
                checksum = digest(data)
                require(subjects.get(name) == checksum == manifest.get(name), f'unsigned binary: {name}')
                binary_hashes[name] = checksum
    require(removed == {'skills', 'skills/umbra-cli', 'skills/umbra-cli/SKILL.md'}, 'unexpected discarded layout')
    require(len(binary_hashes) == 3, 'expected three original binaries')
    args.output.mkdir(parents=True, exist_ok=False)
    with (args.output / archive_name).open('wb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.GNU_FORMAT) as repaired:
                for member, data in sorted(kept, key=lambda item: item[0].name):
                    member.uid = member.gid = 0
                    member.uname = member.gname = ''
                    member.mtime = pins['source_epoch']
                    repaired.addfile(member, io.BytesIO(data) if data is not None else None)
    extracted = args.output / 'verified-tree'
    subprocess.run(['python3', str(HERE / 'extract-cli-release-tree.py'),
                    str(args.output / archive_name), str(extracted), '0.1.0'], check=True)
    for name, checksum in binary_hashes.items():
        require(digest(extracted.joinpath(name).read_bytes()) == checksum, 'binary changed during recovery')
    shutil.rmtree(extracted)
    for name, data in original.items():
        if name not in {archive_name, 'SHA256SUMS', provenance_name}:
            (args.output / name).write_bytes(data)
    evidence_names = {
        archive_name: 'umbra-cli-original-release-tree.tar.gz',
        'SHA256SUMS': 'umbra-cli-original-SHA256SUMS',
        provenance_name: 'umbra-cli-original.intoto.jsonl',
    }
    for source, target in evidence_names.items():
        (args.output / target).write_bytes(original[source])
    receipt = {
        'operation': 'remove tracked skill from unpublished 0.1.0 distribution',
        'binary_source_commit': pins['source_commit'],
        'binary_source_run': pins['source_run'],
        'packaging_commit': args.packaging_commit,
        'original_assets': pins['assets'],
        'repaired_archive_sha256': digest((args.output / archive_name).read_bytes()),
        'unchanged_binary_sha256': binary_hashes,
        'unchanged_crate_sha256': pins['crate_checksum'],
        'removed_entries': sorted(removed),
    }
    (args.output / 'umbra-cli-repair-receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    for path in args.output.iterdir():
        manifest[path.name] = digest(path.read_bytes())
    (args.output / 'SHA256SUMS').write_text(''.join(f'{checksum}  {name}\n' for name, checksum in sorted(manifest.items())))
    subprocess.run(['python3', str(HERE / 'verify-cli-release-manifest.py'),
                    str(args.output / 'SHA256SUMS'), '0.1.0',
                    *[str(path) for path in args.output.iterdir() if path.name != 'SHA256SUMS']], check=True)
    manifest['SHA256SUMS'] = digest((args.output / 'SHA256SUMS').read_bytes())
    subjects_text = ''.join(f'{checksum}  {name}\n' for name, checksum in sorted(manifest.items()))
    (args.output / 'provenance-subjects.sha256').write_text(subjects_text)
    print('Verified recovery: all three original signed binaries are unchanged.')


if __name__ == '__main__':
    main()
