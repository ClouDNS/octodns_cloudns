"""Publish only the approved 0.0.19 source and verify both distributions."""

import argparse
import email
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time
from urllib.error import HTTPError
from urllib.request import urlopen
import zipfile


VERSION = '0.0.19'
TAG = 'v' + VERSION
REPO = 'ClouDNS/octodns_cloudns'
API = 'https://api.github.com/repos/' + REPO
PYPI = 'https://pypi.org/pypi/octodns-cloudns/' + VERSION + '/json'
VALIDATED = 'ce36fe06efb38bc86e144a5825ca6ba9fc723cf2'
NAMES = ('octodns_cloudns-0.0.19-py3-none-any.whl',
         'octodns_cloudns-0.0.19.tar.gz')
PUBLICATION_FILES = {
    'CHANGELOG.md', 'docs/release-0.0.19.md',
    'docs/release-notes-0.0.19.md', 'scripts/publish_0019.py',
    'tests/test_release_0019.py', '.github/workflows/publish-0.0.19.yml', 'MANIFEST.in',
}


def read_json(url):
    try:
        with urlopen(url, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise


def run(*args):
    subprocess.run(list(map(str, args)), check=True)


def head():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()


def check_source():
    changed = set(subprocess.check_output(
        ['git', 'diff', '--name-only', VALIDATED, 'HEAD'], text=True).splitlines())
    if changed - PUBLICATION_FILES:
        raise RuntimeError('Source differs from live-validated implementation')
    if subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip():
        raise RuntimeError('Source checkout is not clean')
    if os.environ.get('GITHUB_SHA', head()) != head():
        raise RuntimeError('Checkout does not match workflow commit')


def check_tag():
    ref = read_json(API + '/git/ref/tags/' + TAG)
    if ref is None:
        return
    target = ref['object']
    while target['type'] == 'tag':
        target = read_json(API + '/git/tags/' + target['sha'])['object']
    if target['type'] != 'commit' or target['sha'] != head():
        raise RuntimeError('Tag does not point to the approved source commit')


def hashes(directory):
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in NAMES}


def check_packages(directory):
    expected = dict(line.split('  ', 1)[::-1] for line in
                    (directory / 'SHA256SUMS').read_text().splitlines())
    if expected != hashes(directory):
        raise RuntimeError('Package hashes do not match SHA256SUMS')
    source = Path('octodns_cloudns/__init__.py').read_bytes()
    with zipfile.ZipFile(directory / NAMES[0]) as archive:
        metadata = email.message_from_bytes(archive.read(
            'octodns_cloudns-0.0.19.dist-info/METADATA'))
        if archive.read('octodns_cloudns/__init__.py') != source:
            raise RuntimeError('Wheel does not match approved provider')
        if any(name.endswith('/ds.py') for name in archive.namelist()):
            raise RuntimeError('Unexpected DS implementation')
        check_metadata(metadata)
    with tarfile.open(directory / NAMES[1]) as archive:
        prefix = 'octodns_cloudns-0.0.19/'
        metadata = email.message_from_bytes(archive.extractfile(
            prefix + 'PKG-INFO').read())
        if archive.extractfile(prefix + 'octodns_cloudns/__init__.py').read() != source:
            raise RuntimeError('Source distribution does not match approved provider')
        check_metadata(metadata)
    return expected


def check_metadata(metadata):
    requirements = metadata.get_all('Requires-Dist', [])
    if (metadata['Version'] != VERSION or metadata['Requires-Python'] != '>=3.6'
            or 'octodns>=0.9.17' not in requirements
            or 'requests>=2.27.0' not in requirements):
        raise RuntimeError('Unexpected package version or dependency floors')


def prepare(directory):
    check_source()
    check_tag()
    directory.mkdir(parents=True, exist_ok=False)
    release = read_json(API + '/releases/tags/' + TAG)
    if release:
        # Resume with the original bytes; never rebuild a published version.
        run('gh', 'release', 'download', TAG, '--repo', REPO, '--dir', directory,
            '--pattern', '*.whl', '--pattern', '*.tar.gz', '--pattern', 'SHA256SUMS')
    else:
        run(sys.executable, '-m', 'build', '--outdir', directory)
        (directory / 'SHA256SUMS').write_text(''.join(
            '{}  {}\n'.format(digest, name) for name, digest in hashes(directory).items()))
    check_packages(directory)


def github(directory):
    check_source()
    check_tag()
    expected = check_packages(directory)
    release = read_json(API + '/releases/tags/' + TAG)
    if release is None:
        run('gh', 'release', 'create', TAG, '--repo', REPO, '--target', head(),
            '--title', 'octodns-cloudns ' + VERSION, '--latest',
            '--notes-file', 'docs/release-notes-0.0.19.md',
            *(directory / name for name in NAMES), directory / 'SHA256SUMS')
        release = read_json(API + '/releases/tags/' + TAG)
    check_tag()
    if release is None or release['draft'] or release['prerelease']:
        raise RuntimeError('Expected a published stable GitHub release')
    assets = {asset['name']: asset.get('digest') for asset in release['assets']}
    expected['SHA256SUMS'] = hashlib.sha256(
        (directory / 'SHA256SUMS').read_bytes()).hexdigest()
    if any(assets.get(name) != 'sha256:' + digest for name, digest in expected.items()):
        raise RuntimeError('GitHub release asset hashes do not match')


def published(expected):
    metadata = read_json(PYPI)
    if metadata is None:
        return set()
    if metadata['info']['version'] != VERSION:
        raise RuntimeError('Unexpected PyPI version')
    found = {}
    for item in metadata['urls']:
        name, digest = item['filename'], item['digests']['sha256']
        if name not in expected or expected[name] != digest:
            raise RuntimeError('PyPI file/hash conflicts with approved artifacts')
        found[name] = digest
    return set(found)


def upload(directory):
    check_tag()
    expected = check_packages(directory)
    missing = set(expected) - published(expected)
    if missing:
        if not os.environ.get('TWINE_PASSWORD'):
            raise RuntimeError('The configured PyPI token is unavailable')
        run(sys.executable, '-m', 'twine', 'upload', '--non-interactive',
            *(directory / name for name in sorted(missing)))


def verify(directory):
    check_tag()
    expected = check_packages(directory)
    for attempt in range(12):
        if published(expected) == set(expected):
            print('Both PyPI package hashes match the approved GitHub assets')
            return
        if attempt < 11:
            time.sleep(5)
    raise RuntimeError('PyPI publication is incomplete')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'github', 'upload', 'verify'))
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    globals()[args.action](args.directory.resolve())
