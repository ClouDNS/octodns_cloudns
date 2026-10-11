"""Publish the approved 0.0.18 release assets without rebuilding them."""

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


VERSION = '0.0.18'
TAG = 'v' + VERSION
COMMIT = '869f7a4a6b049a2cb985fd86fdefd197538c0fc5'
API = 'https://api.github.com/repos/ClouDNS/octodns_cloudns'
PYPI = 'https://pypi.org/pypi/octodns-cloudns/' + VERSION + '/json'
HASHES = {
    'octodns_cloudns-0.0.18-py3-none-any.whl':
        '25d7cf54279676ed1e40895db0267fc2eacc22248de908fbb24b3490e41e9be3',
    'octodns_cloudns-0.0.18.tar.gz':
        'a155c36359d3ca68b6b252238dccc239b454697d0ab5ec501ac933d0e9bf81e2',
}


def read_json(url):
    with urlopen(url, timeout=60) as response:
        return json.load(response)


def published():
    try:
        data = read_json(PYPI)
    except HTTPError as error:
        if error.code == 404:
            return {}
        raise
    if data['info']['version'] != VERSION:
        raise RuntimeError('Unexpected PyPI version')
    files = {item['filename']: item['digests']['sha256'] for item in data['urls']}
    for name, digest in HASHES.items():
        if name in files and files[name] != digest:
            raise RuntimeError('PyPI hash mismatch for ' + name)
    return files


def check_packages(directory):
    for name, digest in HASHES.items():
        path = directory / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Local package hash mismatch for ' + name)
        if name.endswith('.whl'):
            with zipfile.ZipFile(path) as archive:
                metadata = archive.read('octodns_cloudns-0.0.18.dist-info/METADATA')
        else:
            with tarfile.open(path) as archive:
                metadata = archive.extractfile('octodns_cloudns-0.0.18/PKG-INFO').read()
        package = email.message_from_bytes(metadata)
        if package['Name'].replace('_', '-').lower() != 'octodns-cloudns' or package['Version'] != VERSION:
            raise RuntimeError('Unexpected package metadata for ' + name)
        print('Verified SHA256 and metadata: ' + name)


def prepare(directory):
    release = read_json(API + '/releases/tags/' + TAG)
    ref = read_json(API + '/git/ref/tags/' + TAG)
    if release['draft'] or release['prerelease'] or ref['object']['sha'] != COMMIT:
        raise RuntimeError('Release does not match the approved source commit')
    assets = {item['name']: item for item in release['assets']}
    directory.mkdir(parents=True, exist_ok=True)
    for name in HASHES:
        url = assets[name]['browser_download_url']
        if not url.startswith('https://github.com/ClouDNS/octodns_cloudns/releases/download/' + TAG + '/'):
            raise RuntimeError('Unexpected release asset URL')
        with urlopen(url, timeout=60) as response:
            (directory / name).write_bytes(response.read())
    check_packages(directory)
    published()  # Reject conflicting existing PyPI files before any upload.


def upload(directory):
    check_packages(directory)
    files = published()
    missing = [str(directory / name) for name in HASHES if name not in files]
    if not missing:
        print('All approved files are already present on PyPI')
        return
    if not os.environ.get('TWINE_PASSWORD'):
        raise RuntimeError('PYPI_API_TOKEN is not configured')
    subprocess.run([
        sys.executable, '-m', 'twine', 'upload', '--non-interactive',
        '--disable-progress-bar', '--repository-url',
        'https://upload.pypi.org/legacy/', *missing,
    ], check=True)


def verify(directory):
    check_packages(directory)
    for attempt in range(12):
        files = published()
        if all(name in files for name in HASHES):
            print('PyPI 0.0.18 has both approved package hashes')
            return
        if attempt < 11:
            time.sleep(10)
    raise RuntimeError('PyPI publication could not be verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'upload', 'verify'))
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    {'prepare': prepare, 'upload': upload, 'verify': verify}[args.command](args.directory)
