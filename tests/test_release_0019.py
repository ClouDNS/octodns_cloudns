"""Publication must fail before uploading conflicting or unapproved bytes."""

import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    'publish_0019', Path(__file__).parents[1] / 'scripts' / 'publish_0019.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def test_conflicting_pypi_hash_aborts(monkeypatch):
    monkeypatch.setattr(release, 'read_json', lambda url: dict(
        info={'version': '0.0.19'}, urls=[dict(
            filename=release.NAMES[0], digests={'sha256': 'unexpected'})]))
    with pytest.raises(RuntimeError, match='conflicts'):
        release.published({release.NAMES[0]: 'approved'})


def test_moved_tag_rejected(monkeypatch):
    monkeypatch.setattr(release, 'head', lambda: 'approved')
    monkeypatch.setattr(release, 'read_json', lambda url: {
        'object': {'type': 'commit', 'sha': 'different'}})
    with pytest.raises(RuntimeError, match='approved source commit'):
        release.check_tag()


def test_partial_upload_only_sends_missing_file(monkeypatch, tmp_path):
    monkeypatch.setattr(release, 'check_tag', lambda: None)
    monkeypatch.setattr(release, 'check_packages', lambda path: dict.fromkeys(release.NAMES, 'hash'))
    monkeypatch.setattr(release, 'published', lambda expected: {release.NAMES[0]})
    monkeypatch.setenv('TWINE_PASSWORD', 'synthetic-test-token')
    calls = []
    monkeypatch.setattr(release, 'run', lambda *args: calls.append(args))
    release.upload(tmp_path)
    assert len(calls) == 1
    assert tmp_path / release.NAMES[1] in calls[0]
    assert tmp_path / release.NAMES[0] not in calls[0]
    assert 'synthetic-test-token' not in calls[0]


def test_complete_publication_does_not_upload_again(monkeypatch, tmp_path):
    monkeypatch.setattr(release, 'check_tag', lambda: None)
    monkeypatch.setattr(release, 'check_packages', lambda path: dict.fromkeys(release.NAMES, 'hash'))
    monkeypatch.setattr(release, 'published', lambda expected: set(release.NAMES))
    monkeypatch.setattr(release, 'run', lambda *args: pytest.fail('Unexpected upload'))
    release.upload(tmp_path)


def test_provider_diff_rejected(monkeypatch):
    monkeypatch.setattr(release.subprocess, 'check_output',
                        lambda *args, **kwargs: 'octodns_cloudns/__init__.py\n')
    with pytest.raises(RuntimeError, match='live-validated'):
        release.check_source()


def test_tampered_package_rejected_before_metadata(monkeypatch, tmp_path):
    for name in release.NAMES:
        (tmp_path / name).write_bytes(b'tampered')
    (tmp_path / 'SHA256SUMS').write_text(''.join(
        'approved  {}\n'.format(name) for name in release.NAMES))
    with pytest.raises(RuntimeError, match='hashes do not match'):
        release.check_packages(tmp_path)
