"""Release safeguards: conflicting hashes must never reach an upload."""

import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    'publish_release', Path(__file__).parents[1] / 'scripts' / 'publish_release.py'
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def test_conflicting_pypi_hash_is_rejected(monkeypatch):
    name = next(iter(release.HASHES))
    monkeypatch.setattr(release, 'read_json', lambda url: {
        'info': {'version': release.VERSION},
        'urls': [{'filename': name, 'digests': {'sha256': 'wrong'}}],
    })
    with pytest.raises(RuntimeError, match='PyPI hash mismatch'):
        release.published()


def test_partial_publication_uploads_only_missing_file(monkeypatch, tmp_path):
    names = list(release.HASHES)
    monkeypatch.setattr(release, 'check_packages', lambda directory: None)
    monkeypatch.setattr(release, 'published', lambda: {names[0]: release.HASHES[names[0]]})
    monkeypatch.setenv('TWINE_PASSWORD', 'synthetic-test-value')
    calls = []
    monkeypatch.setattr(release.subprocess, 'run', lambda args, **kwargs: calls.append(args))
    release.upload(tmp_path)
    assert len(calls) == 1
    assert str(tmp_path / names[1]) in calls[0]
    assert str(tmp_path / names[0]) not in calls[0]
    assert 'synthetic-test-value' not in calls[0]


def test_matching_existing_release_needs_no_upload(monkeypatch, tmp_path):
    monkeypatch.setattr(release, 'check_packages', lambda directory: None)
    monkeypatch.setattr(release, 'published', lambda: dict(release.HASHES))
    monkeypatch.setattr(release.subprocess, 'run', lambda *args, **kwargs: pytest.fail('Unexpected upload'))
    release.upload(tmp_path)


def test_moved_tag_is_rejected_before_download(monkeypatch, tmp_path):
    def metadata(url):
        if '/releases/' in url:
            return {'draft': False, 'prerelease': False, 'assets': []}
        return {'object': {'sha': 'different-commit'}}
    monkeypatch.setattr(release, 'read_json', metadata)
    with pytest.raises(RuntimeError, match='approved source commit'):
        release.prepare(tmp_path / 'packages')
    assert not (tmp_path / 'packages').exists()


def test_tampered_package_is_rejected_before_upload(monkeypatch, tmp_path):
    name = next(iter(release.HASHES))
    (tmp_path / name).write_bytes(b'tampered')
    monkeypatch.setattr(release, 'published', lambda: pytest.fail('Unexpected PyPI lookup'))
    monkeypatch.setattr(release.subprocess, 'run', lambda *args, **kwargs: pytest.fail('Unexpected upload'))
    with pytest.raises(RuntimeError, match='Local package hash mismatch'):
        release.upload(tmp_path)
