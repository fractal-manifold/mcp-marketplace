"""macOS Keychain fallback for Claude creds.

On darwin a missing ~/.claude/.credentials.json falls back to the login
Keychain, which serves the same {"claudeAiOauth": {...}} JSON blob. A present
file always wins; on Linux there is no fallback.
"""

from __future__ import annotations

import sys

import pytest

from tmon_mcp import creds

BLOB = '{"claudeAiOauth":{"accessToken":"kc","expiresAt":1700000000000}}'


def test_file_wins_over_keychain(tmp_path):
    def boom(_service):
        raise AssertionError("keychain must not be consulted when the file exists")

    prev = creds.set_keychain_reader(boom)
    try:
        p = tmp_path / "creds.json"
        p.write_text('{"claudeAiOauth":{"accessToken":"f","expiresAt":1700000000000}}')
        c = creds.load(str(p))
        assert c.access_token == "f"
    finally:
        creds.set_keychain_reader(prev)


@pytest.mark.skipif(sys.platform != "darwin", reason="keychain fallback is darwin-only")
def test_darwin_missing_default_file_falls_back_to_keychain(tmp_path, monkeypatch):
    missing = str(tmp_path / "does-not-exist.json")
    monkeypatch.setattr(creds, "_default_oauth_path", lambda: missing)
    seen = {}

    def reader(service):
        seen["service"] = service
        return BLOB

    prev = creds.set_keychain_reader(reader)
    try:
        c = creds.load(missing)
        assert c.access_token == "kc"
        assert seen["service"] == creds.KEYCHAIN_SERVICE
    finally:
        creds.set_keychain_reader(prev)


@pytest.mark.skipif(sys.platform != "darwin", reason="keychain fallback is darwin-only")
def test_darwin_explicit_override_does_not_hit_keychain(tmp_path, monkeypatch):
    monkeypatch.setattr(creds, "_default_oauth_path", lambda: "/the/default/.credentials.json")

    def reader(_service):
        raise AssertionError("keychain must not be consulted for an explicit override")

    prev = creds.set_keychain_reader(reader)
    try:
        with pytest.raises(creds.CredsFileMissing):
            creds.load(str(tmp_path / "custom-missing.json"))
    finally:
        creds.set_keychain_reader(prev)


@pytest.mark.skipif(sys.platform != "darwin", reason="keychain fallback is darwin-only")
def test_darwin_keychain_miss_raises_missing(tmp_path, monkeypatch):
    missing = str(tmp_path / "does-not-exist.json")
    monkeypatch.setattr(creds, "_default_oauth_path", lambda: missing)

    def reader(_service):
        raise RuntimeError("not found")

    prev = creds.set_keychain_reader(reader)
    try:
        with pytest.raises(creds.CredsFileMissing):
            creds.load(missing)
    finally:
        creds.set_keychain_reader(prev)


@pytest.mark.skipif(sys.platform == "darwin", reason="non-darwin has no keychain fallback")
def test_non_darwin_missing_file_raises_missing(tmp_path):
    with pytest.raises(creds.CredsFileMissing):
        creds.load(str(tmp_path / "does-not-exist.json"))
