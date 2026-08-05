"""First-run config bootstrap (mirror of Go config/bootstrap_test.go).

Before this, load() on a machine with no ~/.config/tokenmonitor/tokenmonitor.toml
raised FileNotFoundError and __main__ exited 2, so the MCP client never saw the
server reach "ready" and silently dropped it from the session.
"""

from __future__ import annotations

import hashlib
import os
import stat

import pytest

from tmon_mcp import config


def default_config_path(home):
    return home / ".config" / "tokenmonitor" / "tokenmonitor.toml"


def test_load_bootstraps_missing_default(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = config.load()

    path = default_config_path(tmp_path)
    assert path.is_file()
    # The file holds a shared secret; it must not be world- or group-readable.
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    assert cfg.auth.psk_passphrase
    assert config._BOOTSTRAP_PASSPHRASE_PLACEHOLDER not in cfg.auth.psk_passphrase
    assert len(cfg.auth.psk_passphrase) == 32
    assert cfg.psk_bytes == hashlib.sha256(cfg.auth.psk_passphrase.encode()).digest()
    # Defaults the device depends on must survive the short template.
    assert cfg.server.bind == "0.0.0.0"
    assert cfg.server.port == 8765


def test_load_bootstrap_is_idempotent(tmp_path, monkeypatch):
    """The second start must adopt the first run's passphrase, not mint a new
    one — rotating it would silently break every device already paired."""
    monkeypatch.setenv("HOME", str(tmp_path))
    first = config.load()
    second = config.load()
    assert first.auth.psk_passphrase == second.auth.psk_passphrase


def test_load_explicit_path_does_not_bootstrap(tmp_path, monkeypatch):
    """--config names a file the user believes exists. Creating it silently
    would hide their typo behind a broker that starts with the wrong settings."""
    monkeypatch.setenv("HOME", str(tmp_path))
    missing = tmp_path / "typo.toml"
    with pytest.raises(FileNotFoundError):
        config.load(str(missing))
    assert not missing.exists()


def test_load_prefers_legacy_over_bootstrap(tmp_path, monkeypatch):
    """An existing service.toml install must keep being honoured rather than
    shadowed by a freshly generated config."""
    monkeypatch.setenv("HOME", str(tmp_path))
    legacy = tmp_path / ".config" / "tokenmonitor" / "service.toml"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('[auth]\npsk_passphrase = "legacy-secret"\n')

    cfg = config.load()
    assert cfg.auth.psk_passphrase == "legacy-secret"
    assert not default_config_path(tmp_path).exists()


def test_load_unreadable_legacy_is_not_shadowed(tmp_path, monkeypatch):
    """A service.toml that exists but cannot be read must fail loudly.
    Bootstrapping over it would start the broker on a brand-new passphrase and
    silently break every device paired against the old one."""
    if os.geteuid() == 0:
        pytest.skip("root bypasses file permissions")
    monkeypatch.setenv("HOME", str(tmp_path))
    legacy = tmp_path / ".config" / "tokenmonitor" / "service.toml"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('[auth]\npsk_passphrase = "legacy-secret"\n')
    legacy.chmod(0o000)

    with pytest.raises(PermissionError):
        config.load()
    assert not default_config_path(tmp_path).exists()


def test_bootstrap_loser_of_the_race_adopts_the_winner(tmp_path):
    """Several tokenmonitor-mcp processes can start simultaneously (leader
    election happens later, on the port). The second writer must return the
    first one's bytes, not overwrite them with a different passphrase."""
    target = tmp_path / "tokenmonitor.toml"
    first = config.bootstrap(target)
    second = config.bootstrap(target)
    assert first == second
