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


def write_default_config(home, auth_body):
    """Drop a config with the given [auth] body at the canonical path."""
    path = default_config_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('[server]\nbind = "0.0.0.0"\nport = 8765\n\n[auth]\n' + auth_body)
    return path


def test_load_empty_psk_falls_back_to_sidecar(tmp_path, monkeypatch):
    """A config that EXISTS but carries no usable PSK used to exit before
    answering `initialize`, so the MCP client dropped the server exactly as it
    did with no config at all. A hand-written psk_hex = "" is the real case."""
    monkeypatch.setenv("HOME", str(tmp_path))
    path = write_default_config(tmp_path, 'psk_hex = ""\n')

    cfg = config.load()
    assert len(cfg.psk_bytes) == 32

    sidecar = path.parent / config.FALLBACK_PSK_NAME
    assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
    # The config itself must be left exactly as the user wrote it.
    assert 'psk_hex = ""' in path.read_text()


def test_load_missing_auth_section_falls_back_to_sidecar(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = default_config_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[server]\nport = 8765\n")

    assert len(config.load().psk_bytes) == 32


def test_load_fallback_psk_is_stable(tmp_path, monkeypatch):
    """A key that changed on every start would break any device holding the
    global PSK."""
    monkeypatch.setenv("HOME", str(tmp_path))
    write_default_config(tmp_path, 'psk_hex = ""\n')
    assert config.load().psk_bytes == config.load().psk_bytes


@pytest.mark.parametrize(
    "auth_body",
    [
        'psk_passphrase = "abc"\n',
        'psk_hex = "abcd"\n',
        'psk_hex = "' + "z" * 64 + '"\n',
        "psk_hex = []\n",
    ],
    ids=["short passphrase", "short hex", "non-hex", "wrong type"],
)
def test_load_malformed_psk_is_dropped_not_fatal(tmp_path, monkeypatch, auth_body):
    """A typo in [auth] must not cost you the broker: it is how a device gets
    configured in the first place. The section is dropped, the sidecar supplies
    a key, and the salvage is reported — the user's file is never rewritten."""
    monkeypatch.setenv("HOME", str(tmp_path))
    path = write_default_config(tmp_path, auth_body)

    cfg = config.load()
    # The bad [auth] is gone, so the sidecar supplies the key.
    assert len(cfg.psk_bytes) == 32
    assert (path.parent / config.FALLBACK_PSK_NAME).exists()
    # The salvage has to be visible, or it is just a silent rewrite of intent.
    assert cfg.salvaged
    # The user's file is never edited — only ignored in part.
    assert auth_body.strip() in path.read_text()


def test_load_salvage_keeps_the_good_sections(tmp_path, monkeypatch):
    """The property the whole salvage exists for: one broken section must not
    cost you the rest of the file, and what survives has to be the values the
    user actually wrote."""
    monkeypatch.setenv("HOME", str(tmp_path))
    path = default_config_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '[server]\nbind = "0.0.0.0"\nport = 9999\n\n'
        '[auth]\npsk_passphrase = "a-good-long-passphrase"\n\n'
        '[logging]\nlevel = "DEBUG"\n\n'
        "[panel\nthis section is broken\n"
    )

    cfg = config.load()
    assert cfg.server.port == 9999
    assert cfg.server.bind == "0.0.0.0"
    assert cfg.auth.psk_passphrase == "a-good-long-passphrase"
    assert cfg.psk_bytes == hashlib.sha256(b"a-good-long-passphrase").digest()
    assert cfg.logging.level == "DEBUG"
    assert cfg.salvaged


def test_load_salvage_never_fabricates_a_section(tmp_path, monkeypatch):
    """The soundness property: a line starting with '[' inside a multi-line
    string is not a header, and a splitter that trusted it would hand the
    salvage a chunk of *string content* that parses as a perfectly good [auth] —
    with a PSK the user never set. Losing data is acceptable; inventing it is
    not."""
    monkeypatch.setenv("HOME", str(tmp_path))
    path = default_config_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # [auth] here is the contents of panel.file, not a section: the '#' makes
    # the closing \"\"\" a comment, so a naive split sees a header.
    path.write_text(
        '[panel]\nfile = """\n[auth] # """\npsk_passphrase = "fabricated-secret"\n\n[broken\nx\n'
    )

    cfg = config.load()
    assert cfg.auth.psk_passphrase == "", "invented an [auth] out of string content"
    assert cfg.psk_bytes != hashlib.sha256(b"fabricated-secret").digest()
    assert len(cfg.psk_bytes) == 32


def test_load_salvage_keeps_a_valid_passphrase_under_a_stale_hex(tmp_path, monkeypatch):
    """load() resolves the passphrase first and never reads psk_hex when one is
    set, so a leftover malformed hex must not condemn the section. Dropping
    [auth] here would swap a working key for the sidecar and desync every paired
    device."""
    monkeypatch.setenv("HOME", str(tmp_path))
    write_default_config(
        tmp_path, 'psk_passphrase = "the-current-valid-secret"\npsk_hex = "bad"\n'
    )

    cfg = config.load()
    assert cfg.psk_bytes == hashlib.sha256(b"the-current-valid-secret").digest()
    assert cfg.salvaged == []


def test_load_salvage_does_not_widen_an_unreadable_bind(tmp_path, monkeypatch):
    """The 0.0.0.0 rescue exists so a device can still reach the broker, but a
    bind we failed to parse is still the user saying something about their
    network boundary. Widening it on their behalf is not a rescue."""
    monkeypatch.setenv("HOME", str(tmp_path))
    path = default_config_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('[server]\nbind = "127.0.0.1"\nport == 8765\n')

    cfg = config.load()
    assert cfg.server.bind != "0.0.0.0"
    assert cfg.salvaged


def test_load_salvage_reports_a_repeated_header(tmp_path, monkeypatch):
    """[[ota.keys]] is one entry per signing key, so the same header appears
    several times. A dropped second entry must still be named — matching
    kept-vs-dropped by presence would let it hide behind the first entry that
    survived, and losing a signing key silently is what the report prevents."""
    monkeypatch.setenv("HOME", str(tmp_path))
    path = default_config_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '[auth]\npsk_passphrase = "a-good-long-passphrase"\n\n'
        '[[ota.keys]]\nkey_id = "k1"\npubkey_b64 = "AAAA"\n\n'
        # A syntax error, not a type error: Go's typed unmarshal rejects a
        # wrong-typed value that py/js would coerce, and this test is about the
        # reporting, so it has to fail identically in all three parsers.
        '[[ota.keys]]\nkey_id = "k2"\npubkey_b64 == "AAAA"\n'
    )

    cfg = config.load()
    assert [k.key_id for k in cfg.ota.keys] == ["k1"]
    assert any("ota.keys" in s for s in cfg.salvaged), cfg.salvaged


def test_load_salvage_binds_for_the_device(tmp_path, monkeypatch):
    """When the rescue loses [server], the code default (loopback) would leave
    the device unable to reach the broker — and the broker is how a device gets
    configured. Fall back to the bind a fresh bootstrap would have written."""
    monkeypatch.setenv("HOME", str(tmp_path))
    path = default_config_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[server\nbroken header\n")

    cfg = config.load()
    assert cfg.server.bind == "0.0.0.0"
    assert cfg.server.port == 8765
    assert len(cfg.psk_bytes) == 32


def test_load_explicit_path_is_strict(tmp_path):
    """--config is the operator's file. Quietly running on half of it would hide
    the mistake behind a broker that works but isn't doing what they wrote."""
    path = tmp_path / "explicit.toml"
    path.write_text("[server]\nport = 9999\n\n[panel\nbroken\n")

    with pytest.raises(ValueError):
        config.load(str(path))


def test_load_explicit_path_does_not_mint_fallback(tmp_path):
    """An operator-supplied --config may be managed from elsewhere; we don't
    quietly add a key beside it."""
    path = tmp_path / "explicit.toml"
    path.write_text('[auth]\npsk_hex = ""\n')

    with pytest.raises(ValueError):
        config.load(str(path))
    assert not (tmp_path / config.FALLBACK_PSK_NAME).exists()


def test_load_corrupt_sidecar_fails(tmp_path, monkeypatch):
    """A sidecar that exists but isn't a 32-byte key is never overwritten — the
    user may have put a specific key there."""
    monkeypatch.setenv("HOME", str(tmp_path))
    path = write_default_config(tmp_path, 'psk_hex = ""\n')
    sidecar = path.parent / config.FALLBACK_PSK_NAME
    sidecar.write_text("not-a-key\n")

    with pytest.raises(ValueError):
        config.load()
    assert sidecar.read_text().strip() == "not-a-key"


def test_bootstrap_loser_of_the_race_adopts_the_winner(tmp_path):
    """Several tokenmonitor-mcp processes can start simultaneously (leader
    election happens later, on the port). The second writer must return the
    first one's bytes, not overwrite them with a different passphrase."""
    target = tmp_path / "tokenmonitor.toml"
    first = config.bootstrap(target)
    second = config.bootstrap(target)
    assert first == second
