"""Validate the registry against compat/registry/golden/*.toml round-trip."""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cwm_mcp.registry.store import (
    ConfigPayload,
    Device,
    ProviderSet,
    Registry,
    _device_from_toml,
)


def _find_compat(rel: str) -> Path:
    """Walk up to the authoritative monorepo `compat/<rel>` (see
    test_auth_vectors._find_compat for why the walk skips the partial
    server/compat/ runtime slice)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "compat" / rel
        if cand.exists():
            return cand
    pytest.skip(f"compat/{rel} not available (standalone checkout)", allow_module_level=True)


GOLDEN_DIR = _find_compat("registry/golden")


def test_golden_round_trips_via_python_writer():
    src = GOLDEN_DIR / "ab12cd34.toml"
    dev = _device_from_toml(src.read_text())
    re_serialised = dev.to_toml()
    dev2 = _device_from_toml(re_serialised)
    # Compare semantic equality (not byte equality — TOML writers can differ on quoting).
    assert dev2.device_id == dev.device_id
    assert dev2.active.payload.broker_url == dev.active.payload.broker_url
    assert dev2.active.payload.psk_hex == dev.active.payload.psk_hex
    assert dev2.active.payload.version == dev.active.payload.version
    assert dev2.active.payload.city == dev.active.payload.city
    assert dev2.active.payload.br_day == dev.active.payload.br_day
    assert dev2.active.payload.br_night == dev.active.payload.br_night
    assert dev2.active.payload.vol == dev.active.payload.vol
    assert (dev2.active.payload.providers is None) == (dev.active.payload.providers is None)
    if dev.active.payload.providers is not None:
        assert vars(dev2.active.payload.providers) == vars(dev.active.payload.providers)
    assert dev2.active.payload.theme_mode == dev.active.payload.theme_mode
    assert (dev2.pending is None) == (dev.pending is None)
    if dev.pending is not None:
        assert dev2.pending.payload.version == dev.pending.payload.version
        assert dev2.pending.payload.broker_url == dev.pending.payload.broker_url
        assert dev2.pending.payload.psk_hex == dev.pending.payload.psk_hex
        assert dev2.pending.payload.theme_mode == dev.pending.payload.theme_mode


def test_register_and_set_pending(tmp_path: Path):
    reg = Registry(str(tmp_path))
    dev = reg.register("abcdef01", ConfigPayload(broker_url="http://example", psk_hex="aa" * 32, city="X"))
    assert dev.active.payload.version == 1
    # Set pending: city only
    dev2 = reg.set_pending("abcdef01", ConfigPayload(city="Y"))
    assert dev2.pending is not None
    assert dev2.pending.payload.version == 2
    assert dev2.pending.payload.city == "Y"
    # Set pending: no-op (same city as current pending) → version still bumps and is then dropped if equal to active
    # Equivalent to active → drops pending
    dev3 = reg.set_pending("abcdef01", ConfigPayload(city="X"))
    assert dev3.pending is None


def test_psks_for_returns_pending_when_distinct(tmp_path: Path):
    reg = Registry(str(tmp_path))
    reg.register("abcdef02", ConfigPayload(broker_url="http://x", psk_hex="aa" * 32))
    reg.set_pending("abcdef02", ConfigPayload(psk_hex="bb" * 32))
    active, pending = reg.psks_for("abcdef02")
    assert active == bytes.fromhex("aa" * 32)
    assert pending == bytes.fromhex("bb" * 32)


def test_theme_mode_only_bumps_pending(tmp_path: Path):
    reg = Registry(str(tmp_path))
    reg.register("abcdef04", ConfigPayload(broker_url="http://x", psk_hex="aa" * 32, theme_mode="day"))
    dev = reg.set_pending("abcdef04", ConfigPayload(theme_mode="night"))
    assert dev.pending is not None
    assert dev.pending.payload.version == 2
    assert dev.pending.payload.theme_mode == "night"
    # No-op: pending equal to active drops pending.
    dev2 = reg.set_pending("abcdef04", ConfigPayload(theme_mode="day"))
    assert dev2.pending is None


def test_maybe_promote_theme_only_with_active_psk(tmp_path: Path):
    reg = Registry(str(tmp_path))
    reg.register("abcdef05", ConfigPayload(broker_url="http://x", psk_hex="aa" * 32, theme_mode="day"))
    reg.set_pending("abcdef05", ConfigPayload(theme_mode="night"))
    # No PSK rotation pending; active-PSK signature must promote.
    promoted = reg.maybe_promote("abcdef05", observed_version=2, used_pending_psk=False)
    assert promoted is True
    dev = reg.load("abcdef05")
    assert dev.pending is None
    assert dev.active.payload.theme_mode == "night"


def test_maybe_promote_rotation_still_requires_pending_psk(tmp_path: Path):
    reg = Registry(str(tmp_path))
    reg.register("abcdef06", ConfigPayload(broker_url="http://x", psk_hex="aa" * 32))
    reg.set_pending("abcdef06", ConfigPayload(psk_hex="bb" * 32))
    assert reg.maybe_promote("abcdef06", observed_version=2, used_pending_psk=False) is False


def test_maybe_promote(tmp_path: Path):
    reg = Registry(str(tmp_path))
    reg.register("abcdef03", ConfigPayload(broker_url="http://x", psk_hex="aa" * 32))
    reg.set_pending("abcdef03", ConfigPayload(psk_hex="bb" * 32, city="Z"))
    promoted = reg.maybe_promote("abcdef03", observed_version=2, used_pending_psk=True)
    assert promoted is True
    dev = reg.load("abcdef03")
    assert dev.pending is None
    assert dev.active.payload.psk_hex == "bb" * 32
    assert dev.active.payload.city == "Z"
