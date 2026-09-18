"""The hand-staging tools must reach the same verdict the device will.

set_device_pending, publish_firmware and revert_firmware are how an operator
pushes a build at a specific unit, and until now they wrote whatever they were
handed on the grounds that "the device-side gate is authoritative". It is — but
its refusal is silent: the device clears the pending, logs nothing to the broker
and reboots. So the operator's only feedback was a device that stubbornly kept
running the old version. Reading a manifest's fields needs no key, so there was
never a reason to stage blind.

Mirror of Go internal/mcp/devices_gate_test.go and JS test/mcp_firmware_gate.test.js.
"""

from __future__ import annotations

import base64

import pytest

from tmon_mcp.config import Config
from tmon_mcp.logbuf import Buffer
from tmon_mcp.mcp.server import (
    Deps,
    _publish_firmware,
    _revert_firmware,
    _set_device_pending,
)
from tmon_mcp.registry.store import ConfigPayload, Registry
from tmon_mcp.state import State

DEVICE = "ab12cd34"
PSK = "ab" * 32
SHA = "a" * 64
# The broker holds no key and never verifies the signature, so any well-shaped
# placeholder stands in for one.
FAKE_SIG = base64.b64encode(b"x" * 64).decode("ascii")


def _manifest_b64(sku: str, version: str, min_sv: int, sha: str = SHA,
                  channel: str = "") -> str:
    head = f'{{"channel":"{channel}",' if channel else "{"
    canonical = (
        head
        + f'"key_id":"ed25519-test","min_secure_version":{min_sv},'
        + f'"sha256":"{sha}","size":2048,"sku":"{sku}","version":"{version}"}}'
    )
    return base64.b64encode(canonical.encode("utf-8")).decode("ascii")


@pytest.fixture
def deps(tmp_path):
    reg = Registry(str(tmp_path / "devices"))
    reg.register(DEVICE, ConfigPayload(psk_hex=PSK, broker_url="https://broker.example"))
    # A production (non-DEV) serial: the shape of every unit in the field.
    reg.set_serial(DEVICE, "CWM-S1-MAD-2620-000001-0", "S1")
    cfg = Config()
    cfg.server.port = 8765
    return Deps(cfg=cfg, state=State(), logs=Buffer(), registry=reg, version="test")


def _floor(deps, sv: int) -> None:
    deps.registry.record_min_sv(DEVICE, sv)


def _running(deps, version: str, local_addr: str = "192.168.2.28:8765") -> None:
    deps.registry.set_active_firmware_version(DEVICE, version)
    deps.registry.touch(DEVICE, "192.168.2.44:9000", local_addr)


# The incident, reached through the operator's hands rather than the auto loop:
# the published 1.0.0 manifest declares packed(0.11.4) as its floor, and the unit
# in front of you already confirmed 1.0.0 before being flashed back down over USB
# (tmon_min_sv is monotonic and survives the flash).
def test_set_pending_refuses_manifest_below_the_device_floor(deps):
    _floor(deps, 16777216)  # packed(1.0.0)
    out = _set_device_pending(deps, {
        "device_id": DEVICE,
        "firmware_url": "https://downloads.example/tmon-S1-1.0.0.bin",
        "firmware_sha256": SHA,
        "firmware_version": "1.0.0",
        "firmware_manifest_b64": _manifest_b64("S1", "1.0.0", 720900),
        "firmware_manifest_sig_b64": FAKE_SIG,
    })
    err = out.get("error", "")
    assert "min-sv-below-floor" in err, out
    for want in ("720900", "16777216", "min_secure_version"):
        assert want in err, f"the message must name {want!r}: {err}"
    assert deps.registry.load(DEVICE).pending is None


def test_set_pending_stages_the_conformant_manifest(deps):
    _floor(deps, 16777216)
    out = _set_device_pending(deps, {
        "device_id": DEVICE,
        "firmware_url": "https://downloads.example/tmon-S1-1.0.1.bin",
        "firmware_sha256": SHA,
        "firmware_version": "1.0.1",
        "firmware_manifest_b64": _manifest_b64("S1", "1.0.1", 16777217),
        "firmware_manifest_sig_b64": FAKE_SIG,
    })
    assert out.get("ok"), out
    assert deps.registry.load(DEVICE).pending.payload.firmware_version == "1.0.1"


def test_set_pending_refuses_manifest_for_a_different_image(deps):
    out = _set_device_pending(deps, {
        "device_id": DEVICE,
        "firmware_url": "https://downloads.example/tmon-S1-1.0.1.bin",
        "firmware_sha256": "b" * 64,
        "firmware_version": "1.0.1",
        "firmware_manifest_b64": _manifest_b64("S1", "1.0.1", 16777217),
        "firmware_manifest_sig_b64": FAKE_SIG,
    })
    assert "sha-mismatch" in out.get("error", ""), out


def test_set_pending_refuses_manifest_for_another_sku(deps):
    out = _set_device_pending(deps, {
        "device_id": DEVICE,
        "firmware_url": "https://downloads.example/tmon-S2-1.0.1.bin",
        "firmware_sha256": SHA,
        "firmware_version": "1.0.1",
        "firmware_manifest_b64": _manifest_b64("S2", "1.0.1", 16777217),
        "firmware_manifest_sig_b64": FAKE_SIG,
    })
    assert "sku" in out.get("error", ""), out


def test_set_pending_refuses_dev_channel_on_production(deps):
    out = _set_device_pending(deps, {
        "device_id": DEVICE,
        "firmware_url": "https://downloads.example/tmon-S1-dev.bin",
        "firmware_sha256": SHA,
        "firmware_version": "1.0.1-dev.202609081200",
        "firmware_manifest_b64": _manifest_b64(
            "S1", "1.0.1-dev.202609081200", 16777217, channel="dev"),
        "firmware_manifest_sig_b64": FAKE_SIG,
    })
    assert "dev-channel-on-production" in out.get("error", ""), out


# An unsigned stage carries nothing to predict from — CI does this against dev
# units built with TMON_OTA_UNSIGNED, and the gate must not stand in its way.
def test_set_pending_unsigned_stage_is_not_judged(deps):
    _floor(deps, 16777216)
    out = _set_device_pending(deps, {
        "device_id": DEVICE,
        "firmware_url": "https://downloads.example/tmon-S1-0.11.4.bin",
        "firmware_sha256": SHA,
        "firmware_version": "0.11.4",
    })
    assert out.get("ok"), out


# The firmware drops any pending whose URL is ≥256 chars before the gate ever
# runs (config_sync.c) — another silent failure worth naming here.
def test_set_pending_refuses_an_overlong_url(deps):
    long_url = "https://downloads.example/" + "x" * 240 + ".bin"
    out = _set_device_pending(deps, {
        "device_id": DEVICE,
        "firmware_url": long_url,
        "firmware_sha256": SHA,
        "firmware_version": "1.0.1",
        "firmware_manifest_b64": _manifest_b64("S1", "1.0.1", 16777217),
        "firmware_manifest_sig_b64": FAKE_SIG,
    })
    assert "256" in out.get("error", ""), out


# revert_firmware used to check an operator-typed target_min_secure_version and
# nothing else, which answered the wrong question: once the floor has risen,
# gate 4b (packed(version) < floor) refuses the older image no matter what its
# manifest declares. A revert past the floor is simply not possible over OTA.
def test_revert_refuses_a_downgrade_below_the_floor(deps):
    _floor(deps, 16777216)  # packed(1.0.0)
    out = _revert_firmware(deps, {
        "device_id": DEVICE,
        "firmware_url": "https://downloads.example/tmon-S1-0.11.4.bin",
        "firmware_sha256": SHA,
        "firmware_version": "0.11.4",
        "firmware_manifest_b64": _manifest_b64("S1", "0.11.4", 720900),
        "firmware_manifest_sig_b64": FAKE_SIG,
    })
    err = out.get("error", "")
    assert "min-sv-below-floor" in err or "version-below-floor" in err, out
    dev = deps.registry.load(DEVICE)
    assert not dev.blocked_firmware_version, "a refused revert must tombstone nothing"


def test_revert_allows_a_revert_the_floor_permits(deps):
    _floor(deps, 720896)  # packed(0.11.0)
    out = _revert_firmware(deps, {
        "device_id": DEVICE,
        "firmware_url": "https://downloads.example/tmon-S1-0.11.4.bin",
        "firmware_sha256": SHA,
        "firmware_version": "0.11.4",
        "firmware_manifest_b64": _manifest_b64("S1", "0.11.4", 720900),
        "firmware_manifest_sig_b64": FAKE_SIG,
    })
    assert out.get("ok"), out
    assert deps.registry.load(DEVICE).pending.payload.firmware_version == "0.11.4"


def test_revert_target_floor_must_match_the_manifest(deps):
    _floor(deps, 720896)
    out = _revert_firmware(deps, {
        "device_id": DEVICE,
        "firmware_url": "https://downloads.example/tmon-S1-0.11.4.bin",
        "firmware_sha256": SHA,
        "firmware_version": "0.11.4",
        "firmware_manifest_b64": _manifest_b64("S1", "0.11.4", 720900),
        "firmware_manifest_sig_b64": FAKE_SIG,
        "target_min_secure_version": 720899,
    })
    assert "720899" in out.get("error", ""), out


# --- Part B: the firmware_url origin ----------------------------------------


def _publish(deps, tmp_path, monkeypatch, **extra):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    binary = home / "tokenmonitor.bin"
    binary.write_bytes(b"not really a firmware image")
    args = {"device_id": DEVICE, "firmware_version": "1.0.1",
            "bin_path": str(binary)}
    args.update(extra)
    return _publish_firmware(deps, args)


# A unit older than 0.10.2 has no CONFIG_TMON_OTA_ALLOW_HTTP: it drops any
# http:// pending in config_sync.c without a word. Serving the .bin off the
# broker's own /firmware/ endpoint is exactly what the local path does, so this
# publish can only ever be silence — say so instead.
def test_publish_refuses_http_below_0102(deps, tmp_path, monkeypatch):
    _running(deps, "0.10.0")
    out = _publish(deps, tmp_path, monkeypatch)
    err = out.get("error", "")
    assert "0.10.2" in err and "external_url" in err, out
    assert deps.registry.load(DEVICE).pending is None


# From 0.10.2 the same publish is fine — signed manifest and SHA are what
# establish trust, not TLS — and it goes out on the origin the device proved.
def test_publish_http_is_fine_from_0102_and_uses_the_proven_origin(deps, tmp_path, monkeypatch):
    _running(deps, "0.10.2")
    out = _publish(deps, tmp_path, monkeypatch)
    assert out.get("ok"), out
    assert out["firmware_url"].startswith("http://192.168.2.28:8765/firmware/"), out
    assert "dialled" in out.get("firmware_url_origin", ""), out


# A device that has never reported a version is not evidence of an old one:
# refusing here would block the first publish to a freshly registered unit.
def test_publish_unknown_version_is_not_treated_as_old(deps, tmp_path, monkeypatch):
    _running(deps, "")
    out = _publish(deps, tmp_path, monkeypatch)
    assert out.get("ok"), out
