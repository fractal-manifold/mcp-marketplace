"""broker_url on tokenmonitor_set_device_pending is a legacy re-point: firmware
older than 1.0.1 cannot follow a broker that moved any other way, and firmware
from 1.0.1 resolves the broker by mDNS and must not be handed one.

Mirrors Go internal/mcp/devices_broker_url_test.go and the /sync tests in
internal/broker/sync_gcm_test.go."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from tmon_mcp import auth, spend, usage
from tmon_mcp.broker import server as broker_server
from tmon_mcp.config import Config
from tmon_mcp.logbuf import Buffer
from tmon_mcp.mcp import server as mcp_server
from tmon_mcp.mcp.server import Deps, _device_summary, _set_device_pending
from tmon_mcp.registry import crypto as reg_crypto
from tmon_mcp.registry.store import ConfigPayload, Registry, broker_url_fw
from tmon_mcp.state import State

ID = "ab12cd34"
PSK_HEX = "aa" * 32
PSK = bytes.fromhex(PSK_HEX)
OLD = "http://192.168.1.28:8765"
NEW = "http://192.168.1.50:8765"


def _deps(tmp_path, fw: str, url: str = OLD) -> Deps:
    """A registered device that last reported firmware `fw` ("" = never seen)."""
    reg = Registry(str(tmp_path / "devices"))
    reg.register(ID, ConfigPayload(psk_hex=PSK_HEX, broker_url=url))
    if fw:
        reg.set_active_firmware_version(ID, fw)
    return Deps(cfg=Config(), state=State(), logs=Buffer(), registry=reg, version="test")


def test_broker_url_fw_classification():
    for fw, want in {
        "0.10.3": (True, True), "0.12.0": (True, True), "1.0.0": (True, True),
        "1.0.0-dev.202609011200": (True, True),
        "1.0.1": (False, True), "1.0.1-dev.202609181200": (False, True), "2.0.0": (False, True),
        "": (False, False), "dev": (False, False), "1.0": (False, False),
    }.items():
        assert broker_url_fw(fw) == want, fw


@pytest.mark.parametrize("fw", ["0.10.3", "0.12.0", "1.0.0", "1.0.0-dev.202609011200"])
def test_staged_for_legacy_firmware(tmp_path, fw):
    deps = _deps(tmp_path, fw)
    out = _set_device_pending(deps, {"device_id": ID, "broker_url": NEW})
    assert out.get("ok") is True, out
    assert "note" not in out  # nothing is held for a known legacy device
    assert out["device"]["pending_changes"] == ["broker_url"]
    rec = deps.registry.load(ID)
    assert rec.pending.payload.broker_url == NEW and rec.active.payload.broker_url == OLD


@pytest.mark.parametrize("fw", ["1.0.1", "1.0.1-dev.202609181200", "1.0.2", "2.0.0"])
def test_refused_from_1_0_1(tmp_path, fw):
    deps = _deps(tmp_path, fw)
    out = _set_device_pending(deps, {"device_id": ID, "broker_url": NEW, "city": "Paris"})
    # Byte-for-byte: compat/mcp-errors.md publishes this string.
    assert out == {
        "error": f"broker_url cannot be staged for device {ID}: it reports firmware {fw}, and "
        "firmware 1.0.1 or newer resolves the broker by mDNS and does not take a pushed "
        "address. Nothing was staged."
    }
    # The refusal covers the whole call: nothing else in it is staged either.
    assert deps.registry.load(ID).pending is None


@pytest.mark.parametrize("fw", ["", "dev"])
def test_held_while_firmware_unknown(tmp_path, fw):
    deps = _deps(tmp_path, fw)
    out = _set_device_pending(deps, {"device_id": ID, "broker_url": NEW})
    assert out.get("ok") is True, out
    assert out["note"] == mcp_server.NOTE_BROKER_URL_HELD
    assert out["device"]["pending_changes"] == [mcp_server.LABEL_BROKER_URL_HELD]


def test_shape(tmp_path):
    deps = _deps(tmp_path, "0.12.0")
    for bad in ("192.168.1.50:8765", "ftp://192.168.1.50", "http://" + "a" * 121):
        out = _set_device_pending(deps, {"device_id": ID, "broker_url": bad})
        assert out == {"error": mcp_server.ERR_BROKER_URL_SHAPE}, bad


def test_labels_and_drop_report(tmp_path):
    # A device that upgraded between the staging and its next poll: until the
    # poll drops the address, the listing says that is what will happen.
    deps = _deps(tmp_path, "1.0.0")
    assert _set_device_pending(deps, {"device_id": ID, "broker_url": NEW}).get("ok")
    deps.registry.set_active_firmware_version(ID, "1.0.2")
    s = _device_summary(deps.registry.load(ID))
    assert s["pending_changes"][0] == mcp_server.LABEL_BROKER_URL_DROP
    # After the drop the listing reports it.
    assert deps.registry.drop_pending_broker_url(ID, 1) == NEW
    s = _device_summary(deps.registry.load(ID))
    assert s["broker_url_dropped"] == NEW and s["pending_version"] == 3
    assert not [c for c in s["pending_changes"] if "broker_url" in c]
    assert s["active_broker_url"] == OLD
    # Staging a new address clears the report; it survives a reload from disk.
    assert Registry(str(tmp_path / "devices")).load(ID).broker_url_dropped == NEW
    deps.registry.set_pending(ID, ConfigPayload(broker_url="http://192.168.1.51:8765"))
    assert deps.registry.load(ID).broker_url_dropped == ""


# --- /sync -------------------------------------------------------------------

_nonce = 0


def _sync_headers(fw: str) -> dict[str, str]:
    global _nonce
    _nonce += 1
    nonce = f"{_nonce:032x}"
    path = f"/device/{ID}/sync"
    ts = str(int(time.time()))
    h = {
        "X-Tmon-Timestamp": ts,
        "X-Tmon-Nonce": nonce,
        "X-Tmon-Device": ID,
        "X-Tmon-Config-Version": "1",
        "X-Tmon-Signature": auth.compute_signature(PSK, "GET", path, ts, nonce, ID, "1"),
    }
    if fw:
        h["X-Tmon-Fw-Version"] = fw
    return h


async def _sync_pending(reg: Registry, fw: str) -> dict | None:
    """Poll /sync as firmware `fw`; return the decrypted pending payload."""
    cfg = Config()
    cfg.psk_bytes = b"psk-32-bytes-of-secret-material!"
    cache = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    app = broker_server.make_app(cfg, cache, State(), None, reg, usage.Cache(30, {}), spend.Cache(300, {}))
    async with TestClient(TestServer(app)) as client:
        resp = await client.get(f"/device/{ID}/sync", headers=_sync_headers(fw))
        assert resp.status == 200, await resp.text()
        body = await resp.json()
    pending = body.get("pending")
    if pending is None:
        return None
    nonce = base64.b64decode(pending["nonce_b64"])
    ct = base64.b64decode(pending["payload_b64"])
    if pending.get("enc") == "gcm":
        pt = reg_crypto.decrypt_pending_gcm(PSK, nonce, ct, pending["version"])
    else:
        pt = reg_crypto.decrypt_pending(PSK, nonce, ct)
    return json.loads(pt)


def _reg(tmp_path: Path, **active) -> Registry:
    reg = Registry(str(tmp_path / "devices"))
    reg.register(ID, ConfigPayload(psk_hex=PSK_HEX, **active))
    return reg


@pytest.mark.parametrize("fw", ["0.12.0", "1.0.0", "1.0.0-dev.202609011200"])
async def test_sync_legacy_fw_receives_staged_broker_url(tmp_path, fw):
    reg = _reg(tmp_path, broker_url=OLD)
    reg.set_pending(ID, ConfigPayload(broker_url=NEW))
    payload = await _sync_pending(reg, fw)
    assert payload["broker_url"] == NEW
    dev = reg.load(ID)
    assert dev.pending is not None and dev.broker_url_dropped == ""


async def test_sync_never_echoes_the_recorded_broker_url(tmp_path):
    reg = _reg(tmp_path, broker_url=OLD, city="Madrid")
    reg.set_pending(ID, ConfigPayload(city="Paris"))
    payload = await _sync_pending(reg, "0.12.0")
    assert "broker_url" not in payload and payload["city"] == "Paris"


@pytest.mark.parametrize("fw", ["1.0.1", "1.0.1-dev.202609181200", "1.2.0", ""])
async def test_sync_upgrade_while_queued_drops_broker_url(tmp_path, fw):
    reg = _reg(tmp_path, broker_url=OLD, city="Madrid")
    reg.set_pending(ID, ConfigPayload(broker_url=NEW, city="Paris"))
    payload = await _sync_pending(reg, fw)
    assert "broker_url" not in payload and payload["city"] == "Paris"
    dev = reg.load(ID)
    assert dev.broker_url_dropped == NEW
    p = dev.pending.payload
    # The version moves on: a candidate the device may hold from the version
    # that carried the address must read as stale.
    assert p.broker_url == OLD and p.city == "Paris" and p.version == 3
    assert not reg.maybe_promote(ID, 2, False)
    assert reg.maybe_promote(ID, 3, False)
    active = reg.load(ID).active.payload
    assert active.broker_url == OLD and active.city == "Paris"


async def test_sync_drop_reversions_a_pending_that_held_nothing_else(tmp_path):
    reg = _reg(tmp_path)
    reg.set_pending(ID, ConfigPayload(broker_url=NEW))
    payload = await _sync_pending(reg, "1.0.2")
    assert "broker_url" not in payload and payload["version"] == 3
    dev = reg.load(ID)
    assert dev.pending.payload.version == 3 and dev.broker_url_dropped == NEW
    assert dev.active.payload.broker_url == ""


def test_drop_leaves_an_applied_repoint_alone(tmp_path):
    # A unit that took the re-point while still legacy and upgraded before its
    # acknowledging poll reports the pending's own version: it did apply the
    # address, so nothing is dropped and the acknowledgement promotes it.
    deps = _deps(tmp_path, "1.0.0")
    assert _set_device_pending(deps, {"device_id": ID, "broker_url": NEW}).get("ok")
    assert deps.registry.drop_pending_broker_url(ID, 2) == ""
    assert deps.registry.maybe_promote(ID, 2, False)
    dev = deps.registry.load(ID)
    assert dev.active.payload.broker_url == NEW and dev.broker_url_dropped == ""
