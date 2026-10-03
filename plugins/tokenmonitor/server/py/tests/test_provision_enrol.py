"""Enrolment over the LAN tool (parity with the Go
internal/mcp/provision_enrol_test.go).

The defect this file exists for: enrolment hung off broker_url, so a provision
with no address pushed no PSK and wrote no registry record, leaving the device
in BOOT_NEEDS_CONFIG. The device finds the broker by mDNS; the PSK is the whole
of the pairing.
"""

import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tmon_mcp.config import Config
from tmon_mcp.mcp import enrol
from tmon_mcp.mcp.server import (
    Deps,
    _device_summary,
    _pending_changes,
    _provision,
    _register_device,
)
from tmon_mcp.registry.store import ConfigPayload, Registry

ID = "ab12cd34"
PSK = "0" * 62 + "cd"
# The mock device listens on loopback, so the address of this broker on the
# route to it — what an enrolment with no broker_url is seeded with — is
# loopback too.
SEED = "http://127.0.0.1:8765"


def _deps(registry, with_cfg: bool = True) -> Deps:
    cfg = None
    if with_cfg:
        cfg = Config()
        cfg.server.port = 8765
    return Deps(cfg=cfg, state=None, logs=None, registry=registry, version="test")


def _run(registry, args: dict, with_cfg: bool = True) -> tuple[dict, dict]:
    """Run _provision against a throwaway /provision endpoint. Returns (the body
    the device received, the tool result)."""
    wire: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length", 0))
            wire.update(json.loads(self.rfile.read(n) or b"{}"))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true,"next":"rebooting"}')

        def log_message(self, *a):  # silence
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    full = {
        "device_id": ID,
        "provision_url": f"http://127.0.0.1:{srv.server_address[1]}/provision",
        "pairing_code": "071718",
    }
    full.update(args)
    out = asyncio.run(_provision(_deps(registry, with_cfg), full))
    srv.server_close()
    return wire, out


def _run_failing(registry, status: int, extra: dict | None = None, with_cfg: bool = True) -> tuple[bool, dict]:
    """Run _provision against a device that answers with `status` (0 = drop the
    connection without answering, -1 = cut the answer off mid-body). Returns (was anything POSTed, tool result)."""
    seen = {"posted": False}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            seen["posted"] = True
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if status <= 0:
                if status < 0:
                    # Headers promising a body that never arrives.
                    self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{"ok":')
                    self.wfile.flush()
                self.connection.close()
                return
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"nope"}')

        def log_message(self, *a):  # silence
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    srv.timeout = 0.5
    t = threading.Thread(target=srv.handle_request, daemon=True)
    t.start()
    args = {
        "device_id": ID,
        "provision_url": f"http://127.0.0.1:{srv.server_address[1]}/provision",
        "pairing_code": "071718",
        "enroll": True,
    }
    args.update(extra or {})
    out = asyncio.run(_provision(_deps(registry, with_cfg), args))
    t.join(2)
    srv.server_close()
    return seen["posted"], out


def _reg(tmp_path) -> Registry:
    return Registry(str(tmp_path / "devices"))


def test_provision_enrols_without_broker_url(tmp_path):
    reg = _reg(tmp_path)
    wire, out = _run(reg, {"city": "Madrid", "enroll": True})
    assert len(wire["psk_hex"]) == 64
    # Firmware older than 1.0.0 cannot leave BOOT_NEEDS_CONFIG on a PSK alone,
    # and the LAN transport cannot tell which firmware it is talking to, so the
    # address of this broker on the route to the device is always sent.
    assert wire["broker_url"] == SEED and out["broker_url_seeded"] == SEED
    assert out["registered"] is True and out["enrolled"] is True and out["psk_generated"] is True
    assert "psk_hex" not in out  # a recorded PSK is not echoed
    dev = reg.load(ID)
    assert dev.active.payload.psk_hex == wire["psk_hex"]
    assert dev.active.payload.city == "Madrid" and dev.active.payload.broker_url == SEED


def test_provision_unknown_device_needs_enrolment_intent(tmp_path):
    # A device this registry has never seen may be paired with another broker,
    # and the LAN gives no way to ask. Minting a key for it needs the caller to
    # say so.
    reg = _reg(tmp_path)
    posted, out = _run_failing(reg, 200, {"enroll": None, "city": "Madrid"})
    assert out == {"error": enrol.ERR_ENROLL_CHOICE} and not posted
    with pytest.raises(Exception):
        reg.load(ID)
    # A broker_url is intent (it is how a pairing was always asked for), and a
    # caller-supplied address is used as given — nothing is seeded.
    wire, out = _run(reg, {"broker_url": "http://10.0.0.5:8787"})
    assert len(wire["psk_hex"]) == 64 and wire["broker_url"] == "http://10.0.0.5:8787"
    assert "broker_url_seeded" not in out and out["registered"] is True


def test_provision_refuses_when_no_address_can_be_seeded(tmp_path):
    # With no way to name an address the device can reach, an enrolment is
    # refused rather than stranding old firmware on "Waiting for setup".
    posted, out = _run_failing(_reg(tmp_path), 200, with_cfg=False)
    assert out == {"error": enrol.ERR_NO_SEED_LAN} and not posted
    assert out["error"] == (
        "could not work out an address of this broker that the device can reach, and "
        "firmware older than 1.0.0 cannot pair without one. Nothing was written. Pass "
        "broker_url (see tokenmonitor_provision_hint)"
    )


def test_provision_psk_precedence(tmp_path):
    reg = _reg(tmp_path)
    reg.register(ID, ConfigPayload(psk_hex=PSK, city="Madrid"))

    # No psk_hex → the registry's PSK is reused, and with no broker_url the
    # record is left exactly as it was.
    wire, out = _run(reg, {})
    assert wire["psk_hex"] == PSK and out["psk_reused"] is True
    # The seeded address travels with the key, but it is not a request to
    # converge the record: that stays as it was.
    assert wire["broker_url"] == SEED and out["broker_url_seeded"] == SEED
    assert reg.load(ID).active.payload.broker_url == ""
    assert out["enrolled"] is True and out["registered"] is False and "reregistered" not in out
    assert reg.load(ID).active.payload.city == "Madrid"

    # Passing the SAME key explicitly is no different: it is the key the
    # registry holds, so the record stays as it is rather than being replaced
    # (which would reset its config version and drop the queued pending).
    reg.set_pending(ID, ConfigPayload(city="Sevilla"))
    _, out = _run(reg, {"psk_hex": PSK})
    assert out["enrolled"] is True and out["registered"] is False and "reregistered" not in out
    dev = reg.load(ID)
    assert dev.active.payload.city == "Madrid" and dev.pending is not None

    # An explicit psk_hex wins over the registry and converges the record.
    other = "1" * 62 + "ef"
    wire, out = _run(reg, {"psk_hex": other})
    assert wire["psk_hex"] == other and out["reregistered"] is True and out["enrolled"] is True
    assert reg.load(ID).active.payload.psk_hex == other


def test_provision_enroll_false_pushes_no_psk(tmp_path):
    reg = _reg(tmp_path)
    wire, out = _run(reg, {"city": "Madrid", "enroll": False})
    assert "psk_hex" not in wire
    assert out["ok"] is True and out["enrolled"] is False and out["registered"] is False
    with pytest.raises(Exception):
        reg.load(ID)


def test_provision_returns_minted_psk_when_registry_write_fails(tmp_path):
    # When the device took the config but the registry could not be written, the
    # minted PSK exists only on the device. It used to be dropped, leaving a
    # factory reset as the only way out.
    reg = _reg(tmp_path)
    # A directory squatting on the save's temp file makes the write fail while
    # the load beforehand still reports a clean "not found".
    os.makedirs(tmp_path / "devices" / f"{ID}.toml.tmp" / "x")
    wire, out = _run(reg, {"enroll": True})
    assert out["ok"] is True and out["registered"] is False and out["enrolled"] is False
    assert out["psk_hex"] == wire["psk_hex"]
    assert "device provisioned but registry" in out["note"]
    assert enrol.NOTE_PSK_UNRECORDED in out["note"]


def test_provision_no_registry_pushes_no_psk():
    wire, out = _run(None, {"broker_url": "http://10.0.0.5:8787"})
    assert "psk_hex" not in wire
    assert out["enrolled"] is False and out["note"] == enrol.NOTE_NO_REGISTRY


def test_register_device_broker_url_optional(tmp_path):
    # broker_url used to be required to register a device. It is only a
    # last-known address now, so a PSK alone must be enough.
    reg = _reg(tmp_path)
    deps = _deps(reg)
    out = _register_device(deps, {"device_id": ID, "psk_hex": PSK})
    assert out.get("ok") is True, out
    dev = reg.load(ID)
    assert dev.active.payload.psk_hex == PSK and dev.active.payload.broker_url == ""
    # A supplied one is still stored, as the last-known address.
    out = _register_device(deps, {"device_id": "ab12cd35", "psk_hex": PSK, "broker_url": "http://10.0.0.5:8787"})
    assert out.get("ok") is True, out
    assert reg.load("ab12cd35").active.payload.broker_url == "http://10.0.0.5:8787"


def test_pending_changes_reports_vol_zero(tmp_path):
    # Muting (vol=0) is a change like any other; a truthiness check dropped it,
    # where Go and JS report it.
    assert _pending_changes(ConfigPayload(vol=40), ConfigPayload(vol=0)) == ["vol"]
    assert _pending_changes(ConfigPayload(vol=0), ConfigPayload(vol=0)) == []
    reg = _reg(tmp_path)
    reg.register(ID, ConfigPayload(psk_hex=PSK, vol=40))
    dev = reg.set_pending(ID, ConfigPayload(vol=0))
    assert "vol" in _device_summary(dev)["pending_changes"]


def test_provision_unreadable_registry_record_aborts(tmp_path):
    # A registry record that exists but cannot be read is not a new device.
    # Minting there would re-key a paired device over a transient read failure,
    # so the call must stop before anything is sent.
    reg = _reg(tmp_path)
    os.makedirs(tmp_path / "devices" / f"{ID}.toml")
    posted, out = _run_failing(reg, 200, {"enroll": None})
    assert out.get("error", "").startswith("registry load: "), out
    assert not posted


def test_provision_failure_after_send_returns_minted_psk(tmp_path):
    # The device reboots right after applying, so a connection that dies after
    # the request was sent may well have delivered a freshly minted PSK. Losing
    # it with the error would orphan the device.
    reg = _reg(tmp_path)
    _, out = _run_failing(reg, 0)
    assert out["ok"] is False and out["outcome_unknown"] is True
    assert len(out["psk_hex"]) == 64 and out["note"] == enrol.NOTE_PSK_UNKNOWN
    with pytest.raises(Exception):
        reg.load(ID)

    # An answer cut off mid-body is the same unknown, in every runtime.
    _, out = _run_failing(reg, -1)
    assert out["outcome_unknown"] is True and len(out["psk_hex"]) == 64

    # A 5xx is a failed write, which can leave a partial config behind.
    _, out = _run_failing(reg, 500)
    assert len(out["psk_hex"]) == 64 and out["note"] == enrol.NOTE_PSK_MAYBE_LIVE
    # A 4xx is a refusal before anything was stored: nothing to recover.
    _, out = _run_failing(reg, 401)
    assert "psk_hex" not in out and out["http_status"] == 401

    # A PSK the registry already holds is not at risk and is never echoed — the
    # plain error is kept.
    reg.register(ID, ConfigPayload(psk_hex=PSK))
    _, out = _run_failing(reg, 0)
    assert set(out) == {"error"} and out["error"].startswith("POST /provision: ")
