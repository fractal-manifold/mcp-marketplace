"""MCP usb_provision payload-building + dispatch parity with mcp/usb.go
(no hardware): the wifi togetherness rule, broker_url-without-psk guard, PSK
reuse-from-registry-else-mint, provider flattening, and error reporting."""

from __future__ import annotations

import asyncio

import pytest

from tmon_mcp import usbprov
from tmon_mcp.config import Config
from tmon_mcp.mcp import server as mcp_server
from tmon_mcp.mcp import usb
from tmon_mcp.registry.store import ConfigPayload, Registry


class _Deps:
    def __init__(self, registry=None):
        self.cfg = Config()
        self.cfg.psk_bytes = b"x" * 32
        self.registry = registry
        self.state = None
        self.logs = None
        self.version = "test"


def test_wifi_togetherness_bare_ssid_error():
    _, _, _, _, err = usb.build_usb_payload(_Deps(), {"wifi_ssid": "net"}, "123456", "")
    assert err and "together" in err


def test_wifi_togetherness_bare_pass_error():
    _, _, _, _, err = usb.build_usb_payload(_Deps(), {"wifi_pass": "pw"}, "123456", "")
    assert err and "together" in err


def test_wifi_open_network_explicit_empty_pass_emitted():
    p, _, _, _, err = usb.build_usb_payload(
        _Deps(), {"wifi_ssid": "net", "wifi_pass": ""}, "123456", ""
    )
    assert err is None
    assert p["wifi_ssid"] == "net" and p["wifi_pass"] == ""


def test_wifi_absent_pair_omitted():
    p, _, _, _, err = usb.build_usb_payload(_Deps(), {}, "123456", "")
    assert err is None
    assert "wifi_ssid" not in p and "wifi_pass" not in p


def test_broker_url_without_psk_or_device_id_error():
    # High finding: a broker the device could never authenticate against.
    _, _, _, _, err = usb.build_usb_payload(_Deps(), {"broker_url": "http://x"}, "123456", "")
    assert err and "device_id" in err


def test_psk_minted_when_new_device(tmp_path):
    reg = Registry(str(tmp_path / "devices"))
    p, psk, gen, reused, err = usb.build_usb_payload(
        _Deps(reg), {"broker_url": "http://x", "device_id": "aabbccdd"}, "123456", "aabbccdd"
    )
    assert err is None and gen and not reused and len(psk) == 64
    assert p["broker_url"] == "http://x" and p["psk_hex"] == psk


def test_psk_reused_from_registry(tmp_path):
    reg = Registry(str(tmp_path / "devices"))
    reg.register("aabbccdd", ConfigPayload(broker_url="http://old", psk_hex="ab" * 32))
    _, psk, gen, reused, err = usb.build_usb_payload(
        _Deps(reg), {"broker_url": "http://x", "device_id": "aabbccdd"}, "123456", "aabbccdd"
    )
    assert err is None and reused and not gen and psk == "ab" * 32


def test_providers_flattened_to_nested():
    p, _, _, _, err = usb.build_usb_payload(
        _Deps(),
        {"provider_claude": True, "provider_codex": False, "provider_antigravity": True},
        "123456",
        "",
    )
    assert err is None
    assert p["providers"] == {"claude": True, "codex": False, "gemini": True}


def test_theme_mode_invalid_error():
    _, _, _, _, err = usb.build_usb_payload(_Deps(), {"theme_mode": "purple"}, "123456", "")
    assert err and "theme_mode" in err


def test_outcome_unknown_report_flagged():
    rep = usb.usb_provision_error_report(usbprov.OutcomeUnknown("lost"))
    assert rep["ok"] is False and rep["outcome_unknown"] is True


def test_device_mismatch_report_flagged():
    rep = usb.usb_provision_error_report(usbprov.DeviceMismatch("nope"))
    assert rep["device_mismatch"] is True


def test_dispatch_routes_usb_tools_and_validates():
    # usb_provision with a bad pairing code short-circuits before any hardware.
    out = asyncio.run(mcp_server._dispatch(_Deps(), "tokenmonitor_usb_provision", {"pairing_code": "12"}))
    assert out == {"error": "pairing_code must be 6 digits"}


def test_usb_provision_rejects_non_ascii_digits():
    # str.isdigit() is Unicode-aware; Go/JS and the schema's [0-9] pattern are
    # not. All three runtimes must agree, so this must be a rejection.
    out = asyncio.run(
        mcp_server._dispatch(
            _Deps(), "tokenmonitor_usb_provision", {"pairing_code": "\u0661\u0662\u0663\u0664\u0665\u0666"}
        )
    )
    assert out == {"error": "pairing_code must be 6 digits"}


def test_usb_provision_accepts_an_absent_pairing_code():
    # The cable is the physical-presence proof: the device's serial transport
    # never demands a code, so an absent one must not short-circuit. Pair it with
    # a bad device_id so the call still stops before any hardware, and assert we
    # got THAT error rather than the pairing-code one.
    out = asyncio.run(
        mcp_server._dispatch(
            _Deps(),
            "tokenmonitor_usb_provision",
            {"port": "/dev/ttyACM0", "device_id": "nothex99"},
        )
    )
    assert out == {"error": "device_id must be 8 lowercase hex chars"}


def test_usb_payload_omits_an_absent_pairing_code():
    # And it must not travel as "" either: the transports that DO check a code
    # read an empty string as supplied-and-wrong, not as absent.
    payload, _, _, _, err = usb.build_usb_payload(_Deps(), {"city": "Madrid"}, "", "")
    assert err is None
    assert "pairing_code" not in payload
    payload, _, _, _, err = usb.build_usb_payload(_Deps(), {"city": "Madrid"}, "071718", "")
    assert err is None and payload["pairing_code"] == "071718"


def test_usb_scan_probe_success_populates_device_fields(monkeypatch):
    # Regression: a successful probe of a probe-tier (Espressif) port must copy
    # device_id/fw/state/sku into the scan result (not silently drop them).
    port = usbprov.Port(path="/dev/ttyACM0", vid=0x303A, pid=0x1001, serial="abc")
    monkeypatch.setattr(usb.usbprov, "enumerate", lambda: [port])

    def _fake_probe(deps, path, timeout, cancel):
        return usbprov.DeviceInfo(device_id="03abcdef", fw="1.2.3", state="prov", sku="S1")

    monkeypatch.setattr(usb, "_probe_blocking", _fake_probe)
    out = asyncio.run(usb.handle_usb_scan(_Deps(), {}))
    entry = out["ports"][0]
    assert entry["tier"] == usbprov.TIER_PROBE
    assert entry["device_id"] == "03abcdef"
    assert entry["fw"] == "1.2.3" and entry["state"] == "prov" and entry["sku"] == "S1"
    assert "probe_error" not in entry


def test_usb_scan_probe_error_reported(monkeypatch):
    port = usbprov.Port(path="/dev/ttyACM0", vid=0x303A, pid=0x1001, serial="abc")
    monkeypatch.setattr(usb.usbprov, "enumerate", lambda: [port])

    def _boom(deps, path, timeout, cancel):
        raise RuntimeError("no response")

    monkeypatch.setattr(usb, "_probe_blocking", _boom)
    out = asyncio.run(usb.handle_usb_scan(_Deps(), {}))
    entry = out["ports"][0]
    assert entry["tier"] == usbprov.TIER_PROBE
    assert "no response" in entry["probe_error"]
    assert "fw" not in entry


def test_dispatch_usb_scan_unsupported_os(monkeypatch):
    # Force enumerate to raise the unsupported error; the tool surfaces guidance.
    def _boom():
        raise usbprov.EnumerateUnsupported("nope")

    monkeypatch.setattr(usb.usbprov, "enumerate", _boom)
    out = asyncio.run(mcp_server._dispatch(_Deps(), "tokenmonitor_usb_scan", {}))
    assert "error" in out and "not supported on this OS" in out["error"]
