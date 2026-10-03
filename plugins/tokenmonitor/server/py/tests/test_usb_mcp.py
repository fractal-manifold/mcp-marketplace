"""MCP usb_provision payload-building + dispatch parity with mcp/usb.go
(no hardware): the wifi togetherness rule, the enrolment rule (PSK
explicit > reuse-from-registry > mint, independent of broker_url, `enroll`
opt-out), provider flattening, and result/error reporting."""

from __future__ import annotations

import asyncio

import pytest

from tmon_mcp import usbprov
from tmon_mcp.config import Config
from tmon_mcp.mcp import server as mcp_server
from tmon_mcp.mcp import enrol, usb
from tmon_mcp.registry.store import ConfigPayload, Registry


class _Deps:
    def __init__(self, registry=None):
        self.cfg = Config()
        self.cfg.psk_bytes = b"x" * 32
        self.registry = registry
        self.state = None
        self.logs = None
        self.version = "test"


def _build(args, code="123456"):
    return usb.build_usb_payload(args, code)


def test_wifi_togetherness_bare_ssid_error():
    _, err = _build({"wifi_ssid": "net"})
    assert err and "together" in err


def test_wifi_togetherness_bare_pass_error():
    _, err = _build({"wifi_pass": "pw"})
    assert err and "together" in err


def test_wifi_open_network_explicit_empty_pass_emitted():
    p, err = _build({"wifi_ssid": "net", "wifi_pass": ""})
    assert err is None
    assert p["wifi_ssid"] == "net" and p["wifi_pass"] == ""


def test_wifi_absent_pair_omitted():
    p, err = _build({})
    assert err is None
    assert "wifi_ssid" not in p and "wifi_pass" not in p


def test_wifi_byte_length_enforced():
    # PROVISION_WIRE §7: the bound is UTF-8 BYTES, not code points. Parity with
    # Go's TestBuildUSBPayload_WiFiByteLengthEnforced, strings included.
    _, err = _build({"wifi_ssid": "ñ" * 32, "wifi_pass": "hunter2"})  # 64 bytes
    assert err == "wifi_ssid must be 1..32 bytes (UTF-8 bytes, not characters)"
    _, err = _build({"wifi_ssid": "", "wifi_pass": "hunter2"})
    assert err == "wifi_ssid must be 1..32 bytes (UTF-8 bytes, not characters)"
    _, err = _build({"wifi_ssid": "HomeNet", "wifi_pass": "a" * 65})
    assert err == "wifi_pass must be at most 64 bytes (UTF-8 bytes, not characters)"
    _, err = _build({"wifi_ssid": "HomeNet", "wifi_pass": "ñ" * 33})  # 66 bytes
    assert err == "wifi_pass must be at most 64 bytes (UTF-8 bytes, not characters)"
    p, err = _build({"wifi_ssid": "a" * 32, "wifi_pass": "b" * 64})
    assert err is None and len(p["wifi_ssid"]) == 32


def test_providers_use_the_antigravity_wire_key():
    # PROVISION_WIRE §3 fixes the nested key set as {claude, codex,
    # antigravity}; this runtime used to emit "gemini" where Go emitted
    # "antigravity".
    p, err = _build({"provider_claude": True, "provider_codex": False, "provider_antigravity": True})
    assert err is None
    assert p["providers"] == {"antigravity": True, "claude": True, "codex": False}
    assert list(p["providers"]) == ["antigravity", "claude", "codex"]  # Go's map order
    # The deprecated arg still maps onto the modern wire key.
    p, _ = _build({"provider_gemini": True})
    assert p["providers"]["antigravity"] is True and "gemini" not in p["providers"]


def test_explicit_psk_validated_before_any_port_is_opened():
    for args, want in [
        ({"psk_hex": "abcd"}, "psk_hex must be 64 hex chars"),
        ({"psk_hex": "z" * 64}, "psk_hex is not valid hex"),
        # Inner whitespace is not hex (bytes.fromhex would have skipped it).
        ({"psk_hex": "ab " * 21 + "a"}, "psk_hex is not valid hex"),
        ({"psk_hex": PSK, "enroll": False}, "enroll=false cannot be combined with psk_hex"),
    ]:
        _, err = _build(args)
        assert err == want


def test_oversize_payload_is_a_client_error_before_any_port_is_opened():
    # It used to surface as outcome_unknown from inside the PROVISION send,
    # although zero bytes had left the host.
    out = asyncio.run(
        usb.handle_usb_provision(_Deps(), {"port": "/dev/ttyACM0", "city": "a" * 1100})
    )
    assert set(out) == {"error"} and "over the 1024-byte device limit" in out["error"]


def test_lease_base_url_is_always_loopback():
    # The lease endpoints are loopback-only whatever the broker binds to, so a
    # follower must dial 127.0.0.1 — not the bind address.
    d = _Deps()
    d.cfg.server.bind = "192.168.1.10"
    d.cfg.server.port = 8765
    assert usb.broker_base_url(d) == "http://127.0.0.1:8765"
    d.cfg.server.bind = "0.0.0.0"
    assert usb.broker_base_url(d) == "http://127.0.0.1:8765"


def test_theme_mode_invalid_error():
    _, err = _build({"theme_mode": "purple"})
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
    payload, err = _build({"city": "Madrid"}, "")
    assert err is None
    assert "pairing_code" not in payload
    payload, err = _build({"city": "Madrid"}, "071718")
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
    # has_psk is three-valued: a device that did not say is "unknown", so the
    # key stays out of the entry rather than reading false.
    assert "has_psk" not in entry


def test_usb_scan_reports_has_psk(monkeypatch):
    port = usbprov.Port(path="/dev/ttyACM0", vid=0x303A, pid=0x1001, serial="abc")
    monkeypatch.setattr(usb.usbprov, "enumerate", lambda: [port])
    for flag in (True, False):
        monkeypatch.setattr(
            usb,
            "_probe_blocking",
            lambda deps, path, timeout, cancel, flag=flag: usbprov.DeviceInfo(
                device_id="03abcdef", fw="1.0.2", state="needs_config", sku="S1", has_psk=flag
            ),
        )
        out = asyncio.run(usb.handle_usb_scan(_Deps(), {}))
        assert out["ports"][0]["has_psk"] is flag


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


# --- enrolment ---------------------------------------------------------------

ID = "02c4777c"
PSK = "0" * 62 + "ab"
RESULT_OK = b'{"ok":true,"device_id":"02c4777c","next":"rebooting"}'


def _result(body: bytes = RESULT_OK) -> usbprov.ProvisionResult:
    return usbprov.ProvisionResult(
        device=usbprov.DeviceInfo(device_id=ID, sku="S1", fw="1.0.1"), result_json=body
    )


def _reg(tmp_path) -> Registry:
    return Registry(str(tmp_path / "devices"))


def _dev(fw: str = "1.0.2", has_psk=None) -> usbprov.DeviceInfo:
    return usbprov.DeviceInfo(device_id=ID, sku="S1", fw=fw, has_psk=has_psk)


# Firmware as it answers the HELLO. has_psk arrived after 1.0.1; older firmware
# does not send it.
FRESH = _dev("1.0.2", False)
PAIRED = _dev("1.0.2", True)
V101 = _dev("1.0.1")  # finds the broker; cannot say has_psk
LEGACY = _dev("0.12.0")  # needs a broker_url; cannot say has_psk
ANCIENT = _dev("0.11.0")
ONE = ["http://192.168.1.10:8765"]
TWO = ["http://192.168.1.10:8765", "http://10.8.0.2:8765"]
WIFI = {"wifi_ssid": "HomeNet", "wifi_pass": "hunter2"}


def _finalize(reg, args, dev, candidates):
    """The two halves of payload construction, the way the handler runs them."""
    base, err = usb.build_usb_payload(args, "")
    assert err is None, err
    return usb.finalize_usb_payload(_Deps(reg), args, base, dev, candidates or [])


def _fin(payload: dict, gen: bool, reused: bool) -> usb.USBFinal:
    return usb.USBFinal(
        device_id=ID,
        payload=payload,
        psk_hex=payload.get("psk_hex", ""),
        psk_generated=gen,
        psk_reused=reused,
        caller_url=bool(payload.get("broker_url")),
    )


def test_fresh_device_pairs_in_one_call(tmp_path):
    # First-time pairing: the device says it holds no PSK, so the headline
    # WiFi-only call also pairs it — no enroll, no broker_url, no device_id.
    f, err = _finalize(_reg(tmp_path), WIFI, FRESH, TWO)
    assert err is None and f.psk_generated and not f.psk_reused and len(f.psk_hex) == 64
    assert f.payload["psk_hex"] == f.psk_hex
    # 1.0.0+ finds the broker by mDNS: no address is pushed.
    assert "broker_url" not in f.payload and f.seeded == ""


def test_paired_unknown_device_is_not_rekeyed(tmp_path):
    reg = _reg(tmp_path)
    _, err = _finalize(reg, WIFI, PAIRED, None)
    # Byte-for-byte: compat/mcp-errors.md publishes this string.
    assert err == (
        "the device already holds a PSK that this registry does not know — it may be "
        "paired with another broker, or an earlier enrolment here was never recorded. "
        "Nothing was written. Pass enroll=false to keep that pairing and change settings "
        "only, enroll=true to re-pair the device with this broker, or psk_hex if you have "
        "the key it holds"
    )
    # Even a broker_url does not override the device's own answer.
    _, err = _finalize(reg, {"broker_url": "http://10.0.0.5:8787"}, PAIRED, None)
    assert err == enrol.ERR_DEVICE_HAS_PSK
    # The three ways out the message names.
    f, err = _finalize(reg, {**WIFI, "enroll": False}, PAIRED, None)
    assert err is None and not f.psk_hex and "psk_hex" not in f.payload and "broker_url" not in f.payload
    f, err = _finalize(reg, {"enroll": True}, PAIRED, None)
    assert err is None and f.psk_generated
    f, err = _finalize(reg, {"psk_hex": PSK}, PAIRED, None)
    assert err is None and f.psk_hex == PSK and not f.psk_generated


def test_firmware_that_cannot_say_needs_intent(tmp_path):
    # Firmware without has_psk (everything up to 1.0.1): "unknown", never
    # "fresh". An unknown device is only re-keyed when the caller says so.
    reg = _reg(tmp_path)
    for dev in (V101, LEGACY):
        _, err = _finalize(reg, WIFI, dev, ONE)
        assert err == (
            "this device is not in the registry and nothing says whether it is already "
            "paired with another broker. Nothing was written. Pass enroll=true to pair it "
            "with this broker (replacing any PSK it holds), or enroll=false to change "
            "settings only"
        )
        # WiFi-only on someone else's device stays possible.
        f, err = _finalize(reg, {**WIFI, "enroll": False}, dev, TWO)
        assert err is None and not f.psk_hex and "broker_url" not in f.payload
        # A broker_url is intent, and is used as given.
        f, err = _finalize(reg, {"broker_url": "http://10.0.0.5:8787"}, dev, TWO)
        assert err is None and f.psk_generated and f.caller_url and f.seeded == ""
        assert f.payload["broker_url"] == "http://10.0.0.5:8787"


def test_legacy_firmware_is_seeded_a_broker_url(tmp_path):
    # Firmware older than 1.0.0 stays on "Waiting for setup" with a PSK alone.
    reg = _reg(tmp_path)
    for dev in (LEGACY, ANCIENT, _dev("")):
        f, err = _finalize(reg, {"enroll": True}, dev, ONE)
        assert err is None and f.seeded == ONE[0] and f.payload["broker_url"] == ONE[0]
        assert not f.caller_url
    # Ambiguous or empty hint: refuse, before anything is written.
    _, err = _finalize(reg, {"enroll": True}, LEGACY, TWO)
    assert err == (
        "this device's firmware (0.12.0) is older than 1.0.0 and cannot find the broker "
        "without an address, and this host has 2 candidate addresses. Nothing was written. "
        "Pass broker_url (see tokenmonitor_provision_hint), or enroll=false to change "
        "settings without pairing"
    )
    _, err = _finalize(reg, {"enroll": True}, LEGACY, [])
    assert "this host has 0 candidate addresses" in err
    _, err = _finalize(reg, {"enroll": True}, _dev(""), [])
    assert "firmware (unknown version)" in err
    # 1.0.1 does not need one.
    f, err = _finalize(reg, {"enroll": True}, V101, TWO)
    assert err is None and f.seeded == "" and "broker_url" not in f.payload


def test_registered_device_reuses_its_psk(tmp_path):
    # device_id comes from the HELLO_RESP, so an explicit port with no
    # device_id argument still finds the registry's key.
    reg = _reg(tmp_path)
    reg.register(ID, ConfigPayload(psk_hex=PSK))
    for dev in (FRESH, PAIRED, V101):
        f, err = _finalize(reg, WIFI, dev, TWO)
        assert err is None and f.psk_reused and not f.psk_generated
        assert f.payload["psk_hex"] == PSK and "broker_url" not in f.payload
    # On legacy firmware the reused key travels with a seeded address.
    f, err = _finalize(reg, WIFI, LEGACY, ONE)
    assert err is None and f.psk_reused and f.seeded == ONE[0]
    # enroll=false leaves even a known device's key alone.
    f, _ = _finalize(reg, {"enroll": False}, PAIRED, None)
    assert not f.psk_hex


def test_no_registry_never_mints_psk():
    # A minted PSK can only be kept if there is a registry to persist it in.
    f, err = _finalize(None, {"broker_url": "http://10.0.0.5:8787"}, LEGACY, None)
    assert err is None and not f.psk_hex and "psk_hex" not in f.payload
    assert f.payload["broker_url"] == "http://10.0.0.5:8787"


def test_wire_bytes_match_go(tmp_path):
    # The exact bytes Go's TestFinalizeUSB_WireBytes pins.
    f, err = _finalize(
        _reg(tmp_path),
        {"psk_hex": PSK, "city": "Madrid", **WIFI, "provider_claude": True, "provider_antigravity": True},
        LEGACY,
        ONE,
    )
    assert err is None
    assert f.body.decode() == (
        '{"broker_url":"http://192.168.1.10:8765","psk_hex":"' + PSK + '","city":"Madrid",'
        '"providers":{"antigravity":true,"claude":true,"codex":false},'
        '"wifi_ssid":"HomeNet","wifi_pass":"hunter2"}'
    )


def test_wire_bytes_escape_like_go(tmp_path):
    # Go's TestFinalizeUSB_WireBytesEscaping: < > & U+2028 U+2029 as \\uXXXX,
    # other non-ASCII as UTF-8.
    f, err = _finalize(_reg(tmp_path), {"enroll": False, "city": "A<b>&c\u2028d\u2029é"}, LEGACY, ONE)
    assert err is None
    assert f.body.decode() == '{"city":"A\\u003cb\\u003e\\u0026c\\u2028d\\u2029é"}'


def test_size_is_checked_again_once_complete(tmp_path):
    _, err = _finalize(_reg(tmp_path), {"city": "a" * (1024 - 60), "enroll": True}, LEGACY, ONE)
    assert "over the 1024-byte device limit" in err


def test_fw_finds_broker_alone():
    for fw, want in {
        "1.0.0": True, "1.0.1": True, "2.3.4": True, "1.0.0-dev": True, "10.0.0": True,
        "0.12.0": False, "0.9.4": False, "": False, "dev": False, "v1.0.0": False, "1.0": False,
    }.items():
        assert enrol.fw_finds_broker_alone(fw) is want, fw


def test_report_carries_the_seeded_url_but_does_not_converge(tmp_path):
    # A seeded address is not a request to converge: a known device's record,
    # config version and queued pending survive.
    reg = _reg(tmp_path)
    reg.register(ID, ConfigPayload(psk_hex=PSK, city="Madrid"))
    reg.set_pending(ID, ConfigPayload(city="Sevilla"))
    f, err = _finalize(reg, WIFI, LEGACY, ONE)
    assert err is None
    out = usb.usb_provision_report(_Deps(reg), _result(), f)
    assert out["broker_url_seeded"] == ONE[0]
    assert out["enrolled"] is True and out["registered"] is False and "reregistered" not in out
    dev = reg.load(ID)
    assert dev.active.payload.broker_url == "" and dev.pending is not None


def test_refusal_is_a_plain_tool_error_with_nothing_written(monkeypatch, tmp_path):
    # End to end through the handler: the refusal is decided after the HELLO and
    # comes back as {error}, like every other refusal.
    def _fake_run(deps, port, finalize, expect_id, cancel):
        finalize(PAIRED)
        raise AssertionError("finalize must refuse")

    monkeypatch.setattr(usb, "_run_provision_blocking", _fake_run)
    out = asyncio.run(
        usb.handle_usb_provision(_Deps(_reg(tmp_path)), {"port": "/dev/ttyACM0", **WIFI})
    )
    assert out == {"error": enrol.ERR_DEVICE_HAS_PSK}


def test_lease_busy_is_a_plain_tool_error(monkeypatch):
    def _busy(deps, port, finalize, expect_id, cancel):
        raise usbprov.LeaseBusy("busy")

    monkeypatch.setattr(usb, "_run_provision_blocking", _busy)
    out = asyncio.run(usb.handle_usb_provision(_Deps(), {"port": "/dev/ttyACM0", "enroll": False}))
    assert out == {"error": "the serial port is leased by another provisioning session; retry shortly"}


def test_report_enrols_new_device_without_broker_url(tmp_path):
    reg = _reg(tmp_path)
    out = usb.usb_provision_report(_Deps(reg), _result(), _fin({"psk_hex": PSK, "city": "Madrid"}, True, False))
    assert out["ok"] is True and out["registered"] is True and out["enrolled"] is True
    assert "psk_hex" not in out and "note" not in out
    dev = reg.load(ID)
    assert dev.active.payload.psk_hex == PSK
    assert dev.active.payload.broker_url == "" and dev.active.payload.city == "Madrid"


def test_report_device_error_is_not_ok_and_writes_nothing(tmp_path):
    # A RESULT frame is only the device ANSWERING. An error RESULT used to come
    # back as ok:true and still be mirrored into the registry.
    reg = _reg(tmp_path)
    out = usb.usb_provision_report(
        _Deps(reg),
        _result(b'{"error":"psk_hex must be 64 lowercase hex chars"}'),
        _fin({"psk_hex": PSK, "broker_url": "http://10.0.0.5:8787"}, True, False),
    )
    assert out["ok"] is False and out["registered"] is False and out["enrolled"] is False
    assert "reregistered" not in out
    assert out["error"] == "psk_hex must be 64 lowercase hex chars"
    with pytest.raises(Exception):
        reg.load(ID)
    # A failed write can leave a partial config, so a minted PSK is handed back.
    assert out["psk_hex"] == PSK and out["note"] == enrol.NOTE_PSK_MAYBE_LIVE
    # A RESULT that is valid JSON but carries no ok:true is an error too.
    out = usb.usb_provision_report(_Deps(reg), _result(b'{"next":"rebooting"}'), _fin({}, False, False))
    assert out["ok"] is False and out["error"] == "device rejected the provisioning payload"


def test_report_reused_psk_leaves_registry_record_alone(tmp_path):
    # The headline WiFi-only call on a device this registry already knows: the
    # same PSK is re-sent and the record must NOT be replaced — replace_active
    # resets the config version to 1 under a live device still at version N,
    # after which every staged pending is numbered too low to be applied.
    reg = _reg(tmp_path)
    reg.register(ID, ConfigPayload(psk_hex=PSK, city="Madrid"))
    reg.set_pending(ID, ConfigPayload(city="Sevilla"))
    out = usb.usb_provision_report(_Deps(reg), _result(), _fin({"psk_hex": PSK}, False, True))
    assert out["ok"] is True and out["enrolled"] is True and out["registered"] is False
    assert "reregistered" not in out and out["psk_reused"] is True
    dev = reg.load(ID)
    assert dev.active.payload.city == "Madrid" and dev.pending is not None

    # Passing that same key explicitly (reused=False) changes nothing: what
    # matters is that it is the key the registry already holds.
    out = usb.usb_provision_report(_Deps(reg), _result(), _fin({"psk_hex": PSK}, False, False))
    assert out["enrolled"] is True and out["registered"] is False and "reregistered" not in out
    dev = reg.load(ID)
    assert dev.active.payload.city == "Madrid" and dev.pending is not None

    # With a caller-supplied broker_url the call is an explicit re-provision and
    # converges the record in place, as it always has.
    out = usb.usb_provision_report(
        _Deps(reg), _result(), _fin({"psk_hex": PSK, "broker_url": "http://10.0.0.5:8787"}, False, True)
    )
    assert out["reregistered"] is True and out["enrolled"] is True
    dev = reg.load(ID)
    assert dev.active.payload.broker_url == "http://10.0.0.5:8787" and dev.pending is None


def test_report_enroll_false_leaves_registry_alone(tmp_path):
    reg = _reg(tmp_path)
    out = usb.usb_provision_report(
        _Deps(reg), _result(), _fin({"wifi_ssid": "HomeNet", "wifi_pass": "x"}, False, False)
    )
    assert out["ok"] is True and out["enrolled"] is False and out["registered"] is False
    assert "psk_hex" not in out
    with pytest.raises(Exception):
        reg.load(ID)


def test_report_providers_reach_the_registry(tmp_path):
    # The USB payload carries the "antigravity" wire key; the registry lift
    # must read that key.
    reg = _reg(tmp_path)
    usb.usb_provision_report(
        _Deps(reg),
        _result(),
        _fin({"psk_hex": PSK, "providers": {"antigravity": True, "claude": True, "codex": False}}, True, False),
    )
    modes = reg.load(ID).active.payload.provider_modes
    assert modes.gemini != modes.codex and modes.gemini == modes.claude


def test_outcome_unknown_echoes_minted_psk():
    rep = usb.usb_provision_error_report(usbprov.OutcomeUnknown("lost"), PSK, True)
    assert rep["outcome_unknown"] is True and rep["psk_hex"] == PSK and "note" in rep
    # A reused/explicit PSK is already known and must not be echoed.
    rep = usb.usb_provision_error_report(usbprov.OutcomeUnknown("lost"), PSK, False)
    assert "psk_hex" not in rep
