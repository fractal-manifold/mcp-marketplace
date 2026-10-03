"""MCP handlers for the two USB-cable provisioning tools.

Port of tokenmonitor-mcp/internal/mcp/usb.go. `tokenmonitor_usb_scan`
enumerates + classifies + sends ONE bounded HELLO only to `probe`-tier ports;
`tokenmonitor_usb_provision` runs the §3 serial session behind the §6 lease. The
blocking serial + lease work runs in a worker thread (asyncio.to_thread).

The provision JSON is the SAME shape POST /provision accepts, plus the
wifi_ssid/wifi_pass pair (togetherness rule). See compat/PROVISION_WIRE.md.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from typing import Any

from .. import usbprov
from . import enrol
from ..registry.store import (
    ConfigPayload,
    NotFound,
    ProviderModeSet,
    provider_mode_from_bool,
    valid_device_id,
)


def registered_skus(deps) -> dict[str, str]:
    """Build the device_id→SKU map resolve() uses for registry-match. A nil
    registry yields an empty map — every port then classifies purely by
    VID/PID, so nothing auto-selects."""
    out: dict[str, str] = {}
    if deps.registry is None:
        return out
    try:
        for dev in deps.registry.list():
            out[dev.device_id] = getattr(dev, "hw_sku", "") or ""
    except Exception:  # noqa: BLE001
        return out
    return out


def broker_base_url(deps) -> str:
    """Loopback URL of this host's broker, for the lease client. The lease
    endpoints are loopback-only (they reject any non-loopback peer REGARDLESS of
    the broker's bind), so this must ALWAYS dial 127.0.0.1 — never the
    configured LAN bind, whose self-connection would present a non-loopback
    source and be rejected 403. A broker bound to 0.0.0.0 also listens on
    loopback; one bound only to a specific LAN IP is simply unreachable here,
    and open_leased then falls back to a direct exclusive open."""
    return f"http://127.0.0.1:{deps.cfg.server.port}"


def _clamp8(v: float, lo: int, hi: int) -> int:
    iv = int(v)
    return max(lo, min(hi, iv))


# --- scan -----------------------------------------------------------------


async def handle_usb_scan(deps, args: dict) -> dict:
    timeout = 3.0
    raw = args.get("timeout_seconds")
    if raw:
        try:
            timeout = float(raw)
            timeout = max(1.0, min(10.0, timeout))
        except (TypeError, ValueError):
            timeout = 3.0

    try:
        ports = usbprov.enumerate()
    except usbprov.EnumerateUnsupported:
        return {
            "error": "USB scan is not supported on this OS yet (Linux and macOS are supported; "
            "Windows enumeration is deferred). Use SoftAP + LAN provisioning instead."
        }
    except Exception as e:  # noqa: BLE001
        return {"error": f"usb enumerate: {e}"}

    results = usbprov.resolve(ports, registered_skus(deps))
    out: list[dict] = []
    for r in results:
        e: dict[str, Any] = {
            "path": r.port.path,
            "vid": f"0x{r.port.vid:04x}",
            "pid": f"0x{r.port.pid:04x}",
            "tier": r.tier,
            "registered": r.registered,
        }
        if r.port.serial:
            e["serial"] = r.port.serial
        if r.label:
            e["label"] = r.label
        if r.device_id:
            e["device_id"] = r.device_id
        if r.sku:
            e["sku"] = r.sku
        # Only `probe`-tier ports get the one bounded HELLO: a registry-match is
        # already identified without a write, and a `shared` bridge must never
        # receive a byte.
        if r.tier == usbprov.TIER_PROBE:
            cancel = threading.Event()
            try:
                dev = await asyncio.to_thread(_probe_blocking, deps, r.port.path, timeout, cancel)
            except asyncio.CancelledError:
                # The MCP request was cancelled: signal the worker so it stops
                # the bounded HELLO and drops the lease/port, then propagate.
                cancel.set()
                raise
            except Exception as ex:  # noqa: BLE001
                e["probe_error"] = str(ex)
            else:
                e["device_id"] = dev.device_id
                if dev.fw:
                    e["fw"] = dev.fw
                if dev.state:
                    e["state"] = dev.state
                if dev.has_psk is not None:
                    e["has_psk"] = dev.has_psk
                if dev.sku:
                    e["sku"] = dev.sku
        out.append(e)
    return {"ports": out}


def _probe_blocking(deps, port: str, timeout: float, cancel: threading.Event) -> usbprov.DeviceInfo:
    """Lease the port from the leader (so it doesn't collide with the log
    tailer), open it exclusively, and send ONE HELLO handshake. Writes nothing
    but the identification HELLO. `cancel` is shared with the async handler so an
    MCP-request cancellation aborts the handshake; a lost lease is folded in."""
    client = usbprov.LeaseClient(broker_base_url(deps), deps.cfg.psk())
    lp = client.open_leased(port, cancel)  # cancel interrupts the lease HTTP + open retry
    stop_watch = _wire_lost(lp, cancel)
    try:
        to = usbprov.default_timeouts()
        to.hello_resp = timeout
        # A scan sends exactly ONE bounded HELLO (PROVISION_WIRE §5). The
        # default 5 tries would cost 5×timeout per silent port — a single
        # non-TokenMonitor ESP32 devkit on the desk would then blow the 10s
        # Codex tool budget.
        to.hello_tries = 1
        return usbprov.identify(lp.handle.conn, to, cancel)
    finally:
        stop_watch.set()
        lp.close()


# --- provision ------------------------------------------------------------


async def handle_usb_provision(deps, args: dict) -> dict:
    # The cable is the physical-presence proof, so the device's serial transport
    # never demands a code. Accept an absent one; still reject a malformed one,
    # because a caller that bothered to pass a code has the device's screen in
    # front of them and a typo should be surfaced, not silently dropped into a
    # payload the device ignores.
    #
    # ASCII digits only: str.isdigit() also accepts Arabic-Indic and other
    # Unicode decimal forms, which the Go/JS runtimes and the schema's [0-9]
    # pattern both reject. The device's parser is ASCII too.
    code = str(args.get("pairing_code", "")).strip()
    if code and (len(code) != 6 or any(c not in "0123456789" for c in code)):
        return {"error": "pairing_code must be 6 digits"}

    expect_id = str(args.get("device_id", "")).strip().lower()
    if expect_id and not valid_device_id(expect_id):
        return {"error": "device_id must be 8 lowercase hex chars"}

    # Resolve the port: explicit wins; else auto-select ONLY when exactly one
    # registry-match exists (a probe/shared port is never auto-picked).
    port = str(args.get("port", "")).strip()
    if not port:
        try:
            ports = usbprov.enumerate()
        except usbprov.EnumerateUnsupported as e:
            return {"error": f"usb enumerate: {e}"}
        except Exception as e:  # noqa: BLE001
            return {"error": f"usb enumerate: {e}"}
        matches = usbprov.registry_matches(usbprov.resolve(ports, registered_skus(deps)))
        if len(matches) == 1:
            port = matches[0].port.path
            if not expect_id:
                expect_id = matches[0].device_id
        elif len(matches) == 0:
            return {
                "error": "no registry-match device found; pass an explicit port from "
                "tokenmonitor_usb_scan (a probe/shared port is never auto-selected)"
            }
        else:
            return {
                "error": "several registry-match devices attached; pass an explicit port "
                "from tokenmonitor_usb_scan"
            }

    # Everything the arguments alone decide; the PSK and a seeded broker_url
    # are added once the device has said who it is (finalize_usb_payload).
    base, err = build_usb_payload(args, code)
    if err is not None:
        return {"error": err}

    # Validate the encoded size HERE, before leasing or opening anything. An
    # over-cap payload fails inside the PROVISION send, which is reported as
    # outcome-unknown — but zero bytes have left the host, so it is a pure
    # client-side error.
    if len(_encode_payload(base)) > usbprov.PAYLOAD_MAX:
        return {"error": _payload_too_big(len(_encode_payload(base)))}

    # What may be sent depends on the HELLO_RESP — which device this is, whether
    # it already holds a PSK, whether its firmware can find the broker without
    # an address — so the payload is finished inside the session, after the
    # handshake and before any PROVISION write.
    candidates = enrol.hint_urls(deps)
    fin: list[USBFinal] = []

    def finalize(dev: usbprov.DeviceInfo) -> bytes:
        # A re-handshake (pre-PROVISION reset recovery) must resend the same
        # bytes — in particular the same minted PSK.
        if fin and fin[0].device_id == dev.device_id:
            return fin[0].body
        f, err_text = finalize_usb_payload(deps, args, base, dev, candidates)
        if err_text is not None:
            raise USBRefusal(err_text)
        fin[:] = [f]
        return f.body

    cancel = threading.Event()
    try:
        res = await asyncio.to_thread(_run_provision_blocking, deps, port, finalize, expect_id, cancel)
    except asyncio.CancelledError:
        # MCP request cancelled mid-session: signal the worker so run_provision
        # unwinds (post-PROVISION it lands on OUTCOME_UNKNOWN inside the thread —
        # NEVER auto-retried) and the lease/port are released, then propagate.
        cancel.set()
        raise
    except USBRefusal as e:
        return {"error": str(e)}
    except usbprov.LeaseBusy:
        return {"error": "the serial port is leased by another provisioning session; retry shortly"}
    except usbprov.PortBusy:
        return {
            "error": "the serial port is held by another process; close other serial monitors "
            "and retry"
        }
    except (
        usbprov.OutcomeUnknown,
        usbprov.DeviceMismatch,
        usbprov.UnsupportedProto,
        usbprov.Handshake,
        usbprov.SessionCancelled,
        usbprov.SessionIO,
    ) as e:
        f0 = fin[0] if fin else None
        return usb_provision_error_report(
            e, f0.psk_hex if f0 else "", f0.psk_generated if f0 else False
        )
    except Exception as e:  # noqa: BLE001
        return {"error": f"open serial port: {e}"}

    return usb_provision_report(deps, res, fin[0], enrol.no_registry_note(deps, args, fin[0].psk_hex))


class USBRefusal(Exception):
    """A decision NOT to provision, taken after the handshake and before any
    PROVISION write. It surfaces as a plain tool error."""


def _encode_payload(payload: dict) -> bytes:
    """The PROVISION body, byte for byte what Go's json.Marshal produces:
    compact (no spaces — saves bytes against the 1024-byte PAYLOAD_MAX budget),
    non-ASCII left as UTF-8 (firmware cJSON decodes it directly), and the five
    characters Go escapes for HTML/JS safety — < > & U+2028 U+2029 — written
    as \\uXXXX. They can only occur inside strings, so a plain replace is
    safe. Without it a city like "Tom & Jerry" would put different bytes (and a
    different size) on the wire than the Go runtime."""
    import json

    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    for ch, esc in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                    ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        text = text.replace(ch, esc)
    return text.encode("utf-8")


def _payload_too_big(n: int) -> str:
    return (
        f"provisioning payload is {n} bytes, over the "
        f"{usbprov.PAYLOAD_MAX}-byte device limit; shorten fields such as city"
    )


@dataclass
class USBFinal:
    """The payload as it actually goes on the wire, with what was decided on
    the way."""

    device_id: str = ""
    payload: dict = field(default_factory=dict)
    body: bytes = b""
    psk_hex: str = ""
    psk_generated: bool = False
    psk_reused: bool = False
    caller_url: bool = False  # the caller supplied broker_url
    seeded: str = ""  # the broker_url this host added, if any


def finalize_usb_payload(
    deps, args: dict, base: dict, dev: usbprov.DeviceInfo, candidates: list[str]
) -> tuple[USBFinal | None, str | None]:
    """Complete the payload for the device that answered the HELLO: the PSK
    (resolve_enrol_psk, with the device's own has_psk as evidence) and, for
    firmware that cannot find the broker by itself, a broker_url. `candidates`
    are the provision hint's URLs. A non-None error is a refusal: nothing has
    been written and nothing will be."""
    f = USBFinal(device_id=dev.device_id, caller_url=bool(base.get("broker_url")))
    f.psk_hex, f.psk_generated, f.psk_reused, err = enrol.resolve_enrol_psk(
        deps, args, dev.device_id, dev.has_psk
    )
    if err is not None:
        return None, err
    broker_url = base.get("broker_url", "")
    # A PSK with no address strands firmware older than 1.0.0 on "Waiting for
    # setup". Over the cable there is no route to read an address off, so the
    # provision hint is used — but only when it names exactly one.
    if f.psk_hex and not f.caller_url and not enrol.fw_finds_broker_alone(dev.fw):
        f.seeded, err = enrol.seed_url_from_hint(dev.fw, candidates)
        if err is not None:
            return None, err
        broker_url = f.seeded
    # Same key order as the Go struct, so the bytes on the wire are identical.
    payload: dict[str, Any] = {}
    if "pairing_code" in base:
        payload["pairing_code"] = base["pairing_code"]
    if broker_url:
        payload["broker_url"] = broker_url
    if f.psk_hex:
        payload["psk_hex"] = f.psk_hex
    for k, v in base.items():
        if k not in ("pairing_code", "broker_url", "psk_hex"):
            payload[k] = v
    f.payload = payload
    f.body = _encode_payload(payload)
    if len(f.body) > usbprov.PAYLOAD_MAX:
        return None, _payload_too_big(len(f.body))
    return f, None


def usb_provision_report(deps, res, fin: USBFinal, note: str = "") -> dict:
    """Turn a received RESULT into the tool result. A RESULT is only the device
    ANSWERING — success and error alike arrive as one (PROVISION_WIRE §3) — so
    top-level ok is the device's own `ok`, and the registry is mirrored only
    when the device says it applied the payload."""
    import json

    psk_hex, psk_generated, psk_reused = fin.psk_hex, fin.psk_generated, fin.psk_reused
    # The device_id echoed in HELLO_RESP is authoritative — use it for the
    # registry mirror below.
    device_id = res.device.device_id
    device_resp: Any = None
    try:
        parsed = json.loads(res.result_json)
        # Only surface an object, like Go's map[string]any unmarshal — a bare
        # array/string/number RESULT is dropped rather than echoed.
        device_resp = parsed if isinstance(parsed, dict) else None
    except (ValueError, UnicodeDecodeError):
        device_resp = None
    applied = device_resp is not None and device_resp.get("ok") is True

    out: dict[str, Any] = {"ok": applied}
    if not applied:
        msg = device_resp.get("error") if device_resp is not None else None
        out["error"] = msg if isinstance(msg, str) and msg else "device rejected the provisioning payload"
    out["device_id"] = device_id
    out["registered"] = False
    out["enrolled"] = False
    if res.device.sku:
        out["sku"] = res.device.sku
    if res.device.fw:
        out["fw"] = res.device.fw
    if psk_generated:
        out["psk_generated"] = True
    if psk_reused:
        out["psk_reused"] = True
    if fin.seeded:
        out["broker_url_seeded"] = fin.seeded
    if device_resp is not None:
        out["device_response"] = device_resp
    if not applied:
        if psk_generated:
            out["psk_hex"] = psk_hex
            out["note"] = enrol.NOTE_PSK_MAYBE_LIVE
        return out

    # Mirror the enrolment into the registry whenever a PSK was pushed and the
    # device_id is well-formed — with or without a broker_url. enroll=false
    # pushed none and leaves the registry untouched.
    if deps.registry is not None and psk_hex and valid_device_id(device_id):
        registered, reregistered, enrolled, note = enrol.mirror_to_registry(
            deps, device_id, usb_registry_payload(fin.payload, psk_hex), fin.caller_url
        )
        out["registered"] = registered
        if reregistered:
            out["reregistered"] = True
        out["enrolled"] = enrolled
    if psk_generated and not out["enrolled"]:
        out["psk_hex"] = psk_hex
        note = enrol.join_notes(note, enrol.NOTE_PSK_UNRECORDED)
    if note:
        out["note"] = note
    return out


def _run_provision_blocking(
    deps, port: str, finalize, expect_id: str, cancel: threading.Event
) -> usbprov.ProvisionResult:
    client = usbprov.LeaseClient(broker_base_url(deps), deps.cfg.psk())
    lp = client.open_leased(port, cancel)  # may raise LeaseBusy / PortBusy; cancel interrupts open
    stop_watch = _wire_lost(lp, cancel)
    try:
        return usbprov.run_provision(
            lp.handle.conn,
            usbprov.ProvisionOpts(expect_device_id=expect_id, finalize=finalize),
            cancel,
        )
    finally:
        stop_watch.set()
        lp.close()


def _wire_lost(lp: usbprov.LeasedPort, cancel: threading.Event) -> threading.Event:
    """Fold a lost lease into the caller-owned `cancel` event: when the lease is
    lost mid-session (the leader reaped it / the broker went away) the session
    MUST abort rather than corrupt the stream. `cancel` is created by the async
    handler so an MCP-request cancellation trips the same abort. Returns a
    stop_watch event; set it to tear the watcher down."""
    stop_watch = threading.Event()

    def _watch() -> None:
        while not stop_watch.wait(0.05):
            if lp.lost.is_set():
                cancel.set()
                return

    threading.Thread(target=_watch, daemon=True, name="usbprov-lost-watch").start()
    return stop_watch


def build_usb_payload(args: dict, code: str) -> tuple[dict, str | None]:
    """Assemble the part of the PROVISION JSON the tool args alone decide,
    including the WiFi pair. Mirrors _provision's field handling and enforces
    the wifi_ssid⇄wifi_pass togetherness rule. An explicit psk_hex is validated
    here; which PSK is finally sent is finalize_usb_payload's call. Returns
    (payload, error_or_None)."""
    broker_url = str(args.get("broker_url", "")).strip()
    psk_hex, err = enrol.explicit_psk(args)
    if err is not None:
        return {}, err

    payload: dict[str, Any] = {}
    if code:
        payload["pairing_code"] = code
    if broker_url:
        payload["broker_url"] = broker_url
    if psk_hex:
        payload["psk_hex"] = psk_hex
    city = str(args.get("city", "")).strip()
    if city:
        payload["city"] = city

    v = args.get("br_day")
    if v is not None and _as_float(v) > 0:
        payload["br_day"] = _clamp8(_as_float(v), 10, 100)
    v = args.get("br_night")
    if v is not None and _as_float(v) > 0:
        payload["br_night"] = _clamp8(_as_float(v), 5, 100)
    v = args.get("vol")
    if v is not None and _as_float(v, -1) >= 0:
        payload["vol"] = _clamp8(_as_float(v), 0, 100)

    tm = str(args.get("theme_mode", "")).strip()
    if tm:
        tm = tm.lower()
        if tm not in ("day", "night", "auto"):
            return {}, "theme_mode must be one of: day, night, auto"
        payload["theme_mode"] = tm

    if "pet_enabled" in args:
        payload["pet_enabled"] = bool(args["pet_enabled"])

    has_claude = "provider_claude" in args
    has_codex = "provider_codex" in args
    has_anti = "provider_antigravity" in args
    has_gemini = "provider_gemini" in args
    if has_claude or has_codex or has_anti or has_gemini:
        # Emit the current "antigravity" wire key (PROVISION_WIRE §3). Every
        # firmware with a serial transport accepts it (the rename predates the
        # transport). Keys go in sorted order — the order Go's json.Marshal
        # gives a map — so all three runtimes put the same bytes on the wire.
        anti_key = "provider_antigravity" if has_anti else "provider_gemini"
        p = {
            "antigravity": bool(args.get(anti_key, False)),
            "claude": bool(args.get("provider_claude", False)),
            "codex": bool(args.get("provider_codex", False)),
        }
        payload["providers"] = p

    # WiFi pair: enforce togetherness. wifi_pass present without wifi_ssid, or
    # wifi_ssid present without wifi_pass, is an error — never a silent open net.
    has_ssid = "wifi_ssid" in args
    has_pass = "wifi_pass" in args
    if has_ssid != has_pass:
        return (
            {},
            "wifi_ssid and wifi_pass must be sent together (an open network needs "
            "wifi_pass set to an explicit empty string)",
        )
    if has_ssid:
        ssid = str(args.get("wifi_ssid", ""))
        wpass = str(args.get("wifi_pass", ""))
        # Length is in UTF-8 BYTES, not code points (PROVISION_WIRE §7): the
        # schema's maxLength counts characters, so a 32-CHARACTER SSID of
        # multibyte glyphs passes it and is then rejected by firmware as
        # BODY_BAD_WIFI after a whole lease + serial session was spent.
        if ssid == "" or len(ssid.encode("utf-8")) > 32:
            return {}, "wifi_ssid must be 1..32 bytes (UTF-8 bytes, not characters)"
        if len(wpass.encode("utf-8")) > 64:
            return {}, "wifi_pass must be at most 64 bytes (UTF-8 bytes, not characters)"
        payload["wifi_ssid"] = ssid
        payload["wifi_pass"] = wpass

    return payload, None


def _as_float(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def usb_registry_payload(payload: dict, psk_hex: str) -> ConfigPayload:
    """Lift the just-applied USB payload into the registry's config shape,
    matching _provision's lift."""
    reg = ConfigPayload(
        broker_url=payload.get("broker_url", ""),
        psk_hex=psk_hex,
        city=payload.get("city", ""),
    )
    if "br_day" in payload:
        reg.br_day = payload["br_day"]
    if "br_night" in payload:
        reg.br_night = payload["br_night"]
    if "vol" in payload:
        reg.vol = payload["vol"]
    if payload.get("theme_mode"):
        reg.theme_mode = payload["theme_mode"]
    if "pet_enabled" in payload:
        reg.pet_enabled = payload["pet_enabled"]
    if "providers" in payload:
        pv = payload["providers"]
        reg.provider_modes = ProviderModeSet(
            claude=provider_mode_from_bool(pv.get("claude", False)),
            codex=provider_mode_from_bool(pv.get("codex", False)),
            # The USB payload carries the "antigravity" wire key; the
            # registry's internal name for that provider is still gemini.
            gemini=provider_mode_from_bool(pv.get("antigravity", False)),
        )
    return reg


def usb_provision_error_report(err: Exception, psk_hex: str = "", psk_generated: bool = False) -> dict:
    """Map a session error to a structured tool result. The outcome-unknown case
    is called out explicitly so the model does NOT blindly re-run (which would
    risk a double-apply / a burned pairing attempt).

    psk_hex/psk_generated surface a freshly-minted PSK on the outcome-unknown
    path: the device MAY have committed it, but the registry was NOT updated (we
    don't know it applied), so without this the device could end up signing with
    a key nobody on the host has. A reused/existing PSK is already persisted, so
    it is not echoed."""
    rep: dict[str, Any] = {"ok": False, "error": str(err)}
    if isinstance(err, usbprov.OutcomeUnknown):
        rep["outcome_unknown"] = True
        if psk_generated:
            rep["psk_hex"] = psk_hex
            rep["note"] = enrol.NOTE_PSK_UNKNOWN
    elif isinstance(err, usbprov.DeviceMismatch):
        rep["device_mismatch"] = True
    return rep
