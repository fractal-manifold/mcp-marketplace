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
import secrets
import threading
from typing import Any

from .. import usbprov
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
    """Loopback URL of this host's broker, for the lease client. A 0.0.0.0/""
    bind is dialled as 127.0.0.1."""
    host = deps.cfg.server.bind
    if host in ("0.0.0.0", ""):
        host = "127.0.0.1"
    return f"http://{host}:{deps.cfg.server.port}"


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
            "error": "USB scan is not supported on this OS yet (Linux is the reference path; "
            "macOS/Windows enumeration is deferred). Use SoftAP + LAN provisioning instead."
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

    payload, psk_hex, psk_generated, psk_reused, err = build_usb_payload(deps, args, code, expect_id)
    if err is not None:
        return {"error": err}

    import json

    # Compact UTF-8, like Go's json.Marshal: no spaces (saves bytes against the
    # 1024-byte PAYLOAD_MAX budget) and no \uXXXX inflation of non-ASCII city
    # names (firmware cJSON decodes UTF-8 directly).
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    cancel = threading.Event()
    try:
        res = await asyncio.to_thread(_run_provision_blocking, deps, port, body, expect_id, cancel)
    except asyncio.CancelledError:
        # MCP request cancelled mid-session: signal the worker so run_provision
        # unwinds (post-PROVISION it lands on OUTCOME_UNKNOWN inside the thread —
        # NEVER auto-retried) and the lease/port are released, then propagate.
        cancel.set()
        raise
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
        return usb_provision_error_report(e)
    except Exception as e:  # noqa: BLE001
        return {"error": f"open serial port: {e}"}

    # The device applied and returned a RESULT. Its device_id is authoritative.
    device_id = res.device.device_id
    device_resp: Any = None
    try:
        parsed = json.loads(res.result_json)
        # Only surface an object, like Go's map[string]any unmarshal — a bare
        # array/string/number RESULT is dropped rather than echoed.
        device_resp = parsed if isinstance(parsed, dict) else None
    except (ValueError, UnicodeDecodeError):
        device_resp = None

    out: dict[str, Any] = {
        "ok": True,
        "device_id": device_id,
        "registered": False,
    }
    if res.device.sku:
        out["sku"] = res.device.sku
    if res.device.fw:
        out["fw"] = res.device.fw
    if psk_generated:
        out["psk_generated"] = True
    if psk_reused:
        out["psk_reused"] = True
    if device_resp is not None:
        out["device_response"] = device_resp

    # Mirror into the registry only when broker_url + psk were pushed and the
    # device_id is well-formed (a partial provision — e.g. only WiFi — leaves the
    # registry untouched).
    if deps.registry is not None and payload.get("broker_url") and psk_hex and valid_device_id(device_id):
        registered, reregistered, note = mirror_to_registry(deps, device_id, payload, psk_hex)
        out["registered"] = registered
        if reregistered:
            out["reregistered"] = True
        if note:
            out["note"] = note
    return out


def _run_provision_blocking(
    deps, port: str, body: bytes, expect_id: str, cancel: threading.Event
) -> usbprov.ProvisionResult:
    client = usbprov.LeaseClient(broker_base_url(deps), deps.cfg.psk())
    lp = client.open_leased(port, cancel)  # may raise LeaseBusy / PortBusy; cancel interrupts open
    stop_watch = _wire_lost(lp, cancel)
    try:
        return usbprov.run_provision(
            lp.handle.conn,
            usbprov.ProvisionOpts(provision_json=body, expect_device_id=expect_id),
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


def build_usb_payload(
    deps, args: dict, code: str, expect_id: str
) -> tuple[dict, str, bool, bool, str | None]:
    """Assemble the PROVISION JSON from the tool args, including the WiFi pair.
    Mirrors handleProvision's field handling plus PSK reuse/gen, and enforces the
    wifi_ssid⇄wifi_pass togetherness rule. Returns
    (payload, psk_hex, psk_generated, psk_reused, error_or_None)."""
    broker_url = str(args.get("broker_url", "")).strip()
    psk_hex = str(args.get("psk_hex", "")).strip().lower()
    psk_generated = False
    psk_reused = False
    if psk_hex:
        if len(psk_hex) != 64:
            return {}, "", False, False, "psk_hex must be 64 hex chars"
        try:
            bytes.fromhex(psk_hex)
        except ValueError:
            return {}, "", False, False, "psk_hex is not valid hex"
    elif broker_url and expect_id:
        # No PSK supplied but a broker is being (re)set: reuse the device's
        # existing registry PSK so the two never drift, else mint a fresh one.
        existing = ""
        if deps.registry is not None:
            try:
                dev = deps.registry.load(expect_id)
                existing = dev.active.payload.psk_hex or ""
            except Exception:  # noqa: BLE001
                existing = ""
        if existing:
            psk_hex, psk_reused = existing, True
        else:
            psk_hex, psk_generated = secrets.token_hex(32), True

    # A broker_url with no PSK to sign with is a dead config: it can only be
    # resolved when we know which device this is. Require device_id or psk_hex.
    if broker_url and not psk_hex:
        return (
            {},
            "",
            False,
            False,
            "setting broker_url over USB needs device_id (so the device's PSK can be "
            "reused/derived) or an explicit psk_hex",
        )

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
            return {}, "", False, False, "theme_mode must be one of: day, night, auto"
        payload["theme_mode"] = tm

    if "pet_enabled" in args:
        payload["pet_enabled"] = bool(args["pet_enabled"])

    has_claude = "provider_claude" in args
    has_codex = "provider_codex" in args
    has_anti = "provider_antigravity" in args
    has_gemini = "provider_gemini" in args
    if has_claude or has_codex or has_anti or has_gemini:
        p = {
            "claude": bool(args.get("provider_claude", False)),
            "codex": bool(args.get("provider_codex", False)),
        }
        if has_anti:
            p["gemini"] = bool(args.get("provider_antigravity", False))
        else:
            p["gemini"] = bool(args.get("provider_gemini", False))
        payload["providers"] = p

    # WiFi pair: enforce togetherness. wifi_pass present without wifi_ssid, or
    # wifi_ssid present without wifi_pass, is an error — never a silent open net.
    has_ssid = "wifi_ssid" in args
    has_pass = "wifi_pass" in args
    if has_ssid != has_pass:
        return (
            {},
            "",
            False,
            False,
            "wifi_ssid and wifi_pass must be sent together (an open network needs "
            "wifi_pass set to an explicit empty string)",
        )
    if has_ssid:
        ssid = str(args.get("wifi_ssid", ""))
        wpass = str(args.get("wifi_pass", ""))
        if ssid == "":
            return {}, "", False, False, "wifi_ssid must be 1..32 bytes"
        payload["wifi_ssid"] = ssid
        payload["wifi_pass"] = wpass

    return payload, psk_hex, psk_generated, psk_reused, None


def _as_float(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def mirror_to_registry(deps, device_id: str, payload: dict, psk_hex: str) -> tuple[bool, bool, str]:
    """Converge the local registry to the just-applied config, matching
    handleProvision's register→replace_active fallback. Returns
    (registered, reregistered, note)."""
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
            gemini=provider_mode_from_bool(pv.get("gemini", False)),
        )
    try:
        deps.registry.register(device_id, reg)
        return True, False, ""
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if "already exists" in msg:
            try:
                deps.registry.replace_active(device_id, reg)
                return False, True, ""
            except Exception as e2:  # noqa: BLE001
                return False, False, f"device provisioned but registry re-register failed: {e2}"
        return False, False, f"device provisioned but registry write failed: {msg}"


def usb_provision_error_report(err: Exception) -> dict:
    """Map a session error to a structured tool result. The outcome-unknown case
    is called out explicitly so the model does NOT blindly re-run (which would
    risk a double-apply / a burned pairing attempt)."""
    rep: dict[str, Any] = {"ok": False, "error": str(err)}
    if isinstance(err, usbprov.OutcomeUnknown):
        rep["outcome_unknown"] = True
    elif isinstance(err, usbprov.DeviceMismatch):
        rep["device_mismatch"] = True
    return rep
