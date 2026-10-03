"""Enrolment — the rule tokenmonitor_provision (LAN) and
tokenmonitor_usb_provision (cable) share for pairing a device with this broker:
which PSK is pushed, which broker address goes with it, and what the registry
records afterwards.

Port of tokenmonitor-mcp/internal/mcp/enrol.go; the strings are canonical
(compat/mcp-errors.md).
"""

from __future__ import annotations

import re
import secrets
import socket

from ..registry.store import ConfigPayload, NotFound

NOTE_NO_REGISTRY = (
    "no device registry is configured on this install, so no PSK was generated or "
    "pushed; pass psk_hex to pair the device"
)
NOTE_PSK_UNRECORDED = (
    "a fresh PSK was generated and is now live on the device, but the registry does "
    "NOT hold it; record psk_hex and register the device with "
    "tokenmonitor_register_device"
)
NOTE_PSK_MAYBE_LIVE = (
    "a fresh PSK was generated and may already be stored on the device (a failed "
    "write can leave a partial config); record psk_hex — the registry was NOT updated"
)
NOTE_PSK_UNKNOWN = (
    "a fresh PSK was generated and may already be live on the device; record it — the "
    "registry was NOT updated because the outcome is unknown. Do not blindly re-run."
)


# Refusals: the call stops before anything is written to the device.
ERR_DEVICE_HAS_PSK = (
    "the device already holds a PSK that this registry does not know — it may be "
    "paired with another broker, or an earlier enrolment here was never recorded. "
    "Nothing was written. Pass enroll=false to keep that pairing and change "
    "settings only, enroll=true to re-pair the device with this broker, or psk_hex "
    "if you have the key it holds"
)
ERR_ENROLL_CHOICE = (
    "this device is not in the registry and nothing says whether it is already "
    "paired with another broker. Nothing was written. Pass enroll=true to pair it "
    "with this broker (replacing any PSK it holds), or enroll=false to change "
    "settings only"
)
ERR_NO_SEED_LAN = (
    "could not work out an address of this broker that the device can reach, and "
    "firmware older than 1.0.0 cannot pair without one. Nothing was written. Pass "
    "broker_url (see tokenmonitor_provision_hint)"
)
# Takes the firmware version and the candidate count.
ERR_NO_SEED_USB_FMT = (
    "this device's firmware ({fw}) is older than 1.0.0 and cannot find the broker "
    "without an address, and this host has {n} candidate addresses. Nothing was "
    "written. Pass broker_url (see tokenmonitor_provision_hint), or enroll=false to "
    "change settings without pairing"
)


def join_notes(a: str, b: str) -> str:
    if not a:
        return b
    return f"{a}; {b}"


def enroll_arg(args: dict) -> tuple[bool, bool]:
    """Read the three-valued `enroll` argument: absent (decide from the
    evidence), true (pair here, whatever the device holds) or false (never).
    Returns (explicit, value)."""
    v = args.get("enroll")
    if v is None:
        return False, True
    return True, bool(v)


def explicit_psk(args: dict) -> tuple[str, str | None]:
    """Validate a caller-supplied psk_hex and the one combination that
    contradicts itself. Needs no device; runs before any port is opened.
    Returns (psk_hex, error_or_None)."""
    psk_hex = str(args.get("psk_hex") or "").strip().lower()
    if not psk_hex:
        return "", None
    explicit, enroll = enroll_arg(args)
    if explicit and not enroll:
        return "", "enroll=false cannot be combined with psk_hex"
    if len(psk_hex) != 64:
        return "", "psk_hex must be 64 hex chars"
    # Not bytes.fromhex(): that skips whitespace, so a 64-character string
    # with spaces in it would pass here and be refused by Go and JS.
    if re.fullmatch(r"[0-9a-f]{64}", psk_hex) is None:
        return "", "psk_hex is not valid hex"
    return psk_hex, None


def resolve_enrol_psk(
    deps, args: dict, device_id: str, has_psk: bool | None
) -> tuple[str, bool, bool, str | None]:
    """Decide which PSK, if any, a call pushes.

    - enroll=false: none. Settings only; PSK and registry untouched.
    - psk_hex: that key.
    - no registry on this install: none (see no_registry_note) — a minted key
      could not be kept and would orphan the device.
    - the registry already holds a PSK for device_id: REUSE it. Rotating the
      key on every reconfigure risks desyncing a device whose push silently
      fails, and re-sending the same key is harmless whatever state the device
      is in.
    - otherwise the device is unknown here, and a fresh key would replace
      whatever it holds. That is only done on evidence the caller means it:
      enroll=true; or the device itself reports it holds no PSK (has_psk=False,
      serial HELLO_RESP on firmware that sends it); or, when the device cannot
      say, a broker_url — which is how every caller asked for a pairing before
      the address stopped being configuration. With no such evidence the call
      is refused rather than re-keying a device that may be paired elsewhere.

    has_psk is None when the device did not say (the LAN transport, or firmware
    that predates the field): "unknown", never "fresh".

    Returns (psk_hex, generated, reused, error_or_None)."""
    explicit, enroll = enroll_arg(args)
    if not enroll:
        return "", False, False, None
    psk_hex = str(args.get("psk_hex") or "").strip().lower()
    if psk_hex:
        return psk_hex, False, False, None
    if deps.registry is None:
        return "", False, False, None
    existing = ""
    try:
        existing = deps.registry.load(device_id).active.payload.psk_hex or ""
    except NotFound:
        existing = ""  # new device
    except Exception as e:  # noqa: BLE001
        # Only "no such device" means a new one. A record that exists but
        # cannot be read (permissions, a torn or malformed file) must not be
        # answered by minting: that would re-key a paired device because of a
        # transient read failure.
        return "", False, False, f"registry load: {e}"
    if existing:
        return existing, False, True, None
    if not explicit:
        if has_psk is True:
            return "", False, False, ERR_DEVICE_HAS_PSK
        if has_psk is None and not str(args.get("broker_url") or "").strip():
            return "", False, False, ERR_ENROLL_CHOICE
    return secrets.token_hex(32), True, False, None


def no_registry_note(deps, args: dict, psk_hex: str) -> str:
    """Explain an enrolment that could not happen because this install has no
    registry to keep a PSK in."""
    if deps.registry is None and not psk_hex and enroll_arg(args)[1]:
        return NOTE_NO_REGISTRY
    return ""


_SEMVER_HEAD = re.compile(r"^(\d+)\.\d+\.\d+")


def fw_finds_broker_alone(fw: str) -> bool:
    """Whether firmware `fw` can leave BOOT_NEEDS_CONFIG on a PSK alone. That
    arrived in 1.0.0 (mDNS bootstrap); everything older needs a broker URL
    beside the key or it waits for setup forever. An empty or unparseable
    version counts as old — the safe reading."""
    m = _SEMVER_HEAD.match((fw or "").strip())
    if m is None:
        return False
    return int(m.group(1)) >= 1


def hint_urls(deps) -> list[str]:
    """The provision hint's candidate list: one URL per LAN interface."""
    from . import server  # lazy: server imports this module

    cfg = getattr(deps, "cfg", None)
    port = cfg.server.port if cfg is not None else 0
    if not port:
        return []
    return [f"http://{ip}:{port}" for ip in server._local_ipv4s()]


def seed_url_towards(deps, host: str, port: int) -> str:
    """The broker URL a device at host:port can demonstrably reach: this host's
    address on the route to it. A connected UDP socket is how the kernel is
    asked for that address — nothing is sent. "" when it cannot be told."""
    cfg = getattr(deps, "cfg", None)
    bport = cfg.server.port if cfg is not None else 0
    if not bport:
        return ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, port))
            ip = s.getsockname()[0]
        finally:
            s.close()
    except Exception:  # noqa: BLE001
        return ""
    if not ip or ip == "0.0.0.0":
        return ""
    return f"http://{ip}:{bport}"


def seed_url_from_hint(fw: str, candidates: list[str]) -> tuple[str, str | None]:
    """Pick the broker URL for a cable-attached device, whose route nobody can
    observe: the provision hint, but only when it is unambiguous. Returns
    (url, refusal_or_None)."""
    if len(candidates) == 1:
        return candidates[0], None
    return "", ERR_NO_SEED_USB_FMT.format(fw=fw or "unknown version", n=len(candidates))


def mirror_to_registry(
    deps, device_id: str, reg: ConfigPayload, converge: bool
) -> tuple[bool, bool, bool, str]:
    """Record a just-applied enrolment. A new device is registered; a known one
    is converged in place (replace_active).

    One case writes nothing: the device is already in the registry, the PSK
    pushed is the one the registry holds (whether it was reused or the caller
    passed that same key), and the caller gave no broker_url (converge=False; an
    auto-seeded address does not count — nobody asked for a converge). The
    record is correct as it stands, and replacing it would reset the config
    version to 1 under a live device still at version N — after which every
    pending the broker stages is numbered below what the device already has and
    is ignored. That is the headline "point it at my WiFi" call.

    Returns (registered, reregistered, enrolled, note)."""
    if not converge:
        try:
            if deps.registry.load(device_id).active.payload.psk_hex == reg.psk_hex:
                return False, False, True, ""
        except Exception:  # noqa: BLE001
            pass  # not there, or unreadable → let register() decide
    try:
        deps.registry.register(device_id, reg)
        return True, False, True, ""
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if "already exists" in msg:
            # Re-provision (device wiped + re-paired): converge the active
            # config in place — the device already applied it and proved
            # presence. Queueing a pending here left a stuck, undecryptable
            # update. Preserves metadata. See #8.
            try:
                deps.registry.replace_active(device_id, reg)
                return False, True, True, ""
            except Exception as e2:  # noqa: BLE001
                return False, False, False, f"device provisioned but registry re-register failed: {e2}"
        return False, False, False, f"device provisioned but registry write failed: {msg}"
