"""USB device-identity table (tiers).

HARDCODED here, not loaded from a data file at runtime, so no configuration
edit can widen the set of devices the tool is willing to write to.
compat/usb-ids.json exists purely as the specification and test fixture;
test_usb_ids.py asserts this hardcoded copy matches it byte-for-value. Port of
tokenmonitor-mcp/internal/usbprov/usbids.go.

See compat/PROVISION_WIRE.md §5.
"""

from __future__ import annotations

from dataclasses import dataclass

# Tier classifies how confidently a port is a TokenMonitor and therefore what
# the tool may do with it.
TIER_REGISTRY_MATCH = "registry-match"
TIER_PROBE = "probe"
TIER_SHARED = "shared"


@dataclass(frozen=True)
class USBID:
    """One hardcoded VID/PID → tier mapping."""

    vid: int
    pid: int
    tier: str
    label: str


# The authoritative hardcoded copy. Keep in sync with compat/usb-ids.json (the
# parity test enforces it). Only probe and shared entries live here;
# registry-match is resolved at runtime.
DEVICE_TABLE: list[USBID] = [
    USBID(0x303A, 0x1001, TIER_PROBE, "Espressif USB-Serial/JTAG (ESP32-S3 / C3 / C6)"),
    USBID(0x1A86, 0x7523, TIER_SHARED, "CH340 USB-UART bridge"),
    USBID(0x10C4, 0xEA60, TIER_SHARED, "CP210x USB-UART bridge"),
    USBID(0x0403, 0x6001, TIER_SHARED, "FTDI FT232 USB-UART bridge"),
]


def classify_vid_pid(vid: int, pid: int) -> tuple[str, bool]:
    """Return the base tier for a (vid, pid) and whether it was found in the
    hardcoded table. An unrecognised serial device degrades to the most
    restrictive tier (shared): never auto-selected, written to ONLY after the
    user names the port explicitly."""
    for e in DEVICE_TABLE:
        if e.vid == vid and e.pid == pid:
            return e.tier, True
    return TIER_SHARED, False


def label_for(vid: int, pid: int) -> str:
    """Return the human label for a (vid, pid), or "" if unknown."""
    for e in DEVICE_TABLE:
        if e.vid == vid and e.pid == pid:
            return e.label
    return ""
