"""Serial-port enumeration and iSerial helpers.

Port of tokenmonitor-mcp/internal/usbprov/enum.go + enum_linux.go. Linux is
the reference path (sysfs, dependency-free); macOS/Windows raise the
unsupported error like Go rather than silently finding nothing.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass


class EnumerateUnsupported(Exception):
    """Raised by enumerate() on an OS whose serial enumeration is not
    implemented (macOS/Windows are deferred, matching the Go stubs)."""


@dataclass
class Port:
    """One enumerated serial port with its USB identity. serial is the raw
    iSerial as the OS reported it; serial_norm is the normalised comparison
    form (see normalize_serial)."""

    path: str = ""
    vid: int = 0
    pid: int = 0
    serial: str = ""
    serial_norm: str = ""


def normalize_serial(s: str) -> str:
    """Lower-case an iSerial and strip the separators different stacks insert
    into a MAC-derived serial (colons, dashes, underscores, spaces), so
    "84:F7:03:AB:CD:EF" and "84f703abcdef" compare equal. Other characters are
    left intact — a bridge's iSerial need not be hex."""
    s = s.strip().lower()
    return "".join(c for c in s if c not in (":", "-", "_", " "))


def device_id_from_serial(serial_norm: str) -> tuple[str, bool]:
    """Derive the 8-hex device_id from a normalised iSerial, mirroring the
    firmware: device_id = last 4 bytes of the MAC as "%02x%02x%02x%02x". The
    USB iSerial on a factory-fused unit is the full 6-byte MAC, so the
    device_id is its last 8 hex characters.

    Returns ("", False) when the normalised serial is not at least 8 trailing
    hex characters. The MATCH itself is still gated on the registry; this only
    produces the candidate key to look up."""
    if len(serial_norm) < 8:
        return "", False
    tail = serial_norm[-8:]
    for c in tail:
        if not (("0" <= c <= "9") or ("a" <= c <= "f")):
            return "", False
    return tail, True


def enumerate() -> list[Port]:
    """List candidate serial ports with their USB VID/PID/iSerial. Only
    enumerates — classification, HELLO probing and registry-match resolution
    are layered on top by the scan, never here. Never opens a port."""
    if sys.platform.startswith("linux"):
        return _enumerate_sysfs("/sys/class/tty", "/dev")
    # macOS/Windows enumeration is deferred, matching the Go stubs.
    raise EnumerateUnsupported(
        "usbprov: serial enumeration not implemented on this OS yet"
    )


def _enumerate_sysfs(sys_class_tty: str, dev_root: str) -> list[Port]:
    """Testable core: list ttys under sys_class_tty and, for the USB-backed
    ones, resolve the sysfs device directory and read USB attributes."""
    try:
        names = os.listdir(sys_class_tty)
    except FileNotFoundError:
        return []
    ports: list[Port] = []
    for name in sorted(names):
        if not (name.startswith("ttyACM") or name.startswith("ttyUSB")):
            continue
        dev_link = os.path.join(sys_class_tty, name, "device")
        try:
            real = os.path.realpath(dev_link)
            if not os.path.exists(real):
                continue
        except OSError:
            continue
        got = _read_usb_attrs(real)
        if got is None:
            continue
        vid, pid, serial = got
        ports.append(
            Port(
                path=os.path.join(dev_root, name),
                vid=vid,
                pid=pid,
                serial=serial,
                serial_norm=normalize_serial(serial),
            )
        )
    return ports


def _read_usb_attrs(start_dir: str) -> tuple[int, int, str] | None:
    """Walk up from a sysfs device directory looking for the nearest ancestor
    carrying both idVendor and idProduct (the USB device node); return the
    parsed VID/PID plus the serial (empty if none)."""
    d = start_dir
    for _ in range(8):  # bounded climb; USB nesting is shallow
        vid_str = _read_attr(d, "idVendor")
        pid_str = _read_attr(d, "idProduct")
        if vid_str is not None and pid_str is not None:
            try:
                vid = int(vid_str, 16)
                pid = int(pid_str, 16)
            except ValueError:
                return None
            if vid < 0 or vid > 0xFFFF or pid < 0 or pid > 0xFFFF:
                return None
            serial = _read_attr(d, "serial") or ""
            return vid, pid, serial
        parent = os.path.dirname(d)
        if parent == d or parent in ("/", "."):
            break
        d = parent
    return None


def _read_attr(d: str, attr: str) -> str | None:
    try:
        with open(os.path.join(d, attr), "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return None
