"""Serial-port enumeration and iSerial helpers.

Port of tokenmonitor-mcp/internal/usbprov/enum.go + enum_linux.go + enum_darwin.go.
Linux is the reference path (sysfs, dependency-free); macOS is enumerated via
``ioreg`` (IORegistry → /dev/cu.* callout nodes); Windows still raises the
unsupported error rather than silently finding nothing.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
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
    if sys.platform == "darwin":
        return _enumerate_ioreg()
    # Windows enumeration is still deferred, matching the Go stub.
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


# --- macOS enumeration (ioreg) ---------------------------------------------
# macOS has no sysfs. The IORegistry is the source of truth: each USB serial
# device hangs an IOSerialBSDClient node exposing "IOCalloutDevice" (/dev/cu.*),
# while the USB idVendor/idProduct/iSerial live on an ANCESTOR IOUSBHostDevice
# node. We read the IOUSBHostDevice subtree as an XML plist (``ioreg -a``) and
# inherit vid/pid/serial down to each callout node — the same shape sysfs gives
# on Linux. Mirrors go/internal/usbprov/enum_darwin.go and the JS enum.js.


def _enumerate_ioreg() -> list[Port]:
    """List macOS USB serial ports via ``ioreg``. An empty tree yields []. A
    broken ioreg invocation (missing binary, timeout, non-zero exit, malformed
    plist) raises a plain RuntimeError — NOT EnumerateUnsupported, which the MCP
    handler would translate into the misleading "macOS is supported, only
    Windows is deferred" message and swallow the real diagnostic."""
    try:
        out = subprocess.run(
            ["ioreg", "-a", "-r", "-l", "-c", "IOUSBHostDevice"],
            capture_output=True,
            timeout=5,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"usbprov: ioreg failed: {e}") from e
    if not out or not out.strip():
        return []  # no IOUSBHostDevice present
    try:
        root = plistlib.loads(out)
    except Exception as e:  # noqa: BLE001 - malformed plist is a hard failure
        raise RuntimeError(f"usbprov: parse ioreg plist: {e}") from e
    return _enumerate_from_plist(root)


def _enumerate_from_plist(root) -> list[Port]:
    """Testable core: walk the IORegistry plist tree, inheriting the nearest
    ancestor's USB vid/pid/iSerial down to every node carrying an
    IOCalloutDevice, and emit one Port per callout (de-duplicated by path)."""
    ports: list[Port] = []
    seen: set[str] = set()

    def visit(node, vid, pid, serial):
        if not isinstance(node, dict):
            return
        v = node.get("idVendor")
        if isinstance(v, int):
            vid = v
        p = node.get("idProduct")
        if isinstance(p, int):
            pid = p
        s = node.get("kUSBSerialNumberString")
        if not isinstance(s, str) or not s:
            s = node.get("USB Serial Number")
        if isinstance(s, str) and s:
            serial = s
        callout = node.get("IOCalloutDevice")
        if (
            isinstance(callout, str)
            and callout
            and callout not in seen
            and isinstance(vid, int)
            and isinstance(pid, int)
            and 0 <= vid <= 0xFFFF
            and 0 <= pid <= 0xFFFF
        ):
            seen.add(callout)
            ports.append(
                Port(
                    path=callout,
                    vid=vid,
                    pid=pid,
                    serial=serial or "",
                    serial_norm=normalize_serial(serial or ""),
                )
            )
        kids = node.get("IORegistryEntryChildren")
        if isinstance(kids, list):
            for k in kids:
                visit(k, vid, pid, serial)

    roots = root if isinstance(root, list) else [root]
    for r in roots:
        visit(r, None, None, "")
    return ports
