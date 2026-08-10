"""macOS enumeration: the IORegistry walk that inherits USB
idVendor/idProduct/iSerial down to each /dev/cu.* callout node. Mirrors the JS
usbprov_enum_darwin.test.js and go enum_plist_test.go. Hardware-free: drives a
captured-shape plist (parsed by the same plistlib the runtime uses) rather than
a live ioreg.
"""

from __future__ import annotations

import plistlib

from tmon_mcp.usbprov.enum import _enumerate_from_plist

# One Espressif USB device whose VID/PID/serial live on the top node, with the
# IOCalloutDevice buried two children deep (device → interface →
# IOSerialBSDClient), plus a sibling child with no callout that must be ignored.
FIXTURE = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>idVendor</key><integer>12346</integer>
    <key>idProduct</key><integer>4097</integer>
    <key>USB Serial Number</key><string>3C:0F:02:C4:77:7C</string>
    <key>IORegistryEntryChildren</key>
    <array>
      <dict>
        <key>IORegistryEntryChildren</key>
        <array>
          <dict>
            <key>IOCalloutDevice</key><string>/dev/cu.usbmodem1101</string>
            <key>IODialinDevice</key><string>/dev/tty.usbmodem1101</string>
          </dict>
        </array>
      </dict>
      <dict>
        <key>IORegistryEntryName</key><string>some-other-interface</string>
      </dict>
    </array>
  </dict>
</array>
</plist>"""


def _walk(xml: bytes):
    return _enumerate_from_plist(plistlib.loads(xml))


def test_inherits_vid_pid_serial_down_to_callout():
    ports = _walk(FIXTURE)
    assert len(ports) == 1
    p = ports[0]
    assert p.path == "/dev/cu.usbmodem1101"  # callout, not dialin
    assert (p.vid, p.pid) == (0x303A, 0x1001)
    assert p.serial == "3C:0F:02:C4:77:7C"
    assert p.serial_norm == "3c0f02c4777c"


def test_kusb_serial_wins_over_usb_serial_number():
    xml = b"""<plist version="1.0"><array><dict>
        <key>idVendor</key><integer>1</integer>
        <key>idProduct</key><integer>2</integer>
        <key>kUSBSerialNumberString</key><string>AA:BB</string>
        <key>USB Serial Number</key><string>ZZ:ZZ</string>
        <key>IOCalloutDevice</key><string>/dev/cu.x</string>
    </dict></array></plist>"""
    ports = _walk(xml)
    assert len(ports) == 1
    assert ports[0].serial == "AA:BB"
    assert ports[0].serial_norm == "aabb"


def test_empty_kusb_serial_falls_back():
    xml = b"""<plist version="1.0"><array><dict>
        <key>idVendor</key><integer>1</integer>
        <key>idProduct</key><integer>2</integer>
        <key>kUSBSerialNumberString</key><string></string>
        <key>USB Serial Number</key><string>3C:0F:02:C4:77:7C</string>
        <key>IOCalloutDevice</key><string>/dev/cu.x</string>
    </dict></array></plist>"""
    ports = _walk(xml)
    assert len(ports) == 1
    assert ports[0].serial == "3C:0F:02:C4:77:7C"
    assert ports[0].serial_norm == "3c0f02c4777c"


def test_callout_without_ancestor_vid_pid_is_skipped():
    xml = b"""<plist version="1.0"><array><dict>
        <key>IOCalloutDevice</key><string>/dev/cu.Bluetooth</string>
    </dict></array></plist>"""
    assert _walk(xml) == []


def test_out_of_range_vid_pid_rejected():
    xml = b"""<plist version="1.0"><array><dict>
        <key>idVendor</key><integer>70000</integer>
        <key>idProduct</key><integer>1</integer>
        <key>IOCalloutDevice</key><string>/dev/cu.x</string>
    </dict></array></plist>"""
    assert _walk(xml) == []


def test_empty_plist_yields_no_ports():
    assert _walk(b"""<plist version="1.0"><array/></plist>""") == []


def test_duplicate_callout_paths_dedupe_first_wins():
    xml = b"""<plist version="1.0"><array><dict>
        <key>idVendor</key><integer>1</integer><key>idProduct</key><integer>2</integer>
        <key>IOCalloutDevice</key><string>/dev/cu.dup</string>
        <key>IORegistryEntryChildren</key><array><dict>
            <key>IOCalloutDevice</key><string>/dev/cu.dup</string>
        </dict></array>
    </dict></array></plist>"""
    ports = _walk(xml)
    assert len(ports) == 1
    assert ports[0].path == "/dev/cu.dup"
