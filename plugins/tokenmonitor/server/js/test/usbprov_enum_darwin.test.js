// macOS enumeration: the `ioreg -a` XML-plist parser + the IORegistry walk that
// inherits USB idVendor/idProduct/iSerial down to each /dev/cu.* callout node.
// Mirrors go enum_plist_test.go and py/tests/test_usb_scan.py::test_ioreg_*.
// Hardware-free: drives a captured-shape plist fixture, not a live ioreg.

import { test } from "node:test";
import assert from "node:assert/strict";

import { parsePlist, enumerateFromPlist } from "../src/usbprov/enum.js";

// A trimmed ioreg -a tree: one Espressif USB device whose VID/PID/serial live on
// the top node, with the IOCalloutDevice buried two children deep (device →
// interface → IOSerialBSDClient), exactly as macOS nests it. A sibling child
// with no callout must be ignored, and the serial carries an XML entity to
// exercise unescaping.
const FIXTURE = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>idVendor</key><integer>12346</integer>
    <key>idProduct</key><integer>4097</integer>
    <key>USB Serial Number</key><string>3C:0F:02:C4:77:7C</string>
    <key>IORegistryEntryName</key><string>ESP32-S3 &amp; JTAG</string>
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
</plist>`;

test("enumerateFromPlist inherits vid/pid/serial down to the callout", () => {
  const ports = enumerateFromPlist(parsePlist(FIXTURE));
  assert.deepEqual(ports, [
    {
      path: "/dev/cu.usbmodem1101",
      vid: 0x303a,
      pid: 0x1001,
      serial: "3C:0F:02:C4:77:7C",
      serialNorm: "3c0f02c4777c",
    },
  ]);
});

test("kUSBSerialNumberString wins over 'USB Serial Number'", () => {
  const xml = `<plist version="1.0"><array><dict>
    <key>idVendor</key><integer>1</integer>
    <key>idProduct</key><integer>2</integer>
    <key>kUSBSerialNumberString</key><string>AA:BB</string>
    <key>USB Serial Number</key><string>ZZ:ZZ</string>
    <key>IOCalloutDevice</key><string>/dev/cu.x</string>
  </dict></array></plist>`;
  const ports = enumerateFromPlist(parsePlist(xml));
  assert.equal(ports.length, 1);
  assert.equal(ports[0].serial, "AA:BB");
  assert.equal(ports[0].serialNorm, "aabb");
});

test("empty kUSBSerialNumberString falls back to 'USB Serial Number'", () => {
  // Regression: a `??` would keep the empty preferred value and drop the serial,
  // breaking registry-match. The fallback must trigger on empty, not just null.
  const xml = `<plist version="1.0"><array><dict>
    <key>idVendor</key><integer>1</integer>
    <key>idProduct</key><integer>2</integer>
    <key>kUSBSerialNumberString</key><string></string>
    <key>USB Serial Number</key><string>3C:0F:02:C4:77:7C</string>
    <key>IOCalloutDevice</key><string>/dev/cu.x</string>
  </dict></array></plist>`;
  const ports = enumerateFromPlist(parsePlist(xml));
  assert.equal(ports.length, 1);
  assert.equal(ports[0].serial, "3C:0F:02:C4:77:7C");
  assert.equal(ports[0].serialNorm, "3c0f02c4777c");
});

test("a callout with no ancestor VID/PID is skipped (not a USB serial device)", () => {
  const xml = `<plist version="1.0"><array><dict>
    <key>IOCalloutDevice</key><string>/dev/cu.Bluetooth</string>
  </dict></array></plist>`;
  assert.deepEqual(enumerateFromPlist(parsePlist(xml)), []);
});

test("out-of-range VID/PID is rejected", () => {
  const xml = `<plist version="1.0"><array><dict>
    <key>idVendor</key><integer>70000</integer>
    <key>idProduct</key><integer>1</integer>
    <key>IOCalloutDevice</key><string>/dev/cu.x</string>
  </dict></array></plist>`;
  assert.deepEqual(enumerateFromPlist(parsePlist(xml)), []);
});

test("empty / childless plist yields no ports", () => {
  assert.deepEqual(enumerateFromPlist(parsePlist(`<plist version="1.0"><array/></plist>`)), []);
});

test("duplicate callout paths de-duplicate (first wins)", () => {
  const xml = `<plist version="1.0"><array>
    <dict>
      <key>idVendor</key><integer>1</integer><key>idProduct</key><integer>2</integer>
      <key>IOCalloutDevice</key><string>/dev/cu.dup</string>
      <key>IORegistryEntryChildren</key><array><dict>
        <key>IOCalloutDevice</key><string>/dev/cu.dup</string>
      </dict></array>
    </dict>
  </array></plist>`;
  const ports = enumerateFromPlist(parsePlist(xml));
  assert.equal(ports.length, 1);
  assert.equal(ports[0].path, "/dev/cu.dup");
});
