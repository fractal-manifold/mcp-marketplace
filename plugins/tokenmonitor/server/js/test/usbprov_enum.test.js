import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { normalizeSerial, deviceIDFromSerial, readUSBAttrs, enumerateSysfs } from "../src/usbprov/enum.js";

test("normalizeSerial", () => {
  const cases = {
    "84:F7:03:AB:CD:EF": "84f703abcdef",
    "84f703abcdef": "84f703abcdef",
    "84-F7-03-AB-CD-EF": "84f703abcdef",
    "  84F703ABCDEF  ": "84f703abcdef",
    AB_CD_EF: "abcdef",
    "": "",
  };
  for (const [inp, want] of Object.entries(cases)) {
    assert.equal(normalizeSerial(inp), want, inp);
  }
});

test("deviceIDFromSerial", () => {
  assert.deepEqual(deviceIDFromSerial("84f703abcdef"), { id: "03abcdef", ok: true });
  assert.deepEqual(deviceIDFromSerial("03abcdef"), { id: "03abcdef", ok: true });
  assert.equal(deviceIDFromSerial("abcd").ok, false);
  assert.equal(deviceIDFromSerial("cp2102nserialx").ok, false);
  // Expects an already-normalised (lowercase) serial; an uppercase tail is
  // treated as non-hex (defensive).
  assert.equal(deviceIDFromSerial("0123ABCD").ok, false);
});

function writeAttr(dir, name, val) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), val + "\n");
}

test("readUSBAttrs walks up to the USB device node", () => {
  const root = mkdtempSync(join(tmpdir(), "tmonenum-"));
  const usbDev = join(root, "usb1", "1-1");
  const iface = join(usbDev, "1-1:1.0", "tty", "ttyACM0");
  writeAttr(usbDev, "idVendor", "303a");
  writeAttr(usbDev, "idProduct", "1001");
  writeAttr(usbDev, "serial", "84F703ABCDEF");
  mkdirSync(iface, { recursive: true });
  const r = readUSBAttrs(iface);
  assert.equal(r.ok, true);
  assert.equal(r.vid, 0x303a);
  assert.equal(r.pid, 0x1001);
  assert.equal(r.serial, "84F703ABCDEF"); // raw
});

test("readUSBAttrs: non-USB serial is not-found", () => {
  const root = mkdtempSync(join(tmpdir(), "tmonenum-"));
  const dir = join(root, "platform-serial");
  mkdirSync(dir, { recursive: true });
  assert.equal(readUSBAttrs(dir).ok, false);
});

test("readUSBAttrs: serial optional", () => {
  const root = mkdtempSync(join(tmpdir(), "tmonenum-"));
  const dev = join(root, "3-2");
  writeAttr(dev, "idVendor", "0403");
  writeAttr(dev, "idProduct", "6001");
  const r = readUSBAttrs(dev);
  assert.equal(r.ok, true);
  assert.equal(r.vid, 0x0403);
  assert.equal(r.pid, 0x6001);
  assert.equal(r.serial, "");
});

test("enumerateSysfs against a fake tree: skips non-USB tty", () => {
  const root = mkdtempSync(join(tmpdir(), "tmonenum-"));
  const sysClassTTY = join(root, "sys", "class", "tty");
  mkdirSync(sysClassTTY, { recursive: true });

  const mkClassLink = (name, ifaceDir) => {
    mkdirSync(join(ifaceDir, "tty", name), { recursive: true });
    const classEntry = join(sysClassTTY, name);
    mkdirSync(classEntry, { recursive: true });
    symlinkSync(ifaceDir, join(classEntry, "device"));
  };

  // Espressif ttyACM0.
  const acmDev = join(root, "sys", "devices", "usb1", "1-1");
  const acmIface = join(acmDev, "1-1:1.0");
  writeAttr(acmDev, "idVendor", "303a");
  writeAttr(acmDev, "idProduct", "1001");
  writeAttr(acmDev, "serial", "84:F7:03:AB:CD:EF");
  mkdirSync(acmIface, { recursive: true });
  mkClassLink("ttyACM0", acmIface);

  // FTDI ttyUSB0.
  const usbDev = join(root, "sys", "devices", "usb2", "2-1");
  const usbIface = join(usbDev, "2-1:1.0");
  writeAttr(usbDev, "idVendor", "0403");
  writeAttr(usbDev, "idProduct", "6001");
  mkdirSync(usbIface, { recursive: true });
  mkClassLink("ttyUSB0", usbIface);

  // Non-USB serial that must be ignored.
  const platIface = join(root, "sys", "devices", "platform", "serial8250");
  mkdirSync(platIface, { recursive: true });
  mkClassLink("ttyS0", platIface);

  const ports = enumerateSysfs(sysClassTTY, "/dev");
  assert.equal(ports.length, 2, "ttyS0 must be skipped");
  const byPath = new Map(ports.map((p) => [p.path, p]));
  const acm = byPath.get("/dev/ttyACM0");
  assert.ok(acm);
  assert.equal(acm.vid, 0x303a);
  assert.equal(acm.pid, 0x1001);
  assert.equal(acm.serialNorm, "84f703abcdef");
  assert.ok(byPath.has("/dev/ttyUSB0"));
  assert.equal(byPath.has("/dev/ttyS0"), false);
});

test("enumerateSysfs: missing /sys/class/tty → empty", () => {
  assert.deepEqual(enumerateSysfs("/nonexistent/sys/class/tty", "/dev"), []);
});
