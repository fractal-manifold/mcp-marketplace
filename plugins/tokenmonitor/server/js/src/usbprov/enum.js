// Serial-port enumeration + iSerial normalisation (compat/PROVISION_WIRE.md §5).
// Linux is the reference/primary path (dev + rescue workflow); macOS and
// Windows enumeration are deferred and throw ErrEnumerateUnsupported rather
// than silently finding nothing. Mirrors go/internal/usbprov/enum*.go.

import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import process from "node:process";

export class EnumerateUnsupportedError extends Error {
  constructor() {
    super("usbprov: serial enumeration not implemented on this OS yet");
    this.name = "EnumerateUnsupportedError";
  }
}

// normalizeSerial lower-cases an iSerial and strips the separators different
// stacks insert into a MAC-derived serial (colons, dashes, underscores,
// spaces), so "84:F7:03:AB:CD:EF" and "84f703abcdef" compare equal. Other
// characters are left intact — a bridge's iSerial need not be hex.
export function normalizeSerial(s) {
  s = String(s ?? "").trim().toLowerCase();
  let out = "";
  for (const ch of s) {
    if (ch === ":" || ch === "-" || ch === "_" || ch === " ") continue;
    out += ch;
  }
  return out;
}

// deviceIDFromSerial derives the 8-hex device_id from a NORMALISED iSerial,
// mirroring the firmware: device_id = last 4 bytes of the MAC printed as
// "%02x%02x%02x%02x". Returns { id, ok }. ok=false when the normalised serial
// is not at least 8 trailing hex characters. The MATCH itself is still gated on
// the registry — a coincidental 8-hex tail is not identity.
export function deviceIDFromSerial(serialNorm) {
  if (!serialNorm || serialNorm.length < 8) return { id: "", ok: false };
  const tail = serialNorm.slice(serialNorm.length - 8);
  for (let i = 0; i < tail.length; i++) {
    const c = tail[i];
    const isHex = (c >= "0" && c <= "9") || (c >= "a" && c <= "f");
    if (!isHex) return { id: "", ok: false };
  }
  return { id: tail, ok: true };
}

// enumerate lists candidate serial ports with their USB VID/PID/iSerial. It
// only enumerates — classification, HELLO probing and registry-match are
// layered on top by the scan, never here. It must never open a port.
// Returns [{ path, vid, pid, serial, serialNorm }].
export function enumerate() {
  if (process.platform === "linux") return enumerateSysfs("/sys/class/tty", "/dev");
  // macOS/Windows enumeration deferred (matching the Go stubs), so a scan there
  // reports the unsupported error rather than silently finding nothing.
  throw new EnumerateUnsupportedError();
}

function readSysAttr(dir, attr) {
  return readFileSync(join(dir, attr), "utf8").trim();
}

// readUSBAttrs walks up from a sysfs device directory looking for the nearest
// ancestor that carries both idVendor and idProduct (the USB device node), and
// returns { vid, pid, serial, ok }. Walking up handles ttyACM (CDC,
// device→interface→usb-device) and ttyUSB (usb-serial) uniformly.
export function readUSBAttrs(startDir) {
  let dir = startDir;
  for (let i = 0; i < 8; i++) {
    let vidStr, pidStr;
    try {
      vidStr = readSysAttr(dir, "idVendor");
      pidStr = readSysAttr(dir, "idProduct");
    } catch {
      vidStr = pidStr = null;
    }
    if (vidStr != null && pidStr != null) {
      const v = parseInt(vidStr, 16);
      const p = parseInt(pidStr, 16);
      if (!Number.isInteger(v) || !Number.isInteger(p) || v < 0 || v > 0xffff || p < 0 || p > 0xffff) {
        return { vid: 0, pid: 0, serial: "", ok: false };
      }
      // Reject non-hex garbage that parseInt would silently truncate.
      if (!/^[0-9a-fA-F]+$/.test(vidStr) || !/^[0-9a-fA-F]+$/.test(pidStr)) {
        return { vid: 0, pid: 0, serial: "", ok: false };
      }
      let serial = "";
      try {
        serial = readSysAttr(dir, "serial");
      } catch {
        /* serial optional */
      }
      return { vid: v, pid: p, serial, ok: true };
    }
    const parent = dirname(dir);
    if (parent === dir || parent === "/" || parent === ".") break;
    dir = parent;
  }
  return { vid: 0, pid: 0, serial: "", ok: false };
}

// enumerateSysfs is the testable core: it lists ttys under sysClassTTY and, for
// the USB-backed ones (ttyACM*/ttyUSB*), resolves the sysfs device directory
// and reads USB attributes from it. devRoot is prefixed onto the tty name to
// form the port path (/dev in production).
export function enumerateSysfs(sysClassTTY, devRoot) {
  let entries;
  try {
    entries = readdirSync(sysClassTTY);
  } catch (e) {
    if (e && e.code === "ENOENT") return [];
    throw e;
  }
  const ports = [];
  for (const name of entries) {
    if (!name.startsWith("ttyACM") && !name.startsWith("ttyUSB")) continue;
    const devLink = join(sysClassTTY, name, "device");
    let real;
    try {
      real = realpathSync(devLink);
    } catch {
      continue; // no backing device dir → not a USB tty we can identify
    }
    const { vid, pid, serial, ok } = readUSBAttrs(real);
    if (!ok) continue; // e.g. a non-USB serial port; skip rather than guess
    ports.push({
      path: join(devRoot, name),
      vid,
      pid,
      serial,
      serialNorm: normalizeSerial(serial),
    });
  }
  return ports;
}
