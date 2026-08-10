// Serial-port enumeration + iSerial normalisation (compat/PROVISION_WIRE.md §5).
// Linux is the reference/primary path (dev + rescue workflow; sysfs). macOS is
// enumerated via `ioreg` (IORegistry → /dev/cu.* callout nodes); Windows
// enumeration is still deferred and throws EnumerateUnsupportedError rather than
// silently finding nothing. Mirrors go/internal/usbprov/enum*.go.

import { execFileSync } from "node:child_process";
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
  if (process.platform === "darwin") return enumerateIoreg();
  // Windows enumeration is still deferred (matching the Go stub), so a scan
  // there reports the unsupported error rather than silently finding nothing.
  throw new EnumerateUnsupportedError();
}

// --- macOS enumeration (ioreg) ---------------------------------------------
// macOS has no sysfs. The IORegistry is the source of truth: every USB serial
// device hangs an IOSerialBSDClient node exposing `IOCalloutDevice`
// (/dev/cu.*), while the USB idVendor/idProduct/iSerial live on an ANCESTOR
// IOUSBHostDevice node. We query the IOUSBHostDevice subtree as an XML plist
// (`ioreg -a`), then inherit vid/pid/serial down to each callout node — the
// same shape sysfs gives on Linux. Mirrors go/internal/usbprov/enum_darwin.go.

// enumerateIoreg runs ioreg and returns [{path,vid,pid,serial,serialNorm}]. An
// empty tree (no USB serial devices) yields []; only a genuinely broken ioreg
// invocation throws.
function enumerateIoreg() {
  let xml;
  try {
    xml = execFileSync("ioreg", ["-a", "-r", "-l", "-c", "IOUSBHostDevice"], {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      timeout: 5000,
    });
  } catch (e) {
    throw new Error(`usbprov: ioreg failed: ${e && e.message}`);
  }
  if (!xml || !xml.trim()) return []; // no IOUSBHostDevice present
  return enumerateFromPlist(parsePlist(xml));
}

// enumerateFromPlist is the testable core: it walks the IORegistry plist tree,
// inheriting the nearest ancestor's USB vid/pid/iSerial down to every node that
// carries an IOCalloutDevice, and emits one port per callout. Ports are
// de-duplicated by path (first wins). Exported for unit tests against a
// captured `ioreg -a` fixture.
export function enumerateFromPlist(root) {
  const ports = [];
  const seen = new Set();
  const visit = (node, vid, pid, serial) => {
    if (!node || typeof node !== "object") return;
    if (Number.isInteger(node.idVendor)) vid = node.idVendor;
    if (Number.isInteger(node.idProduct)) pid = node.idProduct;
    // Prefer kUSBSerialNumberString, but fall back when it is present-but-EMPTY
    // (a `??` would keep the empty string and lose a populated "USB Serial
    // Number"). Matches the Go/Python "&& s != ''" fallback.
    let s = node.kUSBSerialNumberString;
    if (typeof s !== "string" || !s) s = node["USB Serial Number"];
    if (typeof s === "string" && s) serial = s;
    const callout = node.IOCalloutDevice;
    if (
      typeof callout === "string" &&
      callout &&
      !seen.has(callout) &&
      Number.isInteger(vid) &&
      Number.isInteger(pid) &&
      vid >= 0 &&
      vid <= 0xffff &&
      pid >= 0 &&
      pid <= 0xffff
    ) {
      seen.add(callout);
      ports.push({
        path: callout,
        vid,
        pid,
        serial: serial || "",
        serialNorm: normalizeSerial(serial || ""),
      });
    }
    const kids = node.IORegistryEntryChildren;
    if (Array.isArray(kids)) for (const k of kids) visit(k, vid, pid, serial);
  };
  for (const r of Array.isArray(root) ? root : [root]) visit(r, undefined, undefined, undefined);
  return ports;
}

// parsePlist is a deliberately small recursive-descent parser for the XML
// plist `ioreg -a` emits (dict/array/key/string/integer/real/true/false/data/
// date only). It is NOT a general plist library — it throws on anything it does
// not recognise. Returns the decoded root value (dict→object, array→array).
export function parsePlist(xml) {
  let pos = 0;
  const n = xml.length;

  const skipWs = () => {
    while (pos < n) {
      const c = xml[pos];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") {
        pos++;
        continue;
      }
      if (xml.startsWith("<?", pos)) {
        const e = xml.indexOf("?>", pos);
        pos = e < 0 ? n : e + 2;
        continue;
      }
      if (xml.startsWith("<!--", pos)) {
        const e = xml.indexOf("-->", pos);
        pos = e < 0 ? n : e + 3;
        continue;
      }
      if (xml.startsWith("<!", pos)) {
        const e = xml.indexOf(">", pos);
        pos = e < 0 ? n : e + 1;
        continue;
      }
      break;
    }
  };

  const readTag = () => {
    if (xml[pos] !== "<") throw new Error(`plist: expected '<' at ${pos}`);
    const end = xml.indexOf(">", pos);
    if (end < 0) throw new Error("plist: unterminated tag");
    let raw = xml.slice(pos + 1, end);
    pos = end + 1;
    const selfClose = raw.endsWith("/");
    if (selfClose) raw = raw.slice(0, -1);
    return { name: raw.trim().split(/\s+/)[0], selfClose };
  };

  const readTextUntilClose = (tag) => {
    const close = `</${tag}>`;
    const end = xml.indexOf(close, pos);
    if (end < 0) throw new Error(`plist: unterminated <${tag}>`);
    const text = xml.slice(pos, end);
    pos = end + close.length;
    return unescapeXML(text);
  };

  const parseValue = () => {
    skipWs();
    const { name, selfClose } = readTag();
    switch (name) {
      case "true":
        if (!selfClose) readTextUntilClose("true");
        return true;
      case "false":
        if (!selfClose) readTextUntilClose("false");
        return false;
      case "string":
        return selfClose ? "" : readTextUntilClose("string");
      case "integer":
        return selfClose ? 0 : parseInt(readTextUntilClose("integer").trim(), 10);
      case "real":
        return selfClose ? 0 : parseFloat(readTextUntilClose("real").trim());
      case "data":
      case "date":
        return selfClose ? "" : readTextUntilClose(name);
      case "dict":
        return parseDict(selfClose);
      case "array":
        return parseArray(selfClose);
      default:
        throw new Error(`plist: unexpected <${name}>`);
    }
  };

  const parseDict = (selfClose) => {
    const obj = {};
    if (selfClose) return obj;
    for (;;) {
      skipWs();
      if (xml.startsWith("</dict>", pos)) {
        pos += "</dict>".length;
        return obj;
      }
      const tag = readTag();
      if (tag.name !== "key") throw new Error(`plist: expected <key>, got <${tag.name}>`);
      const key = tag.selfClose ? "" : readTextUntilClose("key");
      obj[key] = parseValue();
    }
  };

  const parseArray = (selfClose) => {
    const arr = [];
    if (selfClose) return arr;
    for (;;) {
      skipWs();
      if (xml.startsWith("</array>", pos)) {
        pos += "</array>".length;
        return arr;
      }
      arr.push(parseValue());
    }
  };

  skipWs();
  const first = readTag();
  if (first.name !== "plist") throw new Error(`plist: expected <plist>, got <${first.name}>`);
  if (first.selfClose) return null;
  return parseValue();
}

function unescapeXML(s) {
  if (s.indexOf("&") < 0) return s;
  return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);/g, (m, e) => {
    switch (e) {
      case "amp":
        return "&";
      case "lt":
        return "<";
      case "gt":
        return ">";
      case "quot":
        return '"';
      case "apos":
        return "'";
      default: {
        const code = e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return Number.isFinite(code) ? String.fromCodePoint(code) : m;
      }
    }
  });
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
