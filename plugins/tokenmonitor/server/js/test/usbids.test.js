import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  deviceTable,
  classifyVIDPID,
  labelFor,
  TIER_PROBE,
  TIER_SHARED,
  TIER_REGISTRY_MATCH,
} from "../src/usbprov/usbids.js";

const here = dirname(fileURLToPath(import.meta.url));
function findCompat(rel) {
  let dir = here;
  for (let i = 0; i < 12; i++) {
    const c = join(dir, "compat", rel);
    if (existsSync(c)) return c;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

const fixPath = findCompat("usb-ids.json");
const skip = fixPath ? false : "compat/usb-ids.json unavailable (standalone checkout)";
const fixture = fixPath ? JSON.parse(readFileSync(fixPath, "utf8")) : { devices: [] };

// The hardcoded deviceTable must be byte-for-value identical to
// compat/usb-ids.json — same VID/PID (parsed), tier and label, same order and
// count. This is what makes "hardcoded, not loaded at runtime" honest.
test("hardcoded deviceTable matches usb-ids.json fixture", { skip }, () => {
  assert.equal(deviceTable.length, fixture.devices.length, "device count");
  for (let i = 0; i < fixture.devices.length; i++) {
    const fd = fixture.devices[i];
    const vid = parseInt(fd.vid, 16);
    const pid = parseInt(fd.pid, 16);
    assert.ok(Number.isInteger(vid) && vid >= 0 && vid <= 0xffff, `fixture[${i}] vid`);
    assert.ok(Number.isInteger(pid) && pid >= 0 && pid <= 0xffff, `fixture[${i}] pid`);
    const hc = deviceTable[i];
    assert.equal(hc.vid, vid, `entry ${i} vid`);
    assert.equal(hc.pid, pid, `entry ${i} pid`);
    assert.equal(hc.tier, fd.tier, `entry ${i} tier`);
    assert.equal(hc.label, fd.label, `entry ${i} label`);
  }
});

test("no duplicate (vid,pid) entries", () => {
  const seen = new Map();
  for (let i = 0; i < deviceTable.length; i++) {
    const e = deviceTable[i];
    const key = (e.vid << 16) | e.pid;
    assert.equal(seen.has(key), false, `duplicate at entry ${i}`);
    seen.set(key, i);
  }
});

test("every hardcoded tier is probe or shared (never registry-match)", () => {
  for (const e of deviceTable) {
    assert.ok(e.tier === TIER_PROBE || e.tier === TIER_SHARED, `${e.vid.toString(16)} tier ${e.tier}`);
    assert.notEqual(e.tier, TIER_REGISTRY_MATCH);
  }
});

test("classifyVIDPID", () => {
  assert.deepEqual(classifyVIDPID(0x303a, 0x1001), { tier: TIER_PROBE, found: true });
  assert.deepEqual(classifyVIDPID(0x1a86, 0x7523), { tier: TIER_SHARED, found: true });
  // Unknown degrades to the most restrictive tier and reports found=false.
  assert.deepEqual(classifyVIDPID(0xdead, 0xbeef), { tier: TIER_SHARED, found: false });
});

test("labelFor", () => {
  assert.equal(labelFor(0x303a, 0x1001), "Espressif USB-Serial/JTAG (ESP32-S3 / C3 / C6)");
  assert.equal(labelFor(0xdead, 0xbeef), "");
});
