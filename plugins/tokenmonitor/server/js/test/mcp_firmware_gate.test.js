// The hand-staging tools must reach the same verdict the device will.
//
// set_device_pending, publish_firmware and revert_firmware are how an operator
// pushes a build at a specific unit, and until now they wrote whatever they
// were handed on the grounds that "the device-side gate is authoritative". It
// is — but its refusal is silent: the device clears the pending, logs nothing
// to the broker and reboots. So the operator's only feedback was a device that
// stubbornly kept running the old version. Reading a manifest's fields needs no
// key, so there was never a reason to stage blind.
//
// Mirror of Go internal/mcp/devices_gate_test.go and
// py/tests/test_mcp_firmware_gate.py.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { Registry } from "../src/registry/store.js";
import { dispatch } from "../src/mcp/server.js";

const DEV = "ab12cd34";
const SHA = "a".repeat(64);
// The broker holds no key and never verifies the signature, so any well-shaped
// placeholder stands in for one.
const FAKE_SIG = Buffer.alloc(64, "x").toString("base64");

function manifestB64(sku, version, minSV, { sha = SHA, channel = "" } = {}) {
  const head = channel ? `{"channel":"${channel}",` : "{";
  const canonical = head +
    `"key_id":"ed25519-test","min_secure_version":${minSV},` +
    `"sha256":"${sha}","size":2048,"sku":"${sku}","version":"${version}"}`;
  return Buffer.from(canonical, "utf8").toString("base64");
}

function mkDeps(t, { floor = 0, running = "", localAddr = "192.168.2.28:8765" } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "tmon-gate-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const reg = new Registry(dir);
  reg.register(DEV, { broker_url: "https://broker.example", psk_hex: "ab".repeat(32) });
  // A production (non-DEV) serial: the shape of every unit in the field.
  reg.setSerial(DEV, "CWM-S1-MAD-2620-000001-0", "S1");
  if (floor > 0) reg.recordMinSV(DEV, floor);
  if (running !== null) reg.setActiveFirmwareVersion(DEV, running);
  reg.touch(DEV, "192.168.2.44:9000", localAddr);
  return { registry: reg, cfg: { server: { port: 8765, bind: "0.0.0.0" } } };
}

const call = (deps, name, args) => dispatch(deps, name, args);

// The incident, reached through the operator's hands rather than the auto loop:
// the published 1.0.0 manifest declares packed(0.11.4) as its floor, and the
// unit in front of you already confirmed 1.0.0 before being flashed back down
// over USB (tmon_min_sv is monotonic and survives the flash).
test("set_device_pending refuses a manifest below the device floor", async (t) => {
  const deps = mkDeps(t, { floor: 16777216 }); // packed(1.0.0)
  const out = await call(deps, "tokenmonitor_set_device_pending", {
    device_id: DEV,
    firmware_url: "https://downloads.example/tmon-S1-1.0.0.bin",
    firmware_sha256: SHA,
    firmware_version: "1.0.0",
    firmware_manifest_b64: manifestB64("S1", "1.0.0", 720900),
    firmware_manifest_sig_b64: FAKE_SIG,
  });
  assert.match(out.error || "", /min-sv-below-floor/);
  for (const want of ["720900", "16777216", "min_secure_version"]) {
    assert.ok(out.error.includes(want), `must name ${want}: ${out.error}`);
  }
  assert.equal(deps.registry.load(DEV).pending, null);
});

test("set_device_pending stages the conformant manifest", async (t) => {
  const deps = mkDeps(t, { floor: 16777216 });
  const out = await call(deps, "tokenmonitor_set_device_pending", {
    device_id: DEV,
    firmware_url: "https://downloads.example/tmon-S1-1.0.1.bin",
    firmware_sha256: SHA,
    firmware_version: "1.0.1",
    firmware_manifest_b64: manifestB64("S1", "1.0.1", 16777217),
    firmware_manifest_sig_b64: FAKE_SIG,
  });
  assert.ok(out.ok, JSON.stringify(out));
  assert.equal(deps.registry.load(DEV).pending.payload.firmware_version, "1.0.1");
});

test("set_device_pending refuses a manifest for a different image", async (t) => {
  const deps = mkDeps(t);
  const out = await call(deps, "tokenmonitor_set_device_pending", {
    device_id: DEV,
    firmware_url: "https://downloads.example/tmon-S1-1.0.1.bin",
    firmware_sha256: "b".repeat(64),
    firmware_version: "1.0.1",
    firmware_manifest_b64: manifestB64("S1", "1.0.1", 16777217),
    firmware_manifest_sig_b64: FAKE_SIG,
  });
  assert.match(out.error || "", /sha-mismatch/);
});

test("set_device_pending refuses a manifest for another SKU", async (t) => {
  const deps = mkDeps(t);
  const out = await call(deps, "tokenmonitor_set_device_pending", {
    device_id: DEV,
    firmware_url: "https://downloads.example/tmon-S2-1.0.1.bin",
    firmware_sha256: SHA,
    firmware_version: "1.0.1",
    firmware_manifest_b64: manifestB64("S2", "1.0.1", 16777217),
    firmware_manifest_sig_b64: FAKE_SIG,
  });
  assert.match(out.error || "", /sku/);
});

test("set_device_pending refuses dev-channel firmware on a production unit", async (t) => {
  const deps = mkDeps(t);
  const out = await call(deps, "tokenmonitor_set_device_pending", {
    device_id: DEV,
    firmware_url: "https://downloads.example/tmon-S1-dev.bin",
    firmware_sha256: SHA,
    firmware_version: "1.0.1-dev.202609081200",
    firmware_manifest_b64: manifestB64("S1", "1.0.1-dev.202609081200", 16777217, { channel: "dev" }),
    firmware_manifest_sig_b64: FAKE_SIG,
  });
  assert.match(out.error || "", /dev-channel-on-production/);
});

// An unsigned stage carries nothing to predict from — CI does this against dev
// units built with TMON_OTA_UNSIGNED, and the gate must not stand in its way.
test("an unsigned stage is not judged", async (t) => {
  const deps = mkDeps(t, { floor: 16777216 });
  const out = await call(deps, "tokenmonitor_set_device_pending", {
    device_id: DEV,
    firmware_url: "https://downloads.example/tmon-S1-0.11.4.bin",
    firmware_sha256: SHA,
    firmware_version: "0.11.4",
  });
  assert.ok(out.ok, JSON.stringify(out));
});

// The firmware drops any pending whose URL is ≥256 chars before the gate ever
// runs (config_sync.c) — another silent failure worth naming here.
test("set_device_pending refuses an overlong URL", async (t) => {
  const deps = mkDeps(t);
  const out = await call(deps, "tokenmonitor_set_device_pending", {
    device_id: DEV,
    firmware_url: "https://downloads.example/" + "x".repeat(240) + ".bin",
    firmware_sha256: SHA,
    firmware_version: "1.0.1",
    firmware_manifest_b64: manifestB64("S1", "1.0.1", 16777217),
    firmware_manifest_sig_b64: FAKE_SIG,
  });
  assert.match(out.error || "", /256/);
});

// revert_firmware used to check an operator-typed target_min_secure_version and
// nothing else, which answered the wrong question: once the floor has risen,
// gate 4b (packed(version) < floor) refuses the older image no matter what its
// manifest declares. A revert past the floor is simply not possible over OTA.
test("revert_firmware refuses a downgrade below the floor", async (t) => {
  const deps = mkDeps(t, { floor: 16777216 });
  const out = await call(deps, "tokenmonitor_revert_firmware", {
    device_id: DEV,
    firmware_url: "https://downloads.example/tmon-S1-0.11.4.bin",
    firmware_sha256: SHA,
    firmware_version: "0.11.4",
    firmware_manifest_b64: manifestB64("S1", "0.11.4", 720900),
    firmware_manifest_sig_b64: FAKE_SIG,
  });
  assert.match(out.error || "", /min-sv-below-floor|version-below-floor/);
  assert.equal(deps.registry.load(DEV).blockedFirmwareVersion, "",
    "a refused revert must tombstone nothing");
});

test("revert_firmware allows a revert the floor permits", async (t) => {
  const deps = mkDeps(t, { floor: 720896 }); // packed(0.11.0)
  const out = await call(deps, "tokenmonitor_revert_firmware", {
    device_id: DEV,
    firmware_url: "https://downloads.example/tmon-S1-0.11.4.bin",
    firmware_sha256: SHA,
    firmware_version: "0.11.4",
    firmware_manifest_b64: manifestB64("S1", "0.11.4", 720900),
    firmware_manifest_sig_b64: FAKE_SIG,
  });
  assert.ok(out.ok, JSON.stringify(out));
  assert.equal(deps.registry.load(DEV).pending.payload.firmware_version, "0.11.4");
});

test("revert_firmware makes target_min_secure_version agree with the manifest", async (t) => {
  const deps = mkDeps(t, { floor: 720896 });
  const out = await call(deps, "tokenmonitor_revert_firmware", {
    device_id: DEV,
    firmware_url: "https://downloads.example/tmon-S1-0.11.4.bin",
    firmware_sha256: SHA,
    firmware_version: "0.11.4",
    firmware_manifest_b64: manifestB64("S1", "0.11.4", 720900),
    firmware_manifest_sig_b64: FAKE_SIG,
    target_min_secure_version: 720899,
  });
  assert.match(out.error || "", /720899/);
});

// --- Part B: the firmware_url origin ----------------------------------------

async function publish(t, deps, extra = {}) {
  const home = mkdtempSync(join(tmpdir(), "tmon-home-"));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const prevHome = process.env.HOME;
  process.env.HOME = home;
  t.after(() => { process.env.HOME = prevHome; });
  const bin = join(home, "tokenmonitor.bin");
  writeFileSync(bin, "not really a firmware image");
  return call(deps, "tokenmonitor_publish_firmware",
    { device_id: DEV, firmware_version: "1.0.1", bin_path: bin, ...extra });
}

// A unit older than 0.10.2 has no CONFIG_TMON_OTA_ALLOW_HTTP: it drops any
// http:// pending in config_sync.c without a word. Serving the .bin off the
// broker's own /firmware/ endpoint is exactly what the local path does, so this
// publish can only ever be silence — say so instead.
test("publish_firmware refuses plain http below 0.10.2", async (t) => {
  const deps = mkDeps(t, { running: "0.10.0" });
  const out = await publish(t, deps);
  assert.ok(out.error, JSON.stringify(out));
  assert.ok(out.error.includes("0.10.2") && out.error.includes("external_url"), out.error);
  assert.equal(deps.registry.load(DEV).pending, null);
});

// From 0.10.2 the same publish is fine — signed manifest and SHA are what
// establish trust, not TLS — and it goes out on the origin the device proved.
test("publish_firmware uses the origin the device dialled", async (t) => {
  const deps = mkDeps(t, { running: "0.10.2" });
  const out = await publish(t, deps);
  assert.ok(out.ok, JSON.stringify(out));
  assert.ok(out.firmware_url.startsWith("http://192.168.2.28:8765/firmware/"), out.firmware_url);
  assert.match(out.firmware_url_origin || "", /dialled/);
});

// A device that has never reported a version is not evidence of an old one:
// refusing here would block the first publish to a freshly registered unit.
test("an unknown running version is not treated as old", async (t) => {
  const deps = mkDeps(t, { running: "" });
  const out = await publish(t, deps);
  assert.ok(out.ok, JSON.stringify(out));
});
