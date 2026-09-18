// Parity tests for the broker's copy of the device manifest gate.
//
// These drive compat/ota/gate_manifest.json — the same rows
// firmware/test/host/test_ota_gate.c runs against the shipping
// tmon_ota_gate_decide(), go/internal/ota/gate_test.go against
// PredictDeviceGate and py/tests/test_ota_gate.py against
// predict_device_gate. Three implementations of one policy only stay honest if
// something checks them against the same table; without it the drift is
// invisible, because a device that refuses a manifest says nothing at all.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import { createPrivateKey, sign as cryptoSign } from "node:crypto";

import * as ota from "../src/ota.js";
import { GATE_OK, predictDeviceGate } from "../src/gate.js";
import { load as loadConfig } from "../src/config.js";
import { Registry, _testing } from "../src/registry/store.js";

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

const gatePath = findCompat("ota/gate_manifest.json");
const vecPath = findCompat("ed25519/vectors.json");
const skip = gatePath && vecPath ? false : "compat vectors unavailable (standalone checkout)";
const CASES = gatePath ? JSON.parse(readFileSync(gatePath, "utf8")).cases : [];
const VEC = vecPath ? JSON.parse(readFileSync(vecPath, "utf8")) : { test_keypair: {} };
const BROKER_CASES = CASES.filter((c) => !c.sides || c.sides.includes("broker"));

const TEST_DEVICE = "ab12cd34";
const TEST_PSK = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee";

test("the shared vector file carries broker rows", { skip }, () => {
  assert.ok(BROKER_CASES.length > 0, "no broker-side cases to run");
});

test("predictDeviceGate matches the shared vectors", { skip }, () => {
  for (const c of BROKER_CASES) {
    // The row's manifest is the byte-exact canonical form the signer emits; the
    // broker reads fields out of it exactly as it does from a real index, never
    // re-encoding.
    const mf = JSON.parse(c.manifest);
    const dev = { floor: c.device.floor, sku: c.device.sku, isDev: !!c.device.is_dev };
    const [verdict, why] = predictDeviceGate(mf, dev);
    const want = c.expect === "ok" ? "" : c.expect;
    assert.equal(verdict, want, `${c.name}: got ${verdict} (${why})`);
    if (verdict !== GATE_OK) {
      assert.ok(why.trim(), "a refusal must carry an explanation an operator can act on");
    }
  }
});

// --- decide()-level: the regression proper ----------------------------------

function signedManifest(sku, version, minSV, channel = "", sha = "a".repeat(64)) {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(VEC.test_keypair.seed_hex, "hex"),
  ]);
  const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const head = channel ? `{"channel":"${channel}",` : "{";
  const canonical = head +
    `"key_id":"ed25519-2026-q2","min_secure_version":${minSV},` +
    `"sha256":"${sha}","size":2048,"sku":"${sku}","version":"${version}"}`;
  return {
    version,
    manifest_b64: Buffer.from(canonical, "utf8").toString("base64"),
    signature_b64: cryptoSign(null, Buffer.from(canonical, "utf8"), key).toString("base64"),
    bin_url: `https://dl.example/tmon-${sku}-${version}.bin`,
  };
}

function mockReleases(idxBySKU) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const m = /^\/releases\/latest\/download\/update-(.+)\.json$/.exec(req.url);
      if (!m || !idxBySKU[m[1]]) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(idxBySKU[m[1]]));
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

function makeCfg(repoURL) {
  const pubB64 = Buffer.from(VEC.test_keypair.pub_hex, "hex").toString("base64");
  const p = join(mkdtempSync(join(tmpdir(), "tmon-gatecfg-")), "tokenmonitor.toml");
  writeFileSync(p, `[auth]
psk_passphrase = "test-pass-123"
[ota]
enabled = true
releases_repo = "${repoURL}"
poll_interval_minutes = 60

[[ota.keys]]
key_id = "ed25519-2026-q2"
pubkey_b64 = "${pubB64}"
`);
  return loadConfig(p);
}

function registryWithDevice(sku, minSV) {
  const reg = new Registry(mkdtempSync(join(tmpdir(), "tmon-gatereg-")));
  reg.register(TEST_DEVICE, { ..._testing.emptyPayload(), broker_url: "https://broker.example", psk_hex: TEST_PSK });
  reg.setSerial(TEST_DEVICE, "CWM-S1-MAD-2620-000001-0", sku);
  if (minSV > 0) reg.recordMinSV(TEST_DEVICE, minSV);
  return reg;
}

// A release the device WANTS (newer than its floor) whose manifest floor locks
// it out must be reported loudly and must not touch the install-loop streak.
// Before this, the broker staged it, the device refused it in silence, and five
// rounds later the release was tombstoned for that device — the shape the
// published 1.0.0 index put every unit at or past 0.12.0 into.
test("decide refuses a manifest whose floor is below the device's", { skip }, async () => {
  const idx = signedManifest("S1", "1.0.1", ota.packSemver("0.11.4"));
  const { server, url } = await mockReleases({ S1: idx });
  try {
    const cfg = makeCfg(url);
    // A unit that has confirmed 1.0.0 and was then re-flashed down over USB:
    // tmon_min_sv is monotonic and survives the flash.
    const reg = registryWithDevice("S1", ota.packSemver("1.0.0"));
    const streaks = new Map();
    // Staging five times in a row is what tombstones a version. Prove that a
    // manifest the device would refuse never gets that far, however often the
    // loop runs.
    for (let i = 0; i < 7; i++) {
      const rep = await ota.check(cfg, reg, { dryRun: false, stageStreaks: streaks });
      const got = rep.devices[0];
      assert.equal(got.action, "skipped:min-sv-below-floor", `round ${i}: ${JSON.stringify(got)}`);
      assert.match(got.reason || "", /min_secure_version/);
      assert.equal(rep.staged, 0);
    }
    const dev = reg.load(TEST_DEVICE);
    assert.equal(dev.blockedFirmwareVersion, "", "a publishing mistake must never tombstone the release");
    assert.equal(dev.pending, null);
  } finally {
    server.close();
  }
});

// The same release with the floor tmtools would have picked stages normally —
// same binary, same device, only the signed floor differs. This is the pair that
// makes the invariant concrete: lowering the floor subtracts devices and buys
// nothing.
test("decide stages the conformant manifest at the same floor", { skip }, async () => {
  const idx = signedManifest("S1", "1.0.1", ota.packSemver("1.0.1"));
  const { server, url } = await mockReleases({ S1: idx });
  try {
    const cfg = makeCfg(url);
    const reg = registryWithDevice("S1", ota.packSemver("1.0.0"));
    const rep = await ota.check(cfg, reg, { dryRun: false, stageStreaks: new Map() });
    assert.equal(rep.devices[0].action, "staged", JSON.stringify(rep.devices[0]));
  } finally {
    server.close();
  }
});
