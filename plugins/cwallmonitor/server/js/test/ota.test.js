import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { createServer } from "node:http";

import * as ota from "../src/ota.js";
import { load as loadConfig } from "../src/config.js";
import { Registry, _testing } from "../src/registry/store.js";

const here = dirname(fileURLToPath(import.meta.url));

// See crypto.test.js findCompat — walks up past the partial server/compat/
// runtime slice to the authoritative monorepo compat/.
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
const vectorsPath = findCompat("ed25519/vectors.json");
const skip = vectorsPath ? false : "compat/ed25519/vectors.json unavailable (standalone checkout)";
const VEC = vectorsPath ? JSON.parse(readFileSync(vectorsPath, "utf8")) : { manifests: [], test_keypair: {} };

const TEST_DEVICE = "ab12cd34";
const TEST_PSK = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee";

function s1Vector() {
  const m = VEC.manifests.find((x) => x.name.includes("S1"));
  assert.ok(m, "no S1 manifest vector");
  return { canonical: m.canonical_string, sigB64: m.signature_b64 };
}

function index(canonical, sigB64, { version = "0.5.1", binURL = "https://dl.example/cwm-S1-0.5.1.bin" } = {}) {
  return {
    version,
    manifest_b64: Buffer.from(canonical, "utf8").toString("base64"),
    signature_b64: sigB64,
    bin_url: binURL,
  };
}

// Start a mock GitHub releases server. SKUs absent from idxBySKU 404.
function mockReleases(idxBySKU) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const m = /^\/releases\/latest\/download\/update-(.+)\.json$/.exec(req.url);
      if (!m) { res.writeHead(404); res.end(); return; }
      const idx = idxBySKU[m[1]];
      if (!idx) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(idx));
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

function makeCfg(repoURL, { withKey = true } = {}) {
  const pubB64 = Buffer.from(VEC.test_keypair.pub_hex, "hex").toString("base64");
  const dir = mkdtempSync(join(tmpdir(), "cwm-otacfg-"));
  const p = join(dir, "cwm.toml");
  const keyBlock = withKey
    ? `\n[[ota.keys]]\nkey_id = "ed25519-2026-q2"\npubkey_b64 = "${pubB64}"\n`
    : "";
  writeFileSync(p, `[auth]
psk_passphrase = "test-pass-123"
[ota]
enabled = true
releases_repo = "${repoURL}"
poll_interval_minutes = 60
${keyBlock}`);
  return loadConfig(p);
}

function registryWithDevice(sku, minSV) {
  const dir = mkdtempSync(join(tmpdir(), "cwm-otareg-"));
  const reg = new Registry(dir);
  reg.register(TEST_DEVICE, { ..._testing.emptyPayload(), broker_url: "https://broker.example", psk_hex: TEST_PSK });
  reg.setSerial(TEST_DEVICE, "CWM-S1-DEV-2620-000001-0", sku);
  if (minSV > 0) reg.bumpMinSV(TEST_DEVICE, minSV);
  return reg;
}

test("packSemver", () => {
  assert.equal(ota.packSemver("0.0.0"), 0);
  assert.equal(ota.packSemver("0.5.1"), (5 << 16) | 1);
  assert.equal(ota.packSemver("1.2.3"), ((1 << 24) | (2 << 16) | 3) >>> 0);
  assert.equal(ota.packSemver("255.255.65535"), ((255 << 24) | (255 << 16) | 65535) >>> 0);
  for (const bad of ["", "1.2", "1.2.3.4", "1.2.x", "v1.2.3", "1..3", " 1.2.3",
                     "01.2.3", "1.02.3", "1.2.03", "256.0.0", "0.256.0", "0.0.65536"]) {
    assert.equal(ota.packSemver(bad), null, bad);
  }
});

test("verifyManifest against compat vectors", { skip }, () => {
  const pub = Buffer.from(VEC.test_keypair.pub_hex, "hex");
  for (const m of VEC.manifests) {
    assert.ok(m.signature_hex, `${m.name}: vector missing signature_hex`);
    const sig = Buffer.from(m.signature_hex, "hex");
    const body = Buffer.from(m.canonical_string, "utf8");
    assert.ok(ota.verifyManifest(pub, body, sig), m.name);
    // signature_b64 must decode to the same bytes.
    assert.deepEqual(Buffer.from(m.signature_b64, "base64"), sig, m.name);
    // Tampered manifest fails.
    const tampered = Buffer.from(body); tampered[0] ^= 0x01;
    assert.ok(!ota.verifyManifest(pub, tampered, sig), m.name);
    // Wrong key fails.
    const wrong = Buffer.from(pub); wrong[0] ^= 0x01;
    assert.ok(!ota.verifyManifest(wrong, body, sig), m.name);
  }
});

test("check stages update, dry-run previews, idempotent", { skip }, async () => {
  const { canonical, sigB64 } = s1Vector();
  const { server, url } = await mockReleases({ S1: index(canonical, sigB64) });
  try {
    const cfg = makeCfg(url);
    const reg = registryWithDevice("S1", 0);

    // Dry run: would_stage, nothing written.
    let rep = await ota.check(cfg, reg, { dryRun: true });
    assert.equal(rep.staged, 0);
    assert.equal(rep.devices.length, 1);
    assert.equal(rep.devices[0].action, "would_stage");
    assert.ok(rep.per_sku[0].verified);
    assert.equal(rep.per_sku[0].latest_version, "0.5.1");
    assert.equal(reg.load(TEST_DEVICE).pending, null);

    // Real run: stages with firmware fields.
    rep = await ota.check(cfg, reg, { dryRun: false });
    assert.equal(rep.staged, 1);
    assert.equal(rep.devices[0].action, "staged");
    const dev = reg.load(TEST_DEVICE);
    assert.ok(dev.pending);
    const p = dev.pending.payload;
    assert.equal(p.firmware_version, "0.5.1");
    assert.equal(p.firmware_url, "https://dl.example/cwm-S1-0.5.1.bin");
    assert.equal(p.firmware_sha256, "abc123");
    assert.equal(p.firmware_manifest_b64, index(canonical, sigB64).manifest_b64);
    assert.equal(p.firmware_manifest_sig_b64, sigB64);

    // Idempotence: pending already carries 0.5.1.
    rep = await ota.check(cfg, reg, { dryRun: false });
    assert.equal(rep.staged, 0);
    assert.equal(rep.devices[0].action, "skipped:already-pending");
  } finally {
    server.close();
  }
});

test("check up_to_date when device floor >= release", { skip }, async () => {
  const { canonical, sigB64 } = s1Vector();
  const { server, url } = await mockReleases({ S1: index(canonical, sigB64) });
  try {
    const cfg = makeCfg(url);
    const reg = registryWithDevice("S1", ota.packSemver("0.5.1"));
    const rep = await ota.check(cfg, reg, { dryRun: false });
    assert.equal(rep.staged, 0);
    assert.equal(rep.devices[0].action, "up_to_date");
  } finally {
    server.close();
  }
});

test("check rejects a tampered signature", { skip }, async () => {
  const { canonical, sigB64 } = s1Vector();
  const bad = (sigB64[0] === "A" ? "B" : "A") + sigB64.slice(1);
  const { server, url } = await mockReleases({ S1: index(canonical, bad) });
  try {
    const cfg = makeCfg(url);
    const reg = registryWithDevice("S1", 0);
    const rep = await ota.check(cfg, reg, { dryRun: false });
    assert.equal(rep.staged, 0);
    assert.ok(!rep.per_sku[0].verified);
    assert.ok(rep.per_sku[0].error);
    assert.equal(rep.devices[0].action, "skipped:no-release");
  } finally {
    server.close();
  }
});

test("check inert when unconfigured (no keys)", async () => {
  const cfg = makeCfg("https://github.com/x/y", { withKey: false });
  const reg = registryWithDevice("S1", 0);
  const rep = await ota.check(cfg, reg, { dryRun: false });
  assert.equal(rep.configured, false);
  assert.equal(rep.staged, 0);
  assert.ok(rep.note);
  assert.equal(rep.devices.length, 0);
});
