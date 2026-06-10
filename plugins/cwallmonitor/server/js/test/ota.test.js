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
  // Production (non-DEV) serial keeps these staging tests single-channel
  // (stable). Dual-channel dev routing has its own test.
  reg.setSerial(TEST_DEVICE, "CWM-S1-MAD-2620-000001-0", sku);
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

test("check up_to_date when device floor is ABOVE release", { skip }, async () => {
  const { canonical, sigB64 } = s1Vector();
  const { server, url } = await mockReleases({ S1: index(canonical, sigB64) });
  try {
    const cfg = makeCfg(url);
    // Floor strictly above the 0.5.1 release → device would refuse it
    // (packed < floor), so the broker must not stage.
    const reg = registryWithDevice("S1", ota.packSemver("0.5.2"));
    const rep = await ota.check(cfg, reg, { dryRun: false });
    assert.equal(rep.staged, 0);
    assert.equal(rep.devices[0].action, "up_to_date");
  } finally {
    server.close();
  }
});

test("check skips the blocked (reverted) version", { skip }, async () => {
  // Revert tombstone: the AUTO-discovery loop must NOT re-stage the exact
  // version the device was reverted away from. Fresh device, tombstone == the
  // release version (0.5.1).
  const { canonical, sigB64 } = s1Vector();
  const { server, url } = await mockReleases({ S1: index(canonical, sigB64) });
  try {
    const cfg = makeCfg(url);
    const reg = registryWithDevice("S1", 0);
    reg.setBlockedFirmwareVersion(TEST_DEVICE, "0.5.1");
    const rep = await ota.check(cfg, reg, { dryRun: false });
    assert.equal(rep.staged, 0);
    assert.equal(rep.devices[0].action, "skipped:blocked-version");
    assert.equal(reg.load(TEST_DEVICE).pending, null);
  } finally {
    server.close();
  }
});

test("check stages a release NEWER than the blocked version", { skip }, async () => {
  // The tombstone matches on version equality only — a newer fixed release
  // over a blocked older one must still stage. Block 0.5.0, release is 0.5.1.
  const { canonical, sigB64 } = s1Vector();
  const { server, url } = await mockReleases({ S1: index(canonical, sigB64) });
  try {
    const cfg = makeCfg(url);
    const reg = registryWithDevice("S1", 0);
    reg.setBlockedFirmwareVersion(TEST_DEVICE, "0.5.0");
    const rep = await ota.check(cfg, reg, { dryRun: false });
    assert.equal(rep.staged, 1);
    assert.equal(rep.devices[0].action, "staged");
    assert.equal(reg.load(TEST_DEVICE).pending.payload.firmware_version, "0.5.1");
  } finally {
    server.close();
  }
});

test("check stages when release packed EQUALS the floor", { skip }, async () => {
  // The device refuses only packed < floor, so a release whose base == floor
  // is installable and must be staged (mirrors a newer same-base dev canary
  // after the floor matured). Fresh device, floor == release base.
  const { canonical, sigB64 } = s1Vector();
  const { server, url } = await mockReleases({ S1: index(canonical, sigB64) });
  try {
    const cfg = makeCfg(url);
    const reg = registryWithDevice("S1", ota.packSemver("0.5.1"));
    const rep = await ota.check(cfg, reg, { dryRun: true });
    assert.equal(rep.devices[0].action, "would_stage");
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

// --- shared cross-runtime version-ordering contract -------------------------
const orderPath = findCompat("ota/semver_order.json");
const ORDER = orderPath ? JSON.parse(readFileSync(orderPath, "utf8")) : null;

test("packSemver + compareSemver match the shared contract", { skip: orderPath ? false : "compat/ota/semver_order.json unavailable" }, () => {
  for (const c of ORDER.pack) {
    const got = ota.packSemver(c.version);
    if (c.ok) assert.equal(got, c.packed, `packSemver(${JSON.stringify(c.version)})`);
    else assert.equal(got, null, `packSemver(${JSON.stringify(c.version)}) should be null`);
  }
  for (const c of ORDER.compare) {
    assert.equal(ota.compareSemver(c.a, c.b), c.sign, `compareSemver(${c.a},${c.b})`);
  }
  for (const c of ORDER.compare_unparseable) {
    assert.equal(ota.compareSemver(c.a, c.b), null, `compareSemver(${c.a},${c.b}) should be null`);
  }
  for (const c of ORDER.valid) {
    assert.equal(ota.validVersion(c.version), c.valid, `validVersion(${JSON.stringify(c.version)})`);
  }
});

// A DEV-serial unit consumes BOTH stable and dev (candidateChannels). When
// only the stable channel has a release (dev asset 404s), it still stages
// stable. Exercises the per-device multi-channel gather + bestChannel pick.
test("dev unit considers both channels (stable wins when dev absent)", { skip }, async () => {
  const { canonical, sigB64 } = s1Vector();
  const { server, url } = await mockReleases({ S1: index(canonical, sigB64) });
  try {
    const cfg = makeCfg(url);
    const reg = registryWithDevice("S1", 0);
    reg.setSerial(TEST_DEVICE, "CWM-S1-DEV-2620-000001-0", "S1"); // flip to DEV

    const rep = await ota.check(cfg, reg, { dryRun: true });
    const stable = rep.per_sku.find(s => s.channel === "stable");
    const dev = rep.per_sku.find(s => s.channel === "dev");
    assert.ok(stable && stable.verified && stable.latest_version === "0.5.1", `stable per-sku: ${JSON.stringify(stable)}`);
    assert.ok(dev && !dev.verified && dev.error, `dev per-sku should have failed: ${JSON.stringify(dev)}`);
    assert.equal(rep.devices.length, 1);
    assert.equal(rep.devices[0].action, "would_stage");
    assert.equal(rep.devices[0].channel, "stable");
    assert.equal(rep.devices[0].to, "0.5.1");
  } finally {
    server.close();
  }
});

test("apiReleasesURL maps github.com to the API and passes through test hosts", () => {
  assert.equal(
    ota.apiReleasesURL("https://github.com/fractal-manifold/cwm-ota-releases"),
    "https://api.github.com/repos/fractal-manifold/cwm-ota-releases/releases?per_page=100");
  assert.equal(
    ota.apiReleasesURL("https://github.com/fractal-manifold/cwm-ota-releases/"),
    "https://api.github.com/repos/fractal-manifold/cwm-ota-releases/releases?per_page=100");
  assert.equal(ota.apiReleasesURL("http://127.0.0.1:5000"), "http://127.0.0.1:5000/releases?per_page=100");
});

test("pickDevAsset selects newest dev prerelease carrying the SKU asset", () => {
  const a = (sku) => ({ name: `update-${sku}.json`, browser_download_url: `u/${sku}` });
  const rels = [
    { tag_name: "v0.6.8-dev.202606022100", prerelease: true, assets: [a("S1")] },
    { tag_name: "v0.9.0-dev.202609090000", prerelease: true, draft: true, assets: [a("S1")] }, // draft → ignored
    { tag_name: "v0.7.0", prerelease: false, assets: [a("S1")] }, // not prerelease → ignored
    { tag_name: "v0.6.8-dev.202606021930", prerelease: true, assets: [a("S1"), a("S2")] },
    { tag_name: "v0.6.7", prerelease: true, assets: [a("S1")] }, // plain version → ignored
  ];
  assert.deepEqual(ota.pickDevAsset(rels, "S1"), { version: "0.6.8-dev.202606022100", tag: "v0.6.8-dev.202606022100" });
  assert.deepEqual(ota.pickDevAsset(rels, "S2"), { version: "0.6.8-dev.202606021930", tag: "v0.6.8-dev.202606021930" });
  assert.equal(ota.pickDevAsset(rels, "S9"), null);
  assert.equal(ota.pickDevAsset(null, "S1"), null);
});

const devSelPath = findCompat("ota/dev_release_select.json");
test("pickDevAsset matches the shared dev-select contract",
  { skip: devSelPath ? false : "compat/ota/dev_release_select.json unavailable" }, () => {
    const fx = JSON.parse(readFileSync(devSelPath, "utf8"));
    assert.ok(fx.cases.length > 0, "fixture carries no cases");
    for (const c of fx.cases) {
      for (const q of c.queries) {
        const got = ota.pickDevAsset(c.releases, q.sku);
        if (q.expect === null) assert.equal(got, null, `${c.name}/${q.sku}`);
        else assert.deepEqual(got, { version: q.expect.version, tag: q.expect.tag }, `${c.name}/${q.sku}`);
      }
    }
  });

function devVector(name) {
  const m = VEC.manifests.find((x) => x.name === name);
  assert.ok(m, `no manifest vector named ${name}`);
  return { canonical: m.canonical_string, sigB64: m.signature_b64 };
}

// Start a mock that serves the stable redirect AND the dev surface: the
// releases-list API at /releases plus each dev release's per-SKU asset at
// /releases/download/v<version>/update-<SKU>.json. devs: [{version, idx:{SKU}}].
function mockReleasesFull(stableBySKU, devs) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const host = req.headers.host;
      const json = (obj) => { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
      if (req.url === "/releases?per_page=100" || req.url === "/releases") {
        return json(devs.map((d) => ({
          tag_name: `v${d.version}`,
          prerelease: true,
          assets: Object.keys(d.idx).map((sku) => ({
            name: `update-${sku}.json`,
            browser_download_url: `http://${host}/releases/download/v${d.version}/update-${sku}.json`,
          })),
        })));
      }
      let m = /^\/releases\/download\/v(.+)\/update-(.+)\.json$/.exec(req.url);
      if (m) {
        const d = devs.find((x) => x.version === m[1]);
        const idx = d && d.idx[m[2]];
        if (!idx) { res.writeHead(404); res.end(); return; }
        return json(idx);
      }
      m = /^\/releases\/latest\/download\/update-(.+)\.json$/.exec(req.url);
      if (m) {
        const idx = stableBySKU[m[1]];
        if (!idx) { res.writeHead(404); res.end(); return; }
        return json(idx);
      }
      res.writeHead(404); res.end();
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

// Full dev path: a DEV unit, the API listing advertises an immutable
// vX.Y.Z-dev.<ts> prerelease, and the broker resolves + verifies its signed
// manifest and stages it on the dev channel.
test("dev unit stages an immutable dev prerelease via the API", { skip }, async () => {
  const DEV_VER = "0.6.8-dev.202606021930";
  const { canonical, sigB64 } = devVector(`ota-S1-dev-v${DEV_VER}`);
  const devIdx = index(canonical, sigB64, { version: DEV_VER, binURL: `https://dl.example/cwm-S1-${DEV_VER}.bin` });
  const { server, url } = await mockReleasesFull({}, [{ version: DEV_VER, idx: { S1: devIdx } }]);
  try {
    const cfg = makeCfg(url);
    // The dev manifest is signed under key_id "ed25519-dev" (same test key).
    cfg.ota.keys.push({ key_id: "ed25519-dev", pubkey_b64: cfg.ota.keys[0].pubkey_b64 });
    const reg = registryWithDevice("S1", 0);
    reg.setSerial(TEST_DEVICE, "CWM-S1-DEV-2620-000001-0", "S1"); // flip to DEV

    const rep = await ota.check(cfg, reg, { dryRun: true });
    const dev = rep.per_sku.find(s => s.channel === "dev");
    assert.ok(dev && dev.verified && dev.latest_version === DEV_VER, `dev per-sku: ${JSON.stringify(dev)}`);
    assert.equal(rep.devices.length, 1);
    assert.equal(rep.devices[0].action, "would_stage");
    assert.equal(rep.devices[0].channel, "dev");
    assert.equal(rep.devices[0].to, DEV_VER);
  } finally {
    server.close();
  }
});
