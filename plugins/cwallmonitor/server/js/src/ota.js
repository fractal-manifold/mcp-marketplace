// Broker-driven OTA update channel. Mirror of Go internal/ota/ota.go.
//
// A periodic check of a public GitHub releases repo that auto-stages a
// pending firmware update for matching registered devices.
//
// Flow per check:
//   1. Collect the distinct hardware SKUs of all registered devices.
//   2. For each SKU, GET <repo>/releases/latest/download/update-<SKU>.json.
//      GitHub 302-redirects this to the newest non-prerelease release's
//      asset; global fetch follows the redirect chain.
//   3. Decode the index's manifest_b64 + signature_b64 and verify the
//      Ed25519 signature against the configured keyring. Defense in depth —
//      the device verifies the same signature again before it installs.
//   4. For every device of that SKU whose installed version (mirrored in
//      active.min_secure_version as packed 8.8.16) is older than the
//      release, stage a pending carrying the firmware fields. The device
//      picks it up on its next /device/<id>/sync.
//
// The broker never holds a signing key — only public verification keys.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";

const DEFAULT_POLL_MINUTES = 60;
const MIN_POLL_MINUTES = 5;
const INITIAL_DELAY_MS = 30_000;
const HTTP_TIMEOUT_MS = 10_000;
const MAX_INDEX_BODY = 64 * 1024; // an update-<SKU>.json is well under 1 KiB

// 12-byte SPKI/DER prefix for an Ed25519 public key (RFC 8410). Prepended
// to the 32-byte raw key so node:crypto can ingest it — node has no direct
// "raw Ed25519 public key" import path.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// packSemver packs MAJOR.MINOR.PATCH into the 8.8.16 u32 layout the
// firmware uses for cwm_min_sv (major<<24 | minor<<16 | patch). Returns
// null on any malformed or out-of-range input. Mirrors Go PackSemver and
// packed_semver() in tools/cwmtools/lib/manifest.py.
export function packSemver(v) {
  const parts = String(v).split(".");
  if (parts.length !== 3) return null;
  const nums = [];
  for (const p of parts) {
    if (!p || !/^[0-9]+$/.test(p)) return null;
    // Reject leading zeros (except the literal "0").
    if (p.length > 1 && p[0] === "0") return null;
    nums.push(Number(p));
  }
  const [maj, min, pat] = nums;
  if (maj > 0xff || min > 0xff || pat > 0xffff) return null;
  // >>> 0 forces an unsigned 32-bit result (255<<24 overflows int32).
  return (((maj << 24) | (min << 16) | pat) >>> 0);
}

// verifyManifest reports whether sig is a valid Ed25519 signature over
// manifest bytes under pubkey (32-byte raw public key, 64-byte sig).
export function verifyManifest(pubkey, manifest, sig) {
  if (!pubkey || pubkey.length !== 32 || !sig || sig.length !== 64) return false;
  try {
    const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubkey)]);
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    return cryptoVerify(null, Buffer.from(manifest), key, Buffer.from(sig));
  } catch {
    return false;
  }
}

function nowISO() {
  return new Date().toISOString();
}

async function fetchIndex(cfg, sku) {
  const url = cfg.ota.releases_repo.replace(/\/+$/, "") +
    `/releases/latest/download/update-${sku}.json`;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), HTTP_TIMEOUT_MS);
  let resp;
  try {
    resp = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": "cwm-mcp-ota" },
      redirect: "follow",
      signal: ac.signal,
    });
  } catch (e) {
    throw new Error(`fetch ${url}: ${e.message}`);
  } finally {
    clearTimeout(timer);
  }
  if (!resp.ok) throw new Error(`fetch ${url}: HTTP ${resp.status}`);
  const text = (await resp.text()).slice(0, MAX_INDEX_BODY);
  let idx;
  try { idx = JSON.parse(text); }
  catch (e) { throw new Error(`decode ${url}: ${e.message}`); }
  if (!idx || typeof idx !== "object") throw new Error(`${url}: not a JSON object`);
  for (const k of ["version", "manifest_b64", "signature_b64", "bin_url"]) {
    if (!idx[k]) throw new Error(`${url} missing required field ${k}`);
  }
  return idx;
}

// resolveSKU verifies + parses a fetched index. Returns
// { resolved, skuResult }; resolved is null on any failure.
function resolveSKU(cfg, idx, sku) {
  const sres = { sku, latest_version: String(idx.version || ""), verified: false };
  let man;
  try { man = Buffer.from(String(idx.manifest_b64).trim(), "base64"); }
  catch { sres.error = "manifest_b64 decode failed"; return { resolved: null, skuResult: sres }; }
  if (!man.length) { sres.error = "manifest_b64 decode failed"; return { resolved: null, skuResult: sres }; }
  const sig = Buffer.from(String(idx.signature_b64).trim(), "base64");
  if (sig.length !== 64) { sres.error = "signature_b64 decode failed or wrong length"; return { resolved: null, skuResult: sres }; }
  let mf;
  try { mf = JSON.parse(man.toString("utf8")); }
  catch { sres.error = "manifest is not valid JSON"; return { resolved: null, skuResult: sres }; }
  const keyID = String(mf.key_id || "");
  const pub = cfg.otaPubkey(keyID);
  if (!pub) { sres.error = `no pubkey configured for key_id ${keyID}`; return { resolved: null, skuResult: sres }; }
  if (!verifyManifest(pub, man, sig)) { sres.error = "Ed25519 signature verify failed"; return { resolved: null, skuResult: sres }; }
  // Sanity: the manifest's SKU must match the index we asked for, and the
  // index version must match the manifest version (the index is untrusted
  // metadata; the manifest is the signed authority).
  if (String(mf.sku || "") !== sku) {
    sres.error = `manifest sku ${JSON.stringify(mf.sku)} != requested ${JSON.stringify(sku)}`;
    return { resolved: null, skuResult: sres };
  }
  if (String(idx.version) !== String(mf.version || "")) {
    sres.error = `index version ${JSON.stringify(idx.version)} != manifest version ${JSON.stringify(mf.version)}`;
    return { resolved: null, skuResult: sres };
  }
  if (!String(idx.bin_url).startsWith("https://")) { sres.error = "bin_url must be HTTPS"; return { resolved: null, skuResult: sres }; }
  if (packSemver(String(mf.version || "")) === null) { sres.error = "manifest version is not MAJOR.MINOR.PATCH"; return { resolved: null, skuResult: sres }; }
  sres.verified = true;
  return { resolved: { idx, mf }, skuResult: sres };
}

// decide computes the action for one device against a resolved release,
// staging a pending when appropriate (unless dryRun). Mirrors Go decide.
function decide(reg, dev, resolved, dryRun, logger) {
  const { idx, mf } = resolved;
  const out = { device_id: dev.deviceID, sku: dev.hwSku, to: String(mf.version || "") };
  const releasePacked = packSemver(String(mf.version || ""));
  if (releasePacked === null) { out.action = "skipped:bad-version"; return out; }
  out.from = dev.active.payload.firmware_version || "";
  if (releasePacked <= Number(dev.active.payload.min_secure_version || 0)) { out.action = "up_to_date"; return out; }
  if (dev.pending && dev.pending.payload.firmware_version === String(mf.version || "")) { out.action = "skipped:already-pending"; return out; }
  if (dryRun) { out.action = "would_stage"; return out; }
  const update = {
    firmware_url: String(idx.bin_url),
    firmware_sha256: String(mf.sha256 || ""),
    firmware_version: String(mf.version || ""),
    firmware_manifest_b64: String(idx.manifest_b64),
    firmware_manifest_sig_b64: String(idx.signature_b64),
  };
  try {
    reg.setPending(dev.deviceID, update);
  } catch (e) {
    out.action = "error:" + e.message;
    return out;
  }
  if (logger) logger.info(`ota: staged ${out.from} -> ${mf.version} for device ${dev.deviceID} (sku=${dev.hwSku})`);
  out.action = "staged";
  return out;
}

function dropEmpty(obj, keys) {
  for (const k of keys) {
    if (k in obj && !obj[k]) delete obj[k];
  }
  return obj;
}

// check runs one pass. dryRun=true reports without writing. skuFilter (if
// non-empty) restricts to one SKU; deviceFilter (if non-empty) restricts
// staging to one device id. Returns an object mirroring Go Report JSON.
export async function check(cfg, reg, { dryRun, skuFilter = "", deviceFilter = "", logger = null } = {}) {
  const o = cfg.ota;
  const rep = {
    repo: o.releases_repo,
    enabled: o.enabled,
    configured: cfg.otaConfigured(),
    dry_run: dryRun,
    checked_at: nowISO(),
    per_sku: [],
    devices: [],
    staged: 0,
  };
  if (!cfg.otaConfigured()) {
    rep.note = "ota auto-staging is not active: set [ota].enabled, releases_repo and at least one [[ota.keys]] in cwm.toml";
    return rep;
  }
  if (!reg) {
    rep.note = "device registry unavailable";
    return rep;
  }

  skuFilter = skuFilter.trim().toUpperCase();
  deviceFilter = deviceFilter.trim().toLowerCase();
  const wanted = [];
  const skuSet = new Set();
  for (const dev of reg.list()) {
    if (!dev.hwSku) continue;
    if (deviceFilter && dev.deviceID !== deviceFilter) continue;
    if (skuFilter && dev.hwSku !== skuFilter) continue;
    wanted.push(dev);
    skuSet.add(dev.hwSku);
  }

  const resolvedBySKU = new Map();
  for (const sku of Array.from(skuSet).sort()) {
    try {
      const idx = await fetchIndex(cfg, sku);
      const { resolved, skuResult } = resolveSKU(cfg, idx, sku);
      rep.per_sku.push(dropEmpty(skuResult, ["latest_version", "error"]));
      if (resolved) resolvedBySKU.set(sku, resolved);
    } catch (e) {
      rep.per_sku.push({ sku, verified: false, error: e.message });
    }
  }

  for (const dev of wanted) {
    const resolved = resolvedBySKU.get(dev.hwSku);
    if (!resolved) {
      rep.devices.push({ device_id: dev.deviceID, sku: dev.hwSku, action: "skipped:no-release" });
      continue;
    }
    const res = decide(reg, dev, resolved, dryRun, logger);
    if (res.action === "staged") rep.staged++;
    rep.devices.push(dropEmpty(res, ["from", "to"]));
  }
  return rep;
}

// sleep that resolves early when abortSignal fires. Returns true if aborted.
function interruptibleSleep(ms, abortSignal) {
  return new Promise((resolve) => {
    if (abortSignal && abortSignal.aborted) return resolve(true);
    const timer = setTimeout(() => {
      if (abortSignal) abortSignal.removeEventListener("abort", onAbort);
      resolve(false);
    }, ms);
    const onAbort = () => { clearTimeout(timer); resolve(true); };
    if (abortSignal) abortSignal.addEventListener("abort", onAbort, { once: true });
  });
}

// run is the background poll loop. Returns immediately (logging once) when
// OTA is not configured; otherwise checks every poll interval until
// abortSignal fires (the leader losing the bind). Mirror of Go ota.Run.
export async function run(cfg, reg, abortSignal, logger) {
  if (!cfg || !cfg.otaConfigured()) {
    if (logger) {
      logger.info(`ota: auto-staging inactive (enabled=${cfg ? cfg.ota.enabled : false} repo=${JSON.stringify(cfg ? cfg.ota.releases_repo : "")} keys=${cfg ? cfg.ota.keys.length : 0})`);
    }
    return;
  }
  if (!reg) {
    if (logger) logger.info("ota: registry unavailable, auto-staging disabled");
    return;
  }
  let minutes = cfg.ota.poll_interval_minutes;
  if (!(minutes > 0)) minutes = DEFAULT_POLL_MINUTES;
  if (minutes < MIN_POLL_MINUTES) minutes = MIN_POLL_MINUTES;
  const intervalMs = minutes * 60 * 1000;
  if (logger) logger.info(`ota: auto-staging active, repo=${cfg.ota.releases_repo} interval=${minutes}m`);

  if (await interruptibleSleep(INITIAL_DELAY_MS, abortSignal)) return;

  while (!(abortSignal && abortSignal.aborted)) {
    try {
      const rep = await check(cfg, reg, { dryRun: false, logger });
      if (logger) logger.info(`ota: check done, staged=${rep.staged} skus=${rep.per_sku.length} devices=${rep.devices.length}`);
    } catch (e) {
      if (logger) logger.warn(`ota: check failed: ${e.message}`);
    }
    if (await interruptibleSleep(intervalMs, abortSignal)) return;
  }
}
