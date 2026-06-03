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

import { effectiveChannel } from "./registry/store.js";

const DEFAULT_POLL_MINUTES = 60;
const MIN_POLL_MINUTES = 5;
const INITIAL_DELAY_MS = 30_000;
const HTTP_TIMEOUT_MS = 10_000;
const MAX_INDEX_BODY = 64 * 1024; // an update-<SKU>.json is well under 1 KiB

// 12-byte SPKI/DER prefix for an Ed25519 public key (RFC 8410). Prepended
// to the 32-byte raw key so node:crypto can ingest it — node has no direct
// "raw Ed25519 public key" import path.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// packSemver packs the MAJOR.MINOR.PATCH base into the 8.8.16 u32 layout the
// firmware uses for cwm_min_sv (major<<24 | minor<<16 | patch). An optional
// "-dev.<ts>" development prerelease suffix is ignored (the anti-rollback
// floor is base-level). Returns null on any malformed or out-of-range input.
// Mirrors Go PackSemver and packed_semver() in tools/cwmtools/lib/manifest.py.
export function packSemver(v) {
  const base = String(v).split("-", 1)[0];
  const parts = base.split(".");
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

// devPrerelease extracts the numeric timestamp from a "-dev.<12 digits>"
// development prerelease suffix (a YYYYMMDDhhmm value). Returns the timestamp
// (as a BigInt) when present and well-formed, or null when the string carries
// no such suffix OR it is malformed (not exactly 12 digits, trailing junk).
// The fixed 12-digit width keeps the value identical across the Go (uint64)
// and Python (int) brokers.
export function devPrerelease(v) {
  const m = /-dev\.([0-9]{12})$/.exec(String(v));
  return m ? BigInt(m[1]) : null;
}

// validVersion reports whether v is a well-formed firmware version:
// MAJOR.MINOR.PATCH (packable) with an OPTIONAL "-dev.<12 digits>" suffix and
// nothing else. The broker gates signed manifests on this so it never stages a
// version the firmware's stricter semver_ok() would refuse. Lock-step with Go
// ValidVersion and semver_ok() in cwm_manifest.c.
export function validVersion(v) {
  if (packSemver(v) === null) return false;
  const i = String(v).indexOf("-");
  if (i < 0) return true;
  return devPrerelease(String(v).slice(i)) !== null;
}

// compareSemver orders two version strings under the project's SemVer subset:
// the MAJOR.MINOR.PATCH base plus an optional "-dev.<ts>" development
// prerelease. Returns -1/0/1 (a<b / a==b / a>b), or null if either string
// isn't a parseable version. Ordering: a differing base wins; with equal bases
// a final build (no suffix) is NEWER than a prerelease, and two prereleases
// compare by their numeric <ts> (larger = newer) — the SemVer rule
// (X.Y.Z-pre < X.Y.Z). Wire-identical to the Go/Python brokers.
export function compareSemver(a, b) {
  const pa = packSemver(a);
  const pb = packSemver(b);
  if (pa === null || pb === null) return null;
  if (pa !== pb) return pa < pb ? -1 : 1;
  const ta = devPrerelease(a);
  const tb = devPrerelease(b);
  if (ta === null && tb === null) return 0;
  if (ta === null) return 1; // a final, b prerelease -> a newer
  if (tb === null) return -1; // a prerelease, b final -> a older
  if (ta < tb) return -1;
  if (ta > tb) return 1;
  return 0;
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

// fetchIndex GETs the per-SKU index for one (sku, channel). Stable rides
// GitHub's latest/download redirect (newest non-prerelease); dev rides the
// rolling prerelease tag, so a dev device never sees a stable build and a
// stable device never sees a prerelease.
async function fetchIndex(cfg, sku, channel = "stable") {
  const base = cfg.ota.releases_repo.replace(/\/+$/, "");
  const url = (channel && channel !== "stable")
    ? `${base}/releases/download/${cfg.ota.dev_tag || "dev"}/update-${sku}.json`
    : `${base}/releases/latest/download/update-${sku}.json`;
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
function resolveSKU(cfg, idx, sku, channel = "stable") {
  const want = (channel && channel !== "stable") ? channel : "stable";
  const sres = { sku, channel: want, latest_version: String(idx.version || ""), verified: false };
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
  // Channel must match what we asked for. Stable manifests OMIT the field
  // (absent == stable); dev manifests carry channel:"dev". This is a sanity
  // check on the signed authority — the device re-checks it too, and refuses
  // a dev manifest outright on a production unit.
  const manChan = mf.channel ? String(mf.channel) : "stable";
  if (manChan !== want) {
    sres.error = `manifest channel ${JSON.stringify(manChan)} != requested ${JSON.stringify(want)}`;
    return { resolved: null, skuResult: sres };
  }
  if (!String(idx.bin_url).startsWith("https://")) { sres.error = "bin_url must be HTTPS"; return { resolved: null, skuResult: sres }; }
  if (!validVersion(String(mf.version || ""))) { sres.error = "manifest version is not MAJOR.MINOR.PATCH[-dev.<12 digits>]"; return { resolved: null, skuResult: sres }; }
  sres.verified = true;
  return { resolved: { idx, mf }, skuResult: sres };
}

// decide computes the action for one device against a resolved release,
// staging a pending when appropriate (unless dryRun). Mirrors Go decide.
function decide(reg, dev, resolved, dryRun, logger) {
  const { idx, mf } = resolved;
  const out = { device_id: dev.deviceID, sku: dev.hwSku, channel: effectiveChannel(dev), to: String(mf.version || "") };
  const releasePacked = packSemver(String(mf.version || ""));
  if (releasePacked === null) { out.action = "skipped:bad-version"; return out; }
  out.from = dev.active.payload.firmware_version || "";
  // Release not strictly newer than the version the device is actually
  // RUNNING? Then it's up to date even if the anti-rollback floor hasn't
  // caught up yet. This matters during a dev unit's canary window (the
  // floor bump is deferred, so the min_secure_version comparison alone
  // would re-stage the running build every poll) and for USB-flashed
  // images whose floor lags the installed version. Uses compareSemver (not
  // raw packed base) so dev iteration works: two "0.6.8-dev.<ts>" builds share
  // a base, and the newer timestamp must still stage over the older. Mirrors
  // Go decide.
  const cmp = compareSemver(String(mf.version || ""), String(dev.active.payload.firmware_version || ""));
  if (cmp !== null && cmp <= 0) { out.action = "up_to_date"; return out; }
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
  // One release lookup per distinct (SKU, channel): a dev S1 device and a
  // stable S1 device pull different assets, so the SKU alone is not the key.
  const targets = new Map();
  for (const dev of reg.list()) {
    if (!dev.hwSku) continue;
    if (deviceFilter && dev.deviceID !== deviceFilter) continue;
    if (skuFilter && dev.hwSku !== skuFilter) continue;
    wanted.push(dev);
    const channel = effectiveChannel(dev);
    targets.set(`${dev.hwSku} ${channel}`, { sku: dev.hwSku, channel });
  }

  const resolvedByKey = new Map();
  for (const key of Array.from(targets.keys()).sort()) {
    const { sku, channel } = targets.get(key);
    try {
      const idx = await fetchIndex(cfg, sku, channel);
      const { resolved, skuResult } = resolveSKU(cfg, idx, sku, channel);
      rep.per_sku.push(dropEmpty(skuResult, ["latest_version", "error"]));
      if (resolved) resolvedByKey.set(key, resolved);
    } catch (e) {
      rep.per_sku.push({ sku, channel, verified: false, error: e.message });
    }
  }

  for (const dev of wanted) {
    const key = `${dev.hwSku} ${effectiveChannel(dev)}`;
    const resolved = resolvedByKey.get(key);
    if (!resolved) {
      rep.devices.push({ device_id: dev.deviceID, sku: dev.hwSku, channel: effectiveChannel(dev), action: "skipped:no-release" });
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
