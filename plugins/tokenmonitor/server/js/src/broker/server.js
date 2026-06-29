// HTTP broker: /credentials, /credentials/codex, /device/<id>/sync,
// /firmware-logs, /usage/{claude,codex,gemini}.
// Wire-compatible with tokenmonitor-mcp/internal/broker/server.go.

import * as auth from "../auth.js";
import * as creds from "../creds.js";
import * as usage from "../usage.js";
import * as spend from "../spend.js";
import * as devlog from "../devlog.js";
import { encryptPending, encryptPendingGCM, gcmFwGate } from "../registry/crypto.js";
import { NotFound, validDeviceID } from "../registry/store.js";
import { firmwarePath } from "../config.js";
import { packSemver } from "../ota.js";
import { createHash } from "node:crypto";
import { createReadStream, statSync } from "node:fs";
import { resolve as resolvePath, sep as pathSep } from "node:path";

function writeJSON(res, status, body) {
  const buf = Buffer.from(JSON.stringify(body), "utf8");
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Length", buf.length);
  res.setHeader("Cache-Control", "no-store");
  res.end(buf);
}
function writeError(res, status, msg) { writeJSON(res, status, { error: msg }); }

function parseUint32(s) {
  if (!s) return 0;
  const n = Number.parseInt(s, 10);
  return Number.isFinite(n) && n >= 0 && n <= 0xffffffff ? n : 0;
}

// Auth header names whose values feed (or gate) the HMAC. Per
// compat/HMAC_CANONICAL.md these are ASCII-only; a non-ASCII byte in any of
// them is rejected with 401 BEFORE the HMAC is computed. Node's http parser
// hands header values back latin-1-decoded, so a raw 0xc3 0xa9 ("é") arrives
// as the two chars U+00C3 U+00A9 — both > 0x7f, which this catches.
const AUTH_HEADER_NAMES = [
  "x-tmon-timestamp", "x-tmon-nonce", "x-tmon-signature",
  "x-tmon-device", "x-tmon-config-version",
];
function authHeadersAreASCII(req) {
  for (const name of AUTH_HEADER_NAMES) {
    const v = req.headers[name];
    if (v == null) continue;
    // Duplicate X-Tmon-* headers would arrive as an array; reject the lot.
    const vals = Array.isArray(v) ? v : [v];
    for (const s of vals) {
      for (let i = 0; i < s.length; i++) {
        if (s.charCodeAt(i) > 0x7f) return false;
      }
    }
  }
  return true;
}

export function createHandler({ cfg, cache, state, fwLogs, registry, logger, usageCache, spendCache }) {
  return (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    // Sign and route off the PERCENT-DECODED path, matching Go's
    // net/http r.URL.Path and aiohttp's req.path (both decoded). So
    // /usage/cla%75de and /usage/claude produce an identical canonical input
    // and route to the same handler. A malformed %-escape can't be decoded →
    // 400 (we never sign the raw encoded form as a fallback).
    let path;
    try {
      path = decodeURIComponent(url.pathname);
    } catch {
      return writeError(res, 400, "bad path encoding");
    }
    // Auth headers are ASCII-only — reject non-ASCII before any HMAC work.
    if (!authHeadersAreASCII(req)) {
      logger.info(`auth rejected ${path}: non-ascii auth header`);
      return writeError(res, 401, "unauthorized");
    }
    if (path === "/credentials" && req.method === "GET") return handleCredentials({ cfg, cache, state, registry, logger }, req, res);
    if (path === "/credentials/codex" && req.method === "GET") return handleCredentialsCodex({ cfg, cache, state, registry, logger }, req, res);
    if (path === "/firmware-logs" && req.method === "GET") return handleFirmwareLogs({ cfg, cache, fwLogs, logger }, req, res, url);
    const usageMatch = path.match(/^\/usage\/([^/]+)$/);
    if (usageMatch && req.method === "GET") {
      return handleUsage({ cfg, cache, state, registry, logger, usageCache, provider: usageMatch[1] }, req, res);
    }
    const spendMatch = path.match(/^\/spend\/([^/]+)$/);
    if (spendMatch && req.method === "GET") {
      return handleSpend({ cfg, cache, state, registry, logger, spendCache, provider: spendMatch[1] }, req, res);
    }
    const m = path.match(/^\/device\/([^/]+)\/sync$/);
    if (m && req.method === "GET") return handleDeviceSync({ cfg, cache, state, registry, logger, deviceID: m[1] }, req, res);
    const lm = path.match(/^\/device\/([^/]+)\/logs$/);
    if (lm && req.method === "POST") return handleDeviceLogs({ cfg, cache, state, registry, logger, deviceID: lm[1] }, req, res);
    const sm = path.match(/^\/device\/([^/]+)\/settings$/);
    if (sm && req.method === "POST") return handleDeviceSettings({ cfg, cache, state, registry, logger, deviceID: sm[1] }, req, res);
    const fwm = path.match(/^\/firmware\/([^/]+)$/);
    if (fwm && (req.method === "GET" || req.method === "HEAD")) {
      return handleFirmware({ cfg, cache, registry, logger, name: fwm[1] }, req, res);
    }
    writeError(res, 404, "not found");
  };
}

const firmwareSHACache = new Map();
function firmwareSHA(filePath, st) {
  const key = filePath;
  const cached = firmwareSHACache.get(key);
  if (cached && cached.mtimeMs === st.mtimeMs && cached.size === st.size) {
    return Promise.resolve(cached.hex);
  }
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    const rs = createReadStream(filePath);
    rs.on("data", (c) => h.update(c));
    rs.on("end", () => {
      const hex = h.digest("hex");
      firmwareSHACache.set(key, { mtimeMs: st.mtimeMs, size: st.size, hex });
      resolve(hex);
    });
    rs.on("error", reject);
  });
}

// Serve OTA binaries from firmwarePath() under HMAC. Mirrors the Go and
// Python handlers byte-for-byte (same auth, same headers); supports
// Range: requests so the device can resume after a transient drop.
async function handleFirmware({ cfg, cache, registry, logger, name }, req, res) {
  if (!name || name.includes("/") || name.includes("\\")) {
    return writeError(res, 400, "invalid filename");
  }
  const base = resolvePath(firmwarePath());
  const full = resolvePath(base, name);
  if (full !== base && !full.startsWith(base + pathSep)) {
    return writeError(res, 400, "invalid path");
  }

  const signedPath = `/firmware/${name}`;
  const psks = [cfg.psk()];
  const devID = req.headers["x-tmon-device"];
  if (registry && validDeviceID(devID)) {
    try {
      const { active, pending } = registry.psksFor(devID);
      if (active) psks.push(active);
      if (pending) psks.push(pending);
    } catch (e) {
      if (!(e instanceof NotFound)) logger.warn(`registry lookup ${devID}: ${e.message}`);
    }
  }
  try {
    auth.verifyMulti(
      psks,
      "GET", signedPath,
      req.headers["x-tmon-timestamp"] || "",
      req.headers["x-tmon-nonce"] || "",
      req.headers["x-tmon-signature"] || "",
      req.headers["x-tmon-device"] || "",
      req.headers["x-tmon-config-version"] || "",
      cache,
      cfg.security.max_timestamp_skew_seconds,
    );
  } catch (e) {
    logger.info(`auth rejected /firmware/${name}: ${e.message}`);
    return writeError(res, 401, "unauthorized");
  }

  let st;
  try { st = statSync(full); } catch { return writeError(res, 404, "firmware not found"); }
  if (!st.isFile()) return writeError(res, 404, "firmware not found");

  let sha;
  try { sha = await firmwareSHA(full, st); } catch { /* best-effort */ }
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Accept-Ranges", "bytes");
  if (sha) {
    res.setHeader("ETag", `"${sha}"`);
    res.setHeader("X-Tmon-Firmware-SHA256", sha);
  }

  // Minimal Range: bytes=START-[END] support. Anything else falls back
  // to a full response. The device's resume path only ever asks for a
  // single open-ended suffix, so the simple case is enough.
  const range = req.headers.range;
  let start = 0, end = st.size - 1, status = 200;
  if (range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(range);
    if (m) {
      const s = m[1] ? Number.parseInt(m[1], 10) : NaN;
      const e = m[2] ? Number.parseInt(m[2], 10) : st.size - 1;
      if (!Number.isNaN(s) && s < st.size) {
        start = s;
        end = Math.min(e, st.size - 1);
        status = 206;
        res.setHeader("Content-Range", `bytes ${start}-${end}/${st.size}`);
      }
    }
  }
  res.setHeader("Content-Length", end - start + 1);
  res.statusCode = status;
  if (req.method === "HEAD") return res.end();
  const stream = createReadStream(full, { start, end });
  stream.on("error", () => res.destroy());
  stream.pipe(res);
}

// verifyForPath runs the same HMAC dance as /credentials but for any
// path. Returns true on success; on failure writes a 4xx response and
// returns false (caller should bail out).
function verifyForPath({ cfg, cache, registry, logger }, req, res, path, recordStatus) {
  const deviceID = req.headers["x-tmon-device"];
  if (registry && deviceID) {
    if (!validDeviceID(deviceID)) { recordStatus.s = 400; writeError(res, 400, "invalid device_id"); return false; }
    let active, pending;
    try { ({ active, pending } = registry.psksFor(deviceID)); }
    catch (e) {
      if (e instanceof NotFound) { recordStatus.s = 404; writeError(res, 404, "unknown device"); return false; }
      logger.warn(`registry lookup ${deviceID}: ${e.message}`);
      recordStatus.s = 500; writeError(res, 500, "registry error"); return false;
    }
    let res2;
    try {
      res2 = auth.verifyMulti(
        [active, pending],
        "GET", path,
        req.headers["x-tmon-timestamp"], req.headers["x-tmon-nonce"], req.headers["x-tmon-signature"],
        req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
        cache, cfg.security.max_timestamp_skew_seconds,
      );
    } catch (e) { logger.info(`auth rejected ${path} device=${deviceID}: ${e.message}`); recordStatus.s = 401; writeError(res, 401, "unauthorized"); return false; }
    const obs = parseUint32(req.headers["x-tmon-config-version"] || "");
    try { registry.maybePromote(deviceID, obs, res2.pskIndex === 1); } catch (e) { logger.warn(`promote ${deviceID}: ${e.message}`); }
    try { registry.touch(deviceID); } catch (e) { logger.warn(`touch ${deviceID}: ${e.message}`); }
    return true;
  }
  try {
    auth.verify(
      cfg.psk(),
      "GET", path,
      req.headers["x-tmon-timestamp"], req.headers["x-tmon-nonce"], req.headers["x-tmon-signature"],
      req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
      cache, cfg.security.max_timestamp_skew_seconds,
    );
  } catch (e) { logger.info(`auth rejected ${path}: ${e.message}`); recordStatus.s = 401; writeError(res, 401, "unauthorized"); return false; }
  return true;
}

function handleCredentialsCodex({ cfg, cache, state, registry, logger }, req, res) {
  const rs = { s: 200 };
  res.on("close", () => { try { state.recordRequest(req.socket.remoteAddress || "", rs.s); } catch {} });
  if (!cfg.codex?.enabled) { rs.s = 404; return writeError(res, 404, "codex provider disabled"); }
  if (!verifyForPath({ cfg, cache, registry, logger }, req, res, "/credentials/codex", rs)) return;
  let c;
  try { c = creds.loadCodex(cfg.codexAuthPathAbs()); }
  catch (e) {
    if (e instanceof creds.CredsFileMissing) { rs.s = 503; return writeError(res, 503, "codex credentials file missing"); }
    logger.warn(`cannot parse codex credentials: ${e.message}`);
    rs.s = 500; return writeError(res, 500, "cannot read codex credentials");
  }
  if (c.isExpired(Date.now())) { rs.s = 503; return writeError(res, 503, "codex token expired, refresh on laptop"); }
  rs.s = 200;
  return writeJSON(res, 200, { access_token: c.accessToken, expires_at: c.expiresAtISO(), account_id: c.accountId });
}

// Read the per-device gemini_models override from the registry,
// preferring pending over active so a freshly-staged override applies
// without waiting for a promotion. Returns [] when no override.
function deviceGeminiModels(registry, deviceID) {
  let dev;
  try {
    dev = registry.load(deviceID);
  } catch {
    return [];
  }
  if (dev?.pending?.payload?.gemini_models && dev.pending.payload.gemini_models.length > 0) {
    return dev.pending.payload.gemini_models.slice();
  }
  if (dev?.active?.payload?.gemini_models && dev.active.payload.gemini_models.length > 0) {
    return dev.active.payload.gemini_models.slice();
  }
  return [];
}

async function handleUsage({ cfg, cache, state, registry, logger, usageCache, provider }, req, res) {
  const rs = { s: 200 };
  res.on("close", () => { try { state.recordRequest(req.socket.remoteAddress || "", rs.s); } catch {} });
  if (!verifyForPath({ cfg, cache, registry, logger }, req, res, `/usage/${provider}`, rs)) return;
  if (!usageCache) { rs.s = 503; return writeError(res, 503, "usage disabled (no providers configured)"); }

  // Per-device Gemini override: bypass the shared cache and fetch the
  // requested model slice. Token cache inside the GeminiFetcher is
  // preserved.
  try {
    const deviceID = req.headers["x-tmon-device"] || "";
    if (
      provider === "gemini" &&
      registry &&
      deviceID &&
      validDeviceID(deviceID) &&
      typeof usageCache.geminiFetcher === "function"
    ) {
      const models = deviceGeminiModels(registry, deviceID);
      if (models.length > 0) {
        const gf = usageCache.geminiFetcher();
        if (gf) {
          const snap = await gf.fetchWithModels(models);
          snap.fetched_at_unix = Math.floor(Date.now() / 1000);
          rs.s = 200;
          return writeJSON(res, 200, snap);
        }
      }
    }
  } catch (e) {
    if (e instanceof usage.CredsMissing) { rs.s = 404; return writeError(res, 404, "creds file missing"); }
    if (e instanceof usage.TokenExpired) { rs.s = 503; return writeError(res, 503, "token expired, refresh on laptop"); }
    if (e instanceof usage.Unauthorized) { rs.s = 401; return writeError(res, 401, "upstream rejected token"); }
    if (e instanceof usage.RateLimited) {
      rs.s = 429;
      if (e.retryAfter > 0) res.setHeader("Retry-After", String(e.retryAfter));
      return writeError(res, 429, "rate limited");
    }
    if (e instanceof usage.UsageError) { rs.s = 502; return writeError(res, 502, `upstream error: ${e.message}`); }
    logger.error(`gemini override fetch crashed: ${e.stack || e.message}`);
    rs.s = 500; return writeError(res, 500, "internal");
  }

  try {
    const snap = await usageCache.get(provider);
    rs.s = 200;
    return writeJSON(res, 200, snap);
  } catch (e) {
    // If the fetcher attached a stale snapshot, serve it with a header
    // so the firmware sees the freshness but keeps rendering.
    if (e.staleSnapshot) {
      rs.s = 200;
      res.setHeader("X-Tmon-Stale-Reason", e.message);
      return writeJSON(res, 200, e.staleSnapshot);
    }
    if (e instanceof usage.NotImplementedProvider) { rs.s = 501; return writeError(res, 501, "provider not enabled"); }
    if (e instanceof usage.CredsMissing) { rs.s = 404; return writeError(res, 404, "creds file missing"); }
    if (e instanceof usage.TokenExpired) { rs.s = 503; return writeError(res, 503, "token expired, refresh on laptop"); }
    if (e instanceof usage.Unauthorized) { rs.s = 401; return writeError(res, 401, "upstream rejected token"); }
    if (e instanceof usage.RateLimited) {
      rs.s = 429;
      if (e.retryAfter > 0) res.setHeader("Retry-After", String(e.retryAfter));
      return writeError(res, 429, "rate limited");
    }
    if (e instanceof usage.UsageError) { rs.s = 502; return writeError(res, 502, `upstream error: ${e.message}`); }
    logger.error(`usage handler crashed: ${e.stack || e.message}`);
    rs.s = 500; return writeError(res, 500, "internal");
  }
}

// handleSpend serves GET /spend/{provider}. Same HMAC envelope as
// /usage; the payload is locally-computed token spend. See
// compat/SPEND_WIRE.md.
async function handleSpend({ cfg, cache, state, registry, logger, spendCache, provider }, req, res) {
  const rs = { s: 200 };
  res.on("close", () => { try { state.recordRequest(req.socket.remoteAddress || "", rs.s); } catch {} });
  if (!verifyForPath({ cfg, cache, registry, logger }, req, res, `/spend/${provider}`, rs)) return;
  if (provider !== "claude" && provider !== "codex" && provider !== "gemini") {
    rs.s = 404; return writeError(res, 404, "unknown spend provider");
  }
  if (!spendCache) { rs.s = 501; return writeError(res, 501, "spend disabled"); }
  try {
    const snap = await spendCache.get(provider);
    rs.s = 200;
    return writeJSON(res, 200, snap);
  } catch (e) {
    if (e.staleSnapshot) {
      rs.s = 200;
      res.setHeader("X-Tmon-Stale-Reason", e.message);
      return writeJSON(res, 200, e.staleSnapshot);
    }
    if (e instanceof spend.NotImplementedProvider) { rs.s = 501; return writeError(res, 501, "provider not enabled"); }
    if (e instanceof spend.SpendUnavailable) { rs.s = 503; return writeError(res, 503, "spend unavailable"); }
    logger.error(`spend handler crashed: ${e.stack || e.message}`);
    rs.s = 500; return writeError(res, 500, "internal");
  }
}

function handleCredentials({ cfg, cache, state, registry, logger }, req, res) {
  let recordStatus = 200;
  const finish = (status, body) => { recordStatus = status; writeJSON(res, status, body); };
  const finishErr = (status, msg) => { recordStatus = status; writeError(res, status, msg); };
  res.on("close", () => { try { state.recordRequest(req.socket.remoteAddress || "", recordStatus); } catch {} });

  const deviceID = req.headers["x-tmon-device"];
  try {
    if (registry && deviceID) {
      if (!validDeviceID(deviceID)) return finishErr(400, "invalid device_id");
      let active, pending;
      try { ({ active, pending } = registry.psksFor(deviceID)); }
      catch (e) {
        if (e instanceof NotFound) return finishErr(404, "unknown device");
        logger.warn(`registry lookup ${deviceID}: ${e.message}`); return finishErr(500, "registry error");
      }
      let res2;
      try {
        res2 = auth.verifyMulti(
          [active, pending],
          "GET", "/credentials",
          req.headers["x-tmon-timestamp"], req.headers["x-tmon-nonce"], req.headers["x-tmon-signature"],
          req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
          cache, cfg.security.max_timestamp_skew_seconds,
        );
      } catch (e) { logger.info(`auth rejected /credentials device=${deviceID}: ${e.message}`); return finishErr(401, "unauthorized"); }
      {
        const obs = parseUint32(req.headers["x-tmon-config-version"] || "");
        try { registry.maybePromote(deviceID, obs, res2.pskIndex === 1); } catch (e) { logger.warn(`promote ${deviceID}: ${e.message}`); }
      }
      try { registry.touch(deviceID); } catch (e) { logger.warn(`touch ${deviceID}: ${e.message}`); }
    } else {
      try {
        auth.verify(
          cfg.psk(),
          "GET", "/credentials",
          req.headers["x-tmon-timestamp"], req.headers["x-tmon-nonce"], req.headers["x-tmon-signature"],
          req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
          cache, cfg.security.max_timestamp_skew_seconds,
        );
      } catch (e) { logger.info(`auth rejected /credentials: ${e.message}`); return finishErr(401, "unauthorized"); }
    }

    let c;
    try { c = creds.load(cfg.oauthPathAbs()); }
    catch (e) {
      if (e instanceof creds.CredsFileMissing) return finishErr(404, "credentials file missing");
      logger.warn(`cannot parse credentials: ${e.message}`); return finishErr(500, "cannot read credentials");
    }
    if (c.isExpired(Date.now())) return finishErr(503, "token expired, refresh on laptop");
    return finish(200, { access_token: c.accessToken, expires_at: c.expiresAtISO() });
  } catch (e) {
    logger.error(`credentials handler crashed: ${e.stack || e.message}`);
    return finishErr(500, "internal");
  }
}

function handleFirmwareLogs({ cfg, cache, fwLogs, logger }, req, res, url) {
  try {
    auth.verify(
      cfg.psk(),
      "GET", "/firmware-logs",
      req.headers["x-tmon-timestamp"], req.headers["x-tmon-nonce"], req.headers["x-tmon-signature"],
      req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
      cache, cfg.security.max_timestamp_skew_seconds,
    );
  } catch (e) { logger.info(`auth rejected /firmware-logs: ${e.message}`); return writeError(res, 401, "unauthorized"); }
  // fwLogs() touches the serial tailer / ring buffer; guard so a throw there
  // becomes a 500, not a process-killing escape from the request listener.
  try {
    let limit = 200;
    const raw = url.searchParams.get("limit");
    if (raw != null) {
      const n = Number.parseInt(raw, 10);
      if (Number.isFinite(n)) limit = Math.max(1, Math.min(2000, n));
    }
    const body = fwLogs ? fwLogs(limit) : { connected: false, total_available: 0, lines: [] };
    return writeJSON(res, 200, body);
  } catch (e) {
    logger.error(`firmware-logs handler crashed: ${e.stack || e.message}`);
    return writeError(res, 500, "internal");
  }
}

function handleDeviceSync({ cfg, cache, state, registry, logger, deviceID }, req, res) {
  let recordStatus = 200;
  const finish = (s, b) => { recordStatus = s; writeJSON(res, s, b); };
  const finishErr = (s, m) => { recordStatus = s; writeError(res, s, m); };
  res.on("close", () => { try { state.recordRequest(req.socket.remoteAddress || "", recordStatus); } catch {} });

  if (!registry) return finishErr(404, "device registry not configured");
  if (!validDeviceID(deviceID)) return finishErr(400, "invalid device_id");

  let active, pending;
  try { ({ active, pending } = registry.psksFor(deviceID)); }
  catch (e) {
    if (e instanceof NotFound) return finishErr(404, "unknown device");
    logger.warn(`registry lookup ${deviceID}: ${e.message}`); return finishErr(500, "registry error");
  }
  const signedPath = `/device/${deviceID}/sync`;
  let res2;
  try {
    res2 = auth.verifyMulti(
      [active, pending],
      "GET", signedPath,
      req.headers["x-tmon-timestamp"], req.headers["x-tmon-nonce"], req.headers["x-tmon-signature"],
      req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
      cache, cfg.security.max_timestamp_skew_seconds,
    );
  } catch (e) { logger.info(`auth rejected ${signedPath}: ${e.message}`); return finishErr(401, "unauthorized"); }

  // Everything past the HMAC check runs under a try/catch: registry.load can
  // race a concurrent device delete (NotFound), hit corrupt TOML, or a bad PSK
  // can blow up encryption. Without this, a throw escapes the request listener
  // and (absent the index.js process guard) would take the broker down. We map
  // it to a 4xx/5xx response instead — mirroring handleCredentials' envelope.
  try {
    const observed = parseUint32(req.headers["x-tmon-config-version"] || "");
    try { registry.maybePromote(deviceID, observed, res2.pskIndex === 1); } catch (e) { logger.warn(`promote: ${e.message}`); }
    try { registry.touch(deviceID); } catch (e) { logger.warn(`touch: ${e.message}`); }
    // Schema v2: capture factory identity from headers. Not bound to
    // HMAC — metadata only; the Ed25519 manifest enforces SKU.
    const serialHdr = String(req.headers["x-tmon-serial"] || "");
    if (serialHdr) {
      try { registry.setSerial(deviceID, serialHdr, String(req.headers["x-tmon-sku"] || "")); }
      catch (e) { logger.warn(`set-serial: ${e.message}`); }
    }
    // Mirror anti-rollback floor. bumpMinSV is monotonic, so a spoofed-high
    // value only locks the device into rejecting downgrades.
    const minSvHdr = String(req.headers["x-tmon-min-sv"] || "");
    if (minSvHdr) {
      const sv = Number.parseInt(minSvHdr, 10);
      if (Number.isFinite(sv) && sv >= 0 && sv <= 0xFFFFFFFF) {
        try { registry.bumpMinSV(deviceID, sv); }
        catch (e) { logger.warn(`bump-min-sv: ${e.message}`); }
      }
    }
    // Persist the device's actually-running firmware version (unsigned
    // metadata, like serial/sku). Only-on-change so a 60s poll doesn't churn
    // the TOML. This keeps active.firmware_version in sync with reality so the
    // OTA auto-discovery loop (ota.js decide()) doesn't re-stage a release the
    // device already runs after a canary revert — its compareSemver/floor
    // guards key off active.payload.firmware_version.
    const fwHdr = String(req.headers["x-tmon-fw-version"] || "").trim();
    if (fwHdr) {
      try { registry.setActiveFirmwareVersion(deviceID, fwHdr); }
      catch (e) { logger.warn(`set-fw-version: ${e.message}`); }
    }

    const dev = registry.load(deviceID);

    // Clear a stale revert tombstone once the device has reached a version
    // STRICTLY NEWER than the blocked one (a fixed release landed), so the
    // tombstone doesn't outlive the bad release. Uses packSemver so an
    // unparseable header never clears it. Mirrors Go/Py.
    if (dev.blockedFirmwareVersion && fwHdr) {
      const got = packSemver(fwHdr);
      const blk = packSemver(dev.blockedFirmwareVersion);
      if (got !== null && blk !== null && got > blk) {
        try { registry.setBlockedFirmwareVersion(deviceID, ""); dev.blockedFirmwareVersion = ""; }
        catch (e) { logger.warn(`clear-blocked: ${e.message}`); }
      }
    }

    const out = { active_version: dev.active.payload.version };
    if (dev.pending && observed < dev.pending.payload.version) {
      if (!active || active.length !== 32) return finishErr(500, "broker config invalid");
      const pt = Buffer.from(pendingPayloadJSON(dev.pending.payload), "utf8");
      const ver = dev.pending.payload.version;
      // Gate the GCM wire format on the LIVE firmware version, never on
      // registry state: a device that just OTA'd to >= 0.9.0 must immediately
      // get GCM even though its stored config predates it. Below the gate (or
      // header absent) → legacy AES-CTR, unchanged.
      if (gcmFwGate(fwHdr)) {
        const { nonce, ciphertext } = encryptPendingGCM(active, pt, ver);
        out.pending = {
          version: ver,
          enc: "gcm",
          nonce_b64: nonce.toString("base64"),
          payload_b64: ciphertext.toString("base64"),
        };
      } else {
        const { nonce, ciphertext } = encryptPending(active, pt);
        out.pending = {
          version: ver,
          nonce_b64: nonce.toString("base64"),
          payload_b64: ciphertext.toString("base64"),
        };
      }
    }
    return finish(200, out);
  } catch (e) {
    if (e instanceof NotFound) return finishErr(404, "unknown device");
    logger.error(`device sync handler crashed: ${e.stack || e.message}`);
    return finishErr(500, "internal");
  }
}

// Receive a diagnostic log batch the device POSTs and append it to the
// per-device log file. Auth is identical to /sync; the signature does not
// cover the body (scrubbed, diagnostic-only). Body is size-capped.
function handleDeviceLogs({ cfg, cache, state, registry, logger, deviceID }, req, res) {
  let recordStatus = 202;
  const finishErr = (s, m) => { recordStatus = s; writeError(res, s, m); };
  res.on("close", () => { try { state.recordRequest(req.socket.remoteAddress || "", recordStatus); } catch {} });

  if (!registry) return finishErr(404, "device registry not configured");
  if (!validDeviceID(deviceID)) return finishErr(400, "invalid device_id");

  let active, pending;
  try { ({ active, pending } = registry.psksFor(deviceID)); }
  catch (e) {
    if (e instanceof NotFound) return finishErr(404, "unknown device");
    logger.warn(`registry lookup ${deviceID}: ${e.message}`); return finishErr(500, "registry error");
  }
  const signedPath = `/device/${deviceID}/logs`;
  try {
    auth.verifyMulti(
      [active, pending],
      "POST", signedPath,
      req.headers["x-tmon-timestamp"] || "", req.headers["x-tmon-nonce"] || "", req.headers["x-tmon-signature"] || "",
      req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
      cache, cfg.security.max_timestamp_skew_seconds,
    );
  } catch (e) { logger.info(`auth rejected ${signedPath}: ${e.message}`); return finishErr(401, "unauthorized"); }

  const cl = Number.parseInt(req.headers["content-length"] || "", 10);
  if (Number.isFinite(cl) && cl > devlog.MAX_BODY_BYTES) return finishErr(413, "body too large");

  const chunks = [];
  let total = 0;
  let aborted = false;
  req.on("data", (c) => {
    total += c.length;
    if (total > devlog.MAX_BODY_BYTES) { aborted = true; req.destroy(); return; }
    chunks.push(c);
  });
  req.on("error", () => { if (!aborted) { aborted = true; try { finishErr(400, "read error"); } catch {} } });
  req.on("end", () => {
    if (aborted) return finishErr(413, "body too large");
    const body = Buffer.concat(chunks).toString("utf8");
    const lines = devlog.stampLines(body, new Date());
    try { devlog.append(registry.dir, deviceID, lines); }
    catch (e) { logger.warn(`devlog append ${deviceID}: ${e.message}`); return finishErr(500, "log store error"); }
    recordStatus = 202;
    writeJSON(res, 202, { stored: lines.length });
  });
}

// validUint checks a JSON value is an integer in [0, max] (uint8/uint16 range),
// mirroring Go's decode into *uint8/*uint16 which rejects floats and overflow.
function validUint(v, max) {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max;
}

// handleDeviceSettings ingests a device-reported display-settings update and
// mirrors it into the registry (compat/SETTINGS_REPORT.md). The device owns
// these fields, so this converges the broker's stored config to the device's
// state instead of pushing a change — no version bump, no reverts. Auth is
// identical to /logs; the signature does not cover the body.
function handleDeviceSettings({ cfg, cache, state, registry, logger, deviceID }, req, res) {
  let recordStatus = 204;
  const finishErr = (s, m) => { recordStatus = s; writeError(res, s, m); };
  res.on("close", () => { try { state.recordRequest(req.socket.remoteAddress || "", recordStatus); } catch {} });

  if (!registry) return finishErr(404, "device registry not configured");
  if (!validDeviceID(deviceID)) return finishErr(400, "invalid device_id");

  let active, pending;
  try { ({ active, pending } = registry.psksFor(deviceID)); }
  catch (e) {
    if (e instanceof NotFound) return finishErr(404, "unknown device");
    logger.warn(`registry lookup ${deviceID}: ${e.message}`); return finishErr(500, "registry error");
  }
  const signedPath = `/device/${deviceID}/settings`;
  try {
    auth.verifyMulti(
      [active, pending],
      "POST", signedPath,
      req.headers["x-tmon-timestamp"] || "", req.headers["x-tmon-nonce"] || "", req.headers["x-tmon-signature"] || "",
      req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
      cache, cfg.security.max_timestamp_skew_seconds,
    );
  } catch (e) { logger.info(`auth rejected ${signedPath}: ${e.message}`); return finishErr(401, "unauthorized"); }

  const cl = Number.parseInt(req.headers["content-length"] || "", 10);
  if (Number.isFinite(cl) && cl > 512) return finishErr(400, "bad settings body");

  const chunks = [];
  let total = 0;
  let aborted = false;
  req.on("data", (c) => {
    total += c.length;
    // Streamed body over the 512-byte cap → 400 (matching the Go MaxBytesReader
    // path), then tear down the read side; the response is already written.
    if (total > 512) { if (!aborted) { aborted = true; finishErr(400, "bad settings body"); } req.destroy(); return; }
    chunks.push(c);
  });
  req.on("error", () => { if (!aborted) { aborted = true; try { finishErr(400, "bad settings body"); } catch {} } });
  req.on("end", () => {
    if (aborted) return;
    const raw = Buffer.concat(chunks).toString("utf8");
    // Canonical body handling shared with the Go/Python brokers: an empty
    // (or whitespace-only) body is a no-op; anything present must be a single
    // JSON object; null / arrays / scalars are rejected.
    let body;
    try {
      body = raw.trim() === "" ? {} : JSON.parse(raw);
    } catch { return finishErr(400, "bad settings body"); }
    if (body === null || typeof body !== "object" || Array.isArray(body)) return finishErr(400, "bad settings body");

    // Type-validate the way Go's strongly-typed decode does: reject a wrong
    // JSON type / overflow with 400 rather than silently coercing it. A field
    // that is absent OR explicit null is treated as "not reported" (omission),
    // matching Go's nil pointer and Python's dict.get() — hence `!= null`.
    const s = {};
    if (body.theme_mode != null) {
      if (typeof body.theme_mode !== "string") return finishErr(400, "bad settings body");
      s.theme_mode = body.theme_mode;  // unknown values ignored downstream
    }
    if (body.br_day != null) {
      if (!validUint(body.br_day, 255)) return finishErr(400, "bad settings body");
      s.br_day = body.br_day;
    }
    if (body.br_night != null) {
      if (!validUint(body.br_night, 255)) return finishErr(400, "bad settings body");
      s.br_night = body.br_night;
    }
    if (body.vol != null) {
      if (!validUint(body.vol, 255)) return finishErr(400, "bad settings body");
      s.vol = body.vol;
    }
    if (body.autorotate_enabled != null) {
      if (typeof body.autorotate_enabled !== "boolean") return finishErr(400, "bad settings body");
      s.autorotate_enabled = body.autorotate_enabled;
    }
    if (body.autorotate_interval_s != null) {
      if (!validUint(body.autorotate_interval_s, 65535)) return finishErr(400, "bad settings body");
      s.autorotate_interval_s = body.autorotate_interval_s;
    }
    if (body.pet_enabled != null) {
      if (typeof body.pet_enabled !== "boolean") return finishErr(400, "bad settings body");
      s.pet_enabled = body.pet_enabled;
    }
    if (body.pet_species != null) {
      // uint (0..255 here); applyReported clamps to the 0..9 enum. Absent →
      // left untouched (device hasn't picked a species).
      if (!validUint(body.pet_species, 255)) return finishErr(400, "bad settings body");
      s.pet_species = body.pet_species;
    }
    if (body.pet_name != null) {
      if (typeof body.pet_name !== "string") return finishErr(400, "bad settings body");
      s.pet_name = body.pet_name;  // truncated to 15 chars downstream
    }

    try { registry.reportSettings(deviceID, s); }
    catch (e) {
      if (e instanceof NotFound) return finishErr(404, "unknown device");
      logger.warn(`report settings ${deviceID}: ${e.message}`); return finishErr(500, "registry error");
    }
    recordStatus = 204;
    res.writeHead(204);
    res.end();
  });
}

function pendingPayloadJSON(p) {
  const wire = { version: p.version };
  if (p.broker_url) wire.broker_url = p.broker_url;
  if (p.psk_hex) wire.psk_hex = p.psk_hex;
  if (p.city) wire.city = p.city;
  // br_day / br_night have documented ranges 10..100 / 5..100, so 0 is
  // out of range and treated as "no change". vol however accepts 0
  // (mute) — only nullish means "no change", to stay consistent with
  // Go and Python.
  if (p.br_day) wire.br_day = p.br_day;
  if (p.br_night) wire.br_night = p.br_night;
  if (p.vol != null) wire.vol = p.vol;
  // Emit the rich provider_modes enum AND a derived legacy providers bool
  // map. New firmware reads provider_modes; pre-mode-split firmware only
  // understands the bool map. Both derive from the same source so they
  // never disagree. (enabled == mode is neither "" nor "disabled".)
  if (p.provider_modes) {
    const pm = p.provider_modes;
    wire.provider_modes = { claude: pm.claude, codex: pm.codex, gemini: pm.gemini };
    const en = (m) => m != null && m !== "" && m !== "disabled";
    wire.providers = { claude: en(pm.claude), codex: en(pm.codex), gemini: en(pm.gemini) };
  }
  if (p.autorotate_enabled != null) wire.autorotate_enabled = p.autorotate_enabled;
  if (p.autorotate_interval_s != null) wire.autorotate_interval_s = p.autorotate_interval_s;
  // firmware/config_sync.c reads "theme_mode" from the decrypted blob
  // and writes it to KEY_THEME_MD. Omitting it here would silently
  // no-op /wall-monitor:theme switches.
  if (p.theme_mode) wire.theme_mode = p.theme_mode;
  if (p.pet_enabled != null) wire.pet_enabled = !!p.pet_enabled;
  if (p.pet_species != null) wire.pet_species = Number(p.pet_species);
  if (p.pet_name) wire.pet_name = String(p.pet_name);
  if (Array.isArray(p.gemini_models) && p.gemini_models.length > 0) {
    // firmware/config_sync.c reads "gemini_models" as a CSV string and
    // writes it to NVS key tmon_gem_mdls.
    wire.gemini_models = p.gemini_models.map(String).join(",");
  }
  if (p.log_enabled != null) wire.log_enabled = !!p.log_enabled;  // → NVS tmon_log_en
  // OTA staging fields. All-or-nothing: the firmware ignores the bundle
  // if any of the three is missing, so don't emit partial state.
  if (p.firmware_url && p.firmware_sha256 && p.firmware_version) {
    wire.firmware_url = p.firmware_url;
    wire.firmware_sha256 = p.firmware_sha256;
    wire.firmware_version = p.firmware_version;
  }
  // Schema v2 manifest envelope. The device-side gate enforces
  // "both or neither" — we forward whichever fields are present.
  if (p.firmware_manifest_b64) wire.firmware_manifest_b64 = p.firmware_manifest_b64;
  if (p.firmware_manifest_sig_b64) wire.firmware_manifest_sig_b64 = p.firmware_manifest_sig_b64;
  // Go's json.Marshal on map[string]any sorts keys alphabetically and Python
  // uses sort_keys=True; mirror both with sortKeysDeep so each runtime emits
  // the SAME key order. The JSON is semantically identical across runtimes,
  // but the bytes are NOT guaranteed equal: Go escapes <, >, & as < etc.,
  // Python's default ensure_ascii escapes non-ASCII to \uXXXX, and this JS
  // emits raw UTF-8 (e.g. "Málaga" stays two bytes 0xc3 0xa1). So for an ASCII
  // payload with none of <>& the ciphertext matches across ports; a payload
  // with those characters will differ byte-for-byte. The wire contract is the
  // decrypted JSON semantics, not a byte-identical blob.
  return JSON.stringify(sortKeysDeep(wire));
}

function sortKeysDeep(v) {
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  if (v && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortKeysDeep(v[k]);
    return out;
  }
  return v;
}
