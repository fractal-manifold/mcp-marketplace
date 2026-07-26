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
import { compareSemver, validVersion } from "../ota.js";
import { LEASE_PATH, LEASE_RENEW_PATH, LEASE_RELEASE_PATH } from "../usbprov/leasewire.js";
import { LeaseBusyError, LeaseUnknownError } from "../usbprov/lease.js";
import { canonicalPort } from "../usbprov/serial.js";
import { createHash } from "node:crypto";
import { createReadStream, statSync, readFileSync } from "node:fs";
import { resolve as resolvePath, sep as pathSep, join as joinPath } from "node:path";

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

export function createHandler({ cfg, cache, state, fwLogs, registry, logger, usageCache, spendCache, leaseManager }) {
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
    // Route by PATH first, then method: a matched path with a wrong method
    // must return 405 (Go/py parity), not fall through to 404.
    const routes = [
      { re: /^\/credentials$/, methods: ["GET"], h: (m2) => handleCredentials({ cfg, cache, state, registry, logger }, req, res) },
      { re: /^\/credentials\/codex$/, methods: ["GET"], h: (m2) => handleCredentialsCodex({ cfg, cache, state, registry, logger }, req, res) },
      { re: /^\/firmware-logs$/, methods: ["GET"], h: (m2) => handleFirmwareLogs({ cfg, cache, fwLogs, logger }, req, res, url) },
      { re: /^\/usage\/([^/]+)$/, methods: ["GET"], h: (m2) => handleUsage({ cfg, cache, state, registry, logger, usageCache, provider: m2[1] }, req, res) },
      { re: /^\/spend\/([^/]+)$/, methods: ["GET"], h: (m2) => handleSpend({ cfg, cache, state, registry, logger, spendCache, provider: m2[1] }, req, res) },
      { re: /^\/device\/([^/]+)\/sync$/, methods: ["GET"], h: (m2) => handleDeviceSync({ cfg, cache, state, registry, logger, deviceID: m2[1] }, req, res) },
      { re: /^\/device\/([^/]+)\/panel$/, methods: ["GET"], h: (m2) => handleDevicePanel({ cfg, cache, state, registry, logger, deviceID: m2[1] }, req, res) },
      { re: /^\/device\/([^/]+)\/logs$/, methods: ["POST"], h: (m2) => handleDeviceLogs({ cfg, cache, state, registry, logger, deviceID: m2[1] }, req, res) },
      { re: /^\/device\/([^/]+)\/settings$/, methods: ["POST"], h: (m2) => handleDeviceSettings({ cfg, cache, state, registry, logger, deviceID: m2[1] }, req, res) },
      { re: /^\/firmware\/([^/]+)$/, methods: ["GET", "HEAD"], h: (m2) => handleFirmware({ cfg, cache, registry, logger, name: m2[1] }, req, res) },
      // Leader-mediated serial lease (compat/PROVISION_WIRE.md §6). anyMethod so
      // the handler itself returns 405 AFTER the 503 (no manager) / 403
      // (non-loopback) checks, matching the Go handler's ordering.
      { re: /^\/serial\/lease$/, anyMethod: true, h: () => handleSerialLease({ cfg, cache, logger, leaseManager, subpath: LEASE_PATH }, req, res) },
      { re: /^\/serial\/lease\/renew$/, anyMethod: true, h: () => handleSerialLease({ cfg, cache, logger, leaseManager, subpath: LEASE_RENEW_PATH }, req, res) },
      { re: /^\/serial\/lease\/release$/, anyMethod: true, h: () => handleSerialLease({ cfg, cache, logger, leaseManager, subpath: LEASE_RELEASE_PATH }, req, res) },
    ];
    for (const route of routes) {
      const rm = path.match(route.re);
      if (!rm) continue;
      if (!route.anyMethod && !route.methods.includes(req.method)) return writeError(res, 405, "method not allowed");
      return route.h(rm);
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

  // Range: bytes=START-[END] and suffix bytes=-N support, matching the Go
  // reference (http.ServeContent). An out-of-range or unsatisfiable request
  // returns 416 + Content-Range: bytes */<size>; an unparseable Range header
  // falls back to a full 200.
  const range = req.headers.range;
  let start = 0, end = st.size - 1, status = 200;
  if (range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(range);
    if (m && (m[1] !== "" || m[2] !== "")) {
      let satisfiable = true;
      if (m[1] === "") {
        // Suffix range: last N bytes. bytes=-0 (or invalid) is unsatisfiable.
        const n = Number.parseInt(m[2], 10);
        if (!Number.isFinite(n) || n <= 0) {
          satisfiable = false;
        } else {
          start = Math.max(0, st.size - n);
          end = st.size - 1;
        }
      } else {
        const s = Number.parseInt(m[1], 10);
        const e = m[2] ? Number.parseInt(m[2], 10) : st.size - 1;
        if (!Number.isFinite(s) || s >= st.size) {
          satisfiable = false;
        } else {
          start = s;
          end = Math.min(e, st.size - 1);
          if (end < start) satisfiable = false;
        }
      }
      if (!satisfiable) {
        res.setHeader("Content-Range", `bytes */${st.size}`);
        res.statusCode = 416;
        return res.end();
      }
      status = 206;
      res.setHeader("Content-Range", `bytes ${start}-${end}/${st.size}`);
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
  // Authenticate BEFORE revealing whether codex is enabled — otherwise an
  // unsigned probe distinguishes enabled (401) from disabled (404), leaking
  // the provider's enablement. Matches the Go reference (verify, then enabled).
  if (!verifyForPath({ cfg, cache, registry, logger }, req, res, "/credentials/codex", rs)) return;
  if (!cfg.codex?.enabled) { rs.s = 404; return writeError(res, 404, "codex provider disabled"); }
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

async function handleUsage({ cfg, cache, state, registry, logger, usageCache, provider }, req, res) {
  const rs = { s: 200 };
  res.on("close", () => { try { state.recordRequest(req.socket.remoteAddress || "", rs.s); } catch {} });
  if (!verifyForPath({ cfg, cache, registry, logger }, req, res, `/usage/${provider}`, rs)) return;
  // HMAC was verified against the literal path above; only now fold the
  // deprecated "gemini" wire alias onto the canonical "antigravity" key for
  // cache/fetcher lookup. Old firmware that signs /usage/gemini keeps working;
  // new firmware uses /usage/antigravity directly.
  provider = usage.canonicalProvider(provider);
  if (!usageCache) { rs.s = 503; return writeError(res, 503, "usage disabled (no providers configured)"); }

  // NOTE: the per-device Antigravity model override was removed (bug 27).
  // fetchWithModels ignored its models arg since the quota went grouped, so
  // the override was a pure cache bypass (two upstream Google calls per poll
  // for an identical result). The gemini_models registry→device wire plumbing
  // is unrelated (device-side config) and is kept.
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
    // 502 bodies are FIXED strings (Go parity: transport vs upstream); the
    // detail is logged, never returned to the client.
    if (e instanceof usage.Transport) { logger.warn(`usage transport error: ${e.message}`); rs.s = 502; return writeError(res, 502, "transport error"); }
    if (e instanceof usage.Upstream || e instanceof usage.ParseUpstream) { logger.warn(`usage upstream error: ${e.message}`); rs.s = 502; return writeError(res, 502, "upstream error"); }
    if (e instanceof usage.UsageError) { logger.warn(`usage internal error: ${e.message}`); rs.s = 500; return writeError(res, 500, "internal error"); }
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
  // Canonicalize the deprecated "gemini" alias AFTER HMAC verification.
  provider = spend.canonicalProvider(provider);
  if (provider !== spend.PROVIDER_CLAUDE && provider !== spend.PROVIDER_CODEX && provider !== spend.PROVIDER_ANTIGRAVITY) {
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

// Bounds the served panel document; the device parses into fixed buffers.
// Keep in sync with compat/PANEL_WIRE.md and the Go panelMaxBytes.
const PANEL_MAX_BYTES = 8 * 1024;
// mtime+size cache: a program rewriting the file in place is picked up next poll.
const panelCache = new Map();

// resolvePanelPath: the explicit [panel.file].<id> entry, then <dir>/<id>.json,
// then <dir>/default.json, then the [panel.file].default entry (a.k.a. the
// legacy bare file). "" ⇒ feature off. deviceID already passed validDeviceID
// (no slashes).
function resolvePanelPath(cfg, deviceID) {
  const explicit = cfg.panelFileExplicitAbs ? cfg.panelFileExplicitAbs(deviceID) : "";
  if (explicit) return explicit;
  const dir = cfg.panelDirAbs ? cfg.panelDirAbs() : "";
  if (dir) {
    if (deviceID) {
      const p = joinPath(dir, `${deviceID}.json`);
      try { if (statSync(p).isFile()) return p; } catch {}
    }
    const d = joinPath(dir, "default.json");
    try { if (statSync(d).isFile()) return d; } catch {}
  }
  const f = cfg.panelFileDefaultAbs ? cfg.panelFileDefaultAbs() : "";
  return f || "";
}

// readPanelFile → { body } on success, or { status, msg } on error
// (404 absent, 422 oversize/non-JSON).
function readPanelFile(path) {
  let st;
  try { st = statSync(path); }
  catch (e) { return e.code === "ENOENT" ? { status: 404, msg: "no panel" } : { status: 500, msg: "panel read error" }; }
  if (!st.isFile()) return { status: 404, msg: "no panel" };
  if (st.size > PANEL_MAX_BYTES) return { status: 422, msg: `panel too large (${st.size} > ${PANEL_MAX_BYTES} bytes)` };
  const cached = panelCache.get(path);
  if (cached && cached.mtimeMs === st.mtimeMs && cached.size === st.size) return { body: cached.body };
  let raw;
  try { raw = readFileSync(path); }
  catch { return { status: 500, msg: "panel read error" }; }
  try { JSON.parse(raw.toString("utf8")); }
  catch { return { status: 422, msg: "panel is not valid JSON" }; }
  panelCache.set(path, { mtimeMs: st.mtimeMs, size: st.size, body: raw });
  return { body: raw };
}

// GET /device/{id}/panel — serve the user-authored panel doc verbatim. Same
// HMAC envelope as /device/{id}/sync. Additive: unconfigured / absent ⇒ 404.
function handleDevicePanel({ cfg, cache, state, registry, logger, deviceID }, req, res) {
  let recordStatus = 200;
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
  const signedPath = `/device/${deviceID}/panel`;
  try {
    auth.verifyMulti(
      [active, pending],
      "GET", signedPath,
      req.headers["x-tmon-timestamp"], req.headers["x-tmon-nonce"], req.headers["x-tmon-signature"],
      req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
      cache, cfg.security.max_timestamp_skew_seconds,
    );
  } catch (e) { logger.info(`auth rejected ${signedPath}: ${e.message}`); return finishErr(401, "unauthorized"); }

  const path = resolvePanelPath(cfg, deviceID);
  if (!path) return finishErr(404, "panel not configured");
  const r = readPanelFile(path);
  if (r.status) { if (r.status === 500) logger.warn(`panel read ${path}`); return finishErr(r.status, r.msg); }
  recordStatus = 200;
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Length", r.body.length);
  res.setHeader("Cache-Control", "no-store");
  res.end(r.body);
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
    // tombstone doesn't outlive the bad release. Uses compareSemver so an
    // unparseable header never clears it — and, unlike packSemver, so that two
    // builds sharing a base still order: packSemver drops the "-dev.<ts>"
    // prerelease, so 0.10.0-dev.<later> would pack EQUAL to a blocked
    // 0.10.0-dev.<earlier> and never clear it. Mirrors Go/Py.
    if (dev.blockedFirmwareVersion && fwHdr) {
      const cmp = compareSemver(fwHdr, dev.blockedFirmwareVersion);
      if (cmp !== null && cmp > 0) {
        try { registry.setBlockedFirmwareVersion(deviceID, ""); dev.blockedFirmwareVersion = ""; }
        catch (e) { logger.warn(`clear-blocked: ${e.message}`); }
      }
    }

    // Install-loop breaker, device-reported half. X-Tmon-Ota-Fail carries the
    // firmware's own verdict on an image it downloaded and booted but that
    // never self-confirmed — the device is the only party that can see a
    // rollback, since from the broker's side every step succeeded. The
    // stage-streak counter in ota.js decide() catches the same loop without
    // any device change, but only at the hourly poll and only while the broker
    // stays up; either trigger alone closes the loop. Mirrors Go/Py.
    const fail = parseOtaFail(String(req.headers["x-tmon-ota-fail"] || ""));
    if (fail && fail.version !== fwHdr && dev.blockedFirmwareVersion !== fail.version) {
      try {
        registry.setBlockedFirmwareVersion(deviceID, fail.version);
        dev.blockedFirmwareVersion = fail.version;
        logger.warn(`device ${deviceID} reports ${fail.version} failed to install ` +
          `${fail.installs} times (${fail.state}); blocking that version — ` +
          `publish a newer one to clear it`);
      } catch (e) { logger.warn(`set-blocked: ${e.message}`); }
    }

    const out = { active_version: dev.active.payload.version };
    // Advertise the broker self-version-check verdict on every 200 so the
    // device can surface a "broker outdated" banner. Only once known — an
    // unchecked/unreachable verdict stays absent (no false banner). Mirrors
    // Go's *bool + omitempty behaviour on the sync response.
    if (state && typeof state.update === "function") {
      const u = state.update();
      if (u && u.known) {
        out.broker_update_available = u.outdated;
        out.broker_version = u.current;
        out.broker_latest = u.latest;
      }
    }
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
// per-device log file. Auth is identical to /sync; when the device sends
// X-Tmon-Body-Sha256 the signature also covers the body (HMAC v3, see
// compat/HMAC_CANONICAL.md). Body is size-capped and assembled before auth —
// safe, since nothing is parsed or stored until the signature checks out.
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
  const cl = Number.parseInt(req.headers["content-length"] || "", 10);
  if (Number.isFinite(cl) && cl > devlog.MAX_BODY_BYTES) return finishErr(413, "body too large");

  const chunks = [];
  let total = 0;
  let aborted = false;
  req.on("data", (c) => {
    total += c.length;
    // Streamed body over the cap → respond 413 FIRST, then tear down the read
    // side (destroy() without an error emits neither `error` nor `end`, so a
    // response written afterwards would never go out and the device would see
    // a bare connection reset instead of the 413 that Go/Python return).
    if (total > devlog.MAX_BODY_BYTES) { if (!aborted) { aborted = true; finishErr(413, "body too large"); } req.destroy(); return; }
    chunks.push(c);
  });
  req.on("error", () => { if (!aborted) { aborted = true; try { finishErr(400, "read error"); } catch {} } });
  req.on("end", () => {
    if (aborted) return;
    const raw = Buffer.concat(chunks);
    // Body-aware auth AFTER the size-bounded body is assembled: the v3
    // canonical covers sha256(body), so the signature can't be checked sooner.
    try {
      auth.verifyMultiBody(
        [active, pending],
        "POST", signedPath,
        req.headers["x-tmon-timestamp"] || "", req.headers["x-tmon-nonce"] || "", req.headers["x-tmon-signature"] || "",
        req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
        req.headers["x-tmon-body-sha256"] || "", raw,
        cache, cfg.security.max_timestamp_skew_seconds,
      );
    } catch (e) { logger.info(`auth rejected ${signedPath}: ${e.message}`); return finishErr(401, "unauthorized"); }
    const body = raw.toString("utf8");
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

// How many failed installs the DEVICE must report before the broker stops
// offering that version. See parseOtaFail.
//
// Two thresholds, mirroring TMON_OTA_MAX_INSTALLS / _SOFT in the firmware. They
// MUST match: the device gives up at its own threshold, and a broker that
// tombstoned earlier would silently shorten the device's retry budget — a
// version the firmware was still willing to try twice more would stop being
// offered after the first two circumstantial failures.
//
// Hard states are faults we can pin on the image (it crashed or hung before
// confirming); everything else — a brownout, a power cut before the confirm
// window closed, a reset we could not attribute — is circumstantial and needs
// more evidence before condemning a build that may well be fine.
//
// Unrecognised states get the SOFT threshold rather than being rejected:
// firmware and broker version independently, so a future firmware adding a
// state must not silently disable the breaker.
const MIN_FAILED_INSTALLS_HARD = 2;
const MIN_FAILED_INSTALLS_SOFT = 4;

function otaFailThreshold(state) {
  return state === "panic" || state === "wdt"
    ? MIN_FAILED_INSTALLS_HARD
    : MIN_FAILED_INSTALLS_SOFT;
}

// parseOtaFail parses X-Tmon-Ota-Fail ("<version>:<installs>:<state>") and
// returns an object ONLY when the value is a well-formed report of a version
// that has definitively failed to install. Everything else — "none", an empty
// header, a malformed value, a still-in-flight "pending" state, or a count
// below the threshold — returns null.
//
// The header is unsigned metadata (like X-Tmon-Fw-Version and X-Tmon-Serial
// alongside it), so it is parsed defensively and fails closed: the worst a
// spoofer can achieve is to deny UPDATES to one device it can already
// impersonate, never to cause an install. See compat/SECURITY.md.
//
// Byte-for-byte mirror of Go parseOTAFail / Py _parse_ota_fail.
function parseOtaFail(h) {
  h = String(h || "").trim();
  if (!h || h === "none" || h.length > 64) return null;
  const parts = h.split(":");
  if (parts.length !== 3) return null;
  const version = parts[0], state = parts[2];
  // Must name a real version, or a garbage string could be written into the
  // tombstone and then never match (and never clear) a published release.
  if (!validVersion(version)) return null;
  // Strict digits, matching Go's strconv.Atoi. parseInt would also accept
  // "2abc" (== 2) and Number() would accept "0x2" / " 2 ", none of which Go
  // takes — and this parser has to agree across all three runtimes.
  if (!/^[+-]?[0-9]+$/.test(parts[1])) return null;
  const installs = Number(parts[1]);
  // The firmware stores installs as 0..255 (tmon_ota_fail_parse enforces it),
  // so anything outside that is not a record we wrote. Without the upper bound
  // a long digit string becomes an imprecise double (or Infinity) that would
  // sail past the threshold.
  if (!Number.isInteger(installs) || installs < 0 || installs > 255) return null;
  // "pending" means the device armed the image but has not yet reported back
  // on it — the install may still succeed, so it is not evidence of failure.
  if (!state || state === "pending") return null;
  if (installs < otaFailThreshold(state)) return null;
  return { version, installs, state };
}

// handleDeviceSettings ingests a device-reported display-settings update and
// mirrors it into the registry (compat/SETTINGS_REPORT.md). The device owns
// these fields, so this converges the broker's stored config to the device's
// state instead of pushing a change — no version bump, no reverts. Auth is
// identical to /logs; when the device sends X-Tmon-Body-Sha256 the signature
// also covers the body (HMAC v3).
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
    const rawBuf = Buffer.concat(chunks);
    // Body-aware auth AFTER the size-bounded body is assembled: the v3
    // canonical covers sha256(body), so the signature can't be checked sooner.
    try {
      auth.verifyMultiBody(
        [active, pending],
        "POST", signedPath,
        req.headers["x-tmon-timestamp"] || "", req.headers["x-tmon-nonce"] || "", req.headers["x-tmon-signature"] || "",
        req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
        req.headers["x-tmon-body-sha256"] || "", rawBuf,
        cache, cfg.security.max_timestamp_skew_seconds,
      );
    } catch (e) { logger.info(`auth rejected ${signedPath}: ${e.message}`); return finishErr(401, "unauthorized"); }
    const raw = rawBuf.toString("utf8");
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
    if (body.panel_enabled != null) {
      if (typeof body.panel_enabled !== "boolean") return finishErr(400, "bad settings body");
      s.panel_enabled = body.panel_enabled;
    }
    if (body.pet_species != null) {
      // uint (0..255 here); applyReported clamps to the 0..9 enum. Absent →
      // left untouched (device hasn't picked a species).
      if (!validUint(body.pet_species, 255)) return finishErr(400, "bad settings body");
      s.pet_species = body.pet_species;
    }
    if (body.wifi_known != null) {
      // Remembered networks, names only. Device input, so it is sanitised
      // before storage: entries with an empty or oversize SSID are dropped and
      // the list is truncated to what the on-device store can hold (8).
      // Absent means firmware too old to report — distinct from an empty list,
      // which means "I remember none".
      if (!Array.isArray(body.wifi_known)) return finishErr(400, "bad settings body");
      const cleaned = [];
      for (const n of body.wifi_known) {
        if (!n || typeof n !== "object") continue;
        const ssid = n.ssid;
        // Bytes, not UTF-16 units: the 802.11 SSID field is 32 OCTETS, which
        // is how the device and the Go broker both measure it.
        if (typeof ssid !== "string" || !ssid || Buffer.byteLength(ssid, "utf8") > 32) continue;
        const verified = n.verified ?? false, isOpen = n.open ?? false;
        // Strict, not truthy: Go's typed decode rejects a non-boolean
        // outright, and a coerced "false" string would silently flip a network
        // to open and make set_wifi refuse it forever.
        if (typeof verified !== "boolean" || typeof isOpen !== "boolean") {
          return finishErr(400, "bad settings body");
        }
        cleaned.push({ ssid, verified, open: isOpen });
        if (cleaned.length === 8) break;
      }
      s.wifi_known = cleaned;
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
    // Dual-emit the Antigravity provider under BOTH the new "antigravity" key
    // and the deprecated "gemini" key. Firmware after the rename reads
    // "antigravity"; deployed firmware still reads "gemini". Both derive from
    // the same source so they never disagree. Drop "gemini" once the fleet has
    // updated. Mirror of Go pendingPayloadJSON.
    wire.provider_modes = { claude: pm.claude, codex: pm.codex, antigravity: pm.gemini, gemini: pm.gemini };
    const en = (m) => m != null && m !== "" && m !== "disabled";
    wire.providers = { claude: en(pm.claude), codex: en(pm.codex), antigravity: en(pm.gemini), gemini: en(pm.gemini) };
  }
  if (p.autorotate_enabled != null) wire.autorotate_enabled = p.autorotate_enabled;
  if (p.autorotate_interval_s != null) wire.autorotate_interval_s = p.autorotate_interval_s;
  // firmware/config_sync.c reads "theme_mode" from the decrypted blob
  // and writes it to KEY_THEME_MD. Omitting it here would silently
  // no-op /tokenmonitor:theme switches.
  if (p.theme_mode) wire.theme_mode = p.theme_mode;
  if (p.pet_enabled != null) wire.pet_enabled = !!p.pet_enabled;
  if (p.pet_species != null) wire.pet_species = Number(p.pet_species);
  if (p.pet_name) wire.pet_name = String(p.pet_name);
  if (p.wifi_ssid) {
    wire.wifi_ssid = String(p.wifi_ssid);
    // Emitted ONLY alongside an SSID, and only when non-empty. A bare
    // wifi_pass is meaningless, and an empty one is not "open network" here
    // the way it is over the cable — the device never auto-joins an open
    // network, so the only thing an empty string could do is overwrite a good
    // stored password with nothing. Absent means "switch to a network you
    // already remember".
    if (p.wifi_pass) wire.wifi_pass = String(p.wifi_pass);
  }
  if (p.panel_enabled != null) wire.panel_enabled = !!p.panel_enabled;
  if (Array.isArray(p.gemini_models) && p.gemini_models.length > 0) {
    // Dual-emit the per-device model override CSV under the new
    // "antigravity_models" key and the deprecated "gemini_models" key.
    // firmware/config_sync.c (post-rename) reads "antigravity_models";
    // deployed firmware reads "gemini_models". Mirror of Go pendingPayloadJSON.
    const csv = p.gemini_models.map(String).join(",");
    wire.antigravity_models = csv;
    wire.gemini_models = csv;
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

// --- Leader-mediated serial lease (compat/PROVISION_WIRE.md §6) -----------
//
// A follower that wants to open the USB port asks the leader to suspend its
// tailer. `leaseManager` is null on a host with no serial device configured
// (the tailer never runs) → 503 so the follower falls back to a direct open.
// Auth is the shared-PSK loopback HMAC with a MANDATORY body digest — an absent
// X-Tmon-Body-Sha256 is rejected (401) rather than silently downgraded to v2.
// Loopback-only, INDEPENDENT of the broker's bind address (the lease grants
// control of a HOST-LOCAL resource; the device PSK must not confer remote
// serial-ownership control).

const MAX_LEASE_BODY_BYTES = 4 << 10;

// isLoopbackAddr reports whether a socket peer address is a loopback IP. A
// missing/unparseable host fails closed (not loopback). Mirrors Go's
// net.IP.IsLoopback including IPv4-mapped IPv6 (::ffff:127.0.0.1).
function isLoopbackAddr(addr) {
  if (!addr) return false;
  let host = addr;
  const mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) host = mapped[1];
  if (host === "::1") return true;
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const o = m.slice(1).map(Number);
    if (o.some((x) => x > 255)) return false;
    return o[0] === 127; // 127.0.0.0/8
  }
  return false;
}

function handleSerialLease({ cfg, cache, logger, leaseManager, subpath }, req, res) {
  if (!leaseManager) {
    return writeError(res, 503, "serial port not configured on this host");
  }
  // RemoteAddr is the real TCP peer — never a spoofable Host/X-Forwarded-For.
  const peer = req.socket && req.socket.remoteAddress;
  if (!isLoopbackAddr(peer)) {
    logger.info(`lease ${subpath} rejected: non-loopback peer ${peer}`);
    return writeError(res, 403, "serial lease is loopback-only");
  }
  if (req.method !== "POST") {
    return writeError(res, 405, "method not allowed");
  }

  const cl = Number.parseInt(req.headers["content-length"] || "", 10);
  if (Number.isFinite(cl) && cl > MAX_LEASE_BODY_BYTES) return writeError(res, 413, "body too large");

  const chunks = [];
  let total = 0;
  let aborted = false;
  req.on("data", (c) => {
    total += c.length;
    if (total > MAX_LEASE_BODY_BYTES) {
      if (!aborted) {
        aborted = true;
        writeError(res, 413, "body too large");
      }
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on("error", () => {
    if (!aborted) {
      aborted = true;
      try {
        writeError(res, 400, "read error");
      } catch {}
    }
  });
  req.on("end", () => {
    if (aborted) return;
    const raw = Buffer.concat(chunks);

    const bodySHA = req.headers["x-tmon-body-sha256"] || "";
    if (!bodySHA) {
      // These endpoints mutate port ownership; refuse an unsigned body rather
      // than fall back to the v2 (body-blind) canonical.
      logger.info(`lease ${subpath} from ${req.socket && req.socket.remoteAddress}: missing body digest`);
      return writeError(res, 401, "unauthorized");
    }
    try {
      auth.verifyMultiBody(
        [cfg.psk()],
        "POST", subpath,
        req.headers["x-tmon-timestamp"] || "", req.headers["x-tmon-nonce"] || "", req.headers["x-tmon-signature"] || "",
        req.headers["x-tmon-device"] || "", req.headers["x-tmon-config-version"] || "",
        bodySHA, raw,
        cache, cfg.security.max_timestamp_skew_seconds,
      );
    } catch (e) {
      logger.info(`auth rejected ${subpath}: ${e.message}`);
      return writeError(res, 401, "unauthorized");
    }

    let body;
    try {
      body = JSON.parse(raw.toString("utf8"));
    } catch {
      body = null;
    }

    if (subpath === LEASE_PATH) return handleLeaseGrant(logger, leaseManager, body, res);
    if (subpath === LEASE_RENEW_PATH) return handleLeaseRenew(logger, leaseManager, body, res);
    if (subpath === LEASE_RELEASE_PATH) return handleLeaseRelease(leaseManager, body, res);
    return writeError(res, 404, "not found");
  });
}

// leaseTTL mirrors Go's json.Unmarshal into an int64 field: a missing ttl_ms is
// the zero value (0, later clamped to the minimum); a present ttl_ms must be an
// integer JSON number — a fractional/NaN/non-number value fails the unmarshal,
// which the caller reports as a 400. Returns null on a bad value.
function leaseTTL(v) {
  if (v === undefined || v === null) return 0;
  if (typeof v !== "number" || !Number.isInteger(v)) return null;
  // int64 range, because Go's unmarshal enforces it: a value Go answers 400 for
  // must not quietly clamp to the max here, or the same request gets two
  // different answers depending on which runtime is leader. (2^63 is not exact
  // in a double, so the comparison is deliberately against the boundary value
  // itself rather than 2^63 - 1.)
  if (v < -(2 ** 63) || v >= 2 ** 63) return null;
  return v;
}

async function handleLeaseGrant(logger, leaseManager, body, res) {
  if (!body || typeof body !== "object" || typeof body.port !== "string" || body.port === "") {
    return writeError(res, 400, "bad lease request");
  }
  const ttlMs = leaseTTL(body.ttl_ms);
  if (ttlMs === null) return writeError(res, 400, "bad lease request");
  let canonical;
  try {
    canonical = canonicalPort(body.port);
  } catch {
    return writeError(res, 400, "unresolvable port");
  }
  try {
    const { id, grantedMs, expiresUnixMs } = await leaseManager.Grant(canonical, ttlMs);
    // Field names are the cross-runtime contract (PROVISION_WIRE §6): `ttl_ms`,
    // and `port` echoing the CANONICAL path — the follower may have asked with
    // an alias, and it keys its own bookkeeping on what comes back.
    return writeJSON(res, 200, {
      lease_id: id,
      port: canonical,
      ttl_ms: grantedMs,
      expires_unix_ms: expiresUnixMs,
    });
  } catch (e) {
    if (e instanceof LeaseBusyError) {
      // PROVISION_WIRE §6: the 409 body is {"error":"busy","holder":...}. Grant
      // suspends the tailer before recording, so here the port is always busy
      // on a competing lease.
      return writeJSON(res, 409, { error: "busy", holder: "lease" });
    }
    logger.info(`lease grant ${canonical}: ${e.message}`);
    return writeError(res, 503, "cannot yield port");
  }
}

function handleLeaseRenew(logger, leaseManager, body, res) {
  if (!body || typeof body !== "object" || typeof body.lease_id !== "string" || body.lease_id === "") {
    return writeError(res, 400, "bad renew request");
  }
  // No ttl_ms is read here BY DESIGN (PROVISION_WIRE §6): the renew request
  // carries only the lease id and the manager re-applies the TTL it originally
  // granted, so a renew can never shrink the window. Honouring a ttl_ms would
  // clamp a conforming follower's lease — which sends none — to the 1 s floor.
  try {
    const { grantedMs, expiresUnixMs } = leaseManager.Renew(body.lease_id);
    return writeJSON(res, 200, { ttl_ms: grantedMs, expires_unix_ms: expiresUnixMs });
  } catch (e) {
    if (e instanceof LeaseUnknownError) {
      // 410 Gone: the lease lapsed or never existed → the follower MUST abort.
      return writeError(res, 410, "lease unknown or expired");
    }
    logger.info(`lease renew: ${e.message}`);
    return writeError(res, 500, "renew error");
  }
}

function handleLeaseRelease(leaseManager, body, res) {
  if (!body || typeof body !== "object" || typeof body.lease_id !== "string" || body.lease_id === "") {
    return writeError(res, 400, "bad release request");
  }
  // Idempotent: an unknown/expired id is still a success.
  leaseManager.Release(body.lease_id);
  return writeJSON(res, 200, { ok: true });
}
