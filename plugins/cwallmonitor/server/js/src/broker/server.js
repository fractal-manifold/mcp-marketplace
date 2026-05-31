// HTTP broker: /credentials, /credentials/codex, /device/<id>/sync,
// /firmware-logs, /usage/{claude,codex,gemini}.
// Wire-compatible with cwm-mcp/internal/broker/server.go.

import * as auth from "../auth.js";
import * as creds from "../creds.js";
import * as usage from "../usage.js";
import { encryptPending } from "../registry/crypto.js";
import { NotFound, validDeviceID } from "../registry/store.js";
import { firmwarePath } from "../config.js";
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

export function createHandler({ cfg, cache, state, fwLogs, registry, logger, usageCache }) {
  return (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const path = url.pathname;
    if (path === "/credentials" && req.method === "GET") return handleCredentials({ cfg, cache, state, registry, logger }, req, res);
    if (path === "/credentials/codex" && req.method === "GET") return handleCredentialsCodex({ cfg, cache, state, registry, logger }, req, res);
    if (path === "/firmware-logs" && req.method === "GET") return handleFirmwareLogs({ cfg, cache, fwLogs, logger }, req, res, url);
    const usageMatch = path.match(/^\/usage\/([^/]+)$/);
    if (usageMatch && req.method === "GET") {
      return handleUsage({ cfg, cache, state, registry, logger, usageCache, provider: usageMatch[1] }, req, res);
    }
    const m = path.match(/^\/device\/([^/]+)\/sync$/);
    if (m && req.method === "GET") return handleDeviceSync({ cfg, cache, state, registry, logger, deviceID: m[1] }, req, res);
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
  const devID = req.headers["x-cwm-device"];
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
      req.headers["x-cwm-timestamp"] || "",
      req.headers["x-cwm-nonce"] || "",
      req.headers["x-cwm-signature"] || "",
      req.headers["x-cwm-device"] || "",
      req.headers["x-cwm-config-version"] || "",
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
    res.setHeader("X-Cwm-Firmware-SHA256", sha);
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
  const deviceID = req.headers["x-cwm-device"];
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
        req.headers["x-cwm-timestamp"], req.headers["x-cwm-nonce"], req.headers["x-cwm-signature"],
        req.headers["x-cwm-device"] || "", req.headers["x-cwm-config-version"] || "",
        cache, cfg.security.max_timestamp_skew_seconds,
      );
    } catch (e) { logger.info(`auth rejected ${path} device=${deviceID}: ${e.message}`); recordStatus.s = 401; writeError(res, 401, "unauthorized"); return false; }
    const obs = parseUint32(req.headers["x-cwm-config-version"] || "");
    try { registry.maybePromote(deviceID, obs, res2.pskIndex === 1); } catch (e) { logger.warn(`promote ${deviceID}: ${e.message}`); }
    try { registry.touch(deviceID); } catch (e) { logger.warn(`touch ${deviceID}: ${e.message}`); }
    return true;
  }
  try {
    auth.verify(
      cfg.psk(),
      "GET", path,
      req.headers["x-cwm-timestamp"], req.headers["x-cwm-nonce"], req.headers["x-cwm-signature"],
      req.headers["x-cwm-device"] || "", req.headers["x-cwm-config-version"] || "",
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
    const deviceID = req.headers["x-cwm-device"] || "";
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
      res.setHeader("X-Cwm-Stale-Reason", e.message);
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

function handleCredentials({ cfg, cache, state, registry, logger }, req, res) {
  let recordStatus = 200;
  const finish = (status, body) => { recordStatus = status; writeJSON(res, status, body); };
  const finishErr = (status, msg) => { recordStatus = status; writeError(res, status, msg); };
  res.on("close", () => { try { state.recordRequest(req.socket.remoteAddress || "", recordStatus); } catch {} });

  const deviceID = req.headers["x-cwm-device"];
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
          req.headers["x-cwm-timestamp"], req.headers["x-cwm-nonce"], req.headers["x-cwm-signature"],
          req.headers["x-cwm-device"] || "", req.headers["x-cwm-config-version"] || "",
          cache, cfg.security.max_timestamp_skew_seconds,
        );
      } catch (e) { logger.info(`auth rejected /credentials device=${deviceID}: ${e.message}`); return finishErr(401, "unauthorized"); }
      {
        const obs = parseUint32(req.headers["x-cwm-config-version"] || "");
        try { registry.maybePromote(deviceID, obs, res2.pskIndex === 1); } catch (e) { logger.warn(`promote ${deviceID}: ${e.message}`); }
      }
      try { registry.touch(deviceID); } catch (e) { logger.warn(`touch ${deviceID}: ${e.message}`); }
    } else {
      try {
        auth.verify(
          cfg.psk(),
          "GET", "/credentials",
          req.headers["x-cwm-timestamp"], req.headers["x-cwm-nonce"], req.headers["x-cwm-signature"],
          req.headers["x-cwm-device"] || "", req.headers["x-cwm-config-version"] || "",
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
      req.headers["x-cwm-timestamp"], req.headers["x-cwm-nonce"], req.headers["x-cwm-signature"],
      req.headers["x-cwm-device"] || "", req.headers["x-cwm-config-version"] || "",
      cache, cfg.security.max_timestamp_skew_seconds,
    );
  } catch (e) { logger.info(`auth rejected /firmware-logs: ${e.message}`); return writeError(res, 401, "unauthorized"); }
  let limit = 200;
  const raw = url.searchParams.get("limit");
  if (raw != null) {
    const n = Number.parseInt(raw, 10);
    if (Number.isFinite(n)) limit = Math.max(1, Math.min(2000, n));
  }
  const body = fwLogs ? fwLogs(limit) : { connected: false, total_available: 0, lines: [] };
  return writeJSON(res, 200, body);
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
      req.headers["x-cwm-timestamp"], req.headers["x-cwm-nonce"], req.headers["x-cwm-signature"],
      req.headers["x-cwm-device"] || "", req.headers["x-cwm-config-version"] || "",
      cache, cfg.security.max_timestamp_skew_seconds,
    );
  } catch (e) { logger.info(`auth rejected ${signedPath}: ${e.message}`); return finishErr(401, "unauthorized"); }

  const observed = parseUint32(req.headers["x-cwm-config-version"] || "");
  try { registry.maybePromote(deviceID, observed, res2.pskIndex === 1); } catch (e) { logger.warn(`promote: ${e.message}`); }
  try { registry.touch(deviceID); } catch (e) { logger.warn(`touch: ${e.message}`); }
  // Schema v2: capture factory identity from headers. Not bound to
  // HMAC — metadata only; the Ed25519 manifest enforces SKU.
  const serialHdr = String(req.headers["x-cwm-serial"] || "");
  if (serialHdr) {
    try { registry.setSerial(deviceID, serialHdr, String(req.headers["x-cwm-sku"] || "")); }
    catch (e) { logger.warn(`set-serial: ${e.message}`); }
  }
  // Mirror anti-rollback floor. bumpMinSV is monotonic, so a spoofed-high
  // value only locks the device into rejecting downgrades.
  const minSvHdr = String(req.headers["x-cwm-min-sv"] || "");
  if (minSvHdr) {
    const sv = Number.parseInt(minSvHdr, 10);
    if (Number.isFinite(sv) && sv >= 0 && sv <= 0xFFFFFFFF) {
      try { registry.bumpMinSV(deviceID, sv); }
      catch (e) { logger.warn(`bump-min-sv: ${e.message}`); }
    }
  }

  const dev = registry.load(deviceID);
  const out = { active_version: dev.active.payload.version };
  if (dev.pending && observed < dev.pending.payload.version) {
    if (!active || active.length !== 32) return finishErr(500, "broker config invalid");
    const pt = Buffer.from(pendingPayloadJSON(dev.pending.payload), "utf8");
    const { nonce, ciphertext } = encryptPending(active, pt);
    out.pending = {
      version: dev.pending.payload.version,
      nonce_b64: nonce.toString("base64"),
      payload_b64: ciphertext.toString("base64"),
    };
  }
  return finish(200, out);
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
  if (p.providers) wire.providers = { claude: p.providers.claude, codex: p.providers.codex, gemini: p.providers.gemini };
  if (p.autorotate_enabled != null) wire.autorotate_enabled = p.autorotate_enabled;
  if (p.autorotate_interval_s != null) wire.autorotate_interval_s = p.autorotate_interval_s;
  // firmware/config_sync.c reads "theme_mode" from the decrypted blob
  // and writes it to KEY_THEME_MD. Omitting it here would silently
  // no-op /wall-monitor:theme switches.
  if (p.theme_mode) wire.theme_mode = p.theme_mode;
  if (Array.isArray(p.gemini_models) && p.gemini_models.length > 0) {
    // firmware/config_sync.c reads "gemini_models" as a CSV string and
    // writes it to NVS key cwm_gem_mdls.
    wire.gemini_models = p.gemini_models.map(String).join(",");
  }
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
  // Go's json.Marshal on map[string]any sorts keys alphabetically and
  // Python uses sort_keys=True; mirror both so the AES-CTR ciphertext
  // is deterministic across runtimes. Recursive — `providers` is a
  // nested object whose own keys must also sort.
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
