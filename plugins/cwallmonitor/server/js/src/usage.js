// Per-provider usage fetchers + TTL cache.
// Wire-compatible with cwm-mcp Go internal/usage and cwm-mcp-py cwm_mcp.usage.
// See compat/USAGE_WIRE.md for the JSON shape served at /usage/{provider}.

import { existsSync, readFileSync } from "node:fs";
import { resolveGeminiOAuthClient } from "./geminiOAuthClient.js";

export const PROVIDER_CLAUDE = "claude";
export const PROVIDER_CODEX = "codex";
export const PROVIDER_GEMINI = "gemini";

// Error sentinels — broker maps each to an HTTP status. Carrying the
// class identity (instead of a tagged string) lets the broker keep using
// `instanceof` and TypeScript-style narrowing if it ever migrates.
export class UsageError extends Error {}
export class CredsMissing extends UsageError {}
export class TokenExpired extends UsageError {}
export class Unauthorized extends UsageError {}
export class RateLimited extends UsageError {
  constructor(retryAfter = 0) {
    super("rate limited");
    this.retryAfter = retryAfter;
  }
}
export class Upstream extends UsageError {}
export class Transport extends UsageError {}
export class ParseUpstream extends UsageError {}
export class NotImplementedProvider extends UsageError {}

function emptySnapshot() {
  return {
    session_pct: 0,
    weekly_pct: 0,
    design_pct: 0,
    design_present: false,
    session_reset_eta_seconds: 0,
    weekly_reset_eta_seconds: 0,
    design_reset_eta_seconds: 0,
    session_window_seconds: 0,
    weekly_window_seconds: 0,
    tier: "unknown",
    fetched_at_unix: 0,
    stale_seconds: 0,
    slots: [],
  };
}

// -----------------------------------------------------------------------
// Cache
// -----------------------------------------------------------------------

export class Cache {
  constructor(ttlSeconds, fetchers) {
    this.ttlMs = Math.max(1, ttlSeconds) * 1000;
    this.fetchers = fetchers;            // { [provider]: { fetch(): Promise<Snapshot> } }
    this.entries = new Map();            // provider -> { snap, fetched }
    this.inflight = new Map();           // provider -> Promise<Snapshot>
    this.now = () => Date.now();
  }

  providers() {
    return Object.keys(this.fetchers).sort();
  }

  geminiFetcher() {
    // Return the wired GeminiFetcher for the per-device override path,
    // or null if Gemini is disabled.
    const f = this.fetchers[PROVIDER_GEMINI];
    return f instanceof GeminiFetcher ? f : null;
  }

  async get(provider) {
    const f = this.fetchers[provider];
    if (!f) throw new NotImplementedProvider(`provider ${provider} not enabled`);
    const now = this.now();
    const entry = this.entries.get(provider);
    if (entry && now - entry.fetched < this.ttlMs) {
      const snap = { ...entry.snap, stale_seconds: Math.floor((now - entry.fetched) / 1000) };
      return snap;
    }
    let pending = this.inflight.get(provider);
    if (!pending) {
      pending = this._refresh(provider, f);
      this.inflight.set(provider, pending);
    }
    try {
      return await pending;
    } catch (e) {
      // Stale-with-error: re-attach the previous snapshot if any so the
      // broker can choose between serving stale-200 and propagating the
      // error to the firmware.
      const cached = this.entries.get(provider);
      if (cached) {
        e.staleSnapshot = { ...cached.snap, stale_seconds: Math.floor((this.now() - cached.fetched) / 1000) };
      }
      throw e;
    }
  }

  async _refresh(provider, fetcher) {
    try {
      const snap = await fetcher.fetch();
      const now = this.now();
      snap.fetched_at_unix = Math.floor(now / 1000);
      snap.stale_seconds = 0;
      this.entries.set(provider, { snap, fetched: now });
      return snap;
    } finally {
      this.inflight.delete(provider);
    }
  }
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

function secondsUntilISO(iso, nowMs) {
  if (!iso) return 0;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return 0;
  const eta = Math.floor((t - nowMs) / 1000);
  return Math.max(0, eta);
}

function retryAfterFromHeaders(headers) {
  const v = headers.get("retry-after");
  if (!v) return 0;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return Math.floor(n);
  const t = Date.parse(v);
  if (Number.isFinite(t)) {
    const eta = Math.floor((t - Date.now()) / 1000);
    if (eta > 0) return eta;
  }
  return 0;
}

async function readJSON(resp) {
  try {
    return await resp.json();
  } catch (e) {
    throw new ParseUpstream(`json: ${e.message}`);
  }
}

async function doFetch(url, init, timeoutMs = 15000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } catch (e) {
    throw new Transport(`${e.name}: ${e.message}`);
  } finally {
    clearTimeout(timer);
  }
}

// -----------------------------------------------------------------------
// Claude
// -----------------------------------------------------------------------

const CLAUDE_URL = "https://api.anthropic.com/api/oauth/usage";
const CLAUDE_BETA = "oauth-2025-04-20";
const CLAUDE_SESSION_WINDOW = 5 * 3600;
const CLAUDE_WEEKLY_WINDOW = 7 * 86400;

export class ClaudeFetcher {
  constructor({ oauthPath, loadCreds }) {
    this.oauthPath = oauthPath;
    this.loadCreds = loadCreds;          // injected creds.load (avoids circular import)
  }
  async fetch() {
    let c;
    try {
      c = this.loadCreds(this.oauthPath);
    } catch (e) {
      if (e.name === "CredsFileMissing") throw new CredsMissing(e.message);
      throw new ParseUpstream(e.message);
    }
    if (c.isExpired(Date.now())) throw new TokenExpired("token expired, refresh on laptop");

    const resp = await doFetch(CLAUDE_URL, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${c.accessToken}`,
        "anthropic-beta": CLAUDE_BETA,
        "Accept": "application/json",
      },
    });
    if (resp.status === 401) throw new Unauthorized("upstream rejected token");
    if (resp.status === 429) throw new RateLimited(retryAfterFromHeaders(resp.headers));
    if (resp.status < 200 || resp.status >= 300) throw new Upstream(`status=${resp.status}`);
    const doc = await readJSON(resp);

    const now = Date.now();
    const snap = emptySnapshot();
    snap.session_window_seconds = CLAUDE_SESSION_WINDOW;
    snap.weekly_window_seconds = CLAUDE_WEEKLY_WINDOW;
    const five = doc.five_hour;
    const seven = doc.seven_day;
    const ome = doc.seven_day_omelette;
    if (five && typeof five === "object") {
      snap.session_pct = Number(five.utilization || 0);
      snap.session_reset_eta_seconds = secondsUntilISO(five.resets_at || "", now);
    }
    if (seven && typeof seven === "object") {
      snap.weekly_pct = Number(seven.utilization || 0);
      snap.weekly_reset_eta_seconds = secondsUntilISO(seven.resets_at || "", now);
    }
    if (ome && typeof ome === "object") {
      snap.design_present = true;
      snap.design_pct = Number(ome.utilization || 0);
      snap.design_reset_eta_seconds = secondsUntilISO(ome.resets_at || "", now);
    }
    const extra = doc.extra_usage || {};
    snap.tier = extra.is_enabled ? "paid" : "unknown";
    return snap;
  }
}

// -----------------------------------------------------------------------
// Codex
// -----------------------------------------------------------------------

const CODEX_URL = "https://chatgpt.com/backend-api/wham/usage";
const CODEX_SESSION_FALLBACK = 5 * 3600;
const CODEX_WEEKLY_FALLBACK = 7 * 86400;

export class CodexFetcher {
  constructor({ authPath, loadCodex }) {
    this.authPath = authPath;
    this.loadCodex = loadCodex;
  }
  async fetch() {
    let c;
    try {
      c = this.loadCodex(this.authPath);
    } catch (e) {
      if (e.name === "CredsFileMissing") throw new CredsMissing(e.message);
      throw new ParseUpstream(e.message);
    }
    if (c.isExpired(Date.now())) throw new TokenExpired("token expired, refresh on laptop");

    const resp = await doFetch(CODEX_URL, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${c.accessToken}`,
        "ChatGPT-Account-Id": c.accountId,
        "Accept": "application/json",
        "User-Agent": "cwm-mcp/usage",
        "OpenAI-Beta": "chatgpt-account=enabled",
      },
    });
    if (resp.status === 401) throw new Unauthorized("upstream rejected token");
    if (resp.status === 429) throw new RateLimited(retryAfterFromHeaders(resp.headers));
    if (resp.status < 200 || resp.status >= 300) throw new Upstream(`status=${resp.status}`);
    const doc = await readJSON(resp);

    const snap = emptySnapshot();
    snap.session_window_seconds = CODEX_SESSION_FALLBACK;
    snap.weekly_window_seconds = CODEX_WEEKLY_FALLBACK;
    snap.tier = String(doc.plan_type || "unknown");
    const rl = doc.rate_limit || {};
    const primary = rl.primary_window;
    const secondary = rl.secondary_window;
    if (primary && typeof primary === "object") {
      snap.session_pct = Number(primary.used_percent || 0);
      const lim = Number(primary.limit_window_seconds);
      if (Number.isFinite(lim) && lim > 0) snap.session_window_seconds = lim;
      snap.session_reset_eta_seconds = codexEta(primary);
    }
    if (secondary && typeof secondary === "object") {
      snap.weekly_pct = Number(secondary.used_percent || 0);
      const lim = Number(secondary.limit_window_seconds);
      if (Number.isFinite(lim) && lim > 0) snap.weekly_window_seconds = lim;
      snap.weekly_reset_eta_seconds = codexEta(secondary);
    }
    return snap;
  }
}

function codexEta(win) {
  if (typeof win.reset_after_seconds === "number") return Math.max(0, Math.floor(win.reset_after_seconds));
  if (typeof win.reset_at === "number") {
    const eta = Math.floor(win.reset_at - Date.now() / 1000);
    return Math.max(0, eta);
  }
  return 0;
}

// -----------------------------------------------------------------------
// Gemini
// -----------------------------------------------------------------------

const GEMINI_CODE_ASSIST = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist";
const GEMINI_USER_QUOTA = "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota";
const GEMINI_TOKEN_URL = "https://oauth2.googleapis.com/token";
// Gemini only has a daily quota — no weekly window. We surface the
// Pro bucket (the headline model users care about most) as session
// (24h) and leave weekly empty so the device hides that card.
const GEMINI_SESSION_FALLBACK = 86400;
const GEMINI_SESSION_MODEL = "gemini-2.5-pro";

export class GeminiFetcher {
  constructor({ credsPath, projectsPath, models = [], modelsFor = null } = {}) {
    this.credsPath = credsPath;
    this.projectsPath = projectsPath;
    // Ordered list of model IDs to expose as Snapshot.slots. Empty
    // falls back to the single Pro bucket; first matched model is
    // mirrored into session_pct for legacy firmware.
    this.models = models;
    // Optional per-request hook (returns string[]). When set, this
    // takes precedence over `models` and lets the broker honour a
    // per-device override stored in the registry.
    this.modelsFor = modelsFor;
    this._cachedToken = { token: "", expiresAtMs: 0 };
  }

  _modelsForRequest() {
    if (typeof this.modelsFor === "function") {
      const m = this.modelsFor();
      if (Array.isArray(m) && m.length > 0) return m;
    }
    if (this.models && this.models.length > 0) return this.models;
    return [GEMINI_SESSION_MODEL];
  }

  async fetchWithModels(models) {
    // Same upstream call as fetch() but honour the supplied model
    // slice (per-device override). Token cache is reused since we
    // share the receiver — the model list is passed via parameter.
    return this._fetchInternal(models);
  }

  async fetch() {
    return this._fetchInternal(this._modelsForRequest());
  }

  async _fetchInternal(models) {
    const tok = await this._token();
    const body = {
      metadata: {
        ideType: "IDE_UNSPECIFIED",
        platform: "PLATFORM_UNSPECIFIED",
        pluginType: "GEMINI",
      },
    };
    const proj = this._activeProject();
    if (proj) {
      body.cloudaicompanionProject = proj;
      body.metadata.duetProject = proj;
    }
    const resp = await doFetch(GEMINI_CODE_ASSIST, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${tok}`,
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify(body),
    }, 20000);
    if (resp.status === 401) throw new Unauthorized("upstream rejected token");
    if (resp.status === 429) throw new RateLimited(retryAfterFromHeaders(resp.headers));
    if (resp.status < 200 || resp.status >= 300) throw new Upstream(`status=${resp.status}`);
    const doc = await readJSON(resp);

    const snap = emptySnapshot();
    snap.session_window_seconds = GEMINI_SESSION_FALLBACK;
    snap.weekly_window_seconds = 0;
    if (doc.paidTier && typeof doc.paidTier === "object") {
      snap.tier = String(doc.paidTier.id || "paid");
    } else if (doc.currentTier && typeof doc.currentTier === "object") {
      snap.tier = String(doc.currentTier.id || "unknown");
    }

    // retrieveUserQuota is the endpoint gemini-cli itself polls for its
    // usage UI: both free and paid tiers return per-model buckets with
    // remainingFraction and resetTime. Without this the device stays at
    // 0 % even when the account has been heavily used.
    const quotaProj = String(doc.cloudaicompanionProject || "") || this._activeProject();
    try {
      const quota = await this._fetchQuota(tok, quotaProj);
      if (quota) geminiApplyQuota(snap, quota, Date.now() / 1000, models);
    } catch {
      // ignore — fall back to tier-only snapshot
    }
    return snap;
  }

  async _fetchQuota(token, project) {
    const body = project ? { project } : {};
    const resp = await doFetch(GEMINI_USER_QUOTA, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify(body),
    }, 20000);
    if (resp.status < 200 || resp.status >= 300) return null;
    return await readJSON(resp);
  }

  async _token() {
    const nowMs = Date.now();
    if (this._cachedToken.token && this._cachedToken.expiresAtMs - nowMs > 60_000) {
      return this._cachedToken.token;
    }
    if (!existsSync(this.credsPath)) throw new CredsMissing(`gemini creds file missing: ${this.credsPath}`);
    let disk;
    try {
      disk = JSON.parse(readFileSync(this.credsPath, "utf8"));
    } catch (e) {
      throw new ParseUpstream(`gemini creds parse error: ${e.message}`);
    }
    const access = disk.access_token || "";
    const refresh = disk.refresh_token || "";
    const expiry = Number(disk.expiry_date || 0);
    if (access && expiry - nowMs > 60_000) {
      this._cachedToken = { token: access, expiresAtMs: expiry };
      return access;
    }
    if (!refresh) throw new TokenExpired("token expired and no refresh_token available");

    const oauth = await resolveGeminiOAuthClient({ fetchImpl: doFetch });
    const form = new URLSearchParams({
      client_id: oauth.clientId,
      client_secret: oauth.clientSecret,
      grant_type: "refresh_token",
      refresh_token: refresh,
    });
    const resp = await doFetch(GEMINI_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    if (resp.status < 200 || resp.status >= 300) {
      const text = await resp.text().catch(() => "");
      throw new Unauthorized(`refresh failed: status=${resp.status} body=${text.slice(0, 200)}`);
    }
    const out = await readJSON(resp);
    const newTok = out.access_token || "";
    if (!newTok) throw new ParseUpstream("refresh returned empty access_token");
    const newExp = nowMs + Number(out.expires_in || 3600) * 1000;
    this._cachedToken = { token: newTok, expiresAtMs: newExp };
    return newTok;
  }

  _activeProject() {
    if (!existsSync(this.projectsPath)) return "";
    try {
      const doc = JSON.parse(readFileSync(this.projectsPath, "utf8"));
      const projects = doc?.projects || {};
      for (const v of Object.values(projects)) return String(v);
    } catch {
      // Ignore — empty project is acceptable to loadCodeAssist.
    }
    return "";
  }
}

function geminiPickBucket(buckets, modelId) {
  for (const b of buckets) {
    if (b && b.modelId === modelId) return b;
  }
  // Prefix fallback covers version drift (e.g. -flash → -flash-002).
  for (const b of buckets) {
    if (b && typeof b.modelId === "string" && b.modelId.startsWith(modelId)) return b;
  }
  return null;
}

function geminiUsedPct(remainingFraction) {
  let r = Number(remainingFraction);
  if (!Number.isFinite(r) || r < 0) r = 0;
  else if (r > 1) r = 1;
  return (1 - r) * 100;
}

function geminiResetEta(iso, nowSec) {
  if (!iso) return 0;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return 0;
  const eta = Math.floor(t / 1000 - nowSec);
  return Math.max(0, eta);
}

function geminiApplyQuota(snap, quota, nowSec, models) {
  const buckets = Array.isArray(quota?.buckets) ? quota.buckets : [];
  let list = Array.isArray(models) && models.length > 0 ? models : [GEMINI_SESSION_MODEL];
  if (list.length > 3) list = list.slice(0, 3);
  let first = true;
  for (const m of list) {
    const b = geminiPickBucket(buckets, m);
    if (!b) continue;
    const pct = geminiUsedPct(b.remainingFraction);
    const eta = geminiResetEta(b.resetTime, nowSec);
    snap.slots.push({
      label: geminiLabel(m),
      pct,
      window_seconds: GEMINI_SESSION_FALLBACK,
      reset_eta_seconds: eta,
    });
    if (first) {
      snap.session_pct = pct;
      snap.session_reset_eta_seconds = eta;
      first = false;
    }
  }
}

// Pill text rendered on the dashboard card. "gemini-2.5-pro" → "Pro".
function geminiLabel(modelId) {
  let tail = String(modelId || "");
  if (tail.startsWith("gemini-")) {
    tail = tail.slice("gemini-".length);
    const idx = tail.indexOf("-");
    if (idx >= 0) tail = tail.slice(idx + 1);
  }
  if (!tail) return modelId;
  const parts = tail.split("-").map((p) => (p ? p[0].toUpperCase() + p.slice(1) : p));
  const out = parts.join("-");
  return out.length > 15 ? out.slice(0, 15) : out;
}

// -----------------------------------------------------------------------
// Factory
// -----------------------------------------------------------------------

export function buildCache(cfg, { credsModule, logger } = {}) {
  // credsModule is creds.js — passed in so we don't create a cycle when
  // creds.js eventually wants to consume usage.js types in tests.
  const fetchers = {
    [PROVIDER_CLAUDE]: new ClaudeFetcher({
      oauthPath: cfg.oauthPathAbs(),
      loadCreds: credsModule.load,
    }),
  };
  if (cfg.codex?.enabled) {
    fetchers[PROVIDER_CODEX] = new CodexFetcher({
      authPath: cfg.codexAuthPathAbs(),
      loadCodex: credsModule.loadCodex,
    });
  }
  if (cfg.gemini?.enabled) {
    fetchers[PROVIDER_GEMINI] = new GeminiFetcher({
      credsPath: cfg.geminiCredsPathAbs(),
      projectsPath: cfg.geminiProjectsPathAbs(),
      models: cfg.geminiModels ? cfg.geminiModels() : [],
    });
  }
  const ttl = cfg.usage?.cache_ttl_seconds || 30;
  logger?.info?.(`usage: providers=${Object.keys(fetchers).sort()} cache_ttl=${ttl}s`);
  return new Cache(ttl, fetchers);
}
