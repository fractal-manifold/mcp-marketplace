// Per-provider usage fetchers + TTL cache.
// Wire-compatible with tokenmonitor-mcp Go internal/usage and tokenmonitor-mcp-py tmon_mcp.usage.
// See compat/USAGE_WIRE.md for the JSON shape served at /usage/{provider}.

import { execFileSync } from "node:child_process";

export const PROVIDER_CLAUDE = "claude";
export const PROVIDER_CODEX = "codex";
export const PROVIDER_ANTIGRAVITY = "antigravity";
// PROVIDER_GEMINI is the DEPRECATED pre-rename wire string for the Antigravity
// provider (Google retired the Gemini CLI 2026-06-18). Deployed firmware still
// polls /usage/gemini and signs that exact path, so the broker keeps it as an
// alias: canonicalProvider() maps it to PROVIDER_ANTIGRAVITY AFTER the HMAC
// check, never before.
export const PROVIDER_GEMINI = "gemini";

// canonicalProvider folds the deprecated "gemini" wire alias onto the
// canonical "antigravity" provider key used for cache/fetcher lookup. Call it
// only AFTER verifying the request signature against the original path.
export function canonicalProvider(p) {
  return p === PROVIDER_GEMINI ? PROVIDER_ANTIGRAVITY : p;
}

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

  antigravityFetcher() {
    // Return the wired AntigravityFetcher for the per-device override path,
    // or null if Antigravity is disabled.
    const f = this.fetchers[PROVIDER_ANTIGRAVITY];
    return f instanceof AntigravityFetcher ? f : null;
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
        "User-Agent": "tokenmonitor-mcp/usage",
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
// Antigravity (agy, successor to the retired Gemini CLI)
// -----------------------------------------------------------------------

// Antigravity's grouped weekly quota is served from the `daily-` CANARY host,
// not prod cloudcode-pa (prod 403s the quota RPC). Verified end-to-end via a
// mitmproxy capture of agy 1.0.13 (2026-06-30) — see the project memory
// "agy-antigravity-cli-format" for the full recipe.
const ANTIGRAVITY_HOST = "https://daily-cloudcode-pa.googleapis.com/v1internal:";
const GEMINI_CODE_ASSIST = ANTIGRAVITY_HOST + "loadCodeAssist";
const GEMINI_USER_QUOTA = ANTIGRAVITY_HOST + "retrieveUserQuotaSummary";
// retrieveUserQuotaSummary is a PRIVATE API gated on the registered client
// User-Agent: without it Google returns 403 PERMISSION_DENIED; with agy's exact
// UA it returns 200. Send it on every call.
const ANTIGRAVITY_UA = "antigravity/cli/1.0.13 (aidev_client; os_type=linux; arch=amd64)";
// Antigravity quota is a WEEKLY per-group limit (Gemini Models / Claude+GPT);
// there is no daily/session window, so the device hides the session card.
const ANTIGRAVITY_WEEKLY = 604800;
// OS keyring service under which agy stores its consumer OAuth token. The token
// is a JSON value {token:{access_token,refresh_token,expiry},…}; only the
// access_token is read here (agy keeps it fresh while it runs).
const ANTIGRAVITY_KEYRING_SERVICE = "gemini";

// readKeyringToken pulls agy's consumer OAuth token from the OS keyring
// (libsecret) via `secret-tool`. The quota RPC requires THIS token — the
// gemini-cli token in oauth_creds.json authenticates loadCodeAssist but is
// rejected (403) by the quota endpoint. Returns the inner token object, or
// null on any failure (no secret-tool, locked/empty keyring, bad JSON) so the
// fetcher degrades to "--" rather than crashing.
function readKeyringToken(service) {
  let raw;
  try {
    raw = execFileSync("secret-tool", ["lookup", "service", service], {
      encoding: "utf8",
      timeout: 5000,
    });
  } catch {
    return null;
  }
  try {
    const d = JSON.parse(raw);
    return d && typeof d.token === "object" ? d.token : null;
  } catch {
    return null;
  }
}

export class AntigravityFetcher {
  constructor({ keyringService = ANTIGRAVITY_KEYRING_SERVICE, models = [], modelsFor = null } = {}) {
    this.keyringService = keyringService;
    // models/modelsFor are retained for call-site compatibility with the
    // per-device override path; the quota is now grouped (Gemini Models /
    // Claude+GPT), not per-model, so they no longer affect the result.
    this.models = models;
    this.modelsFor = modelsFor;
    this._cachedToken = { token: "", expiresAtMs: 0 };
  }

  async fetchWithModels() {
    // Grouped quota ignores the per-device model slice; kept for call-site compat.
    return this._fetchInternal();
  }

  async fetch() {
    return this._fetchInternal();
  }

  async _fetchInternal() {
    const tok = this._token();
    const resp = await doFetch(GEMINI_CODE_ASSIST, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${tok}`,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": ANTIGRAVITY_UA,
      },
      // agy sends exactly this: ideType ANTIGRAVITY, no pluginType. The
      // response carries cloudaicompanionProject, used for the quota call.
      body: JSON.stringify({ metadata: { ideType: "ANTIGRAVITY" } }),
    }, 20000);
    if (resp.status === 401) throw new Unauthorized("upstream rejected token");
    if (resp.status === 429) throw new RateLimited(retryAfterFromHeaders(resp.headers));
    if (resp.status < 200 || resp.status >= 300) throw new Upstream(`status=${resp.status}`);
    const doc = await readJSON(resp);

    const snap = emptySnapshot();
    // Weekly-only quota: hide the session/daily card, surface the weekly one.
    snap.session_window_seconds = 0;
    snap.weekly_window_seconds = ANTIGRAVITY_WEEKLY;
    if (doc.paidTier && typeof doc.paidTier === "object") {
      snap.tier = String(doc.paidTier.id || "paid");
    } else if (doc.currentTier && typeof doc.currentTier === "object") {
      snap.tier = String(doc.currentTier.id || "unknown");
    }

    const project = String(doc.cloudaicompanionProject || "");
    try {
      const quota = await this._fetchQuota(tok, project);
      if (quota) antigravityApplyQuota(snap, quota, Date.now() / 1000);
    } catch {
      // ignore — fall back to tier-only snapshot
    }
    return snap;
  }

  async _fetchQuota(token, project) {
    // retrieveUserQuotaSummary requires a top-level `project` (empty body → 403)
    // and rejects loadCodeAssist-style metadata fields. Verified 2026-06-30.
    const body = {};
    if (project) body.project = project;
    const resp = await doFetch(GEMINI_USER_QUOTA, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": ANTIGRAVITY_UA,
      },
      body: JSON.stringify(body),
    }, 20000);
    if (resp.status < 200 || resp.status >= 300) return null;
    return await readJSON(resp);
  }

  // Read-only: agy's consumer token from the keyring. Per the maintainer's
  // choice we do NOT refresh it here — agy keeps it fresh while it runs. A
  // missing/expired token surfaces as CredsMissing/TokenExpired, which the
  // broker maps to 404/503 and the device renders as "--".
  _token() {
    const nowMs = Date.now();
    if (this._cachedToken.token && this._cachedToken.expiresAtMs - nowMs > 60_000) {
      return this._cachedToken.token;
    }
    const t = readKeyringToken(this.keyringService);
    if (!t || !t.access_token) {
      throw new CredsMissing(`antigravity keyring token not found (service="${this.keyringService}"; sign in with agy)`);
    }
    const expMs = Date.parse(t.expiry || "") || 0;
    if (expMs && expMs - nowMs < 60_000) {
      throw new TokenExpired("antigravity keyring token expired (run agy to refresh it)");
    }
    this._cachedToken = { token: t.access_token, expiresAtMs: expMs || (nowMs + 300_000) };
    return t.access_token;
  }
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

// antigravityApplyQuota maps the real retrieveUserQuotaSummary response —
// {groups:[{displayName,description,buckets:[{window,resetTime,remainingFraction}]}]}
// — onto the device snapshot. Each group becomes one weekly slot; the
// "Gemini Models" group drives the headline weekly bar (maintainer's choice),
// falling back to the first group if no Gemini group is present. Verified
// against a live capture (agy 1.0.13, 2026-06-30).
function antigravityApplyQuota(snap, quota, nowSec) {
  const groups = Array.isArray(quota?.groups) ? quota.groups : [];
  let headlineSet = false;
  for (const g of groups) {
    const gbuckets = Array.isArray(g?.buckets) ? g.buckets : [];
    const b = gbuckets.find((x) => x && x.window === "weekly") || gbuckets[0];
    if (!b) continue;
    const pct = geminiUsedPct(b.remainingFraction);
    const eta = geminiResetEta(b.resetTime, nowSec);
    snap.slots.push({
      label: antigravityGroupLabel(g.displayName),
      pct,
      window_seconds: ANTIGRAVITY_WEEKLY,
      reset_eta_seconds: eta,
    });
    const isGemini = /gemini/i.test(String(g.displayName || "")) ||
      String(b.bucketId || "").toLowerCase().startsWith("gemini");
    if (isGemini && !headlineSet) {
      snap.weekly_pct = pct;
      snap.weekly_reset_eta_seconds = eta;
      headlineSet = true;
    }
  }
  if (!headlineSet && snap.slots.length > 0) {
    snap.weekly_pct = snap.slots[0].pct;
    snap.weekly_reset_eta_seconds = snap.slots[0].reset_eta_seconds;
  }
}

// Group pill label: "Gemini Models" → "Gemini", "Claude and GPT models" →
// "Claude and GPT". Capped to the device's 15-char slot label budget.
function antigravityGroupLabel(displayName) {
  let s = String(displayName || "").trim().replace(/\s+models$/i, "");
  if (!s) return "Quota";
  return s.length > 15 ? s.slice(0, 15) : s;
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
  if (cfg.antigravity?.enabled) {
    // Registered under the canonical "antigravity" key. The broker folds the
    // deprecated /usage/gemini alias onto it AFTER HMAC verification.
    fetchers[PROVIDER_ANTIGRAVITY] = new AntigravityFetcher({
      keyringService: cfg.antigravity.keyring_service || "gemini",
      models: cfg.antigravityModels ? cfg.antigravityModels() : [],
    });
  }
  const ttl = cfg.usage?.cache_ttl_seconds || 30;
  logger?.info?.(`usage: providers=${Object.keys(fetchers).sort()} cache_ttl=${ttl}s`);
  return new Cache(ttl, fetchers);
}
