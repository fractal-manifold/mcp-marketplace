// Locally-computed token spend per provider. Parses the CLI logs on this
// host, buckets tokens into today/week/month windows (local time), prices
// them via pricing.js, and serves the /spend/{provider} wire shape.
// Wire-compatible with tokenmonitor-mcp Go internal/spend and tokenmonitor-mcp-py
// tmon_mcp.spend. See compat/SPEND_WIRE.md for the JSON shape and the
// per-provider mapping.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { Pricing } from "./pricing.js";
import { clipCodePoints } from "./textutil.js";
import { readRaw } from "./creds.js";

export const PROVIDER_CLAUDE = "claude";
export const PROVIDER_CODEX = "codex";
export const PROVIDER_ANTIGRAVITY = "antigravity";
// PROVIDER_GEMINI is the DEPRECATED pre-rename wire alias. No spend fetcher is
// registered for Antigravity (the Gemini-CLI JSONL chat logs are gone; the
// Antigravity CLI writes a proto+SQLite trajectory store with no recoverable
// per-turn token counts yet — see the 2026-06-30 spike). /spend/antigravity
// therefore returns NotImplementedProvider → the device renders "--" with no
// stale dollars. Re-enable when a token source lands.
export const PROVIDER_GEMINI = "gemini";

// canonicalProvider folds the deprecated "gemini" wire alias onto the
// canonical "antigravity" key. Call only AFTER HMAC verification of the
// original request path.
export function canonicalProvider(p) {
  return p === PROVIDER_GEMINI ? PROVIDER_ANTIGRAVITY : p;
}

export class SpendError extends Error {}
export class SpendUnavailable extends SpendError {}
export class NotImplementedProvider extends SpendError {}

const MAX_MODELS = 8; // mirrors TMON_SPEND_MAX_MODELS

export function emptySpend() {
  return {
    currency: "USD",
    has_subscription: false,
    today_usd: 0, week_usd: 0, month_usd: 0,
    today_tokens: 0, week_tokens: 0, month_tokens: 0,
    pricing_source: "none",
    pricing_stale: false,
    models: [],
    fetched_at_unix: 0,
    stale_seconds: 0,
  };
}

// -----------------------------------------------------------------------
// Time windows (local timezone)
// -----------------------------------------------------------------------

// Returns {today, week, month} epoch-ms thresholds for "start of window".
export function windowStarts(nowMs) {
  const d = new Date(nowMs);
  const today = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  // ISO week: Monday start. getDay() is 0=Sun..6=Sat.
  const dow = (d.getDay() + 6) % 7; // 0=Mon..6=Sun
  // Step back whole calendar days, not dow*86400s: a DST transition inside the
  // week makes a day 23 or 25 h long, so fixed-second subtraction lands an hour
  // off the local Monday-00:00 boundary. Date() normalises negative day-of-month.
  const week = new Date(d.getFullYear(), d.getMonth(), d.getDate() - dow).getTime();
  const month = new Date(d.getFullYear(), d.getMonth(), 1).getTime();
  return { today, week, month };
}

// -----------------------------------------------------------------------
// Token bundles + accumulation
// -----------------------------------------------------------------------

function newBundle() {
  return { input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_creation_tokens: 0 };
}
function addInto(dst, rec) {
  dst.input_tokens += rec.input_tokens || 0;
  dst.output_tokens += rec.output_tokens || 0;
  dst.cache_read_tokens += rec.cache_read_tokens || 0;
  dst.cache_creation_tokens += rec.cache_creation_tokens || 0;
}
function bundleTotal(b) {
  return b.input_tokens + b.output_tokens + b.cache_read_tokens + b.cache_creation_tokens;
}

// Accumulator: per-window maps of model -> bundle.
class Acc {
  constructor(starts) {
    this.starts = starts;
    this.today = new Map();
    this.week = new Map();
    this.month = new Map();
  }
  _addTo(map, rec) {
    let b = map.get(rec.model);
    if (!b) { b = newBundle(); map.set(rec.model, b); }
    addInto(b, rec);
  }
  // rec: {model, ts(ms), input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens}
  add(rec) {
    if (!rec.model || !Number.isFinite(rec.ts)) return;
    if (rec.ts < this.starts.month) return; // outside all windows we report
    this._addTo(this.month, rec);
    if (rec.ts >= this.starts.week) this._addTo(this.week, rec);
    if (rec.ts >= this.starts.today) this._addTo(this.today, rec);
  }
}

// -----------------------------------------------------------------------
// Labels
// -----------------------------------------------------------------------

export function labelFor(model) {
  let m = String(model || "");
  // claude-opus-4-8 -> "Opus 4.8"; claude-haiku-4-5-20251001 -> "Haiku 4.5"
  let mm = m.match(/^claude-(opus|sonnet|haiku)-(\d+)-(\d+)/i);
  if (mm) {
    const fam = mm[1][0].toUpperCase() + mm[1].slice(1);
    return clip(`${fam} ${mm[2]}.${mm[3]}`);
  }
  // gpt-5-codex -> "GPT-5 Codex"; gpt-5 -> "GPT-5"
  if (/^gpt-/i.test(m)) {
    return clip(m.replace(/^gpt-/i, "GPT-").replace(/-codex$/i, " Codex").replace(/-/g, " "));
  }
  // gemini-3-flash-preview -> "Flash"; gemini-2.5-pro -> "Pro"
  mm = m.match(/^gemini-[\d.]+-([a-z]+)/i);
  if (mm) return clip(mm[1][0].toUpperCase() + mm[1].slice(1));
  return clip(m);
}
function clip(s) { return clipCodePoints(s, 15); }

// -----------------------------------------------------------------------
// File walking with a per-file record cache (incremental parsing)
// -----------------------------------------------------------------------

// Recursively list files under dir matching `match(name)`. Returns
// [{path, mtimeMs, size}]. Missing dir -> [].
function listFiles(dir, match, out = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); }
  catch { return out; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) { listFiles(p, match, out); continue; }
    if (!e.isFile() || !match(e.name)) continue;
    try {
      const st = statSync(p);
      out.push({ path: p, mtimeMs: st.mtimeMs, size: st.size });
    } catch { /* race: file vanished */ }
  }
  return out;
}

// Per-file parsed-record cache so a recompute only re-reads changed files.
// Records are time-stamped; re-bucketing into shifting windows is cheap.
class FileRecordCache {
  constructor() { this.entries = new Map(); } // path -> {mtimeMs, size, records}
  get(file, parse) {
    const hit = this.entries.get(file.path);
    if (hit && hit.mtimeMs === file.mtimeMs && hit.size === file.size) return hit.records;
    const records = parse(file.path);
    this.entries.set(file.path, { mtimeMs: file.mtimeMs, size: file.size, records });
    return records;
  }
}

function readLines(path) {
  let text;
  try { text = readFileSync(path, "utf8"); } catch { return []; }
  return text.length ? text.split("\n") : [];
}

function parseISO(ts) {
  if (!ts) return NaN;
  const t = Date.parse(ts);
  return Number.isFinite(t) ? t : NaN;
}

// -----------------------------------------------------------------------
// Claude — ~/.claude/projects/**/*.jsonl (per-message usage)
// -----------------------------------------------------------------------

function claudeRecords(path) {
  const out = [];
  for (const line of readLines(path)) {
    if (!line) continue;
    let o;
    try { o = JSON.parse(line); } catch { continue; }
    const msg = o.message;
    if (!msg || typeof msg !== "object") continue;
    const model = msg.model;
    if (!model || model === "<synthetic>") continue;
    const u = msg.usage;
    if (!u || typeof u !== "object") continue;
    const ts = parseISO(o.timestamp);
    if (!Number.isFinite(ts)) continue;
    out.push({
      model,
      ts,
      input_tokens: Number(u.input_tokens) || 0,
      output_tokens: Number(u.output_tokens) || 0,
      cache_read_tokens: Number(u.cache_read_input_tokens) || 0,
      cache_creation_tokens: Number(u.cache_creation_input_tokens) || 0,
    });
  }
  return out;
}

// -----------------------------------------------------------------------
// Codex — ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl (accumulated/session)
// -----------------------------------------------------------------------

function codexRecords(path) {
  let model = "";
  let sessionTs = NaN;
  let lastTotal = null;
  for (const line of readLines(path)) {
    if (!line) continue;
    let o;
    try { o = JSON.parse(line); } catch { continue; }
    if (!o || typeof o !== "object") continue;
    if (o.type === "session_meta" || o.session_meta) {
      const meta = o.session_meta || o.payload || o;
      model = model || meta.model || meta.originator || "";
      sessionTs = Number.isFinite(sessionTs) ? sessionTs : parseISO(meta.timestamp || o.timestamp);
    }
    if (o.type === "turn_context" && o.payload) {
      model = o.payload.model || model;
    }
    // token_count is only counted when inside the nested `payload` (Go
    // semantics). A top-level token_count with no payload is ignored — the old
    // `o.payload || o` fallback double-counted it.
    const payload = o.payload;
    if (payload && payload.type === "token_count" && payload.info) {
      const t = payload.info.total_token_usage;
      if (t) lastTotal = t; // accumulated — keep the last
    }
  }
  if (!lastTotal) return [];
  if (!Number.isFinite(sessionTs)) {
    // fall back to file path date YYYY/MM/DD
    const m = path.match(/(\d{4})\/(\d{2})\/(\d{2})/);
    if (m) sessionTs = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])).getTime();
  }
  const cached = Number(lastTotal.cached_input_tokens) || 0;
  const input = Math.max(0, (Number(lastTotal.input_tokens) || 0) - cached);
  const output = (Number(lastTotal.output_tokens) || 0) + (Number(lastTotal.reasoning_output_tokens) || 0);
  return [{
    model: model || "gpt-5-codex",
    ts: sessionTs,
    input_tokens: input,
    output_tokens: output,
    cache_read_tokens: cached,
    cache_creation_tokens: 0,
  }];
}

// -----------------------------------------------------------------------
// Gemini — ~/.gemini/tmp/<project>/chats/session-*.jsonl (per-message)
// -----------------------------------------------------------------------

function geminiRecords(path) {
  const out = [];
  for (const line of readLines(path)) {
    if (!line) continue;
    let o;
    try { o = JSON.parse(line); } catch { continue; }
    if (o.type !== "gemini") continue;
    const t = o.tokens;
    if (!t || typeof t !== "object") continue;
    const ts = parseISO(o.timestamp);
    if (!Number.isFinite(ts)) continue;
    out.push({
      model: o.model || "gemini-2.5-pro",
      ts,
      input_tokens: Number(t.input) || 0,
      output_tokens: (Number(t.output) || 0) + (Number(t.thoughts) || 0),
      cache_read_tokens: Number(t.cached) || 0,
      cache_creation_tokens: 0,
    });
  }
  return out;
}

// -----------------------------------------------------------------------
// Subscription detection (on-disk, no remote call)
// -----------------------------------------------------------------------

function readJSONFile(path) {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
}

function claudeHasSubscription(credsPath) {
  // Keychain-aware on macOS (same source as the OAuth token); a plain file
  // read would see nothing there and mis-report the account as pay-as-you-go.
  let doc = null;
  try { doc = JSON.parse(readRaw(credsPath)); } catch { doc = null; }
  const o = doc?.claudeAiOauth;
  if (!o) return false;
  const sub = String(o.subscriptionType || "").toLowerCase();
  if (sub && sub !== "free") return true;
  const tier = String(o.rateLimitTier || "").toLowerCase();
  return tier !== "" && tier !== "free";
}

function codexHasSubscription(authPath) {
  const doc = readJSONFile(authPath);
  if (!doc) return false;
  // has_subscription = "quota-based view (%)" vs "pay-as-you-go ($)", NOT
  // "paid plan". A ChatGPT OAuth login consumes against the ChatGPT plan's
  // quota (free or paid alike) → keep %. A bare API key is per-token → $.
  // Free vs paid ChatGPT is intentionally not distinguished (needs a remote
  // plan_type call). See compat/SPEND_WIRE.md → Subscription detection.
  if (doc.tokens || doc.access_token || doc.OPENAI_ACCESS_TOKEN) return true;
  return false;
}

// -----------------------------------------------------------------------
// Per-provider fetchers
// -----------------------------------------------------------------------

class ProviderSpend {
  // kind: "claude" | "codex" | "gemini"
  constructor(kind, { root, fileMatch, parse, hasSub, pricing }) {
    this.kind = kind;
    this.root = root;
    this.fileMatch = fileMatch;
    this.parse = parse;
    this.hasSub = hasSub;
    this.pricing = pricing;
    this.fileCache = new FileRecordCache();
  }

  async fetch(nowMs = Date.now()) {
    const starts = windowStarts(nowMs);
    // 1-day slack so a session crossing local midnight at month start is
    // not dropped by the mtime prefilter.
    const cutoff = starts.month - 86400_000;
    const files = listFiles(this.root, this.fileMatch).filter((f) => f.mtimeMs >= cutoff);

    const acc = new Acc(starts);
    for (const f of files) {
      const records = this.fileCache.get(f, this.parse);
      for (const r of records) acc.add(r);
    }

    const table = await this.pricing.table(nowMs);
    const snap = emptySpend();
    snap.has_subscription = !!this.hasSub();
    snap.pricing_source = table.source;
    snap.pricing_stale = table.stale;

    // Sum in sorted-key order so the float accumulation order is identical
    // across runtimes (float addition is not associative, so an unordered
    // sum could round to a different cent under Go's randomized map order or
    // a differently-discovered file order). See compat/SPEND_WIRE.md.
    const priceMap = (map) => {
      let usd = 0, tokens = 0;
      for (const model of [...map.keys()].sort()) {
        const b = map.get(model);
        usd += table.costFor(model, b);
        tokens += bundleTotal(b);
      }
      return { usd, tokens };
    };
    const t = priceMap(acc.today), w = priceMap(acc.week), m = priceMap(acc.month);
    snap.today_usd = round2(t.usd); snap.today_tokens = t.tokens;
    snap.week_usd = round2(w.usd); snap.week_tokens = w.tokens;
    snap.month_usd = round2(m.usd); snap.month_tokens = m.tokens;

    // Per-model month breakdown, sorted by usd desc then tokens desc.
    const rows = [];
    for (const [model, b] of acc.month) {
      rows.push({
        model,
        label: labelFor(model),
        input_tokens: b.input_tokens,
        output_tokens: b.output_tokens,
        cache_read_tokens: b.cache_read_tokens,
        cache_creation_tokens: b.cache_creation_tokens,
        usd: round2(table.costFor(model, b)),
        _tot: bundleTotal(b),
      });
    }
    // Code-point compare for the final tie-break (NOT localeCompare, which is
    // locale-dependent and would order rows differently than Go's `<` / Py's
    // str compare on some hosts). Keeps row order identical across runtimes.
    rows.sort((a, b) => (b.usd - a.usd) || (b._tot - a._tot)
      || (a.model < b.model ? -1 : a.model > b.model ? 1 : 0));
    snap.models = foldModels(rows);
    return snap;
  }
}

// Cap to MAX_MODELS, folding the tail into a single "Other" row.
function foldModels(rows) {
  if (rows.length <= MAX_MODELS) return rows.map(stripTmp);
  const head = rows.slice(0, MAX_MODELS - 1).map(stripTmp);
  const tail = rows.slice(MAX_MODELS - 1);
  const other = {
    model: "other", label: "Other",
    input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_creation_tokens: 0, usd: 0,
  };
  for (const r of tail) {
    other.input_tokens += r.input_tokens;
    other.output_tokens += r.output_tokens;
    other.cache_read_tokens += r.cache_read_tokens;
    other.cache_creation_tokens += r.cache_creation_tokens;
    other.usd += r.usd;
  }
  other.usd = round2(other.usd);
  head.push(other);
  return head;
}
function stripTmp(r) { const { _tot, ...rest } = r; return rest; }
function round2(x) { return Math.round(x * 100) / 100; }

// -----------------------------------------------------------------------
// Cache (TTL + stale-with-error, mirrors usage.Cache)
// -----------------------------------------------------------------------

export class SpendCache {
  constructor(ttlSeconds, fetchers) {
    this.ttlMs = Math.max(1, ttlSeconds) * 1000;
    this.fetchers = fetchers;
    this.entries = new Map();
    this.inflight = new Map();
    this.now = () => Date.now();
  }
  providers() { return Object.keys(this.fetchers).sort(); }

  async get(provider) {
    const f = this.fetchers[provider];
    if (!f) throw new NotImplementedProvider(`spend provider ${provider} not enabled`);
    const now = this.now();
    const entry = this.entries.get(provider);
    if (entry && now - entry.fetched < this.ttlMs) {
      return { ...entry.snap, stale_seconds: Math.floor((now - entry.fetched) / 1000) };
    }
    let pending = this.inflight.get(provider);
    if (!pending) { pending = this._refresh(provider, f); this.inflight.set(provider, pending); }
    try {
      return await pending;
    } catch (e) {
      const cached = this.entries.get(provider);
      if (cached) e.staleSnapshot = { ...cached.snap, stale_seconds: Math.floor((this.now() - cached.fetched) / 1000) };
      throw e;
    }
  }

  async _refresh(provider, fetcher) {
    try {
      const snap = await fetcher.fetch(this.now());
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
// Factory
// -----------------------------------------------------------------------

export function buildSpendCache(cfg, { logger } = {}) {
  if (!cfg.spend?.enabled) return null;
  const pricing = new Pricing({
    url: cfg.pricing.url,
    cachePath: cfg.pricingCachePathAbs(),
    ttlHours: cfg.pricing.ttl_hours,
    logger,
  });

  const fetchers = {
    [PROVIDER_CLAUDE]: new ProviderSpend(PROVIDER_CLAUDE, {
      root: cfg.claudeProjectsPathAbs(),
      fileMatch: (n) => n.endsWith(".jsonl"),
      parse: claudeRecords,
      hasSub: () => claudeHasSubscription(cfg.oauthPathAbs()),
      pricing,
    }),
  };
  if (cfg.codex?.enabled) {
    fetchers[PROVIDER_CODEX] = new ProviderSpend(PROVIDER_CODEX, {
      root: cfg.codexSessionsPathAbs(),
      fileMatch: (n) => n.startsWith("rollout-") && n.endsWith(".jsonl"),
      parse: codexRecords,
      hasSub: () => codexHasSubscription(cfg.codexAuthPathAbs()),
      pricing,
    });
  }
  // Antigravity spend is intentionally NOT wired: the Gemini-CLI chat-log
  // JSONL source is gone, and the Antigravity CLI's proto+SQLite trajectory
  // store has no recoverable per-turn token counts yet (spike 2026-06-30).
  // With no fetcher, /spend/antigravity returns NotImplementedProvider → the
  // device renders "--" with no stale dollars. geminiRecords is kept (below,
  // and in _internals) for when a token source lands.
  const ttl = cfg.spend?.cache_ttl_seconds || 300;
  logger?.info?.(`spend: providers=${Object.keys(fetchers).sort()} cache_ttl=${ttl}s`);
  return new SpendCache(ttl, fetchers);
}

// Exposed for the compat suite / unit tests.
export const _internals = {
  claudeRecords, codexRecords, geminiRecords, windowStarts, labelFor,
  Acc, foldModels, ProviderSpend,
};
