// Model price table: turns token counts into USD.
//
// Source of truth is LiteLLM's machine-readable price table (the same
// data ccusage uses), fetched over HTTP and cached on disk. An embedded
// fallback table covers the common models so `$` works offline / on the
// first run. See compat/SPEND_WIRE.md ("Pricing").
//
// Wire-compatible note: the *output* of pricing (the per-model USD on
// /spend) must match the Go and Python impls for the same inputs, so the
// fallback table and the cost formula are kept byte-identical across the
// three runtimes. The cost formula is:
//   usd = input*in + output*out + cache_read*cr + cache_creation*cc
// where each rate is USD-per-token.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// Per-token USD rates. Keep in sync with go/internal/spend/pricing.go and
// py/src/tmon_mcp/pricing.py. Cache read = 0.1x input, cache write = 1.25x
// input for Claude; OpenAI/Gemini cache read rates from their published
// tables. Values are best-effort fallbacks — LiteLLM overrides them.
export const FALLBACK_PRICES = {
  // Anthropic — $5/$25 (Opus), $3/$15 (Sonnet), $1/$5 (Haiku) per 1M.
  "claude-opus-4-8":   { input: 5e-6,  output: 25e-6, cache_read: 0.5e-6,  cache_creation: 6.25e-6 },
  "claude-opus-4-7":   { input: 5e-6,  output: 25e-6, cache_read: 0.5e-6,  cache_creation: 6.25e-6 },
  "claude-opus-4-6":   { input: 5e-6,  output: 25e-6, cache_read: 0.5e-6,  cache_creation: 6.25e-6 },
  "claude-opus-4-5":   { input: 5e-6,  output: 25e-6, cache_read: 0.5e-6,  cache_creation: 6.25e-6 },
  "claude-opus-4-1":   { input: 15e-6, output: 75e-6, cache_read: 1.5e-6,  cache_creation: 18.75e-6 },
  "claude-sonnet-4-6": { input: 3e-6,  output: 15e-6, cache_read: 0.3e-6,  cache_creation: 3.75e-6 },
  "claude-sonnet-4-5": { input: 3e-6,  output: 15e-6, cache_read: 0.3e-6,  cache_creation: 3.75e-6 },
  "claude-haiku-4-5":  { input: 1e-6,  output: 5e-6,  cache_read: 0.1e-6,  cache_creation: 1.25e-6 },
  // OpenAI / Codex — approximate; LiteLLM is authoritative.
  "gpt-5":             { input: 1.25e-6, output: 10e-6, cache_read: 0.125e-6, cache_creation: 0 },
  "gpt-5-codex":       { input: 1.25e-6, output: 10e-6, cache_read: 0.125e-6, cache_creation: 0 },
  "o4-mini":           { input: 1.1e-6,  output: 4.4e-6, cache_read: 0.275e-6, cache_creation: 0 },
  // Google / Gemini — approximate; LiteLLM is authoritative.
  "gemini-2.5-pro":          { input: 1.25e-6, output: 10e-6,  cache_read: 0.31e-6,  cache_creation: 0 },
  "gemini-2.5-flash":        { input: 0.3e-6,  output: 2.5e-6, cache_read: 0.075e-6, cache_creation: 0 },
  "gemini-3-flash-preview":  { input: 0.3e-6,  output: 2.5e-6, cache_read: 0.075e-6, cache_creation: 0 },
  // Antigravity defaults (agy). Prefix-matched so effort suffixes
  // (-low/-medium/-high) resolve to the same rate.
  "gemini-3.5-flash":        { input: 0.3e-6,  output: 2.5e-6, cache_read: 0.075e-6, cache_creation: 0 },
  "gemini-3.1-pro":          { input: 1.25e-6, output: 10e-6,  cache_read: 0.31e-6,  cache_creation: 0 },
};

// Normalise a LiteLLM entry (USD-per-token fields) to our shape. LiteLLM
// keys: input_cost_per_token, output_cost_per_token,
// cache_read_input_token_cost, cache_creation_input_token_cost.
function fromLiteLLM(e) {
  if (!e || typeof e !== "object") return null;
  const inn = Number(e.input_cost_per_token);
  const out = Number(e.output_cost_per_token);
  if (!Number.isFinite(inn) || !Number.isFinite(out)) return null;
  return {
    input: inn,
    output: out,
    cache_read: Number(e.cache_read_input_token_cost) || 0,
    cache_creation: Number(e.cache_creation_input_token_cost) || 0,
  };
}

export class PriceTable {
  // source: "litellm" | "fallback" | "none"
  constructor(map, source, stale) {
    this.map = map || {};
    this.source = source || "none";
    this.stale = !!stale;
  }

  // Best-effort model → rate lookup. Tries exact, basename-after-slash,
  // then longest prefix match (covers date-suffixed ids like
  // claude-opus-4-5-20251101 and provider-prefixed litellm keys).
  rateFor(model) {
    if (!model) return null;
    if (this.map[model]) return this.map[model];
    const base = model.includes("/") ? model.slice(model.lastIndexOf("/") + 1) : model;
    if (this.map[base]) return this.map[base];
    // Deterministic across runtimes: prefer the longest basename match,
    // breaking ties by the lexicographically smallest full key. Object key
    // order (JS), dict insertion order (Py) and map iteration order (Go,
    // randomized) must NOT influence which rate wins, or the per-model USD
    // would diverge between the three impls. See compat/SPEND_WIRE.md.
    let bestKey = null;
    let bestLen = -1;
    for (const key of Object.keys(this.map)) {
      const k = key.includes("/") ? key.slice(key.lastIndexOf("/") + 1) : key;
      if (!(base.startsWith(k) || k.startsWith(base))) continue;
      if (k.length > bestLen || (k.length === bestLen && (bestKey === null || key < bestKey))) {
        bestKey = key;
        bestLen = k.length;
      }
    }
    return bestKey === null ? null : this.map[bestKey];
  }

  // USD cost for a token bundle. Returns 0 (not null) when the model is
  // unpriced so callers can still surface the real token counts.
  costFor(model, tok) {
    const r = this.rateFor(model);
    if (!r) return 0;
    return (
      (tok.input_tokens || 0) * r.input +
      (tok.output_tokens || 0) * r.output +
      (tok.cache_read_tokens || 0) * r.cache_read +
      (tok.cache_creation_tokens || 0) * r.cache_creation
    );
  }

  has(model) { return this.rateFor(model) != null; }
}

function fallbackTable() {
  return new PriceTable({ ...FALLBACK_PRICES }, "fallback", false);
}

function parseLiteLLM(doc) {
  const map = {};
  for (const [key, val] of Object.entries(doc || {})) {
    if (key === "sample_spec") continue;
    const r = fromLiteLLM(val);
    if (r) map[key] = r;
  }
  return map;
}

// Loads the price table: disk cache if fresh, else refetch from LiteLLM
// and rewrite the cache, else stale disk cache, else embedded fallback.
// Never throws — pricing problems degrade to fallback/none, they don't
// blank the spend response.
export class Pricing {
  constructor({ url, cachePath, ttlHours = 24, fetchImpl = fetch, logger } = {}) {
    this.url = url;
    this.cachePath = cachePath;
    this.ttlMs = Math.max(1, ttlHours) * 3600 * 1000;
    this.fetchImpl = fetchImpl;
    this.logger = logger;
    this._table = null;
    this._loadedAt = 0;
    this._inflight = null;
  }

  _readDiskCache() {
    if (!this.cachePath || !existsSync(this.cachePath)) return null;
    try {
      const doc = JSON.parse(readFileSync(this.cachePath, "utf8"));
      const map = doc && doc.prices ? doc.prices : null;
      if (!map || typeof map !== "object") return null;
      return { map, fetchedAt: Number(doc.fetched_at_ms) || 0 };
    } catch {
      return null;
    }
  }

  _writeDiskCache(map, fetchedAtMs) {
    if (!this.cachePath) return;
    try {
      mkdirSync(dirname(this.cachePath), { recursive: true });
      writeFileSync(this.cachePath, JSON.stringify({ fetched_at_ms: fetchedAtMs, prices: map }));
    } catch (e) {
      this.logger?.info?.(`pricing: cache write failed: ${e.message}`);
    }
  }

  async _fetchLive() {
    const resp = await this.fetchImpl(this.url, { method: "GET" });
    if (!resp || resp.status < 200 || resp.status >= 300) {
      throw new Error(`pricing fetch status=${resp ? resp.status : "?"}`);
    }
    const doc = await resp.json();
    const map = parseLiteLLM(doc);
    if (Object.keys(map).length === 0) throw new Error("pricing table empty");
    return map;
  }

  // Returns a PriceTable. nowMs lets tests pin time.
  async table(nowMs = Date.now()) {
    if (this._table && nowMs - this._loadedAt < this.ttlMs) return this._table;

    const disk = this._readDiskCache();
    if (disk && nowMs - disk.fetchedAt < this.ttlMs) {
      this._table = new PriceTable(disk.map, "litellm", false);
      this._loadedAt = nowMs;
      return this._table;
    }

    if (!this._inflight) {
      this._inflight = (async () => {
        try {
          const map = await this._fetchLive();
          this._writeDiskCache(map, nowMs);
          return new PriceTable(map, "litellm", false);
        } catch (e) {
          this.logger?.info?.(`pricing: live fetch failed (${e.message}); using ${disk ? "stale cache" : "fallback"}`);
          if (disk) return new PriceTable(disk.map, "litellm", true);
          return fallbackTable();
        } finally {
          this._inflight = null;
        }
      })();
    }
    this._table = await this._inflight;
    this._loadedAt = nowMs;
    return this._table;
  }
}
