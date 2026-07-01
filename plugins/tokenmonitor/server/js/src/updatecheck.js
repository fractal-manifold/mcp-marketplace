// updatecheck answers one question the broker cannot otherwise see: is a newer
// TokenMonitor broker/plugin release published than the one this process is
// running? The broker does NOT auto-update, so over time it drifts behind the
// firmware it feeds. This module periodically fetches the public marketplace
// catalog, compares the tokenmonitor entry's version against the installed
// release version, and stashes the verdict in the shared State so three
// surfaces can advertise it: the /device/<id>/sync body (-> on-device banner),
// tokenmonitor_health / tokenmonitor_status (-> Claude Code), and a stderr WARN.
//
// It is strictly best-effort: any network/parse failure leaves the cached
// verdict `known:false` (never a false "up to date" or "outdated") and never
// blocks or errors the broker. Wire-identical to the Go internal/updatecheck.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

import { compareSemver } from "./ota.js";
import { VERSION } from "./version.js";

// PluginName is the marketplace entry whose version tracks releases.
export const PLUGIN_NAME = "tokenmonitor";

// DEFAULT_MARKETPLACE_URL is the raw catalog on the marketplace repo's default
// branch — the single source of truth for "latest published". Overridable via
// TOKENMONITOR_MARKETPLACE_URL (used by tests).
export const DEFAULT_MARKETPLACE_URL =
  "https://raw.githubusercontent.com/fractal-manifold/mcp-marketplace/main/.claude-plugin/marketplace.json";

const HTTP_TIMEOUT_MS = 10_000;
const POLL_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6h
const INITIAL_DELAY_MS = 30_000; // 30s
const MAX_BODY = 1 * 1024 * 1024;

// marketplaceURL returns the catalog URL, honouring the test/CI override.
export function marketplaceURL() {
  return process.env.TOKENMONITOR_MARKETPLACE_URL || DEFAULT_MARKETPLACE_URL;
}

// installedVersion resolves the running release version. It prefers the
// bundle's plugin.json (the release/marketplace axis, apples-to-apples with the
// catalog) found via CLAUDE_PLUGIN_ROOT, and falls back to the baked-in broker
// build VERSION when that file is absent or unreadable. Mirrors Go
// InstalledVersion.
export function installedVersion(baked = VERSION) {
  const root = process.env.CLAUDE_PLUGIN_ROOT;
  if (root) {
    try {
      const raw = readFileSync(join(root, ".claude-plugin", "plugin.json"), "utf8");
      const m = JSON.parse(raw);
      if (m && typeof m.version === "string" && m.version) return m.version;
    } catch {
      // fall through to baked
    }
  }
  return baked;
}

// fetchLatest GETs the marketplace catalog and returns the tokenmonitor entry's
// version. An empty string means the entry was absent; throws on any HTTP/parse
// error. Callers treat both as "advertise nothing".
export async function fetchLatest(url = marketplaceURL()) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  let resp;
  try {
    resp = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: ctrl.signal,
      headers: { Accept: "application/json", "User-Agent": "tokenmonitor-mcp-updatecheck" },
    });
  } finally {
    clearTimeout(timer);
  }
  if (!resp.ok) throw new Error(`marketplace fetch: HTTP ${resp.status}`);
  const buf = Buffer.from(await resp.arrayBuffer());
  const doc = JSON.parse(buf.subarray(0, MAX_BODY).toString("utf8"));
  const plugins = Array.isArray(doc?.plugins) ? doc.plugins : [];
  for (const p of plugins) {
    if (p && p.name === PLUGIN_NAME) return String(p.version || "");
  }
  return "";
}

// check performs one fetch+compare and returns the verdict. On any failure it
// returns { known:false, current } — callers must treat that as "advertise
// nothing". Mirrors Go Check.
export async function check(current, url = marketplaceURL()) {
  let latest;
  try {
    latest = await fetchLatest(url);
  } catch {
    return { known: false, outdated: false, current, latest: "", checkedAt: 0 };
  }
  if (!latest) return { known: false, outdated: false, current, latest: "", checkedAt: 0 };
  const cmp = compareSemver(latest, current);
  if (cmp === null) {
    // Either version is unparseable under the project's semver subset; don't
    // guess.
    return { known: false, outdated: false, current, latest: "", checkedAt: 0 };
  }
  return {
    known: true,
    outdated: cmp > 0,
    current,
    latest,
    checkedAt: Math.floor(Date.now() / 1000),
  };
}

// run polls the marketplace catalog on a slow cadence and publishes each
// verdict into `state`. It is best-effort and never throws. Pass an
// AbortSignal to stop it. `baked` is the compiled-in broker version, used only
// as the installed-version fallback. Mirrors Go Run.
export function run(state, { baked = VERSION, logger = null, abortSignal = null } = {}) {
  if (!state) return;
  const current = installedVersion(baked);
  let stopped = false;
  let timer = null;
  const stop = () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
  if (abortSignal) {
    if (abortSignal.aborted) return;
    abortSignal.addEventListener("abort", stop, { once: true });
  }
  const tick = async () => {
    if (stopped) return;
    try {
      const info = await check(current);
      state.setUpdate(info);
      if (logger) {
        if (info.known && info.outdated) {
          logger.warn(`updatecheck: WARNING broker ${info.current} is behind published ${info.latest} — update the tokenmonitor plugin`);
        } else if (info.known && logger.info) {
          logger.info(`updatecheck: broker ${info.current} is up to date`);
        }
      }
    } catch {
      // best-effort: never let a check failure escape.
    }
    if (!stopped) {
      timer = setTimeout(tick, POLL_INTERVAL_MS);
      if (timer && typeof timer.unref === "function") timer.unref();
    }
  };
  timer = setTimeout(tick, INITIAL_DELAY_MS);
  // Don't keep the event loop alive for the poller alone.
  if (timer && typeof timer.unref === "function") timer.unref();
}
