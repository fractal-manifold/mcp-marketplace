#!/usr/bin/env node
// TokenMonitor SessionStart hook.
//
// The tokenmonitor-mcp broker does NOT auto-update, so it drifts behind the
// firmware it feeds. This hook — which runs in the Claude Code harness, NOT in
// the broker process, so it works even against an ancient broker binary —
// compares the installed plugin version against the latest published in the
// marketplace catalog and, when a newer release exists, emits additionalContext
// nudging the user to update.
//
// It fires for every Claude Code session in every directory, so it must NEVER
// fail or noise up an unrelated session: any error, timeout, or "up to date"
// verdict exits 0 silently. Result is cached with a TTL so we don't hit the
// network on every session start.
//
// Cross-platform: Node 20+ stdlib only (mirrors the agentnetwork hook).

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const http = require('node:http');
const { spawn } = require('node:child_process');

const PLUGIN_NAME = 'tokenmonitor';
const DEFAULT_MARKETPLACE_URL =
  'https://raw.githubusercontent.com/fractal-manifold/mcp-marketplace/main/.claude-plugin/marketplace.json';
const FETCH_TIMEOUT_MS = 2500;
const WATCHDOG_MS = 3500;
const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6h
const CACHE_DIR = path.join(
  process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'),
  'tokenmonitor',
);
const CACHE_FILE = path.join(CACHE_DIR, 'updatecheck.json');

function silentExit() {
  process.exit(0);
}

// Overall watchdog: whatever happens, never hang a session start.
const watchdog = setTimeout(silentExit, WATCHDOG_MS);
watchdog.unref();

function marketplaceURL() {
  // TMON_ is the project's env-var convention; TOKENMONITOR_MARKETPLACE_URL is
  // kept as a backward-compat alias (TMON_ wins when both are set).
  return (
    process.env.TMON_MARKETPLACE_URL ||
    process.env.TOKENMONITOR_MARKETPLACE_URL ||
    DEFAULT_MARKETPLACE_URL
  );
}

// pluginRoot resolves the installed plugin directory WITHOUT depending on a
// host-provided variable: Claude/Codex set CLAUDE_PLUGIN_ROOT, but Antigravity
// never does. This file always lives at <root>/hooks/session-start.js, so
// __dirname/.. is the root on every client.
function pluginRoot() {
  return process.env.CLAUDE_PLUGIN_ROOT || path.join(__dirname, '..');
}

// prewarm kicks the launcher's --prewarm mode detached, so the MCP runtime
// (esp. a first-run Go fetch/build) is cached before the client's MCP
// handshake. Strictly best-effort and fire-and-forget: never blocks, never
// fails the session, stdio fully detached. It is a next-launch optimization —
// it cannot guarantee the current session's MCP connect wins the race.
function prewarm() {
  try {
    if (process.env.TMON_NO_PREWARM) return; // opt-out (tests/CI/users)
    const launcher = path.join(pluginRoot(), 'server', 'tokenmonitor-mcp');
    if (!fs.existsSync(launcher)) return;
    const child = spawn('sh', [launcher, '--prewarm'], {
      detached: true,
      stdio: 'ignore',
    });
    child.on('error', () => {});
    child.unref();
  } catch (_) {
    /* best-effort */
  }
}

// Parse "MAJOR.MINOR.PATCH[-suffix]" into [maj, min, pat]; suffix ignored.
// Returns null on anything malformed (matches the broker's strict subset
// closely enough for an advisory: leading zeros / out-of-range still parse
// numerically here, which is fine — this only decides whether to show a hint).
function parseSemver(v) {
  if (typeof v !== 'string') return null;
  const base = v.split('-', 1)[0];
  const parts = base.split('.');
  if (parts.length !== 3) return null;
  const nums = parts.map((p) => (/^\d+$/.test(p) ? Number(p) : NaN));
  if (nums.some((n) => !Number.isFinite(n))) return null;
  return nums;
}

// Returns 1 if a > b, -1 if a < b, 0 if equal, or null if either unparseable.
function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i++) {
    if (pa[i] > pb[i]) return 1;
    if (pa[i] < pb[i]) return -1;
  }
  return 0;
}

function installedVersion() {
  try {
    const raw = fs.readFileSync(
      path.join(pluginRoot(), '.claude-plugin', 'plugin.json'),
      'utf8',
    );
    const v = JSON.parse(raw).version;
    return typeof v === 'string' && v ? v : null;
  } catch (_) {
    return null;
  }
}

function readCache() {
  try {
    const c = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    if (
      c &&
      typeof c.latest === 'string' &&
      typeof c.checkedAt === 'number' &&
      Date.now() - c.checkedAt < CACHE_TTL_MS
    ) {
      return c.latest;
    }
  } catch (_) {
    /* no / stale / corrupt cache */
  }
  return null;
}

function writeCache(latest) {
  try {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(
      CACHE_FILE,
      JSON.stringify({ latest, checkedAt: Date.now() }),
    );
  } catch (_) {
    /* best-effort */
  }
}

function fetchLatest(cb) {
  const url = marketplaceURL();
  const mod = url.startsWith('http://') ? http : https;
  let done = false;
  const finish = (val) => {
    if (done) return;
    done = true;
    cb(val);
  };
  let req;
  try {
    req = mod.get(url, { timeout: FETCH_TIMEOUT_MS }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return finish(null);
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        body += chunk;
        if (body.length > 1024 * 1024) req.destroy(); // 1 MiB cap
      });
      res.on('end', () => {
        try {
          const doc = JSON.parse(body);
          const entry = (doc.plugins || []).find((p) => p.name === PLUGIN_NAME);
          finish(entry && typeof entry.version === 'string' ? entry.version : null);
        } catch (_) {
          finish(null);
        }
      });
    });
  } catch (_) {
    return finish(null);
  }
  req.on('timeout', () => req.destroy());
  req.on('error', () => finish(null));
}

function emit(installed, latest) {
  const msg =
    `TokenMonitor: the tokenmonitor plugin/broker is out of date — ` +
    `${installed} installed, ${latest} published. The broker does not ` +
    `auto-update; offer to update it via /plugin (or the marketplace) so the ` +
    `device stops showing stale data. Skip silently if the user is busy.`;
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: msg,
      },
    }) + '\n',
  );
}

function decide(installed, latest) {
  if (installed && latest && compareSemver(latest, installed) === 1) {
    emit(installed, latest);
  }
  process.exit(0);
}

try {
  // Fire the detached prewarm first (best-effort), so the runtime warms while
  // we do the update check regardless of its verdict.
  prewarm();

  const installed = installedVersion();
  if (!installed) silentExit();

  const cached = readCache();
  if (cached) {
    decide(installed, cached);
  } else {
    fetchLatest((latest) => {
      if (latest) writeCache(latest);
      decide(installed, latest);
    });
  }
} catch (_) {
  silentExit();
}
