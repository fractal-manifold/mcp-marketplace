// Antigravity provider migration (Gemini CLI retired 2026-06-18 → agy).
// Proves: the new [antigravity] config section + default models load; a legacy
// [gemini] section / gemini_tmp_path still merges forward (back-compat); and
// the deprecated /usage/gemini & /spend/gemini wire paths still work as
// aliases, canonicalized to "antigravity" only AFTER HMAC verification.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EventEmitter } from "node:events";

import { load, DEFAULT_ANTIGRAVITY_MODELS } from "../src/config.js";
import { createHandler } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import * as usage from "../src/usage.js";
import * as spend from "../src/spend.js";
import { State } from "../src/state.js";

const DEFAULT_PSK = Buffer.from("00".repeat(32), "hex");

function writeCfg(body) {
  const dir = mkdtempSync(join(tmpdir(), "tmon-cfg-"));
  const path = join(dir, "tokenmonitor.toml");
  writeFileSync(path, body, "utf8");
  return { dir, path };
}

// -----------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------

test("config: new [antigravity] section + default models load", () => {
  const { dir, path } = writeCfg(`
[auth]
psk_passphrase = "test-passphrase"

[antigravity]
enabled = true
creds_path = "~/.gemini/oauth_creds.json"
`);
  try {
    const cfg = load(path);
    assert.equal(cfg.antigravity.enabled, true);
    assert.equal(cfg.antigravityCredsPathAbs().endsWith("/.gemini/oauth_creds.json"), true);
    // Empty models → the default Flash + Pro list.
    assert.deepEqual(cfg.antigravityModels(), DEFAULT_ANTIGRAVITY_MODELS);
    assert.deepEqual(DEFAULT_ANTIGRAVITY_MODELS, ["gemini-3.5-flash", "gemini-3.1-pro"]);
    // Default conversation path is the agy trajectory store.
    assert.equal(cfg.antigravityConvPathAbs().endsWith("/.gemini/antigravity/conversations"), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("config: legacy [gemini] section + gemini_tmp_path merge into antigravity fields", () => {
  const { dir, path } = writeCfg(`
[auth]
psk_passphrase = "test-passphrase"

[gemini]
enabled = true
creds_path = "/custom/oauth_creds.json"
projects_path = "/custom/projects.json"
models = ["gemini-3.1-pro"]

[spend]
gemini_tmp_path = "/legacy/gemini/tmp"
`);
  try {
    const cfg = load(path);
    // Legacy [gemini] folded into the canonical antigravity fields.
    assert.equal(cfg.antigravity.enabled, true);
    assert.equal(cfg.antigravityCredsPathAbs(), "/custom/oauth_creds.json");
    assert.equal(cfg.antigravityProjectsPathAbs(), "/custom/projects.json");
    assert.deepEqual(cfg.antigravityModels(), ["gemini-3.1-pro"]);
    // Legacy gemini_tmp_path folded into the conversation path; the deprecated
    // key is dropped from the resolved config.
    assert.equal(cfg.antigravityConvPathAbs(), "/legacy/gemini/tmp");
    assert.equal("gemini_tmp_path" in cfg.spend, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("config: new [antigravity] section wins when both sections present", () => {
  const { dir, path } = writeCfg(`
[auth]
psk_passphrase = "test-passphrase"

[antigravity]
enabled = true
creds_path = "/new/oauth_creds.json"

[gemini]
enabled = false
creds_path = "/legacy/oauth_creds.json"
`);
  try {
    const cfg = load(path);
    assert.equal(cfg.antigravity.enabled, true);
    assert.equal(cfg.antigravityCredsPathAbs(), "/new/oauth_creds.json");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// -----------------------------------------------------------------------
// Wire aliases: /usage/gemini and /spend/gemini canonicalize to antigravity
// -----------------------------------------------------------------------

function makeCfg() {
  return {
    psk: () => DEFAULT_PSK,
    security: { max_timestamp_skew_seconds: 60 },
    codex: { enabled: false },
  };
}

class FakeRes extends EventEmitter {
  constructor() {
    super();
    this.statusCode = 200;
    this.headers = {};
    this.body = "";
    this.ended = false;
    this.socket = { remoteAddress: "127.0.0.1" };
  }
  setHeader(k, v) { this.headers[k.toLowerCase()] = v; }
  writeHead(s) { this.statusCode = s; }
  end(buf) {
    if (buf) this.body += buf.toString("utf8");
    this.ended = true;
    this.emit("close");
  }
}

function makeReq(method, rawUrl, headers) {
  const req = new EventEmitter();
  req.method = method;
  req.url = rawUrl;
  req.headers = Object.assign({ host: "localhost" }, headers);
  req.socket = { remoteAddress: "127.0.0.1" };
  return req;
}

function dispatch(handler, req, res) {
  return new Promise((resolve) => {
    res.on("close", () => resolve());
    handler(req, res);
    if (res.ended) resolve();
  });
}

function silentLogger() {
  return { info: () => {}, warn: () => {}, error: () => {} };
}

// Sign the LITERAL request path with the default PSK (registry=null path),
// exactly as deployed firmware signs /usage/gemini.
function signedHeaders(method, path) {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = "0123456789abcdef" + Math.random().toString(16).slice(2).padEnd(16, "0").slice(0, 16);
  const sig = auth.computeSignature(DEFAULT_PSK, method, path, ts, nonce, "", "");
  return { "x-tmon-timestamp": ts, "x-tmon-nonce": nonce, "x-tmon-signature": sig };
}

test("/usage/gemini canonicalizes to antigravity after HMAC (legacy alias)", async () => {
  const calls = [];
  const usageCache = {
    async get(provider) {
      calls.push(provider);
      return { session_pct: 0, slots: [], tier: "free" };
    },
    antigravityFetcher() { return null; },
  };
  const handler = createHandler({
    cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: null, logger: silentLogger(), usageCache,
  });
  const req = makeReq("GET", "/usage/gemini", signedHeaders("GET", "/usage/gemini"));
  const res = new FakeRes();
  await dispatch(handler, req, res);
  assert.equal(res.statusCode, 200, res.body);
  // The deprecated wire path was folded onto the canonical fetcher key.
  assert.deepEqual(calls, [usage.PROVIDER_ANTIGRAVITY]);
});

test("/usage/antigravity reaches the same canonical fetcher key", async () => {
  const calls = [];
  const usageCache = {
    async get(provider) { calls.push(provider); return { slots: [], tier: "free" }; },
    antigravityFetcher() { return null; },
  };
  const handler = createHandler({
    cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: null, logger: silentLogger(), usageCache,
  });
  const req = makeReq("GET", "/usage/antigravity", signedHeaders("GET", "/usage/antigravity"));
  const res = new FakeRes();
  await dispatch(handler, req, res);
  assert.equal(res.statusCode, 200, res.body);
  assert.deepEqual(calls, [usage.PROVIDER_ANTIGRAVITY]);
});

test("/spend/gemini canonicalizes to antigravity after HMAC (legacy alias)", async () => {
  const calls = [];
  const spendCache = {
    async get(provider) {
      calls.push(provider);
      // Mirror the real cache: no antigravity spend fetcher → not implemented.
      throw new spend.NotImplementedProvider(`spend provider ${provider} not enabled`);
    },
  };
  const handler = createHandler({
    cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: null, logger: silentLogger(), spendCache,
  });
  const req = makeReq("GET", "/spend/gemini", signedHeaders("GET", "/spend/gemini"));
  const res = new FakeRes();
  await dispatch(handler, req, res);
  // No antigravity spend fetcher → 501 not-implemented (device shows "--").
  assert.equal(res.statusCode, 501, res.body);
  assert.deepEqual(calls, [spend.PROVIDER_ANTIGRAVITY]);
});

test("/usage/gemini signed against a different path is still rejected (401)", async () => {
  const usageCache = { async get() { return { slots: [] }; }, antigravityFetcher() { return null; } };
  const handler = createHandler({
    cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: null, logger: silentLogger(), usageCache,
  });
  // Sign /usage/antigravity but request /usage/gemini → signature mismatch.
  const req = makeReq("GET", "/usage/gemini", signedHeaders("GET", "/usage/antigravity"));
  const res = new FakeRes();
  await dispatch(handler, req, res);
  assert.equal(res.statusCode, 401, res.body);
});
