// Broker HTTP status parity with the Go reference (bug 21):
//   - a matched path with the wrong method → 405 "method not allowed";
//   - non-ASCII auth headers → 401;
//   - 502 bodies are fixed strings (transport error / upstream error), never
//     the upstream detail.

import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";

import { createHandler } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import * as usage from "../src/usage.js";
import { State } from "../src/state.js";

const DEFAULT_PSK = Buffer.from("00".repeat(32), "hex");

class FakeRes extends EventEmitter {
  constructor() { super(); this.statusCode = 200; this.headers = {}; this.body = ""; this.ended = false; this.socket = { remoteAddress: "127.0.0.1" }; }
  setHeader(k, v) { this.headers[k.toLowerCase()] = v; }
  writeHead(s) { this.statusCode = s; }
  end(buf) { if (buf) this.body += buf.toString("utf8"); this.ended = true; this.emit("close"); }
}

function makeReq(method, url, headers = {}) {
  const req = new EventEmitter();
  req.method = method; req.url = url;
  req.headers = Object.assign({ host: "localhost" }, headers);
  req.socket = { remoteAddress: "127.0.0.1" };
  return req;
}

function makeCfg() { return { psk: () => DEFAULT_PSK, security: { max_timestamp_skew_seconds: 60 }, codex: { enabled: false } }; }
function silentLogger() { return { info() {}, warn() {}, error() {} }; }
function dispatch(handler, req, res) {
  return new Promise((resolve) => { res.on("close", () => resolve()); handler(req, res); if (res.ended) resolve(); });
}
function signedHeaders(path, extra = {}) {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16).toString("hex");
  const sig = auth.computeSignature(DEFAULT_PSK, "GET", path, ts, nonce, "", "");
  return { "x-tmon-timestamp": ts, "x-tmon-nonce": nonce, "x-tmon-signature": sig, ...extra };
}

function handlerWith(opts = {}) {
  return createHandler({
    cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: null, logger: silentLogger(), ...opts,
  });
}

test("wrong method on a known path returns 405", async () => {
  const handler = handlerWith();
  const req = makeReq("POST", "/usage/claude"); // GET-only route
  const res = new FakeRes();
  await dispatch(handler, req, res);
  assert.equal(res.statusCode, 405, res.body);
  assert.match(res.body, /method not allowed/);
});

test("unknown path returns 404", async () => {
  const handler = handlerWith();
  const req = makeReq("GET", "/nope");
  const res = new FakeRes();
  await dispatch(handler, req, res);
  assert.equal(res.statusCode, 404, res.body);
});

test("non-ASCII auth header returns 401", async () => {
  const handler = handlerWith();
  const req = makeReq("GET", "/usage/claude", { "x-tmon-nonce": "café", "x-tmon-timestamp": "1", "x-tmon-signature": "ab" });
  const res = new FakeRes();
  await dispatch(handler, req, res);
  assert.equal(res.statusCode, 401, res.body);
});

test("502 body is the fixed 'transport error' / 'upstream error' string", async () => {
  for (const [errClass, want] of [[usage.Transport, "transport error"], [usage.Upstream, "upstream error"]]) {
    const usageCache = { async get() { throw new errClass("secret detail 12345"); }, antigravityFetcher() { return null; } };
    const handler = handlerWith({ usageCache });
    const path = "/usage/claude";
    const req = makeReq("GET", path, signedHeaders(path));
    const res = new FakeRes();
    await dispatch(handler, req, res);
    assert.equal(res.statusCode, 502, res.body);
    assert.match(res.body, new RegExp(want));
    assert.doesNotMatch(res.body, /secret detail/); // detail never leaks
  }
});
