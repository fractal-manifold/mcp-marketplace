// /credentials/codex authenticates BEFORE checking enablement (bug 11).
//
// An unsigned probe must return 401 whether or not codex is enabled, so an
// unauthenticated caller cannot distinguish enabled (401) from disabled (was
// 404) and learn the provider's enablement. Matches the Go reference.

import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";

import { createHandler } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import { State } from "../src/state.js";

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
  end(buf) { if (buf) this.body += buf.toString("utf8"); this.ended = true; this.emit("close"); }
}

function makeReq(method, url, headers = {}) {
  const req = new EventEmitter();
  req.method = method;
  req.url = url;
  req.headers = Object.assign({ host: "localhost" }, headers);
  req.socket = { remoteAddress: "127.0.0.1" };
  return req;
}

function makeCfg(codexEnabled) {
  return {
    psk: () => Buffer.from("00".repeat(32), "hex"),
    security: { max_timestamp_skew_seconds: 60 },
    codex: { enabled: codexEnabled },
    codexAuthPathAbs: () => "/nonexistent/codex/auth.json",
  };
}

function dispatch(handler, req, res) {
  return new Promise((resolve) => {
    res.on("close", () => resolve());
    handler(req, res);
    if (res.ended) resolve();
  });
}

function silentLogger() { return { info() {}, warn() {}, error() {} }; }

async function statusFor(codexEnabled) {
  const handler = createHandler({
    cfg: makeCfg(codexEnabled), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: null, logger: silentLogger(),
  });
  // No HMAC headers → unsigned.
  const req = makeReq("GET", "/credentials/codex");
  const res = new FakeRes();
  await dispatch(handler, req, res);
  return res.statusCode;
}

test("unsigned /credentials/codex with codex disabled is 401 (not 404)", async () => {
  assert.equal(await statusFor(false), 401);
});

test("unsigned /credentials/codex with codex enabled is also 401 (no leak)", async () => {
  assert.equal(await statusFor(true), 401);
});
