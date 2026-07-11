// Endpoint coverage for the HMAC v3 body digest (compat/HMAC_CANONICAL.md):
// /device/{id}/settings and /logs must accept a correctly-digested body,
// reject a tampered or malformed digest with 401, keep accepting legacy v2
// (no header) requests, and keep the oversize behavior intact. Mirrors the
// Go device_body_digest_test.go contract.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EventEmitter } from "node:events";

import { createHandler } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import * as devlog from "../src/devlog.js";
import { State } from "../src/state.js";
import { Registry, _testing } from "../src/registry/store.js";

const PSK_HEX = "aa".repeat(32);
const PSK = Buffer.from(PSK_HEX, "hex");
const DEVID = "ab12cd34";

function makeCfg() {
  return {
    psk: () => Buffer.from("00".repeat(32), "hex"),
    security: { max_timestamp_skew_seconds: 60 },
    codex: { enabled: false },
  };
}

function silentLogger() {
  return { info: () => {}, warn: () => {}, error: () => {} };
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

let nonceCounter = 0;
function nextNonce() {
  nonceCounter += 1;
  return nonceCounter.toString(16).padStart(32, "0");
}

// digest === "auto" → correct v3 signing; null → legacy v2 (no header);
// any other string → sent verbatim as X-Tmon-Body-Sha256 and signed v3.
function makePost(endpoint, body, digest = "auto") {
  const path = `/device/${DEVID}/${endpoint}`;
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = nextNonce();
  const headers = {
    host: "localhost",
    "x-tmon-timestamp": ts,
    "x-tmon-nonce": nonce,
    "x-tmon-device": DEVID,
    "x-tmon-config-version": "1",
    "content-length": String(body.length),
  };
  if (digest === null) {
    headers["x-tmon-signature"] = auth.computeSignature(PSK, "POST", path, ts, nonce, DEVID, "1");
  } else {
    const d = digest === "auto" ? createHash("sha256").update(body).digest("hex") : digest;
    headers["x-tmon-body-sha256"] = d;
    headers["x-tmon-signature"] = auth.computeSignatureBody(PSK, "POST", path, ts, nonce, DEVID, "1", d);
  }
  const req = new EventEmitter();
  req.method = "POST";
  req.url = path;
  req.headers = headers;
  req.socket = { remoteAddress: "127.0.0.1" };
  req.destroy = () => { req.destroyed = true; };
  return req;
}

function newBroker() {
  const dir = mkdtempSync(join(tmpdir(), "tmon-bodydigest-"));
  const reg = new Registry(dir);
  reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX });
  const handler = createHandler({
    cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: reg, logger: silentLogger(),
  });
  return { dir, reg, handler };
}

// Drives the handler and streams `body` through the req in one chunk.
function dispatchPost(handler, req, res, body) {
  return new Promise((resolve) => {
    res.on("close", () => resolve());
    handler(req, res);
    req.emit("data", body);
    if (!req.destroyed) req.emit("end");
    if (res.ended) resolve();
  });
}

test("settings: v3 digest accepts and persists", async () => {
  const { dir, reg, handler } = newBroker();
  try {
    const body = Buffer.from('{"vol":25}', "utf8");
    const res = new FakeRes();
    await dispatchPost(handler, makePost("settings", body), res, body);
    assert.equal(res.statusCode, 204, res.body);
    const dev = reg.load(DEVID);
    assert.equal(dev.active.payload.vol, 25);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("settings: tampered body rejected 401, nothing persisted", async () => {
  const { dir, reg, handler } = newBroker();
  try {
    // Digest of {"vol":25}, but the wire body says vol:99 — on-path tamper.
    const good = createHash("sha256").update('{"vol":25}').digest("hex");
    const body = Buffer.from('{"vol":99}', "utf8");
    const res = new FakeRes();
    await dispatchPost(handler, makePost("settings", body, good), res, body);
    assert.equal(res.statusCode, 401, res.body);
    assert.equal(reg.load(DEVID).active.payload.vol ?? null, null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("settings: malformed digest rejected 401", async () => {
  const { dir, handler } = newBroker();
  try {
    for (const bad of ["A".repeat(64), "a".repeat(63), "g".repeat(64)]) {
      const body = Buffer.from('{"vol":25}', "utf8");
      const res = new FakeRes();
      await dispatchPost(handler, makePost("settings", body, bad), res, body);
      assert.equal(res.statusCode, 401, `digest ${bad}: ${res.body}`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("settings: no header falls back to legacy v2 and persists", async () => {
  const { dir, reg, handler } = newBroker();
  try {
    const body = Buffer.from('{"vol":30}', "utf8");
    const res = new FakeRes();
    await dispatchPost(handler, makePost("settings", body, null), res, body);
    assert.equal(res.statusCode, 204, res.body);
    assert.equal(reg.load(DEVID).active.payload.vol, 30);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("logs: v3 digest accepted", async () => {
  const { dir, handler } = newBroker();
  try {
    const body = Buffer.from("I (123) tmon: boot\n", "utf8");
    const res = new FakeRes();
    await dispatchPost(handler, makePost("logs", body), res, body);
    assert.equal(res.statusCode, 202, res.body);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("logs: oversize body still answers 413", async () => {
  const { dir, handler } = newBroker();
  try {
    const body = Buffer.alloc(devlog.MAX_BODY_BYTES + 1, 0x78);
    const res = new FakeRes();
    await dispatchPost(handler, makePost("logs", body), res, body);
    assert.equal(res.statusCode, 413, res.body);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
