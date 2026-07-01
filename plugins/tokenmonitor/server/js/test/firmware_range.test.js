// /firmware Range support (bug 20): suffix ranges and out-of-range requests
// must match the Go reference (http.ServeContent) — bytes=-N → 206 of the last
// N bytes; an out-of-range start → 416 + Content-Range: bytes */<size>.
//
// HOME is overridden BEFORE importing the server so firmwarePath() (which calls
// os.homedir() at request time) resolves under a temp dir we control.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const HOME = mkdtempSync(join(tmpdir(), "tmon-fw-home-"));
process.env.HOME = HOME;

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";

import { createHandler } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import { State } from "../src/state.js";

const DEFAULT_PSK = Buffer.from("00".repeat(32), "hex");
const SIZE = 500;
const FW_DIR = join(HOME, ".config", "tokenmonitor", "firmware");
mkdirSync(FW_DIR, { recursive: true });
writeFileSync(join(FW_DIR, "fw.bin"), Buffer.alloc(SIZE, 7));

after(() => rmSync(HOME, { recursive: true, force: true }));

class FakeRes extends EventEmitter {
  constructor() {
    super();
    this.statusCode = 200;
    this.headers = {};
    this.chunks = [];
    this.ended = false;
    this.socket = { remoteAddress: "127.0.0.1" };
  }
  setHeader(k, v) { this.headers[k.toLowerCase()] = v; }
  writeHead(s) { this.statusCode = s; }
  destroy() { this.ended = true; this.emit("close"); }
  end(buf) { if (buf) this.chunks.push(buf); this.ended = true; this.emit("close"); }
  write(buf) { this.chunks.push(buf); return true; }
}

function makeReq(method, url, headers) {
  const req = new EventEmitter();
  req.method = method;
  req.url = url;
  req.headers = Object.assign({ host: "localhost" }, headers);
  req.socket = { remoteAddress: "127.0.0.1" };
  return req;
}

function signedHeaders(path, extra = {}) {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16).toString("hex"); // 32 hex chars
  const sig = auth.computeSignature(DEFAULT_PSK, "GET", path, ts, nonce, "", "");
  return { "x-tmon-timestamp": ts, "x-tmon-nonce": nonce, "x-tmon-signature": sig, ...extra };
}

function makeCfg() {
  return { psk: () => DEFAULT_PSK, security: { max_timestamp_skew_seconds: 60 }, codex: { enabled: false } };
}

function dispatch(handler, req, res) {
  return new Promise((resolve) => {
    res.on("close", () => resolve());
    handler(req, res);
    if (res.ended) resolve();
  });
}

async function fetchRange(rangeHeader) {
  const handler = createHandler({
    cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: null, logger: { info() {}, warn() {}, error() {} },
  });
  const path = "/firmware/fw.bin";
  const req = makeReq("GET", path, signedHeaders(path, rangeHeader ? { range: rangeHeader } : {}));
  const res = new FakeRes();
  await dispatch(handler, req, res);
  return res;
}

test("suffix range bytes=-100 serves the last 100 bytes (206)", async () => {
  const res = await fetchRange("bytes=-100");
  assert.equal(res.statusCode, 206);
  assert.equal(res.headers["content-range"], `bytes 400-499/${SIZE}`);
  assert.equal(String(res.headers["content-length"]), "100");
});

test("out-of-range start bytes=999999- returns 416 with Content-Range */size", async () => {
  const res = await fetchRange("bytes=999999-");
  assert.equal(res.statusCode, 416);
  assert.equal(res.headers["content-range"], `bytes */${SIZE}`);
});

test("no Range header serves the whole file (200)", async () => {
  const res = await fetchRange(null);
  assert.equal(res.statusCode, 200);
  assert.equal(String(res.headers["content-length"]), String(SIZE));
});
