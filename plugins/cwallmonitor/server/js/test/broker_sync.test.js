// Handler-level tests for the broker request path: device-sync crash-proofing
// (just-deleted device → error, not a crash), AES-GCM gating on the live
// X-Cwm-Fw-Version header, persisting that header into active.firmware_version,
// percent-decoded path canonicalization, and the non-ASCII auth-header reject.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EventEmitter } from "node:events";

import { createHandler } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import { State } from "../src/state.js";
import { Registry, NotFound, _testing } from "../src/registry/store.js";
import { decryptPending, decryptPendingGCM } from "../src/registry/crypto.js";

const PSK_HEX = "aa".repeat(32);
const PSK = Buffer.from(PSK_HEX, "hex");
const DEVID = "ab12cd34";

function makeCfg() {
  return {
    psk: () => Buffer.from("00".repeat(32), "hex"), // broker default PSK (unused for device paths)
    security: { max_timestamp_skew_seconds: 60 },
    codex: { enabled: false },
  };
}

// Minimal fake ServerResponse: records statusCode/body, emits 'close' on end so
// the handlers' state.recordRequest hooks fire (and any throw there is caught).
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

// Build signed sync headers. `signPath` defaults to the decoded path.
function syncHeaders(deviceID, version, extra = {}, signPath = `/device/${deviceID}/sync`) {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = "0123456789abcdef" + Math.random().toString(16).slice(2).padEnd(16, "0").slice(0, 16);
  const sig = auth.computeSignature(PSK, "GET", signPath, ts, nonce, deviceID, String(version));
  return {
    "x-cwm-timestamp": ts,
    "x-cwm-nonce": nonce,
    "x-cwm-signature": sig,
    "x-cwm-device": deviceID,
    "x-cwm-config-version": String(version),
    ...extra,
  };
}

function newReg() {
  const dir = mkdtempSync(join(tmpdir(), "cwm-sync-"));
  return { dir, reg: new Registry(dir) };
}

function dispatch(handler, req, res) {
  return new Promise((resolve) => {
    res.on("close", () => resolve());
    handler(req, res);
    // Sync handler ends synchronously; if not, resolve on close above.
    if (res.ended) resolve();
  });
}

test("device-sync for a just-deleted device returns an error, not a crash", async () => {
  const { dir, reg } = newReg();
  try {
    reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX });
    const handler = createHandler({
      cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
      fwLogs: null, registry: reg, logger: silentLogger(),
    });
    // Delete the device file AFTER the PSK lookup would succeed... but we
    // simulate the race by deleting before the request: psksFor → NotFound 404.
    rmSync(join(dir, `${DEVID}.toml`));
    const req = makeReq("GET", `/device/${DEVID}/sync`, syncHeaders(DEVID, 0));
    const res = new FakeRes();
    await dispatch(handler, req, res);
    assert.equal(res.statusCode, 404);
    assert.match(res.body, /unknown device/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("device-sync survives a delete racing AFTER auth (load throws NotFound → 404)", async () => {
  const { dir, reg } = newReg();
  try {
    reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX });
    // Wrap load so the FIRST call (psksFor) succeeds and the post-auth
    // registry.load() throws NotFound — exactly the race the try/catch guards.
    const realLoad = reg.load.bind(reg);
    let calls = 0;
    reg.load = (id) => {
      calls += 1;
      // psksFor calls load once; the next load inside the handler body is the
      // one we make fail with NotFound — exactly the post-auth delete race.
      if (calls >= 2) throw new NotFound(`device ${id} gone`);
      return realLoad(id);
    };
    const handler = createHandler({
      cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
      fwLogs: null, registry: reg, logger: silentLogger(),
    });
    const req = makeReq("GET", `/device/${DEVID}/sync`, syncHeaders(DEVID, 0));
    const res = new FakeRes();
    await dispatch(handler, req, res);
    assert.equal(res.statusCode, 404, res.body);
    assert.match(res.body, /unknown device/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("device-sync emits legacy CTR pending when fw header is below the GCM floor", async () => {
  const { dir, reg } = newReg();
  try {
    reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX, city: "Madrid" });
    reg.setPending(DEVID, { ..._testing.emptyPayload(), city: "Paris" });
    const handler = createHandler({
      cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
      fwLogs: null, registry: reg, logger: silentLogger(),
    });
    const req = makeReq("GET", `/device/${DEVID}/sync`, syncHeaders(DEVID, 1, { "x-cwm-fw-version": "0.8.0" }));
    const res = new FakeRes();
    await dispatch(handler, req, res);
    assert.equal(res.statusCode, 200, res.body);
    const out = JSON.parse(res.body);
    assert.ok(out.pending, "pending present");
    assert.equal(out.pending.enc, undefined, "no enc field for CTR");
    const nonce = Buffer.from(out.pending.nonce_b64, "base64");
    assert.equal(nonce.length, 16);
    const ct = Buffer.from(out.pending.payload_b64, "base64");
    const pt = decryptPending(PSK, nonce, ct).toString("utf8");
    assert.match(pt, /"city":"Paris"/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("device-sync emits enc=gcm pending when fw header is >= 0.9.0", async () => {
  const { dir, reg } = newReg();
  try {
    reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX, city: "Madrid" });
    reg.setPending(DEVID, { ..._testing.emptyPayload(), city: "Paris" });
    const handler = createHandler({
      cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
      fwLogs: null, registry: reg, logger: silentLogger(),
    });
    const req = makeReq("GET", `/device/${DEVID}/sync`, syncHeaders(DEVID, 1, { "x-cwm-fw-version": "0.9.0-dev.202606" }));
    const res = new FakeRes();
    await dispatch(handler, req, res);
    assert.equal(res.statusCode, 200, res.body);
    const out = JSON.parse(res.body);
    assert.ok(out.pending, "pending present");
    assert.equal(out.pending.enc, "gcm");
    const nonce = Buffer.from(out.pending.nonce_b64, "base64");
    assert.equal(nonce.length, 12);
    const ct = Buffer.from(out.pending.payload_b64, "base64");
    const pt = decryptPendingGCM(PSK, nonce, ct, out.pending.version).toString("utf8");
    assert.match(pt, /"city":"Paris"/);
    // Wrong AAD (version) must fail — AAD is bound to pending.version.
    assert.throws(() => decryptPendingGCM(PSK, nonce, ct, out.pending.version + 1));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("device-sync persists X-Cwm-Fw-Version into active.firmware_version only on change", async () => {
  const { dir, reg } = newReg();
  try {
    reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX });
    const handler = createHandler({
      cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
      fwLogs: null, registry: reg, logger: silentLogger(),
    });
    // First sync reports 0.9.0 → persisted.
    let req = makeReq("GET", `/device/${DEVID}/sync`, syncHeaders(DEVID, 0, { "x-cwm-fw-version": "0.9.0" }));
    let res = new FakeRes();
    await dispatch(handler, req, res);
    assert.equal(res.statusCode, 200, res.body);
    assert.equal(reg.load(DEVID).active.payload.firmware_version, "0.9.0");

    // A no-change sync must not error (and stays 0.9.0).
    req = makeReq("GET", `/device/${DEVID}/sync`, syncHeaders(DEVID, 0, { "x-cwm-fw-version": "0.9.0" }));
    res = new FakeRes();
    await dispatch(handler, req, res);
    assert.equal(res.statusCode, 200, res.body);
    assert.equal(reg.load(DEVID).active.payload.firmware_version, "0.9.0");

    // A new version updates it.
    req = makeReq("GET", `/device/${DEVID}/sync`, syncHeaders(DEVID, 0, { "x-cwm-fw-version": "0.9.1" }));
    res = new FakeRes();
    await dispatch(handler, req, res);
    assert.equal(res.statusCode, 200, res.body);
    assert.equal(reg.load(DEVID).active.payload.firmware_version, "0.9.1");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("device-sync clears a revert tombstone once the device reports a newer version", async () => {
  const { dir, reg } = newReg();
  try {
    reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX });
    reg.setBlockedFirmwareVersion(DEVID, "0.9.1");
    const handler = createHandler({
      cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
      fwLogs: null, registry: reg, logger: silentLogger(),
    });

    // Device still on the blocked version → tombstone stays.
    let req = makeReq("GET", `/device/${DEVID}/sync`, syncHeaders(DEVID, 0, { "x-cwm-fw-version": "0.9.1" }));
    let res = new FakeRes();
    await dispatch(handler, req, res);
    assert.equal(res.statusCode, 200, res.body);
    assert.equal(reg.load(DEVID).blockedFirmwareVersion, "0.9.1");

    // Device reaches a newer version (the fix) → tombstone cleared.
    req = makeReq("GET", `/device/${DEVID}/sync`, syncHeaders(DEVID, 0, { "x-cwm-fw-version": "0.9.2" }));
    res = new FakeRes();
    await dispatch(handler, req, res);
    assert.equal(res.statusCode, 200, res.body);
    assert.equal(reg.load(DEVID).blockedFirmwareVersion, "");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("percent-encoded usage path verifies against the DECODED signature", async () => {
  // /usage/cla%75de on the wire; the device signs /usage/claude. The handler
  // must decode before HMAC, so the (default-PSK) verify path is reached and
  // routing lands on the usage handler (503 because no usageCache configured).
  const handler = createHandler({
    cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: null, logger: silentLogger(),
    usageCache: null,
  });
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = "0123456789abcdef0123456789abcdef";
  // Sign the DECODED path with the broker default PSK (registry=null path).
  const sig = auth.computeSignature(Buffer.from("00".repeat(32), "hex"), "GET", "/usage/claude", ts, nonce, "", "");
  const req = makeReq("GET", "/usage/cla%75de", {
    "x-cwm-timestamp": ts, "x-cwm-nonce": nonce, "x-cwm-signature": sig,
  });
  const res = new FakeRes();
  await dispatch(handler, req, res);
  // 503 (usage disabled) proves auth PASSED on the decoded path. A wrong-path
  // signature would have produced 401 instead.
  assert.equal(res.statusCode, 503, res.body);
});

test("non-ASCII auth header is rejected with 401 before HMAC", async () => {
  const handler = createHandler({
    cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: null, logger: silentLogger(),
  });
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = "0123456789abcdef0123456789abcdef";
  // X-Cwm-Device carries "café" as latin-1-decoded bytes (é = 0xc3 0xa9).
  const badDevice = Buffer.from("636166c3a9", "hex").toString("latin1");
  const req = makeReq("GET", "/credentials", {
    "x-cwm-timestamp": ts, "x-cwm-nonce": nonce, "x-cwm-signature": "ab".repeat(32),
    "x-cwm-device": badDevice,
  });
  const res = new FakeRes();
  await dispatch(handler, req, res);
  assert.equal(res.statusCode, 401, res.body);
});

test("malformed percent-escape in path → 400", async () => {
  const handler = createHandler({
    cfg: makeCfg(), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: null, logger: silentLogger(),
  });
  const req = makeReq("GET", "/usage/%zz", {
    "x-cwm-timestamp": "1", "x-cwm-nonce": "0123456789abcdef0123456789abcdef", "x-cwm-signature": "ab".repeat(32),
  });
  const res = new FakeRes();
  await dispatch(handler, req, res);
  assert.equal(res.statusCode, 400, res.body);
});

function silentLogger() {
  return { info: () => {}, warn: () => {}, error: () => {} };
}
