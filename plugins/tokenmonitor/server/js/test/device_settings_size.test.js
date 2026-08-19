// Size coverage for /device/{id}/settings (compat/SETTINGS_REPORT.md).
//
// This cap had NO test in any of the three runtimes, and the value it carried —
// 512 bytes — was under the size of a perfectly ordinary report. A device that
// remembered ~7 networks had every report rejected, and because the firmware's
// dirty flag only clears on a 2xx, the rejection permanently vetoed every
// broker-pushed display setting. The eight-network case below is the regression
// that would have caught it. Mirrors the Go device_settings_size_test.go
// contract.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EventEmitter } from "node:events";

import { createHandler, MAX_SETTINGS_BODY_BYTES } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import { State } from "../src/state.js";
import { Registry, _testing } from "../src/registry/store.js";

const PSK_HEX = "aa".repeat(32);
const PSK = Buffer.from(PSK_HEX, "hex");
const DEVID = "ab12cd34";

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

// signed === false sends a garbage signature, for the "rejected before auth"
// case; otherwise the body is correctly signed under the v3 canonical.
function makePost(body, { signed = true, contentLength = true } = {}) {
  const path = `/device/${DEVID}/settings`;
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = nextNonce();
  const d = createHash("sha256").update(body).digest("hex");
  const headers = {
    host: "localhost",
    "x-tmon-timestamp": ts,
    "x-tmon-nonce": nonce,
    "x-tmon-device": DEVID,
    "x-tmon-config-version": "1",
    "x-tmon-body-sha256": d,
    "x-tmon-signature": signed
      ? auth.computeSignatureBody(PSK, "POST", path, ts, nonce, DEVID, "1", d)
      : "0".repeat(64),
  };
  if (contentLength) headers["content-length"] = String(body.length);
  const req = new EventEmitter();
  req.method = "POST";
  req.url = path;
  req.headers = headers;
  req.socket = { remoteAddress: "127.0.0.1" };
  req.destroy = () => { req.destroyed = true; };
  return req;
}

function newBroker() {
  const dir = mkdtempSync(join(tmpdir(), "tmon-setsize-"));
  const reg = new Registry(dir);
  reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX });
  const handler = createHandler({
    cfg: { psk: () => Buffer.from("00".repeat(32), "hex"),
           security: { max_timestamp_skew_seconds: 60 },
           codex: { enabled: false } },
    cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: reg, logger: { info: () => {}, warn: () => {}, error: () => {} },
  });
  return { dir, reg, handler };
}

function dispatchPost(handler, req, res, body) {
  return new Promise((resolve) => {
    res.on("close", () => resolve());
    handler(req, res);
    req.emit("data", body);
    if (!req.destroyed) req.emit("end");
    if (res.ended) resolve();
  });
}

// A settings report shaped exactly like the firmware's (config_sync.c: the flat
// device-owned fields plus wifi_known), with n remembered networks whose SSIDs
// are ssidLen characters long.
function fullReportBody(n, ssidLen) {
  const wifi_known = [];
  for (let i = 0; i < n; i++) {
    wifi_known.push({
      ssid: String(i).padStart(2, "0") + "w".repeat(ssidLen - 2),
      verified: i % 2 === 0,
      open: i % 3 === 0,
    });
  }
  return Buffer.from(JSON.stringify({
    theme_mode: "night", br_day: 100, br_night: 30, vol: 80,
    autorotate_enabled: true, autorotate_interval_s: 30,
    pet_enabled: true, panel_enabled: true, pet_species: 2,
    pet_name: "Mochi", wifi_known,
  }), "utf8");
}

// The regression. Eight networks is what the store holds (TMON_WIFI_MAX_NETS)
// and 32 characters is the longest SSID 802.11 allows, so this is the largest
// report real firmware can produce from real inputs — it must be accepted, and
// the fields in it must actually land in the registry.
test("settings: full report with eight 32-char SSIDs is accepted", async () => {
  const { dir, reg, handler } = newBroker();
  try {
    const body = fullReportBody(8, 32);
    assert.ok(body.length > 512, "test body no longer exercises the old cap");
    const res = new FakeRes();
    await dispatchPost(handler, makePost(body), res, body);
    assert.equal(res.statusCode, 204, `${body.length} bytes: ${res.body}`);
    const dev = reg.load(DEVID);
    assert.equal(dev.active.payload.vol, 80);
    assert.equal((dev.active.wifiKnown ?? []).length, 8);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// A body sitting exactly on the cap is inside it, not over it — and must be
// APPLIED, not merely "not 413". Asserting 204 is what makes this test fail
// against the old 512-byte broker, which answered 400 here.
test("settings: body of exactly the cap is accepted and applied", async () => {
  const { dir, reg, handler } = newBroker();
  try {
    // pet_name is length-clamped downstream, not rejected, so an at-cap body
    // built this way is a perfectly valid report.
    const prefix = '{"vol":42,"pet_name":"', suffix = '"}';
    const body = Buffer.from(prefix + "p".repeat(MAX_SETTINGS_BODY_BYTES - prefix.length - suffix.length) + suffix, "utf8");
    assert.equal(body.length, MAX_SETTINGS_BODY_BYTES);
    const res = new FakeRes();
    await dispatchPost(handler, makePost(body), res, body);
    assert.equal(res.statusCode, 204, res.body);
    assert.equal(reg.load(DEVID).active.payload.vol, 42);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// One byte over is 413 — a distinct answer from 400, because the device
// downgrades its own wifi_known budget on 413 and retries, whereas 400 means
// the bytes were unreadable and a shorter list would not help.
test("settings: one byte over the cap answers 413 and persists nothing", async () => {
  const { dir, reg, handler } = newBroker();
  try {
    // EXACTLY one byte over. A body of cap+10 would still pass against an
    // implementation that let cap+1 through, which is the off-by-one this test
    // is here to catch.
    const payload = Buffer.from('{"vol":25}');
    const body = Buffer.concat([Buffer.alloc(MAX_SETTINGS_BODY_BYTES + 1 - payload.length, 0x20), payload]);
    assert.equal(body.length, MAX_SETTINGS_BODY_BYTES + 1);
    const res = new FakeRes();
    await dispatchPost(handler, makePost(body), res, body);
    assert.equal(res.statusCode, 413, res.body);
    assert.equal(reg.load(DEVID).active.payload.vol ?? null, null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// The streamed path (no Content-Length) must reach the same verdict as the
// header path — this broker is the only one of the three that has two.
test("settings: oversize without Content-Length is caught while streaming", async () => {
  const { dir, handler } = newBroker();
  try {
    const body = Buffer.alloc(MAX_SETTINGS_BODY_BYTES + 1, 0x78);
    const res = new FakeRes();
    await dispatchPost(handler, makePost(body, { contentLength: false }), res, body);
    assert.equal(res.statusCode, 413, res.body);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// The size gate runs before signature verification (the v3 canonical covers
// sha256(body), so the raw bytes are needed either way) — an oversize body from
// an unauthenticated peer must cost a size check, not a PSK comparison.
test("settings: oversize is rejected before auth", async () => {
  const { dir, handler } = newBroker();
  try {
    const body = Buffer.alloc(MAX_SETTINGS_BODY_BYTES + 1, 0x78);
    const res = new FakeRes();
    await dispatchPost(handler, makePost(body, { signed: false }), res, body);
    assert.equal(res.statusCode, 413, res.body);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// The three runtimes must not drift: go and py carry the same number under
// maxSettingsBodyBytes / _MAX_SETTINGS_BODY_BYTES, and the firmware picks a
// smaller budget for itself so neither side depends on the other's value.
test("settings: cap matches the cross-runtime constant", () => {
  assert.equal(MAX_SETTINGS_BODY_BYTES, 4 << 10);
});
