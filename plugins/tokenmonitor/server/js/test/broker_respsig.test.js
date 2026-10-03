// End-to-end coverage for X-Tmon-Resp-Signature (compat/HMAC_CANONICAL.md).
//
// The tag is what a device uses to decide that an address it found by mDNS is
// really its broker. Two things have to hold, and neither is visible from the
// auth-module vector tests:
//
//   * the header actually reaches the wire, computed over the bytes and status
//     the client received — the response wrapper has to see the finished
//     response, not the handler's intent;
//   * it is absent on anything that did not authenticate as this device,
//     because a tag emitted before auth would let an unauthenticated caller use
//     the broker as a signing oracle.
//
// Mirrors the Go resp_sig_test.go and py test_response_signature.py contracts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EventEmitter } from "node:events";

import { createHandler, _testing as brokerTesting } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import { State } from "../src/state.js";
import { Registry, _testing } from "../src/registry/store.js";

const PSK_HEX = "aa".repeat(32);
const PSK = Buffer.from(PSK_HEX, "hex");
const DEVID = "ab12cd34";
const SYNC_PATH = `/device/${DEVID}/sync`;
// What makeReq's fake socket reports as its local end, i.e. what a device
// dialling this broker would compute for HOST.
const AUTHORITY = "127.0.0.1:8765";

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
  end(buf) {
    if (buf) this.chunks.push(Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf)));
    this.ended = true;
    this.emit("close");
  }
  get body() { return Buffer.concat(this.chunks); }
}

function silentLogger() {
  return { info: () => {}, warn: () => {}, error: () => {} };
}

let nonceCounter = 0;
function nextNonce() {
  nonceCounter += 1;
  return nonceCounter.toString(16).padStart(32, "0");
}

function syncHeaders(nonce, psk = PSK) {
  const ts = String(Math.floor(Date.now() / 1000));
  return {
    host: "localhost",
    "x-tmon-timestamp": ts,
    "x-tmon-nonce": nonce,
    "x-tmon-signature": auth.computeSignature(psk, "GET", SYNC_PATH, ts, nonce, DEVID, "0"),
    "x-tmon-device": DEVID,
    "x-tmon-config-version": "0",
  };
}

function makeReq(headers) {
  const req = new EventEmitter();
  req.method = "GET";
  req.url = SYNC_PATH;
  req.headers = headers;
  req.socket = { remoteAddress: "127.0.0.1", localAddress: "127.0.0.1", localPort: 8765 };
  return req;
}

function newBroker() {
  const dir = mkdtempSync(join(tmpdir(), "tmon-respsig-"));
  const reg = new Registry(dir);
  reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX });
  const handler = createHandler({
    cfg: { psk: () => Buffer.from("00".repeat(32), "hex"),
           security: { max_timestamp_skew_seconds: 60 },
           codex: { enabled: false } },
    cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: reg, logger: silentLogger(),
  });
  return { dir, reg, handler };
}

function dispatch(handler, req, res) {
  return new Promise((resolve) => {
    res.on("close", () => resolve());
    handler(req, res);
    if (res.ended) resolve();
  });
}

test("sync response carries a tag the device PSK verifies", async () => {
  const { dir, handler } = newBroker();
  try {
    const nonce = nextNonce();
    const res = new FakeRes();
    await dispatch(handler, makeReq(syncHeaders(nonce)), res);
    const sig = res.headers[auth.RESPONSE_SIG_HEADER.toLowerCase()];
    assert.ok(sig, "authenticated response carried no pairing proof");
    // The device computes HOST from the address it dialled; the broker takes
    // it from its own end of the socket. They agree only when nothing relays.
    const want = auth.computeResponseSignature(
      PSK, DEVID, nonce, AUTHORITY, SYNC_PATH, res.statusCode,
      createHash("sha256").update(res.body).digest("hex"),
    );
    assert.equal(sig, want);

    // Bound to the address that answered. This is the anti-relay property: an
    // impostor on the LAN can forward our request to the real broker and hand
    // back this very tag, and the only thing that stops the device adopting
    // the relay is that the tag names the broker's address, not the relay's.
    const relayed = auth.computeResponseSignature(
      PSK, DEVID, nonce, "192.168.1.99:8765", SYNC_PATH, res.statusCode,
      createHash("sha256").update(res.body).digest("hex"),
    );
    assert.notEqual(sig, relayed);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the tag is bound to this request's nonce", async () => {
  // The binding that makes it a challenge-response: same broker, same path,
  // same body, different nonce → a different tag. Otherwise an impostor could
  // record one answer and replay it forever.
  const { dir, handler } = newBroker();
  try {
    const sigs = [];
    for (let i = 0; i < 2; i++) {
      const res = new FakeRes();
      await dispatch(handler, makeReq(syncHeaders(nextNonce())), res);
      sigs.push(res.headers[auth.RESPONSE_SIG_HEADER.toLowerCase()]);
    }
    assert.ok(sigs[0] && sigs[1]);
    assert.notEqual(sigs[0], sigs[1]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("no tag on an unauthorized response", async () => {
  // A 401 must not be signed: we hold no proof that the caller is the paired
  // device, and signing anything it chose the nonce for would turn the broker
  // into an oracle for the PSK it just failed to demonstrate.
  const { dir, handler } = newBroker();
  try {
    const res = new FakeRes();
    await dispatch(handler, makeReq(syncHeaders(nextNonce(), Buffer.alloc(32))), res);
    assert.equal(res.statusCode, 401);
    assert.equal(res.headers[auth.RESPONSE_SIG_HEADER.toLowerCase()], undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("pending payload: broker_url is a legacy re-point", () => {
  // broker_url travels in a pending under two conditions at once: an operator
  // staged it (it differs from the active record's address — the registry's
  // own value is never echoed), and the device asking reports firmware older
  // than 1.0.1, the release where the address stopped being configuration.
  // Mirror of Go TestPendingPayloadJSON_BrokerURLIsALegacyRepoint.
  const staged = "http://192.168.1.50:8765";
  const recorded = "http://192.168.1.28:8765";
  const cases = [
    ["legacy 0.12.0", staged, recorded, "0.12.0", true],
    ["legacy 1.0.0", staged, recorded, "1.0.0", true],
    ["legacy dev build", staged, recorded, "1.0.0-dev.202609011200", true],
    ["legacy, registry had no address", staged, "", "0.10.3", true],
    ["1.0.1", staged, recorded, "1.0.1", false],
    ["1.0.1 dev build", staged, recorded, "1.0.1-dev.202609181200", false],
    ["2.0.0", staged, recorded, "2.0.0", false],
    ["no version reported", staged, recorded, "", false],
    ["unparseable version", staged, recorded, "dev", false],
    ["legacy, but only the registry's own address", recorded, recorded, "0.12.0", false],
    ["legacy, nothing staged", "", recorded, "0.12.0", false],
  ];
  for (const [name, pendingURL, activeURL, fw, want] of cases) {
    const wire = JSON.parse(brokerTesting.pendingPayloadJSON(
      { ..._testing.emptyPayload(), version: 9, broker_url: pendingURL, city: "Barcelona" }, activeURL, fw));
    assert.equal("broker_url" in wire, want, name);
    if (want) assert.equal(wire.broker_url, staged, name);
    assert.equal(wire.city, "Barcelona", name);
  }
});
