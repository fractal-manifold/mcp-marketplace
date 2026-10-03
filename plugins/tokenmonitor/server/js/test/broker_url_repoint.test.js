// broker_url on tokenmonitor_set_device_pending is a legacy re-point: firmware
// older than 1.0.1 cannot follow a broker that moved any other way, and
// firmware from 1.0.1 resolves the broker by mDNS and must not be handed one.
//
// Mirrors Go internal/mcp/devices_broker_url_test.go and the /sync tests in
// internal/broker/sync_gcm_test.go, and py test_broker_url_repoint.py.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EventEmitter } from "node:events";

import { createHandler } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import { State } from "../src/state.js";
import { Registry, _testing } from "../src/registry/store.js";
import { decryptPending, decryptPendingGCM } from "../src/registry/crypto.js";
import { brokerURLFw } from "../src/ota.js";
import {
  dispatch, deviceSummary, ERR_BROKER_URL_SHAPE, NOTE_BROKER_URL_HELD, LABEL_BROKER_URL_HELD, LABEL_BROKER_URL_DROP,
} from "../src/mcp/server.js";

const ID = "ab12cd34";
const PSK_HEX = "aa".repeat(32);
const PSK = Buffer.from(PSK_HEX, "hex");
const OLD = "http://192.168.1.28:8765";
const NEW = "http://192.168.1.50:8765";

// Runs fn with a registry holding the device, which last reported firmware fw
// ("" = never seen).
async function withDevice(fw, fn, active = { broker_url: OLD }) {
  const dir = mkdtempSync(join(tmpdir(), "tmon-repoint-"));
  try {
    const reg = new Registry(dir);
    reg.register(ID, { ..._testing.emptyPayload(), psk_hex: PSK_HEX, ...active });
    if (fw) reg.setActiveFirmwareVersion(ID, fw);
    await fn(reg, { cfg: {}, state: {}, logs: null, registry: reg, version: "test" }, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("brokerURLFw classification", () => {
  const cases = {
    "0.10.3": [true, true], "0.12.0": [true, true], "1.0.0": [true, true], "1.0.0-dev.202609011200": [true, true],
    "1.0.1": [false, true], "1.0.1-dev.202609181200": [false, true], "2.0.0": [false, true],
    "": [false, false], dev: [false, false], "1.0": [false, false],
  };
  for (const [fw, [legacy, known]] of Object.entries(cases)) assert.deepEqual(brokerURLFw(fw), { legacy, known }, fw);
});

test("staged for legacy firmware", async () => {
  for (const fw of ["0.10.3", "0.12.0", "1.0.0", "1.0.0-dev.202609011200"]) {
    await withDevice(fw, async (reg, deps) => {
      const out = await dispatch(deps, "tokenmonitor_set_device_pending", { device_id: ID, broker_url: NEW });
      assert.equal(out.ok, true, JSON.stringify(out));
      assert.ok(!("note" in out), fw);
      assert.deepEqual(out.device.pending_changes, ["broker_url"]);
      const rec = reg.load(ID);
      assert.equal(rec.pending.payload.broker_url, NEW);
      assert.equal(rec.active.payload.broker_url, OLD);
    });
  }
});

test("refused from 1.0.1", async () => {
  for (const fw of ["1.0.1", "1.0.1-dev.202609181200", "1.0.2", "2.0.0"]) {
    await withDevice(fw, async (reg, deps) => {
      const out = await dispatch(deps, "tokenmonitor_set_device_pending", { device_id: ID, broker_url: NEW, city: "Paris" });
      // Byte-for-byte: compat/mcp-errors.md publishes this string.
      assert.deepEqual(out, {
        error: `broker_url cannot be staged for device ${ID}: it reports firmware ${fw}, and firmware 1.0.1 or newer resolves the broker by mDNS and does not take a pushed address. Nothing was staged.`,
      });
      // The refusal covers the whole call: nothing else in it is staged either.
      assert.equal(reg.load(ID).pending, null);
    });
  }
});

test("held while the firmware is unknown", async () => {
  for (const fw of ["", "dev"]) {
    await withDevice(fw, async (reg, deps) => {
      const out = await dispatch(deps, "tokenmonitor_set_device_pending", { device_id: ID, broker_url: NEW });
      assert.equal(out.ok, true, JSON.stringify(out));
      assert.equal(out.note, NOTE_BROKER_URL_HELD);
      assert.deepEqual(out.device.pending_changes, [LABEL_BROKER_URL_HELD]);
    });
  }
});

test("shape", async () => {
  await withDevice("0.12.0", async (reg, deps) => {
    for (const bad of ["192.168.1.50:8765", "ftp://192.168.1.50", "http://" + "a".repeat(121)]) {
      assert.deepEqual(await dispatch(deps, "tokenmonitor_set_device_pending", { device_id: ID, broker_url: bad }), { error: ERR_BROKER_URL_SHAPE }, bad);
    }
  });
});

test("labels and the drop report", async () => {
  await withDevice("1.0.0", async (reg, deps, dir) => {
    assert.equal((await dispatch(deps, "tokenmonitor_set_device_pending", { device_id: ID, broker_url: NEW })).ok, true);
    // A device that upgraded between the staging and its next poll: until the
    // poll drops the address, the listing says that is what will happen.
    reg.setActiveFirmwareVersion(ID, "1.0.2");
    assert.equal(deviceSummary(reg.load(ID)).pending_changes[0], LABEL_BROKER_URL_DROP);
    // After the drop the listing reports it, and it survives a reload.
    assert.equal(reg.dropPendingBrokerURL(ID, 1), NEW);
    const s = deviceSummary(new Registry(dir).load(ID));
    assert.equal(s.pending_version, 3);
    assert.deepEqual(s.pending_changes.filter((c) => c.includes("broker_url")), []);
    assert.equal(s.broker_url_dropped, NEW);
    assert.equal(s.active_broker_url, OLD);
    // Staging a new address clears the report.
    reg.setPending(ID, { ..._testing.emptyPayload(), broker_url: "http://192.168.1.51:8765" });
    assert.equal(reg.load(ID).brokerURLDropped, "");
  });
});

// --- /sync -------------------------------------------------------------------

class FakeRes extends EventEmitter {
  constructor() { super(); this.statusCode = 200; this.headers = {}; this.chunks = []; this.ended = false; this.socket = { remoteAddress: "127.0.0.1" }; }
  setHeader(k, v) { this.headers[k.toLowerCase()] = v; }
  writeHead(s) { this.statusCode = s; }
  end(buf) { if (buf) this.chunks.push(Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf))); this.ended = true; this.emit("close"); }
  get body() { return Buffer.concat(this.chunks); }
}

let nonceCounter = 0;

// Poll /sync as firmware fw; resolves with the decrypted pending payload, or
// null when the response carries none.
async function syncPending(reg, fw) {
  const path = `/device/${ID}/sync`;
  nonceCounter += 1;
  const nonce = nonceCounter.toString(16).padStart(32, "0");
  const ts = String(Math.floor(Date.now() / 1000));
  const headers = {
    host: "localhost",
    "x-tmon-timestamp": ts,
    "x-tmon-nonce": nonce,
    "x-tmon-signature": auth.computeSignature(PSK, "GET", path, ts, nonce, ID, "1"),
    "x-tmon-device": ID,
    "x-tmon-config-version": "1",
  };
  if (fw) headers["x-tmon-fw-version"] = fw;
  const req = new EventEmitter();
  req.method = "GET";
  req.url = path;
  req.headers = headers;
  req.socket = { remoteAddress: "127.0.0.1", localAddress: "127.0.0.1", localPort: 8765 };
  const handler = createHandler({
    cfg: { psk: () => Buffer.from("00".repeat(32), "hex"), security: { max_timestamp_skew_seconds: 60 }, codex: { enabled: false } },
    cache: new auth.NonceCache(300), state: new State(), fwLogs: null, registry: reg,
    logger: { info: () => {}, warn: () => {}, error: () => {} },
  });
  const res = new FakeRes();
  await new Promise((resolve) => { res.on("close", resolve); handler(req, res); if (res.ended) resolve(); });
  assert.equal(res.statusCode, 200, res.body.toString());
  const body = JSON.parse(res.body.toString());
  if (!body.pending) return null;
  const n = Buffer.from(body.pending.nonce_b64, "base64");
  const ct = Buffer.from(body.pending.payload_b64, "base64");
  const pt = body.pending.enc === "gcm" ? decryptPendingGCM(PSK, n, ct, body.pending.version) : decryptPending(PSK, n, ct);
  return JSON.parse(Buffer.from(pt).toString("utf8"));
}

test("sync: legacy firmware receives the staged broker_url", async () => {
  for (const fw of ["0.12.0", "1.0.0", "1.0.0-dev.202609011200"]) {
    await withDevice("", async (reg) => {
      reg.setPending(ID, { ..._testing.emptyPayload(), broker_url: NEW });
      const payload = await syncPending(reg, fw);
      assert.equal(payload.broker_url, NEW, fw);
      const dev = reg.load(ID);
      assert.ok(dev.pending);
      assert.equal(dev.brokerURLDropped, "");
    });
  }
});

test("sync: the recorded broker_url is never echoed", async () => {
  await withDevice("", async (reg) => {
    reg.setPending(ID, { ..._testing.emptyPayload(), city: "Paris" });
    const payload = await syncPending(reg, "0.12.0");
    assert.ok(!("broker_url" in payload));
    assert.equal(payload.city, "Paris");
  }, { broker_url: OLD, city: "Madrid" });
});

test("sync: an upgrade while queued drops the broker_url", async () => {
  for (const fw of ["1.0.1", "1.0.1-dev.202609181200", "1.2.0", ""]) {
    await withDevice("", async (reg) => {
      reg.setPending(ID, { ..._testing.emptyPayload(), broker_url: NEW, city: "Paris" });
      const payload = await syncPending(reg, fw);
      assert.ok(!("broker_url" in payload), fw);
      assert.equal(payload.city, "Paris");
      const dev = reg.load(ID);
      assert.equal(dev.brokerURLDropped, NEW);
      assert.equal(dev.pending.payload.broker_url, OLD);
      assert.equal(dev.pending.payload.city, "Paris");
      // The version moves on: a candidate the device may hold from the
      // version that carried the address must read as stale.
      assert.equal(dev.pending.payload.version, 3);
      assert.equal(reg.maybePromote(ID, 2, false), false);
      assert.equal(reg.maybePromote(ID, 3, false), true);
      const active = reg.load(ID).active.payload;
      assert.equal(active.broker_url, OLD);
      assert.equal(active.city, "Paris");
    }, { broker_url: OLD, city: "Madrid" });
  }
  // A pending that held nothing but the address is still delivered, empty,
  // under the new version — for the same reason.
  await withDevice("", async (reg) => {
    reg.setPending(ID, { ..._testing.emptyPayload(), broker_url: NEW });
    const payload = await syncPending(reg, "1.0.2");
    assert.ok(!("broker_url" in payload));
    assert.equal(payload.version, 3);
    const dev = reg.load(ID);
    assert.equal(dev.pending.payload.version, 3);
    assert.equal(dev.brokerURLDropped, NEW);
    assert.equal(dev.active.payload.broker_url, "");
  }, {});
});

test("drop leaves an applied re-point alone", async () => {
  // A unit that took the re-point while still legacy and upgraded before its
  // acknowledging poll reports the pending's own version: it did apply the
  // address, so nothing is dropped and the acknowledgement promotes it.
  await withDevice("1.0.0", async (reg, deps) => {
    assert.equal((await dispatch(deps, "tokenmonitor_set_device_pending", { device_id: ID, broker_url: NEW })).ok, true);
    assert.equal(reg.dropPendingBrokerURL(ID, 2), "");
    assert.equal(reg.maybePromote(ID, 2, false), true);
    const dev = reg.load(ID);
    assert.equal(dev.active.payload.broker_url, NEW);
    assert.equal(dev.brokerURLDropped, "");
  });
});
