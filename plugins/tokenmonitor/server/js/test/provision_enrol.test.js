// Enrolment over the LAN tool (parity with the Go
// internal/mcp/provision_enrol_test.go and py test_provision_enrol.py).
//
// The defect this file exists for: enrolment hung off broker_url, so a provision
// with no address pushed no PSK and wrote no registry record, leaving the device
// in BOOT_NEEDS_CONFIG. The device finds the broker by mDNS; the PSK is the
// whole of the pairing.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { provisionTool, dispatch } from "../src/mcp/server.js";
import { NOTE_NO_REGISTRY, NOTE_PSK_UNRECORDED, NOTE_PSK_MAYBE_LIVE, NOTE_PSK_UNKNOWN, ERR_ENROLL_CHOICE } from "../src/mcp/enrol.js";
import { Registry } from "../src/registry/store.js";

const ID = "ab12cd34";
const PSK = "0".repeat(62) + "cd";
// The mock device listens on loopback, so the address of this broker on the
// route to it — what an enrolment with no broker_url is seeded with — is
// loopback too.
const SEED = "http://127.0.0.1:8765";

const depsFor = (registry, withCfg = true) => ({
  cfg: withCfg ? { server: { port: 8765 } } : {},
  state: {},
  logs: null,
  registry,
  version: "test",
});

// Run provisionTool against a throwaway /provision endpoint. Resolves with
// { wire, out }: the body the device received and the tool result.
async function run(registry, args) {
  let wire = {};
  const srv = createServer((req, res) => {
    let buf = "";
    req.on("data", (c) => { buf += c; });
    req.on("end", () => {
      wire = JSON.parse(buf || "{}");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true,"next":"rebooting"}');
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const full = {
    device_id: ID,
    provision_url: `http://127.0.0.1:${srv.address().port}/provision`,
    pairing_code: "071718",
    ...args,
  };
  const out = await provisionTool(depsFor(registry), full);
  await new Promise((r) => srv.close(r));
  return { wire, out };
}

async function withRegistry(fn) {
  const tmp = mkdtempSync(join(tmpdir(), "tmon-enrol-"));
  try {
    await fn(new Registry(tmp), tmp);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

test("provision enrols without broker_url", async () => {
  await withRegistry(async (reg) => {
    const { wire, out } = await run(reg, { city: "Madrid", enroll: true });
    assert.equal(wire.psk_hex.length, 64);
    // Firmware older than 1.0.0 cannot leave BOOT_NEEDS_CONFIG on a PSK alone,
    // and the LAN transport cannot tell which firmware it is talking to, so
    // the address of this broker on the route to the device is always sent.
    assert.equal(wire.broker_url, SEED);
    assert.equal(out.broker_url_seeded, SEED);
    assert.equal(out.registered, true);
    assert.equal(out.enrolled, true);
    assert.equal(out.psk_generated, true);
    assert.ok(!("psk_hex" in out), "a recorded PSK is not echoed");
    const dev = reg.load(ID);
    assert.equal(dev.active.payload.psk_hex, wire.psk_hex);
    assert.equal(dev.active.payload.city, "Madrid");
    assert.equal(dev.active.payload.broker_url, SEED);
  });
});

test("provision: an unknown device needs enrolment intent", async () => {
  // A device this registry has never seen may be paired with another broker,
  // and the LAN gives no way to ask. Minting a key for it needs the caller to
  // say so.
  await withRegistry(async (reg) => {
    const { posted, out } = await runFailing(reg, 200, { enroll: undefined, city: "Madrid" });
    assert.deepEqual(out, { error: ERR_ENROLL_CHOICE });
    assert.equal(posted, false);
    assert.throws(() => reg.load(ID));
    // A broker_url is intent (it is how a pairing was always asked for), and a
    // caller-supplied address is used as given — nothing is seeded.
    const r = await run(reg, { broker_url: "http://10.0.0.5:8787" });
    assert.equal(r.wire.psk_hex.length, 64);
    assert.equal(r.wire.broker_url, "http://10.0.0.5:8787");
    assert.ok(!("broker_url_seeded" in r.out));
    assert.equal(r.out.registered, true);
  });
});

test("provision refuses when no address can be seeded", async () => {
  // With no way to name an address the device can reach, an enrolment is
  // refused rather than stranding old firmware on "Waiting for setup".
  await withRegistry(async (reg) => {
    const { posted, out } = await runFailing(reg, 200, {}, false);
    assert.deepEqual(out, {
      error:
        "could not work out an address of this broker that the device can reach, and firmware older than 1.0.0 cannot pair without one. Nothing was written. Pass broker_url (see tokenmonitor_provision_hint)",
    });
    assert.equal(posted, false);
  });
});

test("provision PSK precedence: explicit > registry > minted", async () => {
  await withRegistry(async (reg) => {
    await dispatch(depsFor(reg), "tokenmonitor_register_device", { device_id: ID, psk_hex: PSK, city: "Madrid" });

    // No psk_hex → the registry's PSK is reused, and with no broker_url the
    // record is left exactly as it was.
    let { wire, out } = await run(reg, {});
    assert.equal(wire.psk_hex, PSK);
    assert.equal(out.psk_reused, true);
    // The seeded address travels with the key, but it is not a request to
    // converge the record: that stays as it was.
    assert.equal(wire.broker_url, SEED);
    assert.equal(out.broker_url_seeded, SEED);
    assert.equal(reg.load(ID).active.payload.broker_url, "");
    assert.equal(out.enrolled, true);
    assert.equal(out.registered, false);
    assert.ok(!("reregistered" in out));
    assert.equal(reg.load(ID).active.payload.city, "Madrid");

    // Passing the SAME key explicitly is no different: it is the key the
    // registry holds, so the record stays as it is rather than being replaced
    // (which would reset its config version and drop the queued pending).
    await dispatch(depsFor(reg), "tokenmonitor_set_device_pending", { device_id: ID, city: "Sevilla" });
    ({ out } = await run(reg, { psk_hex: PSK }));
    assert.equal(out.enrolled, true);
    assert.equal(out.registered, false);
    assert.ok(!("reregistered" in out));
    assert.equal(reg.load(ID).active.payload.city, "Madrid");
    assert.ok(reg.load(ID).pending);

    // An explicit psk_hex wins over the registry and converges the record.
    const other = "1".repeat(62) + "ef";
    ({ wire, out } = await run(reg, { psk_hex: other }));
    assert.equal(wire.psk_hex, other);
    assert.equal(out.reregistered, true);
    assert.equal(out.enrolled, true);
    assert.equal(reg.load(ID).active.payload.psk_hex, other);
  });
});

test("provision enroll=false pushes no PSK", async () => {
  await withRegistry(async (reg) => {
    const { wire, out } = await run(reg, { city: "Madrid", enroll: false });
    assert.ok(!("psk_hex" in wire));
    assert.equal(out.ok, true);
    assert.equal(out.enrolled, false);
    assert.equal(out.registered, false);
    assert.throws(() => reg.load(ID));
  });
});

test("provision returns the minted PSK when the registry write fails", async () => {
  // When the device took the config but the registry could not be written, the
  // minted PSK exists only on the device. It used to be dropped, leaving a
  // factory reset as the only way out.
  await withRegistry(async (reg, dir) => {
    // A directory squatting on the save's temp file makes the write fail
    // while the load beforehand still reports a clean "not found".
    mkdirSync(join(dir, `${ID}.toml.tmp`, "x"), { recursive: true });
    const { wire, out } = await run(reg, { enroll: true });
    assert.equal(out.ok, true);
    assert.equal(out.registered, false);
    assert.equal(out.enrolled, false);
    assert.equal(out.psk_hex, wire.psk_hex);
    assert.match(out.note, /device provisioned but registry/);
    assert.ok(out.note.includes(NOTE_PSK_UNRECORDED));
  });
});

test("provision with no registry pushes no PSK", async () => {
  const { wire, out } = await run(null, { broker_url: "http://10.0.0.5:8787" });
  assert.ok(!("psk_hex" in wire));
  assert.equal(out.enrolled, false);
  assert.equal(out.note, NOTE_NO_REGISTRY);
});

test("register_device: broker_url is optional", async () => {
  // broker_url used to be required to register a device. It is only a
  // last-known address now, so a PSK alone must be enough.
  await withRegistry(async (reg) => {
    let out = await dispatch(depsFor(reg), "tokenmonitor_register_device", { device_id: ID, psk_hex: PSK });
    assert.equal(out.ok, true, JSON.stringify(out));
    assert.equal(reg.load(ID).active.payload.psk_hex, PSK);
    assert.equal(reg.load(ID).active.payload.broker_url, "");
    // A supplied one is still stored, as the last-known address.
    out = await dispatch(depsFor(reg), "tokenmonitor_register_device", { device_id: "ab12cd35", psk_hex: PSK, broker_url: "http://10.0.0.5:8787" });
    assert.equal(out.ok, true, JSON.stringify(out));
    assert.equal(reg.load("ab12cd35").active.payload.broker_url, "http://10.0.0.5:8787");
  });
});

// Run provisionTool against a device that answers with `status` (0 = drop the
// connection without answering, -1 = cut the answer off mid-body). Resolves with { posted, out }.
async function runFailing(registry, status, extra = {}, withCfg = true) {
  let posted = false;
  const srv = createServer((req, res) => {
    posted = true;
    req.on("data", () => {});
    req.on("end", () => {
      if (status <= 0) {
        // -1: headers promising a body that never arrives.
        if (status < 0) req.socket.write('HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{"ok":');
        req.socket.destroy();
        return;
      }
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end('{"error":"nope"}');
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const args = { device_id: ID, provision_url: `http://127.0.0.1:${srv.address().port}/provision`, pairing_code: "071718", enroll: true, ...extra };
  const out = await provisionTool(depsFor(registry, withCfg), args);
  await new Promise((r) => srv.close(r));
  return { posted, out };
}

test("provision aborts on an unreadable registry record", async () => {
  // A registry record that exists but cannot be read is not a new device.
  // Minting there would re-key a paired device over a transient read failure,
  // so the call must stop before anything is sent.
  await withRegistry(async (reg, dir) => {
    mkdirSync(join(dir, `${ID}.toml`));
    const { posted, out } = await runFailing(reg, 200, { enroll: undefined });
    assert.match(out.error, /^registry load: /);
    assert.equal(posted, false);
  });
});

test("provision hands back a minted PSK when the request fails after being sent", async () => {
  // The device reboots right after applying, so a connection that dies after
  // the request was sent may well have delivered a freshly minted PSK. Losing
  // it with the error would orphan the device.
  await withRegistry(async (reg) => {
    let { out } = await runFailing(reg, 0);
    assert.equal(out.ok, false);
    assert.equal(out.outcome_unknown, true);
    assert.equal(out.psk_hex.length, 64);
    assert.equal(out.note, NOTE_PSK_UNKNOWN);
    assert.throws(() => reg.load(ID));

    // An answer cut off mid-body is the same unknown, in every runtime.
    ({ out } = await runFailing(reg, -1));
    assert.equal(out.outcome_unknown, true);
    assert.equal(out.psk_hex.length, 64);

    // A 5xx is a failed write, which can leave a partial config behind.
    ({ out } = await runFailing(reg, 500));
    assert.equal(out.psk_hex.length, 64);
    assert.equal(out.note, NOTE_PSK_MAYBE_LIVE);
    // A 4xx is a refusal before anything was stored: nothing to recover.
    ({ out } = await runFailing(reg, 401));
    assert.ok(!("psk_hex" in out));
    assert.equal(out.http_status, 401);

    // A PSK the registry already holds is not at risk and is never echoed —
    // the plain error is kept.
    await dispatch(depsFor(reg), "tokenmonitor_register_device", { device_id: ID, psk_hex: PSK });
    ({ out } = await runFailing(reg, 0));
    assert.deepEqual(Object.keys(out), ["error"]);
    assert.match(out.error, /^POST \/provision: /);
  });
});
