import { test } from "node:test";
import assert from "node:assert/strict";

import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { createServer } from "node:http";

import { handleUSBProvision, usbProvisionErrorReport, usbProvisionReport, buildUSBPayload, finalizeUSBPayload } from "../src/mcp/usb.js";
import { OutcomeUnknownError, DeviceMismatchError } from "../src/usbprov/session.js";
import { NOTE_PSK_MAYBE_LIVE, ERR_DEVICE_HAS_PSK, ERR_ENROLL_CHOICE, fwFindsBrokerAlone } from "../src/mcp/enrol.js";
import { dispatch } from "../src/mcp/server.js";
import { Registry } from "../src/registry/store.js";

// deps with no registry — so port auto-selection never finds a registry-match,
// and the validation branches below all return BEFORE any port is opened (no
// hardware side effects).
function mkDeps() {
  return {
    cfg: { server: { bind: "127.0.0.1", port: 8765 }, psk: () => Buffer.alloc(32) },
    registry: null,
  };
}

test("pairing_code must be 6 digits", async () => {
  const r = await handleUSBProvision(mkDeps(), { pairing_code: "12345", port: "/dev/ttyACM0" });
  assert.match(r.error, /pairing_code must be 6 digits/);
});

test("device_id must be 8 lowercase hex", async () => {
  const r = await handleUSBProvision(mkDeps(), { pairing_code: "123456", device_id: "nothex99", port: "/dev/ttyACM0" });
  assert.match(r.error, /device_id must be 8 lowercase hex/);
});

test("no explicit port + no registry-match → error, never auto-picks probe/shared", async () => {
  const r = await handleUSBProvision(mkDeps(), { pairing_code: "123456" });
  assert.match(r.error, /no registry-match device found/);
});

test("bare wifi_ssid (no wifi_pass) → togetherness error", async () => {
  const r = await handleUSBProvision(mkDeps(), { pairing_code: "123456", port: "/dev/ttyACM0", wifi_ssid: "Home" });
  assert.match(r.error, /wifi_ssid and wifi_pass must be sent together/);
});

test("bare wifi_pass (no wifi_ssid) → togetherness error", async () => {
  const r = await handleUSBProvision(mkDeps(), { pairing_code: "123456", port: "/dev/ttyACM0", wifi_pass: "secret" });
  assert.match(r.error, /wifi_ssid and wifi_pass must be sent together/);
});

test("empty wifi_ssid with present wifi_pass → 1..32 bytes error", async () => {
  const r = await handleUSBProvision(mkDeps(), { pairing_code: "123456", port: "/dev/ttyACM0", wifi_ssid: "", wifi_pass: "" });
  assert.match(r.error, /wifi_ssid must be 1\.\.32 bytes/);
});

test("WiFi lengths are UTF-8 bytes, with Go's strings", () => {
  // PROVISION_WIRE §7: the bound is bytes, not code points or UTF-16 units.
  // This runtime used to count .length and so let a 64-byte SSID through.
  const ssidErr = "wifi_ssid must be 1..32 bytes (UTF-8 bytes, not characters)";
  const passErr = "wifi_pass must be at most 64 bytes (UTF-8 bytes, not characters)";
  assert.equal(buildUSBPayload({ wifi_ssid: "ñ".repeat(32), wifi_pass: "hunter2" }, "").error, ssidErr);
  assert.equal(buildUSBPayload({ wifi_ssid: "", wifi_pass: "hunter2" }, "").error, ssidErr);
  assert.equal(buildUSBPayload({ wifi_ssid: "HomeNet", wifi_pass: "a".repeat(65) }, "").error, passErr);
  assert.equal(buildUSBPayload({ wifi_ssid: "HomeNet", wifi_pass: "ñ".repeat(33) }, "").error, passErr);
  assert.equal(buildUSBPayload({ wifi_ssid: "a".repeat(32), wifi_pass: "b".repeat(64) }, "").error, undefined);
});

test("providers use the antigravity wire key", () => {
  // PROVISION_WIRE §3 fixes the nested key set as {claude, codex,
  // antigravity}; this runtime used to emit "gemini" where Go emitted
  // "antigravity".
  let r = buildUSBPayload({ provider_claude: true, provider_codex: false, provider_antigravity: true }, "");
  assert.deepEqual(r.payload.providers, { antigravity: true, claude: true, codex: false });
  assert.deepEqual(Object.keys(r.payload.providers), ["antigravity", "claude", "codex"]); // Go's map order
  // The deprecated arg still maps onto the modern wire key.
  r = buildUSBPayload({ provider_gemini: true }, "");
  assert.equal(r.payload.providers.antigravity, true);
  assert.ok(!("gemini" in r.payload.providers));
});

test("an oversize payload is a client error before any port is opened", async () => {
  // It used to surface as outcome_unknown from inside the PROVISION send,
  // although zero bytes had left the host.
  const r = await handleUSBProvision(mkDeps(), { port: "/dev/ttyACM0", city: "a".repeat(1100) });
  assert.deepEqual(Object.keys(r), ["error"]);
  assert.match(r.error, /over the 1024-byte device limit/);
});

test("the lease is dialled on loopback, and a busy lease is a plain tool error", async () => {
  // Two divergences from Go in one: this runtime dialled the BIND address
  // (the lease endpoints are loopback-only whatever the broker binds to), and
  // reported a busy lease as {ok:false,error} instead of a tool error.
  let hits = 0;
  const srv = createServer((req, res) => {
    hits++;
    req.resume();
    res.writeHead(409, { "Content-Type": "application/json" });
    res.end('{"error":"busy","holder":"lease"}');
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const deps = mkDeps();
    deps.cfg.server.bind = "192.0.2.1"; // unroutable: only loopback can answer
    deps.cfg.server.port = srv.address().port;
    const r = await handleUSBProvision(deps, { port: "/dev/ttyACM0", enroll: false });
    assert.deepEqual(r, { error: "the serial port is leased by another provisioning session; retry shortly" });
    assert.ok(hits >= 1);
  } finally {
    srv.close();
  }
});

test("malformed psk_hex → error", async () => {
  const r = await handleUSBProvision(mkDeps(), { pairing_code: "123456", port: "/dev/ttyACM0", psk_hex: "abc" });
  assert.match(r.error, /psk_hex must be 64 hex chars/);
});

test("invalid theme_mode → error", async () => {
  const r = await handleUSBProvision(mkDeps(), { pairing_code: "123456", port: "/dev/ttyACM0", theme_mode: "sepia" });
  assert.match(r.error, /theme_mode must be one of/);
});

test("usbProvisionErrorReport flags outcome_unknown and device_mismatch", () => {
  const ou = usbProvisionErrorReport(new OutcomeUnknownError());
  assert.equal(ou.ok, false);
  assert.equal(ou.outcome_unknown, true);
  const dm = usbProvisionErrorReport(new DeviceMismatchError("x"));
  assert.equal(dm.device_mismatch, true);
});

test("an absent pairing_code is accepted over USB", async () => {
  // The cable is the physical-presence proof: the device's serial transport
  // never demands a code, so an absent one must not short-circuit. Pair it with
  // a bad device_id so the call still stops before any hardware, and assert we
  // got THAT error rather than the pairing-code one.
  const r = await handleUSBProvision(mkDeps(), { port: "/dev/ttyACM0", device_id: "nothex99" });
  assert.match(r.error, /device_id must be 8 lowercase hex chars/);
});

test("an absent pairing_code stays off the wire", () => {
  // Not even as "": the transports that DO check a code read an empty string as
  // supplied-and-wrong, not as absent.
  let built = buildUSBPayload({ city: "Madrid" }, "");
  assert.equal(built.error, undefined);
  assert.ok(!("pairing_code" in built.payload));
  built = buildUSBPayload({ city: "Madrid" }, "071718");
  assert.equal(built.error, undefined);
  assert.equal(built.payload.pairing_code, "071718");
});

// --- enrolment ---------------------------------------------------------------

const ID = "02c4777c";
const PSK = "0".repeat(62) + "ab";
const RESULT_OK = '{"ok":true,"device_id":"02c4777c","next":"rebooting"}';

function result(body = RESULT_OK) {
  return { device: { deviceID: ID, sku: "S1", fw: "1.0.1" }, resultJSON: Buffer.from(body, "utf8") };
}

// Runs fn with deps backed by a throwaway on-disk registry.
async function withRegistry(fn) {
  const tmp = mkdtempSync(join(tmpdir(), "tmon-usb-"));
  try {
    const deps = { ...mkDeps(), registry: new Registry(tmp) };
    await fn(deps, deps.registry);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

// Firmware as it answers the HELLO. has_psk arrived after 1.0.1; older firmware
// does not send it.
const mkDev = (fw = "1.0.2", hasPSK = undefined) => ({ deviceID: ID, sku: "S1", fw, hasPSK });
const FRESH = mkDev("1.0.2", false);
const PAIRED = mkDev("1.0.2", true);
const V101 = mkDev("1.0.1"); // finds the broker; cannot say has_psk
const LEGACY = mkDev("0.12.0"); // needs a broker_url; cannot say has_psk
const ANCIENT = mkDev("0.11.0");
const ONE = ["http://192.168.1.10:8765"];
const TWO = ["http://192.168.1.10:8765", "http://10.8.0.2:8765"];
const WIFI = { wifi_ssid: "HomeNet", wifi_pass: "hunter2" };

// The two halves of payload construction, the way the handler runs them.
function finalize(deps, args, dev, candidates) {
  const built = buildUSBPayload(args, "");
  assert.equal(built.error, undefined);
  return finalizeUSBPayload(deps, args, built.payload, dev, candidates || []);
}

// A finalized payload as the report sees it.
function fin(payload, gen, reused) {
  return { deviceID: ID, payload, pskHex: payload.psk_hex || "", pskGenerated: gen, pskReused: reused, callerURL: !!payload.broker_url, seeded: "" };
}

test("explicit psk_hex is validated before any port is opened", () => {
  assert.equal(buildUSBPayload({ psk_hex: "abcd" }, "").error, "psk_hex must be 64 hex chars");
  assert.equal(buildUSBPayload({ psk_hex: "z".repeat(64) }, "").error, "psk_hex is not valid hex");
  assert.equal(buildUSBPayload({ psk_hex: PSK, enroll: false }, "").error, "enroll=false cannot be combined with psk_hex");
});

test("a fresh device pairs in one call", async () => {
  // First-time pairing: the device says it holds no PSK, so the headline
  // WiFi-only call also pairs it — no enroll, no broker_url, no device_id.
  await withRegistry((deps) => {
    const f = finalize(deps, WIFI, FRESH, TWO);
    assert.equal(f.error, undefined);
    assert.ok(f.pskGenerated && !f.pskReused && f.pskHex.length === 64);
    assert.equal(f.payload.psk_hex, f.pskHex);
    // 1.0.0+ finds the broker by mDNS: no address is pushed.
    assert.ok(!("broker_url" in f.payload));
    assert.equal(f.seeded, "");
  });
});

test("a paired device this registry does not know is not re-keyed", async () => {
  await withRegistry((deps) => {
    // Byte-for-byte: compat/mcp-errors.md publishes this string.
    assert.equal(
      finalize(deps, WIFI, PAIRED).error,
      "the device already holds a PSK that this registry does not know — it may be paired with another broker, or an earlier enrolment here was never recorded. Nothing was written. Pass enroll=false to keep that pairing and change settings only, enroll=true to re-pair the device with this broker, or psk_hex if you have the key it holds",
    );
    // Even a broker_url does not override the device's own answer.
    assert.equal(finalize(deps, { broker_url: "http://10.0.0.5:8787" }, PAIRED).error, ERR_DEVICE_HAS_PSK);
    // The three ways out the message names.
    let f = finalize(deps, { ...WIFI, enroll: false }, PAIRED);
    assert.ok(!f.error && !f.pskHex && !("psk_hex" in f.payload) && !("broker_url" in f.payload));
    f = finalize(deps, { enroll: true }, PAIRED);
    assert.ok(!f.error && f.pskGenerated);
    f = finalize(deps, { psk_hex: PSK }, PAIRED);
    assert.ok(!f.error && f.pskHex === PSK && !f.pskGenerated);
  });
});

test("firmware that cannot say has_psk needs enrolment intent", async () => {
  // Firmware without has_psk (everything up to 1.0.1): "unknown", never
  // "fresh". An unknown device is only re-keyed when the caller says so.
  await withRegistry((deps) => {
    for (const dev of [V101, LEGACY]) {
      assert.equal(
        finalize(deps, WIFI, dev, ONE).error,
        "this device is not in the registry and nothing says whether it is already paired with another broker. Nothing was written. Pass enroll=true to pair it with this broker (replacing any PSK it holds), or enroll=false to change settings only",
      );
      // WiFi-only on someone else's device stays possible.
      let f = finalize(deps, { ...WIFI, enroll: false }, dev, TWO);
      assert.ok(!f.error && !f.pskHex && !("broker_url" in f.payload));
      // A broker_url is intent, and is used as given.
      f = finalize(deps, { broker_url: "http://10.0.0.5:8787" }, dev, TWO);
      assert.ok(!f.error && f.pskGenerated && f.callerURL && f.seeded === "");
      assert.equal(f.payload.broker_url, "http://10.0.0.5:8787");
    }
    assert.equal(ERR_ENROLL_CHOICE.length > 0, true);
  });
});

test("legacy firmware is seeded a broker_url", async () => {
  // Firmware older than 1.0.0 stays on "Waiting for setup" with a PSK alone.
  await withRegistry((deps) => {
    for (const dev of [LEGACY, ANCIENT, mkDev("")]) {
      const f = finalize(deps, { enroll: true }, dev, ONE);
      assert.equal(f.error, undefined);
      assert.equal(f.seeded, ONE[0]);
      assert.equal(f.payload.broker_url, ONE[0]);
      assert.equal(f.callerURL, false);
    }
    // Ambiguous or empty hint: refuse, before anything is written.
    assert.equal(
      finalize(deps, { enroll: true }, LEGACY, TWO).error,
      "this device's firmware (0.12.0) is older than 1.0.0 and cannot find the broker without an address, and this host has 2 candidate addresses. Nothing was written. Pass broker_url (see tokenmonitor_provision_hint), or enroll=false to change settings without pairing",
    );
    assert.match(finalize(deps, { enroll: true }, LEGACY, []).error, /this host has 0 candidate addresses/);
    assert.match(finalize(deps, { enroll: true }, mkDev(""), []).error, /firmware \(unknown version\)/);
    // 1.0.1 does not need one.
    const f = finalize(deps, { enroll: true }, V101, TWO);
    assert.ok(!f.error && f.seeded === "" && !("broker_url" in f.payload));
  });
});

test("a registered device reuses its PSK", async () => {
  // device_id comes from the HELLO_RESP, so an explicit port with no device_id
  // argument still finds the registry's key.
  await withRegistry(async (deps, reg) => {
    await dispatch(deps, "tokenmonitor_register_device", { device_id: ID, psk_hex: PSK, city: "Madrid" });
    await dispatch(deps, "tokenmonitor_set_device_pending", { device_id: ID, city: "Sevilla" });
    for (const dev of [FRESH, PAIRED, V101]) {
      const f = finalize(deps, WIFI, dev, TWO);
      assert.ok(!f.error && f.pskReused && !f.pskGenerated);
      assert.equal(f.payload.psk_hex, PSK);
      assert.ok(!("broker_url" in f.payload));
    }
    // On legacy firmware the reused key travels with a seeded address — which
    // is not a request to converge: the record and its pending survive.
    const f = finalize(deps, WIFI, LEGACY, ONE);
    assert.ok(!f.error && f.pskReused);
    assert.equal(f.seeded, ONE[0]);
    const out = usbProvisionReport(deps, result(), f);
    assert.equal(out.broker_url_seeded, ONE[0]);
    assert.equal(out.enrolled, true);
    assert.equal(out.registered, false);
    assert.ok(!("reregistered" in out));
    const dev = reg.load(ID);
    assert.equal(dev.active.payload.broker_url, "");
    assert.ok(dev.pending);
    // enroll=false leaves even a known device's key alone.
    assert.equal(finalize(deps, { enroll: false }, PAIRED).pskHex, "");
  });
});

test("no registry → never mints a PSK, with or without broker_url", () => {
  // A minted PSK can only be kept if there is a registry to persist it in.
  const f = finalize(mkDeps(), { broker_url: "http://10.0.0.5:8787" }, LEGACY);
  assert.ok(!f.error && !f.pskHex && !("psk_hex" in f.payload));
  assert.equal(f.payload.broker_url, "http://10.0.0.5:8787");
});

test("wire bytes match Go", async () => {
  // The exact bytes Go's TestFinalizeUSB_WireBytes pins.
  await withRegistry((deps) => {
    const f = finalize(deps, { psk_hex: PSK, city: "Madrid", ...WIFI, provider_claude: true, provider_antigravity: true }, LEGACY, ONE);
    assert.equal(
      f.body.toString("utf8"),
      `{"broker_url":"http://192.168.1.10:8765","psk_hex":"${PSK}","city":"Madrid","providers":{"antigravity":true,"claude":true,"codex":false},"wifi_ssid":"HomeNet","wifi_pass":"hunter2"}`,
    );
  });
});

test("wire bytes escape like Go", async () => {
  // Go's TestFinalizeUSB_WireBytesEscaping: < > & U+2028 U+2029 as \\uXXXX,
  // other non-ASCII as UTF-8.
  await withRegistry((deps) => {
    const f = finalize(deps, { enroll: false, city: "A<b>&c\u2028d\u2029é" }, LEGACY, ONE);
    assert.ok(!f.error);
    assert.equal(f.body.toString("utf8"), '{"city":"A\\u003cb\\u003e\\u0026c\\u2028d\\u2029é"}');
  });
});

test("size is checked again once the payload is complete", async () => {
  await withRegistry((deps) => {
    const f = finalize(deps, { city: "a".repeat(1024 - 60), enroll: true }, LEGACY, ONE);
    assert.match(f.error, /over the 1024-byte device limit/);
  });
});

test("fwFindsBrokerAlone", () => {
  const cases = {
    "1.0.0": true, "1.0.1": true, "2.3.4": true, "1.0.0-dev": true, "10.0.0": true,
    "0.12.0": false, "0.9.4": false, "": false, dev: false, "v1.0.0": false, "1.0": false,
  };
  for (const [fw, want] of Object.entries(cases)) assert.equal(fwFindsBrokerAlone(fw), want, fw);
});

test("report: a new device is enrolled without broker_url", async () => {
  await withRegistry((deps, reg) => {
    const out = usbProvisionReport(deps, result(), fin({ psk_hex: PSK, city: "Madrid" }, true, false));
    assert.equal(out.ok, true);
    assert.equal(out.registered, true);
    assert.equal(out.enrolled, true);
    assert.ok(!("psk_hex" in out) && !("note" in out));
    const dev = reg.load(ID);
    assert.equal(dev.active.payload.psk_hex, PSK);
    assert.equal(dev.active.payload.broker_url, "");
    assert.equal(dev.active.payload.city, "Madrid");
  });
});

test("report: a device-side error is not ok and writes nothing", async () => {
  // A RESULT frame is only the device ANSWERING. An error RESULT used to come
  // back as ok:true and still be mirrored into the registry.
  await withRegistry((deps, reg) => {
    let out = usbProvisionReport(
      deps,
      result('{"error":"psk_hex must be 64 lowercase hex chars"}'),
      fin({ psk_hex: PSK, broker_url: "http://10.0.0.5:8787" }, true, false),
    );
    assert.equal(out.ok, false);
    assert.equal(out.registered, false);
    assert.equal(out.enrolled, false);
    assert.ok(!("reregistered" in out));
    assert.equal(out.error, "psk_hex must be 64 lowercase hex chars");
    assert.throws(() => reg.load(ID));
    // A failed write can leave a partial config, so a minted PSK is handed back.
    assert.equal(out.psk_hex, PSK);
    assert.equal(out.note, NOTE_PSK_MAYBE_LIVE);
    // A RESULT that is valid JSON but carries no ok:true is an error too.
    out = usbProvisionReport(deps, result('{"next":"rebooting"}'), fin({}, false, false));
    assert.equal(out.ok, false);
    assert.equal(out.error, "device rejected the provisioning payload");
  });
});

test("report: a reused PSK leaves the registry record alone", async () => {
  // The headline WiFi-only call on a device this registry already knows: the
  // same PSK is re-sent and the record must NOT be replaced — replaceActive
  // resets the config version to 1 under a live device still at version N,
  // after which every staged pending is numbered too low to be applied.
  await withRegistry(async (deps, reg) => {
    await dispatch(deps, "tokenmonitor_register_device", { device_id: ID, psk_hex: PSK, city: "Madrid" });
    await dispatch(deps, "tokenmonitor_set_device_pending", { device_id: ID, city: "Sevilla" });
    let out = usbProvisionReport(deps, result(), fin({ psk_hex: PSK }, false, true));
    assert.equal(out.ok, true);
    assert.equal(out.enrolled, true);
    assert.equal(out.registered, false);
    assert.ok(!("reregistered" in out));
    assert.equal(out.psk_reused, true);
    let dev = reg.load(ID);
    assert.equal(dev.active.payload.city, "Madrid");
    assert.ok(dev.pending);

    // Passing that same key explicitly (reused=false) changes nothing: what
    // matters is that it is the key the registry already holds.
    out = usbProvisionReport(deps, result(), fin({ psk_hex: PSK }, false, false));
    assert.equal(out.enrolled, true);
    assert.equal(out.registered, false);
    assert.ok(!("reregistered" in out));
    dev = reg.load(ID);
    assert.equal(dev.active.payload.city, "Madrid");
    assert.ok(dev.pending);

    // With a broker_url the call is an explicit re-provision and converges the
    // record in place, as it always has.
    out = usbProvisionReport(deps, result(), fin({ psk_hex: PSK, broker_url: "http://10.0.0.5:8787" }, false, true));
    assert.equal(out.reregistered, true);
    assert.equal(out.enrolled, true);
    dev = reg.load(ID);
    assert.equal(dev.active.payload.broker_url, "http://10.0.0.5:8787");
    assert.ok(!dev.pending);
  });
});

test("report: enroll=false leaves the registry alone", async () => {
  await withRegistry((deps, reg) => {
    const out = usbProvisionReport(deps, result(), fin({ wifi_ssid: "HomeNet", wifi_pass: "x" }, false, false));
    assert.equal(out.ok, true);
    assert.equal(out.enrolled, false);
    assert.equal(out.registered, false);
    assert.ok(!("psk_hex" in out));
    assert.throws(() => reg.load(ID));
  });
});

test("outcome-unknown hands back a minted PSK, never a known one", () => {
  let rep = usbProvisionErrorReport(new OutcomeUnknownError(), PSK, true);
  assert.equal(rep.outcome_unknown, true);
  assert.equal(rep.psk_hex, PSK);
  assert.ok(rep.note);
  rep = usbProvisionErrorReport(new OutcomeUnknownError(), PSK, false);
  assert.ok(!("psk_hex" in rep));
});

test("report: providers reach the registry", async () => {
  // The USB payload carries the "antigravity" wire key; the registry lift must
  // read that key.
  await withRegistry((deps, reg) => {
    usbProvisionReport(deps, result(), fin({ psk_hex: PSK, providers: { antigravity: true, claude: true, codex: false } }, true, false));
    const modes = reg.load(ID).active.payload.provider_modes;
    assert.equal(modes.gemini, modes.claude);
    assert.notEqual(modes.gemini, modes.codex);
  });
});
