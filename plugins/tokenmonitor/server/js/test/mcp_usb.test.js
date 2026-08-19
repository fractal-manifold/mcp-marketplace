import { test } from "node:test";
import assert from "node:assert/strict";

import { handleUSBProvision, usbProvisionErrorReport, buildUSBPayload } from "../src/mcp/usb.js";
import { OutcomeUnknownError, DeviceMismatchError } from "../src/usbprov/session.js";

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

test("broker_url with no psk_hex and no device_id → error (High finding)", async () => {
  const r = await handleUSBProvision(mkDeps(), { pairing_code: "123456", port: "/dev/ttyACM0", broker_url: "http://192.168.1.9:8765" });
  assert.match(r.error, /setting broker_url over USB needs device_id/);
});

test("broker_url + device_id but no registry → refuses to mint an orphan PSK", () => {
  // A minted PSK can only be kept if there is a registry to persist it in.
  // Without one it would be pushed to the device and immediately lost, leaving
  // the device signing with a key nobody on the host has. Parity with Go's
  // TestBuildUSBPayload_NoRegistryRefusesToMintPSK.
  const r = buildUSBPayload(mkDeps(), { broker_url: "http://10.0.0.5:8787" }, "123456", "02c4777c");
  // Byte-for-byte, not a substring: compat/mcp-errors.md publishes this string
  // as the cross-runtime contract, and a substring match would let the three
  // runtimes drift apart in the parenthetical that explains the refusal.
  assert.equal(
    r.error,
    "setting broker_url over USB without a device registry needs an explicit psk_hex " +
      "(a generated PSK cannot be persisted here and would orphan the device)",
  );
  assert.ok(!r.pskGenerated, "no PSK may be minted without somewhere to keep it");
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
  let built = buildUSBPayload(mkDeps(), { city: "Madrid" }, "", "");
  assert.equal(built.error, undefined);
  assert.ok(!("pairing_code" in built.payload));
  built = buildUSBPayload(mkDeps(), { city: "Madrid" }, "071718", "");
  assert.equal(built.error, undefined);
  assert.equal(built.payload.pairing_code, "071718");
});
