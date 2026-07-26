import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { Registry } from "../src/registry/store.js";
import { setWiFiTool } from "../src/mcp/wifi.js";

const DEV = "02c46d94";

// Mirror of Go's wifi_test.go and Python's test_mcp_set_wifi.py — the three
// runtimes must answer the same question the same way, because the same MCP
// client talks to whichever one the launcher picked.
function mkRegistry(t, known) {
  const dir = mkdtempSync(join(tmpdir(), "tmon-wifi-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const r = new Registry(dir);
  r.register(DEV, { broker_url: "http://h:8765", psk_hex: "ab".repeat(32) });
  if (known) r.reportSettings(DEV, { wifi_known: known });
  return r;
}

const call = (r, args) => setWiFiTool({ registry: r }, args);

// The headline case, and the reason this is a tool and not two more fields on
// set_device_pending: a network the device already remembers needs no
// password, because the device is holding it.
test("a remembered network needs no password", (t) => {
  const r = mkRegistry(t, [
    { ssid: "Office", verified: true, open: false },
    { ssid: "HomeNet", verified: true, open: false },
  ]);
  const res = call(r, { device_id: DEV, ssid: "Office" });
  assert.equal(res.error, undefined, `remembered network refused: ${res.error}`);

  const dev = r.load(DEV);
  assert.ok(dev.pending, "a pending must be staged");
  assert.equal(dev.pending.payload.wifi_ssid, "Office");
  assert.equal(dev.pending.payload.wifi_pass, "", "no password was supplied or needed");
});

// The other half: an unknown network must ASK, and the message has to be
// actionable — the caller needs to know a password is what is missing, and
// what the device does know.
test("an unknown network asks for the password and lists what is known", (t) => {
  const r = mkRegistry(t, [{ ssid: "HomeNet", verified: true, open: false }]);
  const res = call(r, { device_id: DEV, ssid: "j2ap" });
  assert.match(res.error, /needs_password=true/);
  assert.match(res.error, /HomeNet/);
  assert.equal(r.load(DEV).pending, null, "nothing may be staged when the request could not be satisfied");
});

test("an unknown network with a password is staged", (t) => {
  const r = mkRegistry(t, [{ ssid: "HomeNet", verified: true, open: false }]);
  const res = call(r, { device_id: DEV, ssid: "j2ap", pass: "j2apj2ap" });
  assert.equal(res.error, undefined);
  const p = r.load(DEV).pending.payload;
  assert.equal(p.wifi_ssid, "j2ap");
  assert.equal(p.wifi_pass, "j2apj2ap");
});

// An open network is remembered but can never be auto-joined, so offering a
// password-free switch to one would stage a change that silently does nothing
// on the device.
test("a remembered OPEN network is refused, not staged", (t) => {
  const r = mkRegistry(t, [{ ssid: "CafeWiFi", verified: false, open: true }]);
  const res = call(r, { device_id: DEV, ssid: "CafeWiFi" });
  assert.match(res.error, /OPEN/);
  assert.equal(r.load(DEV).pending, null);
});

// Old firmware reports no list at all. That is NOT the same as "it does not
// know the network", and telling the user to supply a password they may not
// need would be guessing.
test("no reported list is distinct from an unknown network", (t) => {
  const r = mkRegistry(t, null);
  const res = call(r, { device_id: DEV, ssid: "Office" });
  assert.ok(res.error, "without a reported list the tool cannot claim the network is known");
  assert.doesNotMatch(res.error, /needs_password=true/);
  assert.match(res.error, /has not reported/);
});

// A WiFi password has one job. Once the device has applied the config it holds
// the credential itself, so the registry must not keep accumulating every
// network password the fleet was ever handed.
test("the password is dropped on promote and wifi_known survives", (t) => {
  const r = mkRegistry(t, [{ ssid: "HomeNet", verified: true, open: false }]);
  call(r, { device_id: DEV, ssid: "j2ap", pass: "j2apj2ap" });
  const ver = r.load(DEV).pending.payload.version;

  assert.equal(r.maybePromote(DEV, ver, false), true, "a wifi-only pending has no PSK rotation, so it must promote");
  const dev = r.load(DEV);
  assert.equal(dev.active.payload.wifi_pass, "", "the password must not survive into Active");
  assert.equal(dev.active.payload.wifi_ssid, "j2ap", "the SSID is not a secret and must survive");
  // Observed state must not be collateral damage of a config promote.
  assert.deepEqual(dev.active.wifiKnown, [{ ssid: "HomeNet", verified: true, open: false }]);
});

// SSIDs may legally contain leading/trailing spaces, and trimming would target
// a different network than the caller named.
test("the SSID is not trimmed", (t) => {
  const r = mkRegistry(t, [{ ssid: " Padded ", verified: true, open: false }]);
  const res = call(r, { device_id: DEV, ssid: " Padded " });
  assert.equal(res.error, undefined, `an SSID with significant spaces must match exactly: ${res.error}`);
  assert.equal(r.load(DEV).pending.payload.wifi_ssid, " Padded ");
});

test("oversize ssid / pass are refused", (t) => {
  const r = mkRegistry(t, null);
  assert.match(call(r, { device_id: DEV, ssid: "S".repeat(33), pass: "x" }).error, /802\.11 limit/);
  assert.match(call(r, { device_id: DEV, ssid: "ok", pass: "P".repeat(64) }).error, /WPA2 limit/);
});

// The distinction between "reported none" and "never reported" only earns its
// keep if it survives the disk: every load() re-reads the TOML, so a collapse
// there would make the empty case unreachable in practice.
test("an empty reported list survives a reload and still asks for the password", (t) => {
  const r = mkRegistry(t, []);
  const dev = r.load(DEV);
  assert.notEqual(dev.active.wifiKnown, null, 'an empty reported list must not read back as "never reported"');
  assert.deepEqual(dev.active.wifiKnown, []);
  const res = call(r, { device_id: DEV, ssid: "Office" });
  assert.match(res.error, /needs_password=true/);
});
