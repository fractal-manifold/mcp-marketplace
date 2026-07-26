import { test } from "node:test";
import assert from "node:assert/strict";

import { resolve, registryMatches } from "../src/usbprov/scan.js";
import { TIER_REGISTRY_MATCH, TIER_PROBE, TIER_SHARED } from "../src/usbprov/usbids.js";

test("registry-match wins over probe", () => {
  const ports = [{ path: "/dev/ttyACM0", vid: 0x303a, pid: 0x1001, serialNorm: "84f703abcdef" }];
  const got = resolve(ports, { "03abcdef": "S1" });
  assert.equal(got.length, 1);
  const r = got[0];
  assert.equal(r.tier, TIER_REGISTRY_MATCH);
  assert.equal(r.registered, true);
  assert.equal(r.deviceID, "03abcdef");
  assert.equal(r.sku, "S1");
});

test("unregistered Espressif stays probe with candidate id", () => {
  const ports = [{ path: "/dev/ttyACM0", vid: 0x303a, pid: 0x1001, serialNorm: "84f70311112222" }];
  const r = resolve(ports, {})[0];
  assert.equal(r.tier, TIER_PROBE);
  assert.equal(r.registered, false);
  assert.equal(r.deviceID, "11112222");
});

test("shared bridge gets no device_id", () => {
  const ports = [{ path: "/dev/ttyUSB0", vid: 0x1a86, pid: 0x7523, serialNorm: "0000deadbeef" }];
  const r = resolve(ports, {})[0];
  assert.equal(r.tier, TIER_SHARED);
  assert.equal(r.deviceID, "");
});

test("registered id promotes even a shared bridge", () => {
  const ports = [{ path: "/dev/ttyUSB0", vid: 0x0403, pid: 0x6001, serialNorm: "84f703abcdef" }];
  const r = resolve(ports, { "03abcdef": "" })[0];
  assert.equal(r.tier, TIER_REGISTRY_MATCH);
  assert.equal(r.registered, true);
  assert.equal(r.deviceID, "03abcdef");
});

test("sorts by trust then path; registryMatches filters", () => {
  const ports = [
    { path: "/dev/ttyUSB9", vid: 0x1a86, pid: 0x7523, serialNorm: "" },
    { path: "/dev/ttyACM5", vid: 0x303a, pid: 0x1001, serialNorm: "84f7aaaaaaaa" },
    { path: "/dev/ttyACM0", vid: 0x303a, pid: 0x1001, serialNorm: "84f703abcdef" },
    { path: "/dev/ttyACM1", vid: 0x303a, pid: 0x1001, serialNorm: "84f7bbbbbbbb" },
  ];
  const got = resolve(ports, { "03abcdef": "S1" });
  assert.deepEqual(
    got.map((r) => r.path),
    ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyACM5", "/dev/ttyUSB9"],
  );
  const m = registryMatches(got);
  assert.equal(m.length, 1);
  assert.equal(m[0].path, "/dev/ttyACM0");
});
