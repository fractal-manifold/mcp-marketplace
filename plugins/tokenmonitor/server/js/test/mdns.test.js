import { test } from "node:test";
import assert from "node:assert/strict";

import { _internal } from "../src/mdns.js";

const { buildTxt, txtEqual, isLoopback, advertisedIps } = _internal;

test("buildTxt dedupes, sorts and tags runtime", () => {
  const txt = buildTxt(["bb", "aa", "bb"]);
  assert.equal(txt.v, "1");
  assert.equal(txt.runtime, "js");
  assert.equal(txt.devs, "aa,bb");
});

test("buildTxt caps devs at a whole-id boundary under 255 bytes", () => {
  // 8-hex ids + comma = 9 bytes each; 40 ids = 359 joined > 250 cap.
  const ids = Array.from({ length: 40 }, (_, i) => i.toString(16).padStart(8, "0"));
  const txt = buildTxt(ids);
  assert.ok(txt.devs.length <= 255 - "devs=".length);
  assert.ok(!txt.devs.endsWith(","));
  // Every surviving entry is a complete 8-char id.
  for (const id of txt.devs.split(",")) assert.equal(id.length, 8);
});

test("txtEqual compares the three published keys", () => {
  const a = buildTxt(["aa"]);
  assert.ok(txtEqual(a, buildTxt(["aa"])));
  assert.ok(!txtEqual(a, buildTxt(["bb"])));
});

test("isLoopback: wildcard binds are publishable, loopback is not", () => {
  assert.equal(isLoopback(""), false);
  assert.equal(isLoopback("0.0.0.0"), false);
  assert.equal(isLoopback("::"), false);
  assert.equal(isLoopback("127.0.0.1"), true);
  assert.equal(isLoopback("localhost"), true);
  assert.equal(isLoopback("::1"), true);
  assert.equal(isLoopback("192.168.1.142"), false);
});

test("advertisedIps: literal bind is pinned verbatim", () => {
  assert.deepEqual(advertisedIps("192.168.1.142"), ["192.168.1.142"]);
});

test("advertisedIps: wildcard bind re-reads interfaces each call", () => {
  // Can't fake OS interfaces here; assert shape + no virtual/loopback.
  const ips = advertisedIps("0.0.0.0");
  assert.ok(Array.isArray(ips));
  for (const ip of ips) {
    assert.match(ip, /^\d+\.\d+\.\d+\.\d+$/);
    assert.ok(!ip.startsWith("127."));
  }
});
