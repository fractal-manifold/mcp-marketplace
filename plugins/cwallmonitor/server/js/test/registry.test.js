import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { Registry, _testing } from "../src/registry/store.js";

const here = dirname(fileURLToPath(import.meta.url));

// See auth.test.js findCompat for why this walks up past the partial
// server/compat/ runtime slice to the authoritative monorepo compat/.
function findCompat(rel) {
  let dir = here;
  for (let i = 0; i < 12; i++) {
    const c = join(dir, "compat", rel);
    if (existsSync(c)) return c;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
const goldenPath = findCompat("registry/golden/ab12cd34.toml");
const skip = goldenPath ? false : "compat/registry/golden unavailable (standalone checkout)";
const golden = goldenPath ? readFileSync(goldenPath, "utf8") : "";

test("golden round-trips via JS reader/writer", { skip }, () => {
  const dev = _testing.deviceFromTOML(golden);
  const reSerialised = _testing.deviceToTOML(dev);
  const dev2 = _testing.deviceFromTOML(reSerialised);
  assert.equal(dev2.deviceID, dev.deviceID);
  assert.equal(dev2.active.payload.broker_url, dev.active.payload.broker_url);
  assert.equal(dev2.active.payload.psk_hex, dev.active.payload.psk_hex);
  assert.equal(dev2.active.payload.version, dev.active.payload.version);
  assert.equal(dev2.active.payload.city, dev.active.payload.city);
  assert.equal(dev2.active.payload.br_day, dev.active.payload.br_day);
  assert.equal(dev2.active.payload.theme_mode, dev.active.payload.theme_mode);
  assert.equal(!!dev2.pending, !!dev.pending);
  if (dev.pending) {
    assert.equal(dev2.pending.payload.version, dev.pending.payload.version);
    assert.equal(dev2.pending.payload.psk_hex, dev.pending.payload.psk_hex);
    assert.equal(dev2.pending.payload.theme_mode, dev.pending.payload.theme_mode);
  }
});

test("theme_mode-only pending bumps version and round-trips", () => {
  const tmp = mkdtempSync(join(tmpdir(), "cwm-reg-"));
  try {
    const reg = new Registry(tmp);
    reg.register("abcdef04", { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: "aa".repeat(32), theme_mode: "day" });
    const d = reg.setPending("abcdef04", { ..._testing.emptyPayload(), theme_mode: "night" });
    assert.ok(d.pending);
    assert.equal(d.pending.payload.version, 2);
    assert.equal(d.pending.payload.theme_mode, "night");
    const d2 = reg.setPending("abcdef04", { ..._testing.emptyPayload(), theme_mode: "day" });
    assert.equal(d2.pending, null);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("register then set_pending workflow", () => {
  const tmp = mkdtempSync(join(tmpdir(), "cwm-reg-"));
  try {
    const reg = new Registry(tmp);
    const dev = reg.register("abcdef01", { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: "aa".repeat(32), city: "X" });
    assert.equal(dev.active.payload.version, 1);
    const d2 = reg.setPending("abcdef01", { ..._testing.emptyPayload(), city: "Y" });
    assert.ok(d2.pending);
    assert.equal(d2.pending.payload.version, 2);
    assert.equal(d2.pending.payload.city, "Y");
    const d3 = reg.setPending("abcdef01", { ..._testing.emptyPayload(), city: "X" });
    assert.equal(d3.pending, null);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("psksFor returns pending when distinct", () => {
  const tmp = mkdtempSync(join(tmpdir(), "cwm-reg-"));
  try {
    const reg = new Registry(tmp);
    reg.register("abcdef02", { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: "aa".repeat(32) });
    reg.setPending("abcdef02", { ..._testing.emptyPayload(), psk_hex: "bb".repeat(32) });
    const { active, pending } = reg.psksFor("abcdef02");
    assert.equal(active.toString("hex"), "aa".repeat(32));
    assert.equal(pending.toString("hex"), "bb".repeat(32));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("maybePromote theme-only promotes with active PSK", () => {
  const tmp = mkdtempSync(join(tmpdir(), "cwm-reg-"));
  try {
    const reg = new Registry(tmp);
    reg.register("abcdef05", { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: "aa".repeat(32), theme_mode: "day" });
    reg.setPending("abcdef05", { ..._testing.emptyPayload(), theme_mode: "night" });
    assert.equal(reg.maybePromote("abcdef05", 2, false), true);
    const dev = reg.load("abcdef05");
    assert.equal(dev.pending, null);
    assert.equal(dev.active.payload.theme_mode, "night");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("maybePromote rotation still requires pending PSK", () => {
  const tmp = mkdtempSync(join(tmpdir(), "cwm-reg-"));
  try {
    const reg = new Registry(tmp);
    reg.register("abcdef06", { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: "aa".repeat(32) });
    reg.setPending("abcdef06", { ..._testing.emptyPayload(), psk_hex: "bb".repeat(32) });
    assert.equal(reg.maybePromote("abcdef06", 2, false), false);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("maybePromote moves pending → active", () => {
  const tmp = mkdtempSync(join(tmpdir(), "cwm-reg-"));
  try {
    const reg = new Registry(tmp);
    reg.register("abcdef03", { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: "aa".repeat(32) });
    reg.setPending("abcdef03", { ..._testing.emptyPayload(), psk_hex: "bb".repeat(32), city: "Z" });
    assert.equal(reg.maybePromote("abcdef03", 2, true), true);
    const dev = reg.load("abcdef03");
    assert.equal(dev.pending, null);
    assert.equal(dev.active.payload.psk_hex, "bb".repeat(32));
    assert.equal(dev.active.payload.city, "Z");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
