import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { Registry, _testing, serialIsDev, candidateChannels } from "../src/registry/store.js";

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
  // The legacy [active.providers] bool table migrates to provider_modes
  // (true→auto, false→disabled) and survives the round-trip.
  assert.equal(dev.active.payload.providers, null); // dropped after migration
  assert.deepEqual(dev.active.payload.provider_modes, { claude: "auto", codex: "disabled", gemini: "disabled" });
  assert.deepEqual(dev2.active.payload.provider_modes, dev.active.payload.provider_modes);
  assert.equal(!!dev2.pending, !!dev.pending);
  if (dev.pending) {
    assert.equal(dev2.pending.payload.version, dev.pending.payload.version);
    assert.equal(dev2.pending.payload.psk_hex, dev.pending.payload.psk_hex);
    assert.equal(dev2.pending.payload.theme_mode, dev.pending.payload.theme_mode);
    assert.deepEqual(dev.pending.payload.provider_modes, { claude: "auto", codex: "auto", gemini: "disabled" });
  }
});

test("theme_mode-only pending bumps version and round-trips", () => {
  const tmp = mkdtempSync(join(tmpdir(), "tmon-reg-"));
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

test("setBlockedFirmwareVersion round-trips, clears, and ignores unknown", () => {
  const tmp = mkdtempSync(join(tmpdir(), "tmon-reg-"));
  try {
    const reg = new Registry(tmp);
    reg.register("abcdef0a", { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: "aa".repeat(32) });

    reg.setBlockedFirmwareVersion("abcdef0a", "0.9.1");
    assert.equal(reg.load("abcdef0a").blockedFirmwareVersion, "0.9.1");
    // Persisted to TOML (survives reload).
    assert.match(readFileSync(join(tmp, "abcdef0a.toml"), "utf8"), /blocked_firmware_version/);

    // Clear with empty string.
    reg.setBlockedFirmwareVersion("abcdef0a", "");
    assert.equal(reg.load("abcdef0a").blockedFirmwareVersion, "");

    // Unknown device is a silent no-op.
    reg.setBlockedFirmwareVersion("ffffffff", "0.9.1");
    assert.equal(existsSync(join(tmp, "ffffffff.toml")), false);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("setActiveFirmwareVersion clears a stale revert tombstone when newer", () => {
  const tmp = mkdtempSync(join(tmpdir(), "tmon-reg-"));
  try {
    const reg = new Registry(tmp);
    reg.register("abcdef0b", { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: "aa".repeat(32) });
    reg.setBlockedFirmwareVersion("abcdef0b", "0.9.1");

    // NOTE: the version-comparison clear lives in the broker /sync handler
    // (broker_sync.test.js); the store setter itself only records the running
    // version. Verify the setter does NOT spuriously clear on its own.
    reg.setActiveFirmwareVersion("abcdef0b", "0.9.2");
    assert.equal(reg.load("abcdef0b").active.payload.firmware_version, "0.9.2");
    assert.equal(reg.load("abcdef0b").blockedFirmwareVersion, "0.9.1");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("register then set_pending workflow", () => {
  const tmp = mkdtempSync(join(tmpdir(), "tmon-reg-"));
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
  const tmp = mkdtempSync(join(tmpdir(), "tmon-reg-"));
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
  const tmp = mkdtempSync(join(tmpdir(), "tmon-reg-"));
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
  const tmp = mkdtempSync(join(tmpdir(), "tmon-reg-"));
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
  const tmp = mkdtempSync(join(tmpdir(), "tmon-reg-"));
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

test("reportSettings updates active and pending without bumping version", () => {
  const tmp = mkdtempSync(join(tmpdir(), "tmon-reg-"));
  try {
    const reg = new Registry(tmp);
    reg.register("abcdef07", { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: "aa".repeat(32), city: "X", theme_mode: "day" });
    // Queue an operator config change (city) so a Pending exists.
    reg.setPending("abcdef07", { ..._testing.emptyPayload(), city: "Y" });
    const activeV = reg.load("abcdef07").active.payload.version;
    const pendingV = reg.load("abcdef07").pending.payload.version;

    // Device reports its user-set display settings; clamp + ignore unknown theme.
    const dev = reg.reportSettings("abcdef07", { theme_mode: "rainbow", br_day: 200, br_night: 45, vol: 255 });
    // Active updated, version unchanged, operator-owned city untouched.
    assert.equal(dev.active.payload.version, activeV);
    assert.equal(dev.active.payload.theme_mode, "day");  // rainbow ignored
    assert.equal(dev.active.payload.br_day, 100);         // clamped
    assert.equal(dev.active.payload.br_night, 45);
    assert.equal(dev.active.payload.vol, 100);            // clamped
    assert.equal(dev.active.payload.city, "X");
    // Pending mirrored too, version unchanged, its operator-owned city untouched.
    assert.ok(dev.pending);
    assert.equal(dev.pending.payload.version, pendingV);
    assert.equal(dev.pending.payload.theme_mode, "day");
    assert.equal(dev.pending.payload.br_day, 100);
    assert.equal(dev.pending.payload.br_night, 45);
    assert.equal(dev.pending.payload.city, "Y");

    // A valid theme is applied and persists across reload.
    reg.reportSettings("abcdef07", { theme_mode: "night" });
    const dev2 = reg.load("abcdef07");
    assert.equal(dev2.active.payload.theme_mode, "night");
    assert.equal(dev2.active.payload.br_day, 100);
    assert.equal(dev2.active.payload.version, activeV);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("reportSettings applies device-owned pet fields (clamp/truncate/absence)", () => {
  const tmp = mkdtempSync(join(tmpdir(), "tmon-reg-"));
  try {
    const reg = new Registry(tmp);
    reg.register("abcdef07", { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: "aa".repeat(32) });

    let dev = reg.reportSettings("abcdef07", { pet_enabled: true, pet_species: 2, pet_name: "Sparky the very long pet name" });
    assert.equal(dev.active.payload.pet_enabled, true);
    assert.equal(dev.active.payload.pet_species, 2);
    assert.equal(dev.active.payload.pet_name, "Sparky the very");  // truncated to 15

    // Out-of-range species clamps to 9.
    dev = reg.reportSettings("abcdef07", { pet_species: 42 });
    assert.equal(dev.active.payload.pet_species, 9);

    // Absent pet_species leaves the stored value untouched.
    dev = reg.reportSettings("abcdef07", { pet_name: "Rex" });
    assert.equal(dev.active.payload.pet_species, 9);
    assert.equal(dev.active.payload.pet_name, "Rex");

    // Survives reload from disk.
    const dev2 = reg.load("abcdef07");
    assert.equal(dev2.active.payload.pet_species, 9);
    assert.equal(dev2.active.payload.pet_name, "Rex");
    assert.equal(dev2.active.payload.pet_enabled, true);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

// Serial-derived channel routing must match the shared cross-runtime contract.
const channelPath = findCompat("registry/channel_routing.json");
const chanSkip = channelPath ? false : "compat/registry/channel_routing.json unavailable (standalone checkout)";
test("serialIsDev + candidateChannels match the shared contract", { skip: chanSkip }, () => {
  const vectors = JSON.parse(readFileSync(channelPath, "utf8"));
  for (const c of vectors.serial_is_dev) {
    assert.equal(serialIsDev(c.serial), c.expected, `serialIsDev(${JSON.stringify(c.serial)})`);
  }
  for (const c of vectors.candidate_channels) {
    const got = candidateChannels({ serialNumber: c.serial, channel: c.channel });
    assert.deepEqual(got, c.expected, `candidateChannels(channel=${JSON.stringify(c.channel)}, serial=${JSON.stringify(c.serial)})`);
  }
});
