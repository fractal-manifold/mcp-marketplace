// Per-device TOML registry with flock(2) interprocess safety.
// Wire-compatible with tokenmonitor-mcp/internal/registry/registry.go.

import { open, openSync, closeSync, mkdirSync, readdirSync, readFileSync, writeFileSync, fsyncSync, renameSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";

import TOML from "@iarna/toml";

// flock(2) interprocess exclusion is mandatory per compat/SECURITY.md.
// We refuse to construct a Registry without it: silently downgrading to
// no-op locks would let two tokenmonitor-mcp processes corrupt the same device
// TOML on PSK rotation.
let flockSync = null;
let flockLoadError = null;
try {
  ({ flockSync } = await import("fs-ext"));
  if (typeof flockSync !== "function") {
    flockLoadError = new Error("fs-ext loaded but flockSync is not a function");
    flockSync = null;
  }
} catch (e) {
  flockLoadError = e;
}

// v2 adds: device.serial_number, device.hw_sku (factory identity from
// X-Tmon-Serial / X-Tmon-Sku headers), pending.firmware_manifest_b64 /
// firmware_manifest_sig_b64 (signed OTA manifest), and
// active.min_secure_version (anti-rollback floor).
// v3 adds: device.channel (release-track override). It's a device-level
// attribute (like serial_number / hw_sku), NOT a config payload field — the
// firmware never receives it; the broker uses it only to pick which GitHub
// asset to fetch. "" == AUTO: the track is derived from the serial (a dev
// unit, FAC=="DEV", consumes stable+dev; production consumes stable). An
// explicit "stable" / "dev" pins that track regardless of serial. v1/v2 files
// load with channel="" (auto) and are re-serialised as v3 on the next save.
export const SCHEMA_VERSION = 3;

const DEVICE_ID_RE = /^[0-9a-f]{8}$/;
export function validDeviceID(id) { return DEVICE_ID_RE.test(id); }

export class RegistryError extends Error {}
export class NotFound extends RegistryError {}

export class Registry {
  constructor(devicesDir) {
    if (!devicesDir) throw new Error("registry: empty directory");
    if (!flockSync) {
      const cause = flockLoadError ? `: ${flockLoadError.message}` : "";
      throw new Error(`registry: flock(2) unavailable (install 'fs-ext')${cause}`);
    }
    this.dir = devicesDir;
    mkdirSync(devicesDir, { recursive: true, mode: 0o700 });
  }

  _path(id) { return join(this.dir, `${id}.toml`); }
  _lockPath(id) { return join(this.dir, `${id}.toml.lock`); }

  _withLock(id, fn) {
    const lockPath = this._lockPath(id);
    const fd = openSync(lockPath, "a+", 0o600);
    flockSync(fd, "ex");
    try {
      return fn();
    } finally {
      try { flockSync(fd, "un"); } catch {}
      closeSync(fd);
    }
  }

  load(id) {
    if (!validDeviceID(id)) throw new RegistryError(`registry: invalid device_id ${JSON.stringify(id)}`);
    return this._withLock(id, () => this._loadLocked(id));
  }

  _loadLocked(id) {
    const path = this._path(id);
    if (!existsSync(path)) throw new NotFound(`registry: device ${id} not found`);
    const raw = readFileSync(path, "utf8");
    const dev = deviceFromTOML(raw);
    // 0 = freshly-decoded zero value; 1 = pre-serial schema; 2 = pre-channel
    // schema. All migrate transparently (missing fields stay empty/default;
    // the next save bumps to the current SCHEMA_VERSION). Anything else is
    // foreign.
    if (![0, 1, 2, SCHEMA_VERSION].includes(dev.schemaVersion)) {
      throw new RegistryError(`registry: schema ${dev.schemaVersion}, expected ${SCHEMA_VERSION}`);
    }
    return dev;
  }

  _saveLocked(dev) {
    if (!validDeviceID(dev.deviceID)) throw new RegistryError(`registry: invalid device_id ${JSON.stringify(dev.deviceID)}`);
    const path = this._path(dev.deviceID);
    const tmp = path + ".tmp";
    writeFileSync(tmp, deviceToTOML(dev), { mode: 0o600 });
    const fd = openSync(tmp, "r");
    try { fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, path);
  }

  register(id, active) {
    if (!validDeviceID(id)) throw new RegistryError(`registry: invalid device_id ${JSON.stringify(id)}`);
    if (!active.psk_hex || !active.broker_url) throw new RegistryError("registry: register requires psk_hex and broker_url");
    if (active.psk_hex.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(active.psk_hex)) {
      throw new RegistryError("registry: psk_hex must be 64 lowercase hex chars");
    }
    active.psk_hex = active.psk_hex.toLowerCase();
    active.version = 1;
    return this._withLock(id, () => {
      try {
        this._loadLocked(id);
        throw new RegistryError(`registry: device ${id} already exists`);
      } catch (e) { if (!(e instanceof NotFound)) throw e; }
      const dev = { schemaVersion: SCHEMA_VERSION, deviceID: id, serialNumber: "", hwSku: "", channel: normalizeChannel(active.channel), blockedFirmwareVersion: "", active: { payload: active, lastSeen: null }, pending: null };
      delete active.channel; // channel is device-level, not part of the config payload
      this._saveLocked(dev);
      return dev;
    });
  }

  // replaceActive overwrites a device's active config in place, preserving ALL
  // device-level metadata (serialNumber, hwSku, channel, blockedFirmwareVersion,
  // …) and clearing any pending. Version resets to 1. For a physical
  // re-provision (user re-ran /tokenmonitor:configure after wiping NVS): the
  // device already applied the new broker_url+psk and proved presence with the
  // pairing code, so converge active rather than queue a pending the wiped
  // device can neither decrypt (sealed with the old psk) nor promote (it reports
  // config version 0). Mirror of Go ReplaceActive. See #8. Device must exist.
  replaceActive(id, active) {
    if (!validDeviceID(id)) throw new RegistryError(`registry: invalid device_id ${JSON.stringify(id)}`);
    if (!active.psk_hex || !active.broker_url) throw new RegistryError("registry: replace requires psk_hex and broker_url");
    if (active.psk_hex.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(active.psk_hex)) {
      throw new RegistryError("registry: psk_hex must be 64 lowercase hex chars");
    }
    active.psk_hex = active.psk_hex.toLowerCase();
    active.version = 1;
    return this._withLock(id, () => {
      const dev = this._loadLocked(id);
      if (active.channel !== undefined && active.channel !== null) dev.channel = normalizeChannel(active.channel);
      delete active.channel; // channel is device-level, not part of the config payload
      dev.active = { payload: active, lastSeen: dev.active ? dev.active.lastSeen : null };
      dev.pending = null;
      this._saveLocked(dev);
      return dev;
    });
  }

  setPending(id, update) {
    if (!validDeviceID(id)) throw new RegistryError(`registry: invalid device_id ${JSON.stringify(id)}`);
    if (update.psk_hex) {
      if (update.psk_hex.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(update.psk_hex)) {
        throw new RegistryError("registry: psk_hex must be 64 lowercase hex chars");
      }
      update.psk_hex = update.psk_hex.toLowerCase();
    }
    return this._withLock(id, () => {
      const dev = this._loadLocked(id);
      const base = dev.pending ? dev.pending.payload : dev.active.payload;
      const merged = mergePayload(base, update);
      let next = dev.active.payload.version + 1;
      if (dev.pending && dev.pending.payload.version >= next) next = dev.pending.payload.version + 1;
      merged.version = next;
      if (payloadEquivalent(merged, dev.active.payload)) {
        dev.pending = null;
      } else {
        dev.pending = { payload: merged, createdAt: new Date() };
      }
      this._saveLocked(dev);
      return dev;
    });
  }

  // reportSettings applies device-reported display settings (theme / brightness
  // / volume / autorotate) to the stored config WITHOUT bumping the version.
  // The device owns these fields (the user sets them on-screen), so the broker
  // mirrors them into Active — and into a queued Pending, if any, so an in-flight
  // OTA/config change does not re-introduce the stale value on promotion.
  // See compat/SETTINGS_REPORT.md.
  reportSettings(id, s) {
    if (!validDeviceID(id)) throw new RegistryError(`registry: invalid device_id ${JSON.stringify(id)}`);
    return this._withLock(id, () => {
      const dev = this._loadLocked(id);
      let changed = applyReported(dev.active.payload, s);
      if (dev.pending) {
        changed = applyReported(dev.pending.payload, s) || changed;
      }
      if (changed) this._saveLocked(dev);
      return dev;
    });
  }

  maybePromote(id, observedVersion, usedPendingPSK) {
    if (!validDeviceID(id)) throw new RegistryError(`registry: invalid device_id ${JSON.stringify(id)}`);
    return this._withLock(id, () => {
      let dev;
      try { dev = this._loadLocked(id); } catch (e) { if (e instanceof NotFound) return false; throw e; }
      if (!dev.pending || observedVersion !== dev.pending.payload.version) return false;
      // Allow promotion without a pending-PSK signature only when the
      // rotation does not actually change the PSK. Otherwise theme- /
      // city- / brightness-only pending updates would never promote.
      if (!usedPendingPSK && dev.pending.payload.psk_hex !== dev.active.payload.psk_hex) return false;
      dev.active = { payload: dev.pending.payload, lastSeen: new Date() };
      dev.pending = null;
      this._saveLocked(dev);
      return true;
    });
  }

  touch(id) {
    if (!validDeviceID(id)) return;
    this._withLock(id, () => {
      let dev;
      try { dev = this._loadLocked(id); } catch (e) { if (e instanceof NotFound) return; throw e; }
      dev.active.lastSeen = new Date();
      this._saveLocked(dev);
    });
  }

  // setSerial persists X-Tmon-Serial / X-Tmon-Sku reported by the
  // device on /sync. Non-destructive: empty strings preserve existing
  // values. Unknown devices are silently ignored.
  setSerial(id, serial, sku) {
    if (!validDeviceID(id)) return;
    this._withLock(id, () => {
      let dev;
      try { dev = this._loadLocked(id); } catch (e) { if (e instanceof NotFound) return; throw e; }
      let changed = false;
      if (serial && serial !== dev.serialNumber) { dev.serialNumber = serial; changed = true; }
      if (sku && sku !== dev.hwSku) { dev.hwSku = sku; changed = true; }
      if (changed) this._saveLocked(dev);
    });
  }

  // setChannel persists the device's release track ("" / "stable" vs "dev").
  // Device-level (like setSerial), applied immediately — it only steers which
  // GitHub asset the OTA loop fetches; the firmware never sees it. Unknown
  // devices are silently ignored.
  setChannel(id, channel) {
    if (!validDeviceID(id)) return;
    const norm = normalizeChannel(channel);
    this._withLock(id, () => {
      let dev;
      try { dev = this._loadLocked(id); } catch (e) { if (e instanceof NotFound) return; throw e; }
      if (norm !== dev.channel) { dev.channel = norm; this._saveLocked(dev); }
    });
  }

  // setActiveFirmwareVersion records the version the device reports it is
  // actually RUNNING (X-Tmon-Fw-Version), into active.firmware_version. Unsigned
  // metadata, like setSerial. Only-on-change to keep TOML churn bounded under a
  // 60s poll. Unknown devices are silently ignored. This keeps the OTA
  // auto-discovery loop honest after a canary revert: decide() compares the
  // candidate release against active.payload.firmware_version, so persisting
  // the real running version stops it re-staging a build the device rolled back.
  setActiveFirmwareVersion(id, version) {
    if (!validDeviceID(id)) return;
    const v = String(version || "");
    if (!v) return;
    this._withLock(id, () => {
      let dev;
      try { dev = this._loadLocked(id); } catch (e) { if (e instanceof NotFound) return; throw e; }
      if (dev.active.payload.firmware_version === v) return;
      dev.active.payload.firmware_version = v;
      this._saveLocked(dev);
    });
  }

  // setBlockedFirmwareVersion records (or clears, when version is "") the
  // per-device OTA revert tombstone — a firmware version the auto-discovery
  // loop must not re-stage. Written by tokenmonitor_revert with the version the
  // device is being reverted FROM. Only-on-change; unknown devices ignored.
  // Mirror of go/py stores.
  setBlockedFirmwareVersion(id, version) {
    if (!validDeviceID(id)) return;
    const v = String(version || "");
    this._withLock(id, () => {
      let dev;
      try { dev = this._loadLocked(id); } catch (e) { if (e instanceof NotFound) return; throw e; }
      if (dev.blockedFirmwareVersion === v) return;
      dev.blockedFirmwareVersion = v;
      this._saveLocked(dev);
    });
  }

  // bumpMinSV is monotonic — never lowers the floor.
  bumpMinSV(id, sv) {
    if (!validDeviceID(id)) return;
    this._withLock(id, () => {
      let dev;
      try { dev = this._loadLocked(id); } catch (e) { if (e instanceof NotFound) return; throw e; }
      const cur = Number(dev.active.payload.min_secure_version || 0);
      if (sv <= cur) return;
      dev.active.payload.min_secure_version = Number(sv);
      this._saveLocked(dev);
    });
  }

  psksFor(id) {
    const dev = this.load(id);
    const active = dev.active.payload.psk_hex ? Buffer.from(dev.active.payload.psk_hex, "hex") : null;
    let pending = null;
    if (dev.pending && dev.pending.payload.psk_hex && dev.pending.payload.psk_hex !== dev.active.payload.psk_hex) {
      pending = Buffer.from(dev.pending.payload.psk_hex, "hex");
    }
    return { active, pending };
  }

  list() {
    const out = [];
    let entries;
    try { entries = readdirSync(this.dir).sort(); }
    catch { return []; }
    for (const name of entries) {
      if (!name.endsWith(".toml")) continue;
      const id = name.slice(0, -5);
      if (!validDeviceID(id)) continue;
      try { out.push(this.load(id)); } catch { /* skip */ }
    }
    return out;
  }

  // listDeviceIds returns just the device_id slugs found on disk, sorted
  // ascending. Cheaper than list() for callers that only need IDs (e.g.
  // the mDNS advertiser populating the TXT `devs=` record).
  listDeviceIds() {
    let entries;
    try { entries = readdirSync(this.dir).sort(); }
    catch { return []; }
    const out = [];
    for (const name of entries) {
      if (!name.endsWith(".toml")) continue;
      const id = name.slice(0, -5);
      if (!validDeviceID(id)) continue;
      out.push(id);
    }
    return out;
  }
}

// Per-provider mode helpers — mirror of the Go registry. "auto" trusts the
// broker's credential detection; "subscription"/"api_key" are device-side
// display overrides; "disabled" hides the provider. The legacy bool set
// (providers) is read for migration only and lifted into provider_modes.
export function providerModeEnabled(m) { return m != null && m !== "" && m !== "disabled"; }
export function validProviderMode(s) {
  return s === "disabled" || s === "auto" || s === "subscription" || s === "api_key";
}
export function providerModeFromBool(b) { return b ? "auto" : "disabled"; }
function providersToModes(p) {
  if (p == null) return null;
  return {
    claude: providerModeFromBool(!!p.claude),
    codex: providerModeFromBool(!!p.codex),
    gemini: providerModeFromBool(!!p.gemini),
  };
}

function emptyPayload() {
  return {
    version: 0, broker_url: "", psk_hex: "", city: "",
    br_day: 0, br_night: 0, vol: 0,
    providers: null, provider_modes: null, autorotate_enabled: null, autorotate_interval_s: null,
    theme_mode: "",
    // Virtual pet — device-owned display settings, synced like theme/brightness.
    // pet_enabled null = no change (default true on-device); pet_species null =
    // not picked yet (no sentinel stored); pet_name "" = use species default.
    pet_enabled: null, pet_species: null, pet_name: "",
    // null = "no opinion" (use global default); [] = clear override.
    gemini_models: null,
    // Diagnostic log upload toggle (NVS tmon_log_en). null = no change;
    // dev units default on, factory units default off on-device.
    log_enabled: null,
    // All-or-nothing OTA fields. Empty strings travel alongside any
    // config change without arming an update; the firmware ignores
    // the trio unless all three are non-empty + well-formed.
    firmware_url: "", firmware_sha256: "", firmware_version: "",
    // Schema v2: signed manifest envelope (paired) + anti-rollback
    // floor (monotonic, packed 8.8.16 = major.minor.patch).
    firmware_manifest_b64: "", firmware_manifest_sig_b64: "",
    min_secure_version: 0,
  };
}

function payloadToTomlObj(p) {
  const d = { version: Number(p.version) };
  if (p.broker_url) d.broker_url = p.broker_url;
  if (p.psk_hex) d.psk_hex = p.psk_hex;
  if (p.city) d.city = p.city;
  if (p.br_day) d.br_day = Number(p.br_day);
  if (p.br_night) d.br_night = Number(p.br_night);
  if (p.vol) d.vol = Number(p.vol);
  // provider_modes is the canonical field; the legacy providers bool table
  // is never written (loadLocked migrates it on read).
  if (p.provider_modes != null) {
    d.provider_modes = {
      claude: String(p.provider_modes.claude || ""),
      codex: String(p.provider_modes.codex || ""),
      gemini: String(p.provider_modes.gemini || ""),
    };
  }
  if (p.autorotate_enabled != null) d.autorotate_enabled = !!p.autorotate_enabled;
  if (p.autorotate_interval_s != null) d.autorotate_interval_s = Number(p.autorotate_interval_s);
  if (p.theme_mode) d.theme_mode = String(p.theme_mode);
  if (p.pet_enabled != null) d.pet_enabled = !!p.pet_enabled;
  if (p.pet_species != null) d.pet_species = Number(p.pet_species);
  if (p.pet_name) d.pet_name = String(p.pet_name);
  if (Array.isArray(p.gemini_models) && p.gemini_models.length > 0) {
    d.gemini_models = p.gemini_models.map(String);
  }
  if (p.log_enabled != null) d.log_enabled = !!p.log_enabled;
  if (p.firmware_url) d.firmware_url = String(p.firmware_url);
  if (p.firmware_sha256) d.firmware_sha256 = String(p.firmware_sha256);
  if (p.firmware_version) d.firmware_version = String(p.firmware_version);
  if (p.firmware_manifest_b64) d.firmware_manifest_b64 = String(p.firmware_manifest_b64);
  if (p.firmware_manifest_sig_b64) d.firmware_manifest_sig_b64 = String(p.firmware_manifest_sig_b64);
  if (p.min_secure_version) d.min_secure_version = Number(p.min_secure_version);
  return d;
}

function tomlObjToPayload(d) {
  d = d || {};
  return {
    version: Number(d.version || 0),
    broker_url: String(d.broker_url || ""),
    psk_hex: String(d.psk_hex || ""),
    city: String(d.city || ""),
    br_day: Number(d.br_day || 0),
    br_night: Number(d.br_night || 0),
    vol: Number(d.vol || 0),
    // Canonical field is provider_modes; fold any legacy providers bool
    // table into it and drop the bool so it is never re-emitted.
    providers: null,
    provider_modes: d.provider_modes
      ? { claude: String(d.provider_modes.claude || ""), codex: String(d.provider_modes.codex || ""), gemini: String(d.provider_modes.gemini || "") }
      : providersToModes(d.providers),
    autorotate_enabled: typeof d.autorotate_enabled === "boolean" ? d.autorotate_enabled : null,
    autorotate_interval_s: typeof d.autorotate_interval_s === "number" ? d.autorotate_interval_s : null,
    theme_mode: String(d.theme_mode || ""),
    pet_enabled: typeof d.pet_enabled === "boolean" ? d.pet_enabled : null,
    pet_species: typeof d.pet_species === "number" ? d.pet_species : null,
    pet_name: String(d.pet_name || ""),
    gemini_models: Array.isArray(d.gemini_models) ? d.gemini_models.map(String) : null,
    log_enabled: typeof d.log_enabled === "boolean" ? d.log_enabled : null,
    firmware_url: String(d.firmware_url || ""),
    firmware_sha256: String(d.firmware_sha256 || ""),
    firmware_version: String(d.firmware_version || ""),
    firmware_manifest_b64: String(d.firmware_manifest_b64 || ""),
    firmware_manifest_sig_b64: String(d.firmware_manifest_sig_b64 || ""),
    min_secure_version: Number(d.min_secure_version || 0),
  };
}

// Release channel normalisation. "" means AUTO — the track is derived from
// the serial (dev unit → dev, production → stable). "stable" / "dev" are
// EXPLICIT pins that override the serial. Trim + lowercase, kept verbatim so
// a "stable" pin stays distinct from auto. Centralised so the registry, the
// OTA loop and the tools agree on the canonical form.
export function normalizeChannel(c) {
  return String(c || "").trim().toLowerCase();
}

// serialIsDev reports whether a factory serial denotes a DEVELOPMENT unit.
// Mirror of the firmware's tmon_serial_is_dev(): true iff the FAC field is
// "DEV". The canonical 24-char serial is "CWM-<SKU2>-<FAC3>-<YYWW4>-<SEQ6>-<C1>"
// (FAC is the 3rd dash-separated field); a blank-eFuse dev unit falls back to
// "DEV-<device_id>". Both the SIM serial and the tmon_dev_sn override bake
// FAC="DEV", so all dev paths land here. Case-insensitive; empty/unparseable
// → false (treated as a production/stable unit). Wire-identical across runtimes.
export function serialIsDev(serial) {
  const s = String(serial || "").trim().toUpperCase();
  if (!s) return false;
  if (s.startsWith("DEV-")) return true;
  const parts = s.split("-");
  return parts.length >= 3 && parts[2] === "DEV";
}

// effectiveChannel returns the device's PRIMARY release track for display
// (list_devices, /info): an explicit channel override wins; otherwise it's
// derived from the serial (dev unit → "dev", production → "stable"). For OTA
// routing use candidateChannels — a dev unit consumes BOTH tracks.
export function effectiveChannel(dev) {
  if (dev && dev.channel) return dev.channel;
  return (dev && serialIsDev(dev.serialNumber)) ? "dev" : "stable";
}

// candidateChannels returns the release tracks the OTA loop must consider for
// a device, newest-wins across them. A dev unit (or a dev override) tracks the
// UNION of stable + dev so it never misses a stable build that is newer than
// the current dev tip (by SemVer, a final X.Y.Z is newer than X.Y.Z-dev.<ts>).
// A production unit, or an explicit stable override, tracks stable only.
export function candidateChannels(dev) {
  const override = dev && dev.channel ? dev.channel : "";
  if (override === "stable") return ["stable"];
  if (override === "dev" || (dev && serialIsDev(dev.serialNumber))) {
    return ["stable", "dev"];
  }
  return ["stable"];
}

function deviceToTOML(dev) {
  const doc = { schema_version: SCHEMA_VERSION, device_id: dev.deviceID };
  if (dev.serialNumber) doc.serial_number = dev.serialNumber;
  if (dev.hwSku) doc.hw_sku = dev.hwSku;
  if (dev.channel) doc.channel = dev.channel;
  if (dev.blockedFirmwareVersion) doc.blocked_firmware_version = dev.blockedFirmwareVersion;
  const a = payloadToTomlObj(dev.active.payload);
  if (dev.active.lastSeen) a.last_seen = dev.active.lastSeen;
  doc.active = a;
  if (dev.pending) {
    const p = payloadToTomlObj(dev.pending.payload);
    p.created_at = dev.pending.createdAt;
    doc.pending = p;
  }
  return TOML.stringify(doc);
}

function deviceFromTOML(text) {
  const d = TOML.parse(text);
  const active = { payload: tomlObjToPayload(d.active), lastSeen: d.active?.last_seen ? new Date(d.active.last_seen) : null };
  let pending = null;
  if (d.pending) {
    pending = { payload: tomlObjToPayload(d.pending), createdAt: d.pending.created_at ? new Date(d.pending.created_at) : new Date() };
  }
  return {
    schemaVersion: Number(d.schema_version || 0),
    deviceID: String(d.device_id || ""),
    serialNumber: String(d.serial_number || ""),
    hwSku: String(d.hw_sku || ""),
    channel: normalizeChannel(d.channel),
    blockedFirmwareVersion: String(d.blocked_firmware_version || ""),
    active,
    pending,
  };
}

// applyReported overlays device-owned fields onto a payload, clamping numeric
// ranges and ignoring an unknown theme_mode. Returns true if anything changed.
// Operator-owned fields (city, providers, firmware, psk, ...) are never touched.
function applyReported(p, s) {
  let changed = false;
  const clamp = (v, lo, hi) => (v < lo ? lo : v > hi ? hi : v);
  if (s.theme_mode === "day" || s.theme_mode === "night" || s.theme_mode === "auto") {
    if (p.theme_mode !== s.theme_mode) { p.theme_mode = s.theme_mode; changed = true; }
  }
  if (s.br_day != null) {
    const v = clamp(Math.trunc(Number(s.br_day)), 10, 100);
    if (p.br_day !== v) { p.br_day = v; changed = true; }
  }
  if (s.br_night != null) {
    const v = clamp(Math.trunc(Number(s.br_night)), 5, 100);
    if (p.br_night !== v) { p.br_night = v; changed = true; }
  }
  if (s.vol != null) {
    const v = clamp(Math.trunc(Number(s.vol)), 0, 100);
    if (p.vol !== v) { p.vol = v; changed = true; }
  }
  if (s.autorotate_enabled != null) {
    const b = Boolean(s.autorotate_enabled);
    if (p.autorotate_enabled !== b) { p.autorotate_enabled = b; changed = true; }
  }
  if (s.autorotate_interval_s != null) {
    const v = clamp(Math.trunc(Number(s.autorotate_interval_s)), 1, 300);
    if (p.autorotate_interval_s !== v) { p.autorotate_interval_s = v; changed = true; }
  }
  if (s.pet_enabled != null) {
    const b = Boolean(s.pet_enabled);
    if (p.pet_enabled !== b) { p.pet_enabled = b; changed = true; }
  }
  if (s.pet_species != null) {
    // Clamp to the species enum 0..9 like every other numeric field. Absence
    // (null) is handled by the caller — the device omits the field until it
    // has picked a species, so no sentinel is stored.
    const v = clamp(Math.trunc(Number(s.pet_species)), 0, 9);
    if (p.pet_species !== v) { p.pet_species = v; changed = true; }
  }
  if (s.pet_name != null) {
    const name = String(s.pet_name).slice(0, 15);
    if (p.pet_name !== name) { p.pet_name = name; changed = true; }
  }
  return changed;
}

function mergePayload(base, upd) {
  return {
    version: base.version,
    broker_url: upd.broker_url || base.broker_url,
    psk_hex: upd.psk_hex || base.psk_hex,
    city: upd.city || base.city,
    br_day: (upd.br_day !== undefined && upd.br_day !== null && upd.br_day !== 0) ? upd.br_day : base.br_day,
    br_night: (upd.br_night !== undefined && upd.br_night !== null && upd.br_night !== 0) ? upd.br_night : base.br_night,
    vol: (upd.vol !== undefined && upd.vol !== null) ? upd.vol : base.vol,
    providers: null,
    provider_modes: upd.provider_modes != null
      ? upd.provider_modes
      : (upd.providers != null ? providersToModes(upd.providers) : (base.provider_modes ?? null)),
    autorotate_enabled: upd.autorotate_enabled != null ? upd.autorotate_enabled : base.autorotate_enabled,
    autorotate_interval_s: upd.autorotate_interval_s != null ? upd.autorotate_interval_s : base.autorotate_interval_s,
    theme_mode: upd.theme_mode || base.theme_mode,
    pet_enabled: upd.pet_enabled != null ? upd.pet_enabled : base.pet_enabled,
    pet_species: upd.pet_species != null ? upd.pet_species : base.pet_species,
    pet_name: upd.pet_name || base.pet_name,
    gemini_models: Array.isArray(upd.gemini_models)
      ? upd.gemini_models.slice()
      : base.gemini_models,
    log_enabled: upd.log_enabled != null ? upd.log_enabled : base.log_enabled,
    firmware_url: upd.firmware_url || base.firmware_url,
    firmware_sha256: upd.firmware_sha256 || base.firmware_sha256,
    firmware_version: upd.firmware_version || base.firmware_version,
    firmware_manifest_b64: upd.firmware_manifest_b64 || base.firmware_manifest_b64,
    firmware_manifest_sig_b64: upd.firmware_manifest_sig_b64 || base.firmware_manifest_sig_b64,
    // Monotonic: never lowers.
    min_secure_version: Math.max(Number(upd.min_secure_version || 0), Number(base.min_secure_version || 0)),
  };
}

function payloadEquivalent(a, b) {
  if (a.broker_url !== b.broker_url || a.psk_hex !== b.psk_hex || a.city !== b.city) return false;
  if (a.br_day !== b.br_day || a.br_night !== b.br_night || a.vol !== b.vol) return false;
  if ((a.provider_modes == null) !== (b.provider_modes == null)) return false;
  if (a.provider_modes != null && (a.provider_modes.claude !== b.provider_modes.claude || a.provider_modes.codex !== b.provider_modes.codex || a.provider_modes.gemini !== b.provider_modes.gemini)) return false;
  if ((a.autorotate_enabled == null) !== (b.autorotate_enabled == null)) return false;
  if (a.autorotate_enabled != null && a.autorotate_enabled !== b.autorotate_enabled) return false;
  if ((a.autorotate_interval_s == null) !== (b.autorotate_interval_s == null)) return false;
  if (a.autorotate_interval_s != null && a.autorotate_interval_s !== b.autorotate_interval_s) return false;
  if ((a.theme_mode || "") !== (b.theme_mode || "")) return false;
  if ((a.pet_enabled == null) !== (b.pet_enabled == null)) return false;
  if (a.pet_enabled != null && a.pet_enabled !== b.pet_enabled) return false;
  if ((a.pet_species == null) !== (b.pet_species == null)) return false;
  if (a.pet_species != null && a.pet_species !== b.pet_species) return false;
  if ((a.pet_name || "") !== (b.pet_name || "")) return false;
  const am = Array.isArray(a.gemini_models) ? a.gemini_models : [];
  const bm = Array.isArray(b.gemini_models) ? b.gemini_models : [];
  if (am.length !== bm.length) return false;
  for (let i = 0; i < am.length; i++) {
    if (am[i] !== bm[i]) return false;
  }
  if ((a.log_enabled == null) !== (b.log_enabled == null)) return false;
  if (a.log_enabled != null && a.log_enabled !== b.log_enabled) return false;
  if ((a.firmware_url || "") !== (b.firmware_url || "")) return false;
  if ((a.firmware_sha256 || "") !== (b.firmware_sha256 || "")) return false;
  if ((a.firmware_version || "") !== (b.firmware_version || "")) return false;
  if ((a.firmware_manifest_b64 || "") !== (b.firmware_manifest_b64 || "")) return false;
  if ((a.firmware_manifest_sig_b64 || "") !== (b.firmware_manifest_sig_b64 || "")) return false;
  if ((a.min_secure_version || 0) !== (b.min_secure_version || 0)) return false;
  return true;
}

export const _testing = { emptyPayload, deviceFromTOML, deviceToTOML };
