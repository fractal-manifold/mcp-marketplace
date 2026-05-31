// Per-device TOML registry with flock(2) interprocess safety.
// Wire-compatible with cwm-mcp/internal/registry/registry.go.

import { open, openSync, closeSync, mkdirSync, readdirSync, readFileSync, writeFileSync, fsyncSync, renameSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";

import TOML from "@iarna/toml";

// flock(2) interprocess exclusion is mandatory per compat/SECURITY.md.
// We refuse to construct a Registry without it: silently downgrading to
// no-op locks would let two cwm-mcp processes corrupt the same device
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
// X-Cwm-Serial / X-Cwm-Sku headers), pending.firmware_manifest_b64 /
// firmware_manifest_sig_b64 (signed OTA manifest), and
// active.min_secure_version (anti-rollback floor). v1 files load with
// empty serial / sku / manifest fields and are re-serialised as v2 on
// the next save.
export const SCHEMA_VERSION = 2;

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
    // 0 = freshly-decoded zero value, 1 = pre-serial schema (migrated
    // transparently — serial/sku stay empty until the next /sync round
    // populates them, next save bumps to v2). Anything else is foreign.
    if (![0, 1, SCHEMA_VERSION].includes(dev.schemaVersion)) {
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
      const dev = { schemaVersion: SCHEMA_VERSION, deviceID: id, serialNumber: "", hwSku: "", active: { payload: active, lastSeen: null }, pending: null };
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

  // setSerial persists X-Cwm-Serial / X-Cwm-Sku reported by the
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

function emptyPayload() {
  return {
    version: 0, broker_url: "", psk_hex: "", city: "",
    br_day: 0, br_night: 0, vol: 0,
    providers: null, autorotate_enabled: null, autorotate_interval_s: null,
    theme_mode: "",
    // null = "no opinion" (use global default); [] = clear override.
    gemini_models: null,
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
  if (p.providers != null) {
    d.providers = { claude: !!p.providers.claude, codex: !!p.providers.codex, gemini: !!p.providers.gemini };
  }
  if (p.autorotate_enabled != null) d.autorotate_enabled = !!p.autorotate_enabled;
  if (p.autorotate_interval_s != null) d.autorotate_interval_s = Number(p.autorotate_interval_s);
  if (p.theme_mode) d.theme_mode = String(p.theme_mode);
  if (Array.isArray(p.gemini_models) && p.gemini_models.length > 0) {
    d.gemini_models = p.gemini_models.map(String);
  }
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
    providers: d.providers ? { claude: !!d.providers.claude, codex: !!d.providers.codex, gemini: !!d.providers.gemini } : null,
    autorotate_enabled: typeof d.autorotate_enabled === "boolean" ? d.autorotate_enabled : null,
    autorotate_interval_s: typeof d.autorotate_interval_s === "number" ? d.autorotate_interval_s : null,
    theme_mode: String(d.theme_mode || ""),
    gemini_models: Array.isArray(d.gemini_models) ? d.gemini_models.map(String) : null,
    firmware_url: String(d.firmware_url || ""),
    firmware_sha256: String(d.firmware_sha256 || ""),
    firmware_version: String(d.firmware_version || ""),
    firmware_manifest_b64: String(d.firmware_manifest_b64 || ""),
    firmware_manifest_sig_b64: String(d.firmware_manifest_sig_b64 || ""),
    min_secure_version: Number(d.min_secure_version || 0),
  };
}

function deviceToTOML(dev) {
  const doc = { schema_version: SCHEMA_VERSION, device_id: dev.deviceID };
  if (dev.serialNumber) doc.serial_number = dev.serialNumber;
  if (dev.hwSku) doc.hw_sku = dev.hwSku;
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
    active,
    pending,
  };
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
    providers: upd.providers != null ? upd.providers : base.providers,
    autorotate_enabled: upd.autorotate_enabled != null ? upd.autorotate_enabled : base.autorotate_enabled,
    autorotate_interval_s: upd.autorotate_interval_s != null ? upd.autorotate_interval_s : base.autorotate_interval_s,
    theme_mode: upd.theme_mode || base.theme_mode,
    gemini_models: Array.isArray(upd.gemini_models)
      ? upd.gemini_models.slice()
      : base.gemini_models,
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
  if ((a.providers == null) !== (b.providers == null)) return false;
  if (a.providers != null && (a.providers.claude !== b.providers.claude || a.providers.codex !== b.providers.codex || a.providers.gemini !== b.providers.gemini)) return false;
  if ((a.autorotate_enabled == null) !== (b.autorotate_enabled == null)) return false;
  if (a.autorotate_enabled != null && a.autorotate_enabled !== b.autorotate_enabled) return false;
  if ((a.autorotate_interval_s == null) !== (b.autorotate_interval_s == null)) return false;
  if (a.autorotate_interval_s != null && a.autorotate_interval_s !== b.autorotate_interval_s) return false;
  if ((a.theme_mode || "") !== (b.theme_mode || "")) return false;
  const am = Array.isArray(a.gemini_models) ? a.gemini_models : [];
  const bm = Array.isArray(b.gemini_models) ? b.gemini_models : [];
  if (am.length !== bm.length) return false;
  for (let i = 0; i < am.length; i++) {
    if (am[i] !== bm[i]) return false;
  }
  if ((a.firmware_url || "") !== (b.firmware_url || "")) return false;
  if ((a.firmware_sha256 || "") !== (b.firmware_sha256 || "")) return false;
  if ((a.firmware_version || "") !== (b.firmware_version || "")) return false;
  if ((a.firmware_manifest_b64 || "") !== (b.firmware_manifest_b64 || "")) return false;
  if ((a.firmware_manifest_sig_b64 || "") !== (b.firmware_manifest_sig_b64 || "")) return false;
  if ((a.min_secure_version || 0) !== (b.min_secure_version || 0)) return false;
  return true;
}

export const _testing = { emptyPayload, deviceFromTOML, deviceToTOML };
