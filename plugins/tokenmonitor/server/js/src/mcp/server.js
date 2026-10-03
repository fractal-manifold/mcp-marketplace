// MCP stdio server with the 10 tokenmonitor_* tools.

import {
  readFileSync, existsSync, statSync, mkdirSync, openSync, readSync, writeSync,
  closeSync, fsyncSync, renameSync,
} from "node:fs";
import { dirname, join, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { request as httpRequest } from "node:http";
import { networkInterfaces } from "node:os";
import { randomBytes, createHash } from "node:crypto";

import * as auth from "../auth.js";
import * as creds from "../creds.js";
import * as ota from "../ota.js";
import { packSemver, brokerURLFw } from "../ota.js";
import {
  GATE_OK,
  gateDeviceOf,
  predictDeviceGate,
  predictPendingCrossCheck,
} from "../gate.js";
import * as devlog from "../devlog.js";
import { validDeviceID, effectiveChannel, providerModeEnabled, providerModeFromBool, validProviderMode } from "../registry/store.js";
import { firmwarePath } from "../config.js";
import { clipCodePoints } from "../textutil.js";
import { handleUSBScan, handleUSBProvision } from "./usb.js";
import { resolveEnrolPSK, explicitPSK, seedURLTowards, noRegistryNote, mirrorToRegistry, joinNotes, NOTE_PSK_UNRECORDED, NOTE_PSK_MAYBE_LIVE, NOTE_PSK_UNKNOWN, ERR_NO_SEED_LAN } from "./enrol.js";
import { setWiFiTool } from "./wifi.js";
import { daemonLogTail, daemonRunning } from "../sessionLife.js";
import { loadSharedSnapshot } from "../state.js";

function compatDir() {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 10; i++) {
    const c = join(dir, "compat", "tool-schemas.json");
    if (existsSync(c)) return join(dir, "compat");
    const parent = resolvePath(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error("could not locate ../compat/ relative to tokenmonitor-mcp-js");
}

export function loadToolSchemas() {
  const data = JSON.parse(readFileSync(join(compatDir(), "tool-schemas.json"), "utf8"));
  return data.tools;
}

function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

function brokerAddr(cfg) { return `${cfg.server.bind}:${cfg.server.port}`; }
function selfHost(cfg) { return cfg.server.bind === "0.0.0.0" || !cfg.server.bind ? "127.0.0.1" : cfg.server.bind; }
function freshHexNonce() { return randomBytes(16).toString("hex"); }

function configInfo(cfg) {
  return {
    max_timestamp_skew_seconds: cfg.security.max_timestamp_skew_seconds,
    nonce_cache_ttl_seconds: cfg.security.nonce_cache_ttl_seconds,
    auth_mode: cfg.auth.psk_passphrase ? "passphrase" : "psk_hex",
    logging_level: cfg.logging.level,
  };
}

function providerNames(p) {
  if (!p) return [];
  const out = [];
  if (providerModeEnabled(p.claude)) out.push("claude");
  if (providerModeEnabled(p.codex)) out.push("codex");
  if (providerModeEnabled(p.gemini)) out.push("antigravity");
  return out;
}

// Canonical strings for the legacy broker_url re-point (compat/mcp-errors.md).
export const errBrokerURLMDNS = (id, fw) =>
  `broker_url cannot be staged for device ${id}: it reports firmware ${fw}, and firmware 1.0.1 or newer resolves the broker by mDNS and does not take a pushed address. Nothing was staged.`;
export const ERR_BROKER_URL_SHAPE = "broker_url must be an http:// or https:// URL of at most 127 bytes";
export const NOTE_BROKER_URL_HELD =
  "broker_url is staged but held: this device has not reported a firmware version yet. It is sent only if the device's next poll reports firmware older than 1.0.1, and dropped if that poll reports 1.0.1 or newer, or no readable version.";
export const LABEL_BROKER_URL_HELD = "broker_url (held: sent only if the device's next poll reports firmware older than 1.0.1)";
export const LABEL_BROKER_URL_DROP = "broker_url (will be dropped: firmware 1.0.1 or newer resolves the broker by mDNS)";

// brokerURLLabel is the pending_changes entry for a staged broker_url. It says
// what will actually happen to it, which depends on the firmware the device
// last reported (active.firmware_version).
function brokerURLLabel(reportedFw) {
  const { legacy, known } = brokerURLFw(reportedFw);
  if (!known) return LABEL_BROKER_URL_HELD;
  return legacy ? "broker_url" : LABEL_BROKER_URL_DROP;
}

export function deviceSummary(dev) {
  const out = { device_id: dev.deviceID, active_version: dev.active.payload.version, has_pending: !!dev.pending };
  if (dev.serialNumber) out.serial_number = dev.serialNumber;
  if (dev.hwSku) out.hw_sku = dev.hwSku;
  out.channel = effectiveChannel(dev);
  if (dev.active.payload.min_secure_version) out.min_secure_version = dev.active.payload.min_secure_version;
  if (dev.active.payload.broker_url) out.active_broker_url = dev.active.payload.broker_url;
  if (dev.active.payload.city) out.active_city = dev.active.payload.city;
  const names = providerNames(dev.active.payload.provider_modes);
  if (names.length) out.active_providers = names;
  if (dev.active.lastSeen) out.last_seen = dev.active.lastSeen.toISOString();
  if (dev.pending) {
    out.pending_version = dev.pending.payload.version;
    out.pending_created_at = dev.pending.createdAt.toISOString();
    out.pending_changes = pendingChanges(dev.active.payload, dev.pending.payload);
  }
  // A staged broker_url that was removed unsent because the device runs
  // firmware that resolves the broker by mDNS.
  if (dev.brokerURLDropped) out.broker_url_dropped = dev.brokerURLDropped;
  return out;
}

function pendingChanges(a, p) {
  const out = [];
  if (p.broker_url && p.broker_url !== a.broker_url) out.push(brokerURLLabel(a.firmware_version));
  if (p.psk_hex && p.psk_hex !== a.psk_hex) out.push("psk_hex (key rotation)");
  if (p.city && p.city !== a.city) out.push("city");
  if (p.br_day && p.br_day !== a.br_day) out.push("br_day");
  if (p.br_night && p.br_night !== a.br_night) out.push("br_night");
  if (p.vol != null && p.vol !== a.vol) out.push("vol");
  if (p.provider_modes && (!a.provider_modes || p.provider_modes.claude !== a.provider_modes.claude || p.provider_modes.codex !== a.provider_modes.codex || p.provider_modes.gemini !== a.provider_modes.gemini)) out.push("providers");
  if (p.autorotate_enabled != null && p.autorotate_enabled !== a.autorotate_enabled) out.push("autorotate_enabled");
  if (p.log_enabled != null && (a.log_enabled == null || p.log_enabled !== a.log_enabled)) out.push("log_enabled");
  if (p.autorotate_interval_s != null && p.autorotate_interval_s !== a.autorotate_interval_s) out.push("autorotate_interval_s");
  if (p.theme_mode && p.theme_mode !== a.theme_mode) out.push("theme_mode");
  if (p.pet_enabled != null && p.pet_enabled !== a.pet_enabled) out.push("pet_enabled");
  if (p.pet_species != null && p.pet_species !== a.pet_species) out.push("pet_species");
  if (p.pet_name && p.pet_name !== a.pet_name) out.push("pet_name");
  if (p.panel_enabled != null && p.panel_enabled !== a.panel_enabled) out.push("panel_enabled");
  if (Array.isArray(p.gemini_models)) {
    const am = Array.isArray(a.gemini_models) ? a.gemini_models : [];
    const same = am.length === p.gemini_models.length && am.every((m, i) => m === p.gemini_models[i]);
    if (!same) out.push("antigravity_models");
  }
  return out;
}

// Interface name prefixes the LAN-side device cannot reach: container
// bridges, VM tunnels, VPN endpoints. Skip them so provision_hint doesn't
// suggest e.g. a Docker bridge IP that the device's WiFi can't route to.
const VIRTUAL_IFACE_PREFIXES = [
  "docker", "br-", "veth", "virbr", "vnet", "tun", "tap",
  "vmnet", "tailscale", "wg", "zt",
];

function isVirtualIface(name) {
  return VIRTUAL_IFACE_PREFIXES.some(p => name.startsWith(p));
}

function localIPv4s() {
  return localIPv4Nets().map((n) => n.address);
}

// localIPv4Nets is localIPv4s with the CIDR kept, in the same order. The prefix
// is what lets a caller ask "which of my addresses is on the same network as
// this device" instead of guessing with the first one.
function localIPv4Nets() {
  const out = [];
  const ifaces = networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    if (isVirtualIface(name)) continue;
    for (const i of ifaces[name] || []) {
      if (i.family === "IPv4" && !i.internal) out.push({ address: i.address, cidr: i.cidr || "" });
    }
  }
  return out.sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
}

// ipv4ToInt returns the address as an unsigned 32-bit number, or null.
function ipv4ToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip || ""));
  if (!m) return null;
  let v = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    v = (v * 256) + o;
  }
  return v;
}

// pickLocalIP is localFirmwareBase's choice, split out because it is the only
// part testable without the host's real interfaces. nets must be non-empty.
export function pickLocalIP(nets, deviceIP) {
  const target = ipv4ToInt(deviceIP);
  if (target != null) {
    for (const n of nets) {
      const [addr, bitsRaw] = String(n.cidr || "").split("/");
      const bits = Number.parseInt(bitsRaw, 10);
      const base = ipv4ToInt(addr);
      if (base == null || !Number.isInteger(bits) || bits < 0 || bits > 32) continue;
      // A /0 mask would be `>>> 32`, which JS evaluates as `>>> 0` — no shift
      // at all — so the all-ones mask has to be spelled out.
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      if (((base & mask) >>> 0) === ((target & mask) >>> 0)) return n.address;
    }
  }
  return nets[0].address;
}

export function registryUnavailableMsg() {
  return "device registry is not configured on this tokenmonitor-mcp install; configure ~/.config/tokenmonitor/devices/ and retry";
}

export async function serve(deps) {
  const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  const { CallToolRequestSchema, ListToolsRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");

  const schemas = loadToolSchemas();
  const server = new Server(
    { name: "tokenmonitor-mcp", version: deps.version },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: schemas.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const result = await dispatch(deps, req.params.name, req.params.arguments || {});
    const text = typeof result === "string" ? result : JSON.stringify(result);
    return { content: [{ type: "text", text }] };
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // connect() returns as soon as the transport is wired up, so without
  // this the process would fall through, tear down the broker and exit
  // before answering a single request. Block until the MCP client
  // disconnects (stdin EOF / transport close) — matching the Go and
  // Python impls, which block inside their serve loop.
  await new Promise((resolve) => { server.onclose = resolve; });
}

// Exported for tests: the tool bodies are plain functions of (deps, args), and
// driving them through the same dispatch the MCP transport uses keeps the tests
// honest about the names.
export async function dispatch(deps, name, args) {
  switch (name) {
    case "tokenmonitor_status": return statusTool(deps);
    case "tokenmonitor_health": return await healthTool(deps);
    case "tokenmonitor_recent_logs": return recentLogsTool(deps, args);
    case "tokenmonitor_firmware_logs": return await firmwareLogsTool(deps, args);
    case "tokenmonitor_device_logs": return deviceLogsTool(deps, args);
    case "tokenmonitor_provision_hint": return provisionHintTool(deps);
    case "tokenmonitor_list_devices": return listDevicesTool(deps);
    case "tokenmonitor_register_device": return registerDeviceTool(deps, args);
    case "tokenmonitor_set_device_pending": return setDevicePendingTool(deps, args);
    case "tokenmonitor_set_wifi": return setWiFiTool(deps, args);
    case "tokenmonitor_publish_firmware": return publishFirmwareTool(deps, args);
    case "tokenmonitor_revert_firmware": return revertFirmwareTool(deps, args);
    case "tokenmonitor_discover_devices": return await discoverDevicesTool(args);
    case "tokenmonitor_provision": return await provisionTool(deps, args);
    case "tokenmonitor_check_updates": return await checkUpdatesTool(deps, args);
    case "tokenmonitor_usb_scan": return await handleUSBScan(deps, args);
    case "tokenmonitor_usb_provision": return await handleUSBProvision(deps, args, hintURLs(deps));
    default: return { error: `unknown tool ${name}` };
  }
}

// Static OTA-channel config for tokenmonitor_status. Live data (latest
// release per SKU, would-stage devices) is intentionally not here — it
// needs a network round-trip and may differ per process; use
// tokenmonitor_check_updates (dry_run) for that. Mirror of Go otaInfoOf.
function otaInfo(cfg) {
  const out = {
    enabled: cfg.ota.enabled,
    configured: cfg.otaConfigured(),
    configured_keys: cfg.ota.keys.length,
  };
  if (cfg.ota.releases_repo) out.releases_repo = cfg.ota.releases_repo;
  if (cfg.ota.poll_interval_minutes) out.poll_interval_minutes = cfg.ota.poll_interval_minutes;
  return out;
}

function statusTool(deps) {
  return {
    version: deps.version,
    addr: brokerAddr(deps.cfg),
    oauth_path: deps.cfg.oauthPathAbs(),
    config: configInfo(deps.cfg),
    ota: otaInfo(deps.cfg),
    snapshot: currentSnapshot(deps.state),
  };
}

// Force an OTA-channel check now and report (or stage) what the background
// loop would do. Works from any process — it only needs the config +
// registry — so a follower session can preview updates even when a
// different process owns the broker. Mirror of Go handleCheckUpdates.
async function checkUpdatesTool(deps, args) {
  if (!deps.registry) return { error: registryUnavailableMsg() };
  const dryRun = args.dry_run === undefined ? true : !!args.dry_run;
  const sku = String(args.sku || "").trim().toUpperCase();
  const deviceID = String(args.device_id || "").trim().toLowerCase();
  return await ota.check(deps.cfg, deps.registry, { dryRun, skuFilter: sku, deviceFilter: deviceID });
}

async function healthTool(deps) {
  const checks = [];
  // First, because when the config failed everything below is reporting on an
  // invented config and a broker that was never started — this check is the
  // explanation for all of it.
  if (deps.configErr) {
    checks.push({
      name: "config",
      pass: false,
      detail: `${deps.configErr.message} — running degraded: MCP tools only, no broker. Fix the config and restart.`,
    });
  } else if (deps.cfg.salvaged && deps.cfg.salvaged.length > 0) {
    // Serving, but not with everything the user wrote. Failing the check is the
    // point: it is the only way they find out.
    checks.push({
      name: "config",
      pass: false,
      detail: `loaded with sections ignored (the rest of the file is in effect): ${deps.cfg.salvaged.join("; ")}`,
    });
  } else {
    checks.push({ name: "config", pass: true, detail: "loaded" });
  }
  try {
    const c = creds.load(deps.cfg.oauthPathAbs());
    if (c.isExpired(Date.now())) checks.push({ name: "credentials", pass: false, detail: `token expired at ${c.expiresAtISO()}` });
    else checks.push({ name: "credentials", pass: true, detail: `valid until ${c.expiresAtISO()}` });
  } catch (e) {
    checks.push({ name: "credentials", pass: false, detail: e.message });
  }
  checks.push(await selfPing(deps));
  const snap = currentSnapshot(deps.state);
  if (!snap.requests_total) checks.push({ name: "observed_traffic", pass: false, detail: "no requests received yet" });
  else if (snap.last_request_status === 200) checks.push({ name: "observed_traffic", pass: true, detail: `last request OK at ${snap.last_request_at || ""}` });
  else checks.push({ name: "observed_traffic", pass: false, detail: `last request returned ${snap.last_request_status}` });
  const ok = checks.every((c) => c.pass);
  // Broker version advisory. Appended AFTER the ok rollup: an available update
  // is informational, not a health failure, so it never flips ok:false.
  // Emitted only once the self-check succeeded. Mirrors Go handleHealth.
  const u = deps.state.update ? deps.state.update() : null;
  if (u && u.known) {
    if (u.outdated) checks.push({ name: "broker_version", pass: false, detail: `${u.current} installed; ${u.latest} available — update the tokenmonitor plugin` });
    else checks.push({ name: "broker_version", pass: true, detail: `${u.current} (up to date)` });
  }
  return { ok, role: snap.role, checks };
}

function selfPing(deps) {
  return new Promise((resolve) => {
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = "1111111111111111deadbeefdeadbeef";
    const sig = auth.computeSignature(deps.cfg.psk(), "GET", "/credentials", ts, nonce, "", "");
    const req = httpRequest({
      host: selfHost(deps.cfg),
      port: deps.cfg.server.port,
      path: "/credentials",
      method: "GET",
      timeout: 2000,
      headers: { "X-Tmon-Timestamp": ts, "X-Tmon-Nonce": nonce, "X-Tmon-Signature": sig },
    }, (res) => {
      res.on("data", () => {}); res.on("end", () => {
        if (res.statusCode === 200) return resolve({ name: "self_ping", pass: true, detail: "broker answered 200" });
        if (res.statusCode === 503) return resolve({ name: "self_ping", pass: false, detail: "broker says token expired (503)" });
        if (res.statusCode === 404) return resolve({ name: "self_ping", pass: false, detail: "broker says credentials file missing (404)" });
        if (res.statusCode === 401) return resolve({ name: "self_ping", pass: false, detail: "broker rejected our signature (401) — PSK mismatch?" });
        resolve({ name: "self_ping", pass: false, detail: `broker returned ${res.statusCode}` });
      });
    });
    req.on("error", (e) => resolve({ name: "self_ping", pass: false, detail: `broker unreachable: ${e.message}` }));
    req.on("timeout", () => { req.destroy(); resolve({ name: "self_ping", pass: false, detail: "broker unreachable: timeout" }); });
    req.end();
  });
}

function recentLogsTool(deps, args) {
  let limit = 50;
  if (args.limit != null && args.limit !== "") {
    const n = Number.parseInt(args.limit, 10);
    if (Number.isFinite(n)) limit = clamp(n, 1, 500);
  }
  try { return daemonLogTail(limit); }
  catch { return { total_available: deps.logs.length, lines: deps.logs.tail(limit) }; }
}

function currentSnapshot(local) {
  try { if (daemonRunning()) return loadSharedSnapshot(); }
  catch { return local.snapshot(); }
  return local.snapshot();
}

function firmwareLogsTool(deps, args) {
  return new Promise((resolve) => {
    let limit = 200;
    if (args.limit != null && args.limit !== "") {
      const n = Number.parseInt(args.limit, 10);
      if (Number.isFinite(n)) limit = clamp(n, 1, 2000);
    }
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = freshHexNonce();
    const sig = auth.computeSignature(deps.cfg.psk(), "GET", "/firmware-logs", ts, nonce, "", "");
    const req = httpRequest({
      host: selfHost(deps.cfg), port: deps.cfg.server.port,
      path: `/firmware-logs?limit=${limit}`, method: "GET", timeout: 3000,
      headers: { "X-Tmon-Timestamp": ts, "X-Tmon-Nonce": nonce, "X-Tmon-Signature": sig },
    }, (res) => {
      let buf = "";
      res.on("data", (c) => { buf += c; });
      res.on("end", () => {
        if (res.statusCode !== 200) return resolve({ ok: false, http_status: res.statusCode, body: buf });
        try { resolve(JSON.parse(buf)); } catch { resolve({ ok: false, body: buf }); }
      });
    });
    req.on("error", (e) => resolve({ ok: false, error: `broker unreachable: ${e.message}` }));
    req.on("timeout", () => { req.destroy(); resolve({ ok: false, error: "broker unreachable: timeout" }); });
    req.end();
  });
}

// Read the scrubbed diagnostic log the device uploaded to the broker
// (POST /device/<id>/logs, stored under <config>/device-logs/<id>.log).
// Works from any tokenmonitor-mcp process — it reads the file directly, no signed
// loopback — so a follower session can inspect a device even when another
// process owns the broker port. Mirror of Go handleDeviceLogs / py _device_logs.
function deviceLogsTool(deps, args) {
  if (!deps.registry) return { error: registryUnavailableMsg() };
  const deviceID = String(args.device_id || "").trim().toLowerCase();
  if (!validDeviceID(deviceID)) return { error: "device_id must be 8 lowercase hex chars" };
  let limit = 200;
  if (args.limit != null && args.limit !== "") {
    const n = Number.parseInt(args.limit, 10);
    if (Number.isFinite(n)) limit = clamp(n, 1, devlog.MAX_LINES);
  }
  const lines = devlog.read(deps.registry.dir, deviceID);
  const total = lines.length;
  return { device_id: deviceID, total_available: total, lines: limit < total ? lines.slice(total - limit) : lines };
}

// httpOTAFloor is packed(0.10.2), the first firmware whose production sdkconfig
// carries CONFIG_TMON_OTA_ALLOW_HTTP. Older units accept https only, and refuse
// anything else in silence.
const HTTP_OTA_FLOOR = (0 << 24) | (10 << 16) | 2;

// firmwareBase returns { url, how } for the origin this device will accept a
// firmware download from, in descending order of proof:
//
//   1. the socket-local address of the device's last authenticated request —
//      literally what it dialled, so it is what its NVS svc_url holds. The
//      firmware compares the firmware_url origin against svc_url with strcmp
//      and attaches the HMAC headers only on an exact match (tmon_ota.c), so
//      any other address of ours yields a 401 on /firmware/ — and that path,
//      unlike the manifest gate, poisons the version on-device after 3 tries;
//   2. the address of ours whose subnet contains the device's last source IP.
//      A laptop on WiFi and Ethernet at once has several usable addresses and
//      only one is on the device's network;
//   3. the first usable address, as before.
//
// The "how" goes into the tool result because the three differ in how much they
// prove. Returns null when this host has no LAN address at all.
function firmwareBase(deps, dev) {
  const lastLocal = dev.active.lastLocalAddr || "";
  if (lastLocal) {
    return {
      url: `http://${lastLocal}`,
      how: "the address the device dialled on its last authenticated request — " +
        "the one origin its OTA download will carry HMAC headers for",
    };
  }
  const nets = localIPv4Nets();
  if (!nets.length) return null;
  const deviceIP = dev.active.lastIP || "";
  const ip = pickLocalIP(nets, deviceIP);
  let how = "this host's first LAN address; the device has not been seen from a " +
    "matching subnet, so if its broker origin differs the download will 401 — " +
    "have it poll /sync once and republish";
  if (deviceIP && ip !== nets[0].ip) {
    how = "this host's address on the device's own subnet (guessed from its " +
      "last source IP, not proven)";
  }
  return { url: `http://${ip}:${deps.cfg.server.port}`, how };
}

// gateStagedFirmware answers, before anything is written to the registry,
// whether the device will actually install what the operator is about to stage.
// Returns an error message, or null when the device would accept it.
//
// It exists because a device that refuses a manifest says NOTHING: tmon_ota.c
// clears the pending, records no poison and sends no X-Tmon-Ota-Fail, so the
// operator sees a device that simply keeps running the old version while every
// refused arm costs it a reboot. The published 1.0.0 index was exactly that
// shape — a signed, verifying manifest whose declared floor locked out every
// unit at or past 0.11.4.
//
// Reading the fields needs no key, so the old stance here ("we do not parse the
// manifest; the device-side gate is authoritative") cost the operator the one
// signal the device never gives. The device-side gate stays authoritative — we
// only decline to stage what it has already told us it will reject.
function gateStagedFirmware(dev, manifestB64, shaHex, version, firmwareURL) {
  // The firmware's own hard limits (config_sync.c): a pending that trips one of
  // these is dropped before the gate ever runs.
  if (String(firmwareURL || "").length >= 256) {
    return `firmware_url is ${String(firmwareURL).length} chars; the device ` +
      "refuses any pending whose URL is ≥256";
  }
  if (!manifestB64) return null;
  let raw;
  try {
    raw = Buffer.from(manifestB64, "base64");
    if (raw.toString("base64").replace(/=+$/, "") !== manifestB64.replace(/=+$/, "")) {
      return "firmware_manifest_b64 is not valid base64";
    }
  } catch {
    return "firmware_manifest_b64 is not valid base64";
  }
  if (raw.length > 512) {
    return `the manifest decodes to ${raw.length} bytes; the device's buffer is ` +
      "512 and it drops the whole pending above that";
  }
  let mf;
  try {
    mf = JSON.parse(raw.toString("utf8"));
    if (mf === null || typeof mf !== "object" || Array.isArray(mf)) throw new Error("not an object");
  } catch (e) {
    return `firmware_manifest_b64 does not decode to a JSON manifest: ${e.message}`;
  }
  let [verdict, why] = predictPendingCrossCheck(mf, shaHex, version);
  if (verdict === GATE_OK) [verdict, why] = predictDeviceGate(mf, gateDeviceOf(dev));
  if (verdict !== GATE_OK) return `the device would refuse this update (${verdict}): ${why}`;
  return null;
}

// hintURLs is the provision hint's candidate list: one URL per LAN interface.
export function hintURLs(deps) {
  const port = deps.cfg?.server?.port || 0;
  if (!port) return [];
  return localIPv4s().map((ip) => `http://${ip}:${port}`);
}

function provisionHintTool(deps) {
  const ips = localIPv4s();
  const port = deps.cfg.server.port;
  const urls = hintURLs(deps);
  const out = { port, bind: deps.cfg.server.bind, hosts: ips, urls };
  if (deps.cfg.server.bind === "127.0.0.1" || deps.cfg.server.bind === "localhost") {
    out.warning = "broker is bound to 127.0.0.1; the device can only reach it from this host. Switch bind to 0.0.0.0 in tokenmonitor.toml.";
  }
  return out;
}

function listDevicesTool(deps) {
  if (!deps.registry) return { error: registryUnavailableMsg() };
  const devs = deps.registry.list();
  return { count: devs.length, devices: devs.map(deviceSummary) };
}

// validChannelArg accepts "stable"/"dev" (and, defensively, any 1..7
// lowercase letters for a future channel). Returns the canonical string or
// null if invalid. "" / "stable" both map to "stable".
function validChannelArg(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (s === "" || s === "stable") return "stable";
  return /^[a-z]{1,7}$/.test(s) ? s : null;
}

function registerDeviceTool(deps, args) {
  if (!deps.registry) return { error: registryUnavailableMsg() };
  const deviceID = String(args.device_id || "").trim().toLowerCase();
  const brokerURL = String(args.broker_url || "").trim();
  const pskHex = String(args.psk_hex || "").trim().toLowerCase();
  if (!validDeviceID(deviceID)) return { error: "device_id must be 8 lowercase hex chars" };
  if (pskHex.length !== 64) return { error: "psk_hex must be exactly 64 hex chars" };
  if (!/^[0-9a-fA-F]{64}$/.test(pskHex)) return { error: "psk_hex is not valid hex" };
  let channel = ""; // "" = auto-derive the track from the serial
  if (args.channel != null && args.channel !== "") {
    channel = validChannelArg(args.channel);
    if (channel === null) return { error: "channel must be 'stable' or 'dev'" };
  }
  // broker_url is optional: the device resolves its broker by mDNS, so the
  // registry only keeps one as the last-known address.
  const payload = { broker_url: brokerURL, psk_hex: pskHex, city: String(args.city || "").trim(), br_day: 0, br_night: 0, vol: null, providers: null, provider_modes: null, autorotate_enabled: null, autorotate_interval_s: null, version: 0, channel };
  if (args.br_day) payload.br_day = clamp(Number.parseInt(args.br_day, 10) || 0, 10, 100);
  if (args.br_night) payload.br_night = clamp(Number.parseInt(args.br_night, 10) || 0, 5, 100);
  if (args.vol != null) payload.vol = clamp(Number.parseInt(args.vol, 10) || 0, 0, 100);
  try { return { ok: true, device: deviceSummary(deps.registry.register(deviceID, payload)) }; }
  catch (e) { return { error: e.message }; }
}

function setDevicePendingTool(deps, args) {
  if (!deps.registry) return { error: registryUnavailableMsg() };
  const deviceID = String(args.device_id || "").trim().toLowerCase();
  if (!validDeviceID(deviceID)) return { error: "device_id must be 8 lowercase hex chars" };
  // Release channel is a device-level attribute (steers which GitHub asset
  // the OTA loop fetches), NOT part of the config pending. Apply it
  // immediately, before any pending merge.
  if (args.channel != null && args.channel !== "") {
    const ch = validChannelArg(args.channel);
    if (ch === null) return { error: "channel must be 'stable' or 'dev'" };
    try { deps.registry.setChannel(deviceID, ch); }
    catch (e) {
      if (/not found/.test(e.message)) return { error: `device ${deviceID} not registered — call tokenmonitor_register_device first` };
      return { error: e.message };
    }
  }
  const upd = { version: 0, broker_url: "", psk_hex: "", city: "", br_day: 0, br_night: 0, vol: null, providers: null, provider_modes: null, autorotate_enabled: null, autorotate_interval_s: null, theme_mode: "", pet_enabled: null, pet_species: null, pet_name: "", panel_enabled: null, gemini_models: null, log_enabled: null, firmware_url: "", firmware_sha256: "", firmware_version: "", firmware_manifest_b64: "", firmware_manifest_sig_b64: "", min_secure_version: 0 };
  // broker_url is a LEGACY re-point. From firmware 1.0.1 the broker's address
  // is not something the control plane sets: the device finds it by mDNS and
  // adopts it on a response signature, so staging one would queue a field that
  // is never sent. Firmware older than that has no other way to follow a
  // broker that moved. This gate exists for those units and must not be
  // removed while any can exist; the /sync side of it is pendingPayloadJSON in
  // broker/server.js. See compat/README.md, "Legacy firmware compatibility".
  let brokerURLHeld = false;
  const stagedURL = String(args.broker_url || "").trim();
  if (stagedURL) {
    if (!/^https?:\/\//.test(stagedURL) || Buffer.byteLength(stagedURL, "utf8") > 127) return { error: ERR_BROKER_URL_SHAPE };
    let cur;
    try { cur = deps.registry.load(deviceID); }
    catch (e) {
      if (/not found/.test(e.message)) return { error: `device ${deviceID} not registered — call tokenmonitor_register_device first` };
      return { error: `load: ${e.message}` };
    }
    const reported = String(cur.active.payload.firmware_version || "");
    const { legacy, known } = brokerURLFw(reported);
    if (known && !legacy) return { error: errBrokerURLMDNS(deviceID, reported) };
    brokerURLHeld = !known;
    upd.broker_url = stagedURL;
  }
  if (args.psk_hex) {
    const v = String(args.psk_hex).trim().toLowerCase();
    if (v.length !== 64) return { error: "psk_hex must be exactly 64 hex chars" };
    if (!/^[0-9a-fA-F]{64}$/.test(v)) return { error: "psk_hex is not valid hex" };
    upd.psk_hex = v;
  }
  if (args.city) upd.city = String(args.city).trim();
  if (args.br_day) upd.br_day = clamp(Number.parseInt(args.br_day, 10) || 0, 10, 100);
  if (args.br_night) upd.br_night = clamp(Number.parseInt(args.br_night, 10) || 0, 5, 100);
  if (args.vol != null) upd.vol = clamp(Number.parseInt(args.vol, 10) || 0, 0, 100);
  // Providers: accept the rich provider_mode_<p> string enum
  // (auto/disabled/subscription/api_key) and/or the legacy provider_<p>
  // bool (true→auto, false→disabled). The string arg wins over the bool
  // when both are given. Read the current view and override only what
  // changed so all three land deterministically in NVS.
  const provKeys = ["provider_claude", "provider_codex", "provider_antigravity", "provider_gemini", "provider_mode_claude", "provider_mode_codex", "provider_mode_antigravity", "provider_mode_gemini"];
  if (provKeys.some((k) => k in args)) {
    let cur;
    try { cur = deps.registry.load(deviceID); }
    catch (e) { return { error: e.message }; }
    const cm = (cur.pending && cur.pending.payload.provider_modes) || cur.active.payload.provider_modes;
    const base = cm ? { claude: cm.claude, codex: cm.codex, gemini: cm.gemini } : { claude: "auto", codex: "disabled", gemini: "disabled" };
    for (const name of ["claude", "codex", "gemini"]) {
      let modeKey = `provider_mode_${name}`;
      let boolKey = `provider_${name}`;
      if (name === "gemini") {
        // Antigravity (formerly Gemini): prefer the new arg names, fall
        // back to the deprecated gemini-named args.
        if ("provider_mode_antigravity" in args) modeKey = "provider_mode_antigravity";
        if ("provider_antigravity" in args) boolKey = "provider_antigravity";
      }
      if (modeKey in args) {
        const s = String(args[modeKey]);
        if (!validProviderMode(s)) return { error: `${modeKey} must be one of auto/disabled/subscription/api_key` };
        base[name] = s;
      } else if (boolKey in args) {
        base[name] = providerModeFromBool(!!args[boolKey]);
      }
    }
    upd.provider_modes = { claude: base.claude, codex: base.codex, gemini: base.gemini };
  }
  if ("autorotate_enabled" in args) upd.autorotate_enabled = !!args.autorotate_enabled;
  if ("log_enabled" in args) upd.log_enabled = !!args.log_enabled;
  if ("autorotate_interval_s" in args) {
    const v = Number.parseInt(args.autorotate_interval_s, 10);
    if (Number.isFinite(v)) upd.autorotate_interval_s = clamp(v, 1, 300);
  }
  if (args.theme_mode) {
    const tm = String(args.theme_mode).trim().toLowerCase();
    if (tm !== "day" && tm !== "night" && tm !== "auto") {
      return { error: "theme_mode must be one of: day, night, auto" };
    }
    upd.theme_mode = tm;
  }
  // Virtual pet — device-owned display settings, same handling shape as
  // theme/brightness/autorotate above.
  if ("pet_enabled" in args) upd.pet_enabled = !!args.pet_enabled;
  if ("pet_species" in args) {
    const v = Number.parseInt(args.pet_species, 10);
    if (Number.isFinite(v)) upd.pet_species = clamp(v, 0, 9);
  }
  if (args.pet_name) upd.pet_name = clipCodePoints(args.pet_name, 15);
  // Custom panel — device-owned display setting, same handling shape as
  // pet_enabled above (default false / opt-in on-device).
  if ("panel_enabled" in args) upd.panel_enabled = !!args.panel_enabled;
  const modelsKey = "antigravity_models" in args ? "antigravity_models" : "gemini_models";
  if (modelsKey in args) {
    const raw = args[modelsKey] == null ? "" : String(args[modelsKey]);
    const parts = raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
    if (parts.length > 3) return { error: `${modelsKey} must list at most 3 entries` };
    upd.gemini_models = parts; // [] clears the override
  }
  const fu = (args.firmware_url || "").toString().trim();
  const fs = (args.firmware_sha256 || "").toString().trim().toLowerCase();
  const fv = (args.firmware_version || "").toString().trim();
  if (fu || fs || fv) {
    if (!(fu && fs && fv)) return { error: "firmware_url, firmware_sha256 and firmware_version must be supplied together" };
    if (!fu.startsWith("https://")) return { error: "firmware_url must be HTTPS" };
    if (fs.length !== 64 || !/^[0-9a-f]{64}$/.test(fs)) return { error: "firmware_sha256 must be 64 lowercase hex chars" };
    if (fv.length > 31) return { error: "firmware_version must be ≤31 chars" };
    upd.firmware_url = fu;
    upd.firmware_sha256 = fs;
    upd.firmware_version = fv;
  }
  // Schema v2 manifest envelope. Paired: both or neither.
  const mb = String(args.firmware_manifest_b64 || "").trim();
  const ms = String(args.firmware_manifest_sig_b64 || "").trim();
  if (mb && mb.length > 4096) return { error: "firmware_manifest_b64 exceeds 4 KiB" };
  if (ms && ms.length > 128) return { error: "firmware_manifest_sig_b64 looks wrong (Ed25519 sig ~88 base64 chars)" };
  if (!!mb !== !!ms) return { error: "firmware_manifest_b64 and firmware_manifest_sig_b64 must be supplied together" };
  if (mb) {
    upd.firmware_manifest_b64 = mb;
    upd.firmware_manifest_sig_b64 = ms;
  }
  // Predict the device-side gate before writing anything. A refusal here is a
  // typo the operator can fix in seconds; the same mistake staged is a reboot
  // the device spends telling nobody.
  if (mb || upd.firmware_url) {
    let cur;
    try { cur = deps.registry.load(deviceID); }
    catch (e) {
      if (/not found/.test(e.message)) return { error: `device ${deviceID} not registered — call tokenmonitor_register_device first` };
      return { error: e.message };
    }
    const bad = gateStagedFirmware(cur, mb, upd.firmware_sha256, upd.firmware_version, upd.firmware_url);
    if (bad) return { error: bad };
  }
  try {
    const dev = deps.registry.setPending(deviceID, upd);
    const out = { ok: true, device: deviceSummary(dev) };
    if (brokerURLHeld && dev.pending && dev.pending.payload.broker_url !== dev.active.payload.broker_url) out.note = NOTE_BROKER_URL_HELD;
    return out;
  }
  catch (e) {
    if (/not found/.test(e.message)) return { error: `device ${deviceID} not registered — call tokenmonitor_register_device first` };
    return { error: e.message };
  }
}

// Mirror of Go's handlePublishFirmware. Copies bin_path into
// firmwarePath() (named tokenmonitor-<version>.bin), computes the SHA-256, then
// stages a pending pointing at this broker's /firmware/<file>. With
// external_url set the file is not copied and the SHA must be supplied.
function publishFirmwareTool(deps, args) {
  if (!deps.registry) return { error: registryUnavailableMsg() };
  const deviceID = String(args.device_id || "").trim().toLowerCase();
  if (!validDeviceID(deviceID)) return { error: "device_id must be 8 lowercase hex chars" };
  const version = String(args.firmware_version || "").trim();
  if (!version) return { error: "firmware_version is required" };
  if (version.length > 31) return { error: "firmware_version must be ≤31 chars" };
  if (/[\s/\\]/.test(version)) return { error: "firmware_version must not contain whitespace or path separators" };

  // Loaded to confirm the device is registered (setPending below needs it, and
  // the error here names the fix). The record's broker_url is NOT used to build
  // the URL any more; its observed lastIP is, only to rank this host's own
  // addresses — see localFirmwareBase.
  let dev;
  try { dev = deps.registry.load(deviceID); }
  catch (e) {
    if (/not found/.test(e.message)) return { error: `device ${deviceID} not registered — call tokenmonitor_register_device first` };
    return { error: e.message };
  }

  let firmwareURL, shaHex;
  let originSource = "";
  const external = String(args.external_url || "").trim();
  if (external) {
    if (!external.startsWith("https://")) return { error: "external_url must be HTTPS" };
    shaHex = String(args.sha256_hex || "").trim().toLowerCase();
    if (shaHex.length !== 64 || !/^[0-9a-f]{64}$/.test(shaHex)) {
      return { error: "sha256_hex required (64 hex chars) when external_url is set" };
    }
    firmwareURL = external;
  } else {
    const binPath = String(args.bin_path || "").trim();
    if (!binPath) return { error: "bin_path required when external_url is not set" };
    if (!existsSync(binPath)) return { error: `cannot open bin_path: ${binPath}` };
    const dir = firmwarePath();
    mkdirSync(dir, { recursive: true, mode: 0o755 });
    const fileName = `tokenmonitor-${version}.bin`;
    const dst = join(dir, fileName);
    const tmp = dst + ".tmp";
    const h = createHash("sha256");
    const fdIn = openSync(binPath, "r");
    const fdOut = openSync(tmp, "w", 0o644);
    try {
      const buf = Buffer.alloc(64 * 1024);
      while (true) {
        const n = readSync(fdIn, buf, 0, buf.length, null);
        if (n <= 0) break;
        h.update(buf.subarray(0, n));
        writeSync(fdOut, buf, 0, n);
      }
      fsyncSync(fdOut);
    } finally {
      closeSync(fdIn);
      closeSync(fdOut);
    }
    renameSync(tmp, dst);
    shaHex = h.digest("hex");
    const chosen = firmwareBase(deps, dev);
    if (!chosen) return { error: "this host has no reachable LAN address; cannot build firmware_url. Connect to the network the device is on, or publish with external_url." };
    originSource = chosen.how;
    firmwareURL = `${chosen.url}/firmware/${fileName}`;
  }

  // Cleartext transport is fine on a modern build — the manifest and the SHA
  // are what establish trust, not TLS — but CONFIG_TMON_OTA_ALLOW_HTTP first
  // appears in sdkconfig.secureboot at v0.10.2. Below that a production unit
  // refuses any http:// firmware_url in config_sync.c and reports nothing, so
  // the whole publish would land as silence.
  if (firmwareURL.startsWith("http://")) {
    const running = packSemver(String(dev.active.payload.firmware_version || ""));
    if (running !== null && running < HTTP_OTA_FLOOR) {
      return { error: `device ${deviceID} runs ${dev.active.payload.firmware_version}, ` +
        "and plain-http OTA only exists from 0.10.2 (CONFIG_TMON_OTA_ALLOW_HTTP); it " +
        "would drop this pending without a word. Publish with external_url over https, " +
        "or use the GitHub release path, to get it past 0.10.2 first." };
    }
  }

  // Optional signed-manifest envelope — same validation as setDevicePending.
  // Lets a signed image staged over the local /firmware/ (plain-HTTP) endpoint
  // install on a production build (which refuses an unsigned OTA). Host signs;
  // the broker never signs.
  const mb = String(args.firmware_manifest_b64 || "").trim();
  const ms = String(args.firmware_manifest_sig_b64 || "").trim();
  if (mb && mb.length > 4096) return { error: "firmware_manifest_b64 exceeds 4 KiB" };
  if (ms && ms.length > 128) return { error: "firmware_manifest_sig_b64 looks wrong (Ed25519 sig is 64 B → ~88 base64 chars)" };
  if (!!mb !== !!ms) return { error: "firmware_manifest_b64 and firmware_manifest_sig_b64 must be supplied together" };

  const upd = { version: 0, broker_url: "", psk_hex: "", city: "", br_day: 0, br_night: 0, vol: null,
                providers: null, provider_modes: null, autorotate_enabled: null, autorotate_interval_s: null,
                theme_mode: "", gemini_models: null,
                firmware_url: firmwareURL, firmware_sha256: shaHex, firmware_version: version,
                firmware_manifest_b64: mb, firmware_manifest_sig_b64: ms };
  const badGate = gateStagedFirmware(dev, mb, shaHex, version, firmwareURL);
  if (badGate) return { error: badGate };

  try {
    const dev2 = deps.registry.setPending(deviceID, upd);
    const out = { ok: true, firmware_url: firmwareURL };
    if (originSource) out.firmware_url_origin = originSource;
    out.firmware_sha256 = shaHex;
    out.firmware_version = version;
    out.signed = !!mb;
    out.device = deviceSummary(dev2);
    return out;
  } catch (e) { return { error: e.message }; }
}

// Mirror of Go's handleRevertFirmware. See compat/tool-schemas.json.
function revertFirmwareTool(deps, args) {
  if (!deps.registry) return { error: registryUnavailableMsg() };
  const deviceID = String(args.device_id || "").trim().toLowerCase();
  if (!validDeviceID(deviceID)) return { error: "device_id must be 8 lowercase hex chars" };
  const fu = String(args.firmware_url || "").trim();
  const fs = String(args.firmware_sha256 || "").trim().toLowerCase();
  const fv = String(args.firmware_version || "").trim();
  const mb = String(args.firmware_manifest_b64 || "").trim();
  const ms = String(args.firmware_manifest_sig_b64 || "").trim();
  const targetSV = Number(args.target_min_secure_version || 0);
  if (!(fu && fs && fv && mb && ms)) {
    return { error: "revert requires firmware_url, firmware_sha256, firmware_version, firmware_manifest_b64 and firmware_manifest_sig_b64" };
  }
  if (!fu.startsWith("https://")) return { error: "firmware_url must be HTTPS" };
  if (fs.length !== 64 || !/^[0-9a-f]{64}$/.test(fs)) return { error: "firmware_sha256 must be 64 lowercase hex chars" };
  let dev;
  try { dev = deps.registry.load(deviceID); }
  catch (e) {
    if (/not found/.test(e.message)) return { error: `device ${deviceID} not registered` };
    return { error: e.message };
  }
  // The real authority is the manifest this call was handed, not the number the
  // operator typed: the device gates on the signed min_secure_version AND on
  // packed(version), and once its floor has risen past the target no manifest
  // can lower it — a revert simply is not possible over OTA any more (USB is
  // the way back). Predicting both here turns a silent on-device refusal, which
  // costs a reboot and reports nothing, into an answer at the call site.
  const badGate = gateStagedFirmware(dev, mb, fs, fv, fu);
  if (badGate) return { error: badGate };
  // target_min_secure_version stays accepted as a cross-check: if the operator
  // states a floor, it must be the one the manifest actually declares, or one
  // of the two is the wrong artifact.
  if (targetSV) {
    let tmf = null;
    try { tmf = JSON.parse(Buffer.from(mb, "base64").toString("utf8")); } catch { /* reported by the gate above */ }
    if (tmf && typeof tmf === "object" && Number(tmf.min_secure_version || 0) !== targetSV) {
      return { error: `target_min_secure_version=${targetSV} but the supplied manifest ` +
        `for ${String(tmf.version || "")} declares ${Number(tmf.min_secure_version || 0)}; ` +
        "one of the two is from a different build" };
    }
  }
  const upd = { version: 0, broker_url: "", psk_hex: "", city: "", br_day: 0, br_night: 0, vol: null,
                providers: null, provider_modes: null, autorotate_enabled: null, autorotate_interval_s: null,
                theme_mode: "", gemini_models: null,
                firmware_url: fu, firmware_sha256: fs, firmware_version: fv,
                firmware_manifest_b64: mb, firmware_manifest_sig_b64: ms,
                min_secure_version: 0 };
  // Tombstone the version we're reverting FROM (the bad release the device is
  // currently running) so the OTA auto-discovery loop doesn't immediately
  // re-stage it once the device reports the older version. Empty active
  // version (fresh device) → nothing to block.
  const bad = dev.active.payload.firmware_version || "";
  if (bad && bad !== fv) {
    try { deps.registry.setBlockedFirmwareVersion(deviceID, bad); }
    catch (e) { return { error: e.message }; }
  }
  try {
    const dev2 = deps.registry.setPending(deviceID, upd);
    return { ok: true, reverts_to: fv, device: deviceSummary(dev2) };
  } catch (e) { return { error: e.message }; }
}

async function discoverDevicesTool(args) {
  let Bonjour;
  try { ({ default: Bonjour } = await import("bonjour-service")); }
  catch (e) { return { error: `bonjour-service unavailable: ${e.message}` }; }
  let timeout = 4000;
  const raw = args.timeout_seconds;
  if (raw != null) {
    const n = Number(raw);
    if (Number.isFinite(n)) timeout = clamp(n, 1, 15) * 1000;
  }
  const bonjour = new Bonjour();
  const found = new Map();
  return new Promise((resolve) => {
    const browser = bonjour.find({ type: "tmon" }, (service) => {
      const txt = service.txt || {};
      const id = String(txt.device_id || "").toLowerCase().trim();
      if (!id || found.has(id)) return;
      const ipv4 = (service.addresses || []).filter((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a));
      const host = ipv4[0] || service.host || "";
      const port = service.port || 80;
      const base = `http://${host}:${port}`;
      found.set(id, {
        device_id: id,
        state: String(txt.state || ""),
        fw: String(txt.fw || ""),
        host: service.host || "",
        port,
        ipv4,
        provision_url: base + "/provision",
        info_url: base + "/info",
      });
    });
    setTimeout(() => {
      try { browser.stop(); bonjour.destroy(); } catch {}
      const devices = Array.from(found.values());
      resolve({ count: devices.length, devices });
    }, timeout);
  });
}

export async function provisionTool(deps, args) {
  const deviceID = String(args.device_id || "").trim().toLowerCase();
  const provisionURL = String(args.provision_url || "").trim();
  const code = String(args.pairing_code || "").trim();
  if (!validDeviceID(deviceID)) return { error: "device_id must be 8 lowercase hex chars" };
  if (!provisionURL.endsWith("/provision")) return { error: "provision_url must end in /provision (use tokenmonitor_discover_devices to get it)" };
  if (code.length !== 6) return { error: "pairing_code must be 6 digits" };
  let brokerURL = String(args.broker_url || "").trim();
  const callerURL = !!brokerURL;
  const given = explicitPSK(args);
  if (given.error) return { error: given.error };
  // /info and the mDNS TXT carry no has_psk, so the LAN never knows whether
  // the device already holds a key: undefined, "unknown".
  const psk = resolveEnrolPSK(deps, args, deviceID, undefined);
  if (psk.error) return { error: psk.error };
  const { pskHex, pskGenerated, pskReused } = psk;
  // A PSK with no address strands firmware older than 1.0.0 on "Waiting for
  // setup": it cannot find the broker by itself. So an enrolment with no
  // broker_url is given the one address the device can demonstrably reach —
  // ours, on the route to it. On 1.0.0+ that is just a cache seed.
  let seeded = "";
  if (pskHex && !brokerURL) {
    try {
      const u = new URL(provisionURL);
      if (u.hostname) seeded = await seedURLTowards(deps, u.hostname.replace(/^\[|\]$/g, ""), Number(u.port) || 80);
    } catch {
      seeded = "";
    }
    if (!seeded) return { error: ERR_NO_SEED_LAN };
    brokerURL = seeded;
  }
  const payload = { pairing_code: code };
  if (brokerURL) payload.broker_url = brokerURL;
  if (pskHex) payload.psk_hex = pskHex;
  const city = String(args.city || "").trim(); if (city) payload.city = city;
  for (const [k, lo, hi] of [["br_day", 10, 100], ["br_night", 5, 100], ["vol", 0, 100]]) {
    const raw = args[k];
    if (raw != null && raw !== "") {
      const n = Number.parseInt(raw, 10);
      if (Number.isFinite(n)) payload[k] = clamp(n, lo, hi);
    }
  }
  if (args.theme_mode != null && args.theme_mode !== "") {
    const tm = String(args.theme_mode).trim().toLowerCase();
    if (!["day", "night", "auto"].includes(tm)) return { error: "theme_mode must be one of: day, night, auto" };
    payload.theme_mode = tm;
  }
  if ("pet_enabled" in args) payload.pet_enabled = !!args.pet_enabled;
  if ("panel_enabled" in args) payload.panel_enabled = !!args.panel_enabled;
  const providers = {};
  const provArgs = ["provider_claude", "provider_codex", "provider_antigravity", "provider_gemini"];
  if (provArgs.some((k) => k in args)) {
    // A provision that names ANY provider is authoritative over the WHOLE
    // set: fill the ones the caller left out as disabled. The device's
    // provision handler only overwrites a provider whose key is present in
    // the payload, so forwarding only the named providers would leave a
    // dropped provider enabled on a re-configure (3→2). Sending all three
    // also matches the registry lift below, which reads an absent provider
    // as disabled — keeping device and registry in sync.
    for (const name of ["claude", "codex", "gemini"]) {
      let key = `provider_${name}`;
      // Antigravity (formerly Gemini): prefer the new arg name, fall back to
      // the deprecated provider_gemini. Internal key stays "gemini".
      if (name === "gemini" && "provider_antigravity" in args) key = "provider_antigravity";
      providers[name] = !!args[key];
    }
    payload.providers = providers;
  }

  const body = JSON.stringify(payload);
  const url = new URL(provisionURL);
  let respText = "";
  let httpStatus = 0;
  try {
    const r = await new Promise((resolve, reject) => {
      const req = httpRequest({
        protocol: url.protocol, host: url.hostname, port: url.port || 80, path: url.pathname,
        method: "POST", timeout: 6000,
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
      }, (res) => {
        let buf = "";
        res.on("data", (c) => { buf += c; });
        res.on("end", () => resolve({ status: res.statusCode, body: buf }));
        // An answer cut off part-way must fail the call, not leave it pending.
        res.on("error", reject);
        res.on("aborted", () => reject(new Error("response aborted")));
      });
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
      req.write(body);
      req.end();
    });
    httpStatus = r.status; respText = r.body;
  } catch (e) {
    if (pskGenerated) {
      // The request may have reached the device before the connection died
      // (it reboots right after applying), so the minted PSK may be live with
      // no copy anywhere on this host. Hand it back rather than lose it with
      // the error.
      return { ok: false, error: `POST /provision: ${e.message}`, outcome_unknown: true, psk_hex: pskHex, note: NOTE_PSK_UNKNOWN };
    }
    return { error: `POST /provision: ${e.message}` };
  }

  if (httpStatus !== 200) {
    const rejected = { ok: false, http_status: httpStatus, body: respText };
    // A 4xx is a refusal before anything was stored. A 5xx is a failed write,
    // and those can leave a partial config behind (PROVISION_WIRE §3) — the
    // minted PSK may be part of it.
    if (pskGenerated && httpStatus >= 500) {
      rejected.psk_hex = pskHex;
      rejected.note = NOTE_PSK_MAYBE_LIVE;
    }
    return rejected;
  }
  let deviceResp;
  try { deviceResp = JSON.parse(respText); } catch { deviceResp = respText; }
  const out = { ok: true, device_id: deviceID, registered: false, enrolled: false, device_response: deviceResp };
  if (pskGenerated) out.psk_generated = true;
  if (pskReused) out.psk_reused = true;
  if (seeded) out.broker_url_seeded = seeded;
  // Mirror the enrolment into the local registry so /device/<id>/sync
  // recognises the device on first poll. This keys on the PSK that was pushed,
  // NOT on broker_url: the device finds the broker by mDNS, so an enrolment
  // with no address is the normal case, not a partial one.
  let note = noRegistryNote(deps, args, pskHex);
  if (deps.registry && pskHex) {
    const regModes = payload.providers
      ? { claude: providerModeFromBool(!!payload.providers.claude), codex: providerModeFromBool(!!payload.providers.codex), gemini: providerModeFromBool(!!payload.providers.gemini) }
      : null;
    const regPayload = { version: 0, broker_url: brokerURL, psk_hex: pskHex, city: payload.city || "", br_day: payload.br_day || 0, br_night: payload.br_night || 0, vol: payload.vol ?? null, providers: null, provider_modes: regModes, autorotate_enabled: null, autorotate_interval_s: null, theme_mode: payload.theme_mode || "", pet_enabled: ("pet_enabled" in payload) ? payload.pet_enabled : null, panel_enabled: ("panel_enabled" in payload) ? payload.panel_enabled : null };
    const m = mirrorToRegistry(deps, deviceID, regPayload, callerURL);
    out.registered = m.registered;
    if (m.reregistered) out.reregistered = true;
    out.enrolled = m.enrolled;
    note = m.note;
  }
  if (pskGenerated && !out.enrolled) {
    // The device now signs with a key that exists nowhere on this host. Hand
    // it back, or the only way out is a factory reset.
    out.psk_hex = pskHex;
    note = joinNotes(note, NOTE_PSK_UNRECORDED);
  }
  if (note) out.note = note;
  return out;
}
