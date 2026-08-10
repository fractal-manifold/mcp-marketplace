// MCP handlers for the two USB-cable provisioning tools. Mirrors
// go/internal/mcp/usb.go EXACTLY. USB is the developer / rescue /
// reconfiguration path (the consumer path stays SoftAP + LAN).

import { randomBytes } from "node:crypto";

import { validDeviceID, providerModeFromBool } from "../registry/store.js";
import { enumerate, EnumerateUnsupportedError } from "../usbprov/enum.js";
import { resolve as resolvePorts, registryMatches } from "../usbprov/scan.js";
import { TIER_PROBE } from "../usbprov/usbids.js";
import { LeaseClient, anySignal } from "../usbprov/leaseclient.js";
import { LeaseBusyError } from "../usbprov/lease.js";
import { PortBusyError } from "../usbprov/serial.js";
import { runProvision, identify, defaultTimeouts, OutcomeUnknownError, DeviceMismatchError } from "../usbprov/session.js";

function isDigits(s) {
  if (!s.length) return false;
  for (let i = 0; i < s.length; i++) if (s[i] < "0" || s[i] > "9") return false;
  return true;
}

function clamp8(v, lo, hi) {
  v = Math.trunc(v);
  return Math.max(lo, Math.min(hi, v));
}

function hex16(n) {
  return "0x" + (n >>> 0).toString(16).padStart(4, "0");
}

// registeredSKUs builds the device_id→SKU map resolve() uses for
// registry-match. A nil registry yields an empty map.
function registeredSKUs(deps) {
  const out = new Map();
  if (!deps.registry) return out;
  let devs;
  try {
    devs = deps.registry.list();
  } catch {
    return out;
  }
  for (const dev of devs) out.set(dev.deviceID, dev.hwSku || "");
  return out;
}

// brokerBaseURL is the loopback URL of this host's broker, for the lease
// client (a 0.0.0.0/"" bind is dialled as 127.0.0.1).
function brokerBaseURL(deps) {
  let host = deps.cfg.server.bind;
  if (host === "0.0.0.0" || !host) host = "127.0.0.1";
  return `http://${host}:${deps.cfg.server.port}`;
}

function leaseAndOpen(deps, port, signal) {
  const client = new LeaseClient({ baseURL: brokerBaseURL(deps), psk: deps.cfg.psk() });
  return client.openLeased(port, signal);
}

export async function handleUSBScan(deps, args) {
  let timeoutMs = 3000;
  const t = Number(args.timeout_seconds);
  if (Number.isFinite(t) && t > 0) {
    let v = t;
    if (v < 1) v = 1;
    if (v > 10) v = 10;
    timeoutMs = v * 1000;
  }

  let ports;
  try {
    ports = enumerate();
  } catch (e) {
    if (e instanceof EnumerateUnsupportedError) {
      return {
        error:
          "USB scan is not supported on this OS yet (Linux and macOS are supported; Windows enumeration is deferred). Use SoftAP + LAN provisioning instead.",
      };
    }
    return { error: `usb enumerate: ${e.message}` };
  }

  const results = resolvePorts(ports, registeredSKUs(deps));
  const out = [];
  for (const r of results) {
    const e = {
      path: r.path,
      vid: hex16(r.vid),
      pid: hex16(r.pid),
      tier: r.tier,
      registered: r.registered,
    };
    if (r.serial) e.serial = r.serial;
    if (r.label) e.label = r.label;
    if (r.deviceID) e.device_id = r.deviceID;
    if (r.sku) e.sku = r.sku;
    // Only `probe`-tier ports get the one bounded HELLO: a registry-match is
    // already identified without a write, and a `shared` bridge must never
    // receive a byte.
    if (r.tier === TIER_PROBE) {
      try {
        const dev = await probePort(deps, r.path, timeoutMs);
        e.device_id = dev.deviceID;
        if (dev.fw) e.fw = dev.fw;
        if (dev.state) e.state = dev.state;
        if (dev.sku) e.sku = dev.sku;
      } catch (perr) {
        e.probe_error = perr.message;
      }
    }
    out.push(e);
  }
  return { ports: out };
}

// probePort leases the port from the leader (so it doesn't collide with the log
// tailer), opens it exclusively, and sends ONE HELLO handshake. It writes
// nothing but the identification HELLO.
async function probePort(deps, port, timeoutMs) {
  const lp = await leaseAndOpen(deps, port, undefined);
  try {
    const sessSignal = anySignal([lp.lostSignal]);
    const to = defaultTimeouts();
    to.helloResp = timeoutMs;
    return await identify(lp.handle.conn, to, sessSignal);
  } finally {
    lp.close();
  }
}

export async function handleUSBProvision(deps, args) {
  // The cable is the physical-presence proof, so the device's serial transport
  // never demands a code. Accept an absent one; still reject a malformed one,
  // because a caller that bothered to pass a code has the device's screen in
  // front of them and a typo should be surfaced, not silently dropped into a
  // payload the device ignores.
  const code = String(args.pairing_code ?? "").trim();
  if (code && (code.length !== 6 || !isDigits(code))) return { error: "pairing_code must be 6 digits" };

  let expectID = String(args.device_id ?? "").trim().toLowerCase();
  if (expectID && !validDeviceID(expectID)) return { error: "device_id must be 8 lowercase hex chars" };

  // Resolve the port: explicit wins; else auto-select ONLY when exactly one
  // registry-match exists.
  let port = String(args.port ?? "").trim();
  if (!port) {
    let ports;
    try {
      ports = enumerate();
    } catch (e) {
      if (e instanceof EnumerateUnsupportedError) {
        return {
          error:
            "USB provisioning is not supported on this OS yet (Linux and macOS are supported; Windows is deferred). Use SoftAP + LAN provisioning instead.",
        };
      }
      return { error: `usb enumerate: ${e.message}` };
    }
    const matches = registryMatches(resolvePorts(ports, registeredSKUs(deps)));
    if (matches.length === 1) {
      port = matches[0].path;
      if (!expectID) expectID = matches[0].deviceID;
    } else if (matches.length === 0) {
      return {
        error:
          "no registry-match device found; pass an explicit port from tokenmonitor_usb_scan (a probe/shared port is never auto-selected)",
      };
    } else {
      return { error: "several registry-match devices attached; pass an explicit port from tokenmonitor_usb_scan" };
    }
  }

  // Build the PROVISION payload — the SAME JSON POST /provision accepts.
  const built = buildUSBPayload(deps, args, code, expectID);
  if (built.error) return { error: built.error };
  const { payload, pskHex, pskGenerated, pskReused } = built;

  const body = Buffer.from(JSON.stringify(payload), "utf8");

  let lp;
  try {
    lp = await leaseAndOpen(deps, port, undefined);
  } catch (e) {
    if (e instanceof LeaseBusyError) {
      return { ok: false, error: "the serial port is leased by another provisioning session; retry shortly" };
    }
    if (e instanceof PortBusyError) {
      return { ok: false, error: "the serial port is held by another process; close other serial monitors and retry" };
    }
    return { ok: false, error: `open serial port: ${e.message}` };
  }

  let res;
  try {
    const sessSignal = anySignal([lp.lostSignal]);
    res = await runProvision(lp.handle.conn, { provisionJSON: body, expectDeviceID: expectID, signal: sessSignal });
  } catch (runErr) {
    return usbProvisionErrorReport(runErr);
  } finally {
    lp.close();
  }

  // The device applied and returned a RESULT. Its device_id is authoritative.
  const deviceID = res.device.deviceID;
  let deviceResp;
  try {
    deviceResp = JSON.parse(res.resultJSON.toString("utf8"));
  } catch {
    deviceResp = undefined;
  }

  const out = { ok: true, device_id: deviceID, registered: false };
  if (res.device.sku) out.sku = res.device.sku;
  if (res.device.fw) out.fw = res.device.fw;
  if (pskGenerated) out.psk_generated = true;
  if (pskReused) out.psk_reused = true;
  if (deviceResp !== undefined) out.device_response = deviceResp;

  // Mirror into the registry only when broker_url + psk were pushed and the
  // device_id is well-formed.
  if (deps.registry && payload.broker_url && pskHex && validDeviceID(deviceID)) {
    const m = mirrorToRegistry(deps, deviceID, payload, pskHex);
    if (m.registered) out.registered = true;
    if (m.reregistered) out.reregistered = true;
    if (m.note) out.note = m.note;
  }

  return out;
}

// buildUSBPayload assembles the PROVISION JSON from the tool args, including the
// WiFi pair and PSK reuse/gen. Returns { payload, pskHex, pskGenerated,
// pskReused } or { error }.
export function buildUSBPayload(deps, args, code, expectID) {
  const brokerURL = String(args.broker_url ?? "").trim();
  let pskHex = String(args.psk_hex ?? "").trim().toLowerCase();
  let pskGenerated = false;
  let pskReused = false;
  if (pskHex) {
    if (pskHex.length !== 64) return { error: "psk_hex must be 64 hex chars" };
    if (!/^[0-9a-f]{64}$/.test(pskHex)) return { error: "psk_hex is not valid hex" };
  } else if (brokerURL && expectID) {
    // No PSK supplied but a broker is being (re)set: reuse the device's
    // existing registry PSK so the two never drift, else mint a fresh one.
    let existing = "";
    if (deps.registry) {
      try {
        existing = deps.registry.load(expectID)?.active?.payload?.psk_hex || "";
      } catch {
        /* NotFound → new device */
      }
    }
    if (existing) {
      pskHex = existing;
      pskReused = true;
    } else {
      pskHex = randomBytes(32).toString("hex");
      pskGenerated = true;
    }
  }
  // A broker_url with no PSK to sign with is a dead config: it can only be
  // resolved when we know which device this is.
  if (brokerURL && !pskHex) {
    return {
      error:
        "setting broker_url over USB needs device_id (so the device's PSK can be reused/derived) or an explicit psk_hex",
    };
  }

  const payload = {};
  if (code) payload.pairing_code = code;
  if (brokerURL) payload.broker_url = brokerURL;
  if (pskHex) payload.psk_hex = pskHex;
  const city = String(args.city ?? "").trim();
  if (city) payload.city = city;

  if (numPresent(args.br_day) && Number(args.br_day) > 0) payload.br_day = clamp8(Number(args.br_day), 10, 100);
  if (numPresent(args.br_night) && Number(args.br_night) > 0) payload.br_night = clamp8(Number(args.br_night), 5, 100);
  if (numPresent(args.vol) && Number(args.vol) >= 0) payload.vol = clamp8(Number(args.vol), 0, 100);

  const themeRaw = String(args.theme_mode ?? "").trim();
  if (themeRaw) {
    const tm = themeRaw.toLowerCase();
    if (tm !== "day" && tm !== "night" && tm !== "auto") return { error: "theme_mode must be one of: day, night, auto" };
    payload.theme_mode = tm;
  }

  if ("pet_enabled" in args) payload.pet_enabled = !!args.pet_enabled;

  const hasClaude = "provider_claude" in args;
  const hasCodex = "provider_codex" in args;
  const hasAnti = "provider_antigravity" in args;
  const hasGemini = "provider_gemini" in args;
  if (hasClaude || hasCodex || hasAnti || hasGemini) {
    const p = {
      claude: !!args.provider_claude,
      codex: !!args.provider_codex,
    };
    // Antigravity (formerly Gemini): prefer the new arg, fall back to the
    // deprecated provider_gemini. Internal key stays "gemini".
    p.gemini = hasAnti ? !!args.provider_antigravity : !!args.provider_gemini;
    payload.providers = p;
  }

  // WiFi pair: enforce togetherness. A bare wifi_ssid or a bare wifi_pass is an
  // error — never a silent open net. An OMITTED wifi_pass while wifi_ssid is
  // present is NOT an open network; only an explicit empty string is.
  const hasSSID = "wifi_ssid" in args;
  const hasPass = "wifi_pass" in args;
  if (hasSSID !== hasPass) {
    return {
      error: "wifi_ssid and wifi_pass must be sent together (an open network needs wifi_pass set to an explicit empty string)",
    };
  }
  if (hasSSID) {
    const ssid = String(args.wifi_ssid ?? "");
    const pass = String(args.wifi_pass ?? "");
    if (ssid === "") return { error: "wifi_ssid must be 1..32 bytes" };
    payload.wifi_ssid = ssid;
    payload.wifi_pass = pass;
  }

  return { payload, pskHex, pskGenerated, pskReused };
}

function numPresent(v) {
  return v != null && v !== "" && Number.isFinite(Number(v));
}

// mirrorToRegistry converges the local registry to the just-applied config,
// matching provisionTool's register→replaceActive fallback.
function mirrorToRegistry(deps, deviceID, payload, pskHex) {
  const regModes = payload.providers
    ? {
        claude: providerModeFromBool(!!payload.providers.claude),
        codex: providerModeFromBool(!!payload.providers.codex),
        gemini: providerModeFromBool(!!payload.providers.gemini),
      }
    : null;
  const regPayload = {
    version: 0,
    broker_url: payload.broker_url,
    psk_hex: pskHex,
    city: payload.city || "",
    br_day: payload.br_day || 0,
    br_night: payload.br_night || 0,
    vol: payload.vol ?? null,
    providers: null,
    provider_modes: regModes,
    autorotate_enabled: null,
    autorotate_interval_s: null,
    theme_mode: payload.theme_mode || "",
    pet_enabled: "pet_enabled" in payload ? payload.pet_enabled : null,
    panel_enabled: null,
  };
  try {
    deps.registry.register(deviceID, regPayload);
    return { registered: true };
  } catch (e) {
    if (/already exists/.test(e.message)) {
      try {
        deps.registry.replaceActive(deviceID, regPayload);
        return { reregistered: true };
      } catch (e2) {
        return { note: `device provisioned but registry re-register failed: ${e2.message}` };
      }
    }
    return { note: `device provisioned but registry write failed: ${e.message}` };
  }
}

// usbProvisionErrorReport maps a session error to a structured tool result. The
// outcome-unknown case is called out explicitly so the model does NOT blindly
// re-run.
export function usbProvisionErrorReport(err) {
  const rep = { ok: false, error: err.message };
  if (err instanceof OutcomeUnknownError) rep.outcome_unknown = true;
  else if (err instanceof DeviceMismatchError) rep.device_mismatch = true;
  return rep;
}
