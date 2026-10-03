// MCP handlers for the two USB-cable provisioning tools. Mirrors
// go/internal/mcp/usb.go EXACTLY. USB is the developer / rescue /
// reconfiguration path (the consumer path stays SoftAP + LAN).

import { validDeviceID, providerModeFromBool } from "../registry/store.js";
import { resolveEnrolPSK, explicitPSK, noRegistryNote, mirrorToRegistry, joinNotes, fwFindsBrokerAlone, seedURLFromHint, NOTE_PSK_UNRECORDED, NOTE_PSK_MAYBE_LIVE, NOTE_PSK_UNKNOWN } from "./enrol.js";
import { enumerate, EnumerateUnsupportedError } from "../usbprov/enum.js";
import { PAYLOAD_MAX } from "../usbprov/frame.js";
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
// client. The lease endpoints are loopback-only (they reject any non-loopback
// peer REGARDLESS of the broker's bind), so this must ALWAYS dial 127.0.0.1 —
// never the configured LAN bind, whose self-connection would present a
// non-loopback source and be rejected 403. A broker bound to 0.0.0.0 also
// listens on loopback; one bound only to a specific LAN IP is simply
// unreachable here, and openLeased then falls back to a direct exclusive open.
function brokerBaseURL(deps) {
  return `http://127.0.0.1:${deps.cfg.server.port}`;
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
        if (dev.hasPSK !== undefined) e.has_psk = dev.hasPSK;
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
    // A scan sends exactly ONE bounded HELLO (PROVISION_WIRE §5). The default
    // 5 tries would cost 5×timeout per silent port — a single non-TokenMonitor
    // ESP32 devkit on the desk would then blow the 10s Codex tool budget.
    to.helloTries = 1;
    return await identify(lp.handle.conn, to, sessSignal);
  } finally {
    lp.close();
  }
}

// candidates are the provision hint's URLs (server.js owns the interface
// walk), used to seed a broker_url for firmware that cannot find the broker.
export async function handleUSBProvision(deps, args, candidates = []) {
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
  // This is everything the arguments alone decide; the PSK and a seeded
  // broker_url are added once the device has said who it is (below).
  const built = buildUSBPayload(args, code);
  if (built.error) return { error: built.error };
  const base = built.payload;

  // Validate the encoded size HERE, before leasing or opening anything. An
  // over-cap payload fails inside the PROVISION send, which is reported as
  // outcome-unknown — but zero bytes have left the host, so it is a pure
  // client-side error.
  const baseLen = encodePayload(base).length;
  if (baseLen > PAYLOAD_MAX) return { error: payloadTooBig(baseLen) };

  let lp;
  try {
    lp = await leaseAndOpen(deps, port, undefined);
  } catch (e) {
    if (e instanceof LeaseBusyError) {
      return { error: "the serial port is leased by another provisioning session; retry shortly" };
    }
    if (e instanceof PortBusyError) {
      return { error: "the serial port is held by another process; close other serial monitors and retry" };
    }
    return { error: `open serial port: ${e.message}` };
  }

  // What may be sent depends on the HELLO_RESP — which device this is, whether
  // it already holds a PSK, whether its firmware can find the broker without
  // an address — so the payload is finished inside the session, after the
  // handshake and before any PROVISION write.
  let fin = null;
  let res;
  try {
    const sessSignal = anySignal([lp.lostSignal]);
    res = await runProvision(lp.handle.conn, {
      expectDeviceID: expectID,
      finalize: (dev) => {
        // A re-handshake (pre-PROVISION reset recovery) must resend the same
        // bytes — in particular the same minted PSK.
        if (fin && fin.deviceID === dev.deviceID) return fin.body;
        const f = finalizeUSBPayload(deps, args, base, dev, candidates);
        if (f.error) throw new USBRefusal(f.error);
        fin = f;
        return f.body;
      },
      signal: sessSignal,
    });
  } catch (runErr) {
    if (runErr instanceof USBRefusal) return { error: runErr.message };
    return usbProvisionErrorReport(runErr, fin?.pskHex ?? "", fin?.pskGenerated ?? false);
  } finally {
    lp.close();
  }

  return usbProvisionReport(deps, res, fin, noRegistryNote(deps, args, fin.pskHex));
}

// USBRefusal is a decision NOT to provision, taken after the handshake and
// before any PROVISION write. It surfaces as a plain tool error.
class USBRefusal extends Error {}

// encodePayload is the PROVISION body, byte for byte what Go's json.Marshal
// produces: JSON.stringify is already compact and leaves non-ASCII as UTF-8,
// but Go additionally writes the five characters < > & U+2028 U+2029 as
// \\uXXXX. They can only occur inside strings, so a plain replace is safe.
// Without it a city like "Tom & Jerry" would put different bytes (and a
// different size) on the wire than the Go runtime.
const GO_JSON_ESCAPES = { "<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "\u2028": "\\u2028", "\u2029": "\\u2029" };
export function encodePayload(payload) {
  return Buffer.from(JSON.stringify(payload).replace(/[<>&\u2028\u2029]/g, (c) => GO_JSON_ESCAPES[c]), "utf8");
}

function payloadTooBig(n) {
  return `provisioning payload is ${n} bytes, over the ${PAYLOAD_MAX}-byte device limit; shorten fields such as city`;
}

// finalizeUSBPayload completes the payload for the device that answered the
// HELLO: the PSK (resolveEnrolPSK, with the device's own has_psk as evidence)
// and, for firmware that cannot find the broker by itself, a broker_url.
// candidates are the provision hint's URLs. Returns { deviceID, payload, body,
// pskHex, pskGenerated, pskReused, callerURL, seeded } or { error } — a
// refusal: nothing has been written and nothing will be.
export function finalizeUSBPayload(deps, args, base, dev, candidates) {
  const callerURL = !!base.broker_url;
  const psk = resolveEnrolPSK(deps, args, dev.deviceID, dev.hasPSK);
  if (psk.error) return { error: psk.error };
  let brokerURL = base.broker_url || "";
  let seeded = "";
  // A PSK with no address strands firmware older than 1.0.0 on "Waiting for
  // setup". Over the cable there is no route to read an address off, so the
  // provision hint is used — but only when it names exactly one.
  if (psk.pskHex && !callerURL && !fwFindsBrokerAlone(dev.fw)) {
    const seed = seedURLFromHint(dev.fw, candidates);
    if (seed.error) return { error: seed.error };
    seeded = seed.url;
    brokerURL = seeded;
  }
  // Same key order as the Go struct, so the bytes on the wire are identical.
  const payload = {};
  if ("pairing_code" in base) payload.pairing_code = base.pairing_code;
  if (brokerURL) payload.broker_url = brokerURL;
  if (psk.pskHex) payload.psk_hex = psk.pskHex;
  for (const [k, v] of Object.entries(base)) {
    if (k !== "pairing_code" && k !== "broker_url" && k !== "psk_hex") payload[k] = v;
  }
  const body = encodePayload(payload);
  if (body.length > PAYLOAD_MAX) return { error: payloadTooBig(body.length) };
  return { deviceID: dev.deviceID, payload, body, pskHex: psk.pskHex, pskGenerated: psk.pskGenerated, pskReused: psk.pskReused, callerURL, seeded };
}

// usbProvisionReport turns a received RESULT into the tool result. A RESULT is
// only the device ANSWERING — success and error alike arrive as one
// (PROVISION_WIRE §3) — so top-level ok is the device's own `ok`, and the
// registry is mirrored only when the device says it applied the payload.
export function usbProvisionReport(deps, res, fin, note = "") {
  const { pskHex, pskGenerated, pskReused } = fin;
  // The device_id echoed in HELLO_RESP is authoritative — use it for the
  // registry mirror below.
  const deviceID = res.device.deviceID;
  let deviceResp;
  try {
    const parsed = JSON.parse(res.resultJSON.toString("utf8"));
    // Only surface an object, like Go's map[string]any unmarshal — a bare
    // array/string/number RESULT is dropped rather than echoed.
    deviceResp = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : undefined;
  } catch {
    deviceResp = undefined;
  }
  const applied = deviceResp !== undefined && deviceResp.ok === true;

  const out = { ok: applied };
  if (!applied) {
    const msg = deviceResp?.error;
    out.error = typeof msg === "string" && msg ? msg : "device rejected the provisioning payload";
  }
  out.device_id = deviceID;
  out.registered = false;
  out.enrolled = false;
  if (res.device.sku) out.sku = res.device.sku;
  if (res.device.fw) out.fw = res.device.fw;
  if (pskGenerated) out.psk_generated = true;
  if (pskReused) out.psk_reused = true;
  if (fin.seeded) out.broker_url_seeded = fin.seeded;
  if (deviceResp !== undefined) out.device_response = deviceResp;
  if (!applied) {
    if (pskGenerated) {
      out.psk_hex = pskHex;
      out.note = NOTE_PSK_MAYBE_LIVE;
    }
    return out;
  }

  // Mirror the enrolment into the registry whenever a PSK was pushed and the
  // device_id is well-formed — with or without a broker_url. enroll=false
  // pushed none and leaves the registry untouched.
  if (deps.registry && pskHex && validDeviceID(deviceID)) {
    const m = mirrorToRegistry(deps, deviceID, usbRegistryPayload(fin.payload, pskHex), fin.callerURL);
    out.registered = m.registered;
    if (m.reregistered) out.reregistered = true;
    out.enrolled = m.enrolled;
    note = m.note;
  }
  if (pskGenerated && !out.enrolled) {
    out.psk_hex = pskHex;
    note = joinNotes(note, NOTE_PSK_UNRECORDED);
  }
  if (note) out.note = note;
  return out;
}

// buildUSBPayload assembles the part of the PROVISION JSON the tool args alone
// decide, including the WiFi pair. An explicit psk_hex is validated here; which
// PSK is finally sent is finalizeUSBPayload's call. Returns { payload } or
// { error }.
export function buildUSBPayload(args, code) {
  const brokerURL = String(args.broker_url ?? "").trim();
  const psk = explicitPSK(args);
  if (psk.error) return { error: psk.error };
  const { pskHex } = psk;

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
    // Emit the current "antigravity" wire key (PROVISION_WIRE §3). Every
    // firmware with a serial transport accepts it (the rename predates the
    // transport). Keys go in sorted order — the order Go's json.Marshal gives
    // a map — so all three runtimes put the same bytes on the wire.
    const p = {
      antigravity: hasAnti ? !!args.provider_antigravity : !!args.provider_gemini,
      claude: !!args.provider_claude,
      codex: !!args.provider_codex,
    };
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
    // Length is in UTF-8 BYTES, not code points (PROVISION_WIRE §7): the
    // schema's maxLength counts characters, so a 32-CHARACTER SSID of multibyte
    // glyphs passes it and is then rejected by firmware as BODY_BAD_WIFI after
    // a whole lease + serial session was spent.
    if (ssid === "" || Buffer.byteLength(ssid, "utf8") > 32) {
      return { error: "wifi_ssid must be 1..32 bytes (UTF-8 bytes, not characters)" };
    }
    if (Buffer.byteLength(pass, "utf8") > 64) {
      return { error: "wifi_pass must be at most 64 bytes (UTF-8 bytes, not characters)" };
    }
    payload.wifi_ssid = ssid;
    payload.wifi_pass = pass;
  }

  return { payload };
}

function numPresent(v) {
  return v != null && v !== "" && Number.isFinite(Number(v));
}

// usbRegistryPayload lifts the just-applied USB payload into the registry's
// config shape, matching provisionTool's lift.
function usbRegistryPayload(payload, pskHex) {
  const regModes = payload.providers
    ? {
        claude: providerModeFromBool(!!payload.providers.claude),
        codex: providerModeFromBool(!!payload.providers.codex),
        // The USB payload carries the "antigravity" wire key; the registry's
        // internal name for that provider is still gemini.
        gemini: providerModeFromBool(!!payload.providers.antigravity),
      }
    : null;
  return {
    version: 0,
    broker_url: payload.broker_url || "",
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
}

// usbProvisionErrorReport maps a session error to a structured tool result. The
// outcome-unknown case is called out explicitly so the model does NOT blindly
// re-run.
//
// pskHex/pskGenerated surface a freshly-minted PSK on the outcome-unknown path:
// the device MAY have committed it, but the registry was NOT updated (we don't
// know it applied), so without this the device could end up signing with a key
// nobody on the host has. A reused/existing PSK is already persisted, so it is
// not echoed.
export function usbProvisionErrorReport(err, pskHex = "", pskGenerated = false) {
  const rep = { ok: false, error: err.message };
  if (err instanceof OutcomeUnknownError) {
    rep.outcome_unknown = true;
    if (pskGenerated) {
      rep.psk_hex = pskHex;
      rep.note = NOTE_PSK_UNKNOWN;
    }
  } else if (err instanceof DeviceMismatchError) {
    rep.device_mismatch = true;
  }
  return rep;
}
