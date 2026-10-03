// Enrolment — the rule tokenmonitor_provision (LAN) and
// tokenmonitor_usb_provision (cable) share for pairing a device with this
// broker: which PSK is pushed, which broker address goes with it, and what the
// registry records afterwards.
// Mirrors go/internal/mcp/enrol.go; the strings are canonical
// (compat/mcp-errors.md).

import { randomBytes } from "node:crypto";
import { createSocket } from "node:dgram";

import { NotFound } from "../registry/store.js";

export const NOTE_NO_REGISTRY =
  "no device registry is configured on this install, so no PSK was generated or pushed; pass psk_hex to pair the device";
export const NOTE_PSK_UNRECORDED =
  "a fresh PSK was generated and is now live on the device, but the registry does NOT hold it; record psk_hex and register the device with tokenmonitor_register_device";
export const NOTE_PSK_MAYBE_LIVE =
  "a fresh PSK was generated and may already be stored on the device (a failed write can leave a partial config); record psk_hex — the registry was NOT updated";

export const NOTE_PSK_UNKNOWN =
  "a fresh PSK was generated and may already be live on the device; record it — the registry was NOT updated because the outcome is unknown. Do not blindly re-run.";

// Refusals: the call stops before anything is written to the device.
export const ERR_DEVICE_HAS_PSK =
  "the device already holds a PSK that this registry does not know — it may be paired with another broker, or an earlier enrolment here was never recorded. Nothing was written. Pass enroll=false to keep that pairing and change settings only, enroll=true to re-pair the device with this broker, or psk_hex if you have the key it holds";
export const ERR_ENROLL_CHOICE =
  "this device is not in the registry and nothing says whether it is already paired with another broker. Nothing was written. Pass enroll=true to pair it with this broker (replacing any PSK it holds), or enroll=false to change settings only";
export const ERR_NO_SEED_LAN =
  "could not work out an address of this broker that the device can reach, and firmware older than 1.0.0 cannot pair without one. Nothing was written. Pass broker_url (see tokenmonitor_provision_hint)";
export function errNoSeedUSB(fw, n) {
  return `this device's firmware (${fw}) is older than 1.0.0 and cannot find the broker without an address, and this host has ${n} candidate addresses. Nothing was written. Pass broker_url (see tokenmonitor_provision_hint), or enroll=false to change settings without pairing`;
}

export function joinNotes(a, b) {
  return a ? `${a}; ${b}` : b;
}

// enrollArg reads the three-valued `enroll` argument: absent (decide from the
// evidence), true (pair here, whatever the device holds) or false (never).
export function enrollArg(args) {
  if (args.enroll === undefined || args.enroll === null) return { explicit: false, value: true };
  return { explicit: true, value: !!args.enroll };
}

// explicitPSK validates a caller-supplied psk_hex and the one combination that
// contradicts itself. It needs no device and runs before any port is opened.
// Returns { pskHex } or { error }.
export function explicitPSK(args) {
  const pskHex = String(args.psk_hex ?? "").trim().toLowerCase();
  if (!pskHex) return { pskHex: "" };
  const { explicit, value } = enrollArg(args);
  if (explicit && !value) return { error: "enroll=false cannot be combined with psk_hex" };
  if (pskHex.length !== 64) return { error: "psk_hex must be 64 hex chars" };
  if (!/^[0-9a-f]{64}$/.test(pskHex)) return { error: "psk_hex is not valid hex" };
  return { pskHex };
}

// resolveEnrolPSK decides which PSK, if any, a call pushes.
//
//   - enroll=false: none. Settings only; PSK and registry untouched.
//   - psk_hex: that key.
//   - no registry on this install: none (see noRegistryNote) — a minted key
//     could not be kept and would orphan the device.
//   - the registry already holds a PSK for deviceID: REUSE it. Rotating the key
//     on every reconfigure risks desyncing a device whose push silently fails,
//     and re-sending the same key is harmless whatever state the device is in.
//   - otherwise the device is unknown here, and a fresh key would replace
//     whatever it holds. That is only done on evidence the caller means it:
//     enroll=true; or the device itself reports it holds no PSK (hasPSK=false,
//     serial HELLO_RESP on firmware that sends it); or, when the device cannot
//     say, a broker_url — which is how every caller asked for a pairing before
//     the address stopped being configuration. With no such evidence the call
//     is refused rather than re-keying a device that may be paired elsewhere.
//
// hasPSK is undefined when the device did not say (the LAN transport, or
// firmware that predates the field): "unknown", never "fresh".
//
// Returns { pskHex, pskGenerated, pskReused } or { error }.
export function resolveEnrolPSK(deps, args, deviceID, hasPSK) {
  const none = { pskHex: "", pskGenerated: false, pskReused: false };
  const { explicit, value: enroll } = enrollArg(args);
  if (!enroll) return none;
  const pskHex = String(args.psk_hex ?? "").trim().toLowerCase();
  if (pskHex) return { pskHex, pskGenerated: false, pskReused: false };
  if (!deps.registry) return none;
  let existing = "";
  try {
    existing = deps.registry.load(deviceID)?.active?.payload?.psk_hex || "";
  } catch (e) {
    // Only "no such device" means a new one. A record that exists but cannot
    // be read (permissions, a torn or malformed file) must not be answered by
    // minting: that would re-key a paired device because of a transient read
    // failure.
    if (!(e instanceof NotFound)) return { error: `registry load: ${e.message}` };
  }
  if (existing) return { pskHex: existing, pskGenerated: false, pskReused: true };
  if (!explicit) {
    if (hasPSK === true) return { error: ERR_DEVICE_HAS_PSK };
    if (hasPSK !== false && !String(args.broker_url ?? "").trim()) return { error: ERR_ENROLL_CHOICE };
  }
  return { pskHex: randomBytes(32).toString("hex"), pskGenerated: true, pskReused: false };
}

// noRegistryNote explains an enrolment that could not happen because this
// install has no registry to keep a PSK in.
export function noRegistryNote(deps, args, pskHex) {
  return !deps.registry && !pskHex && enrollArg(args).value ? NOTE_NO_REGISTRY : "";
}

// fwFindsBrokerAlone reports whether firmware `fw` can leave BOOT_NEEDS_CONFIG
// on a PSK alone. That arrived in 1.0.0 (mDNS bootstrap); everything older
// needs a broker URL beside the key or it waits for setup forever. An empty or
// unparseable version counts as old — the safe reading.
export function fwFindsBrokerAlone(fw) {
  const m = /^(\d+)\.\d+\.\d+/.exec(String(fw ?? "").trim());
  return m !== null && Number(m[1]) >= 1;
}

// seedURLTowards is the broker URL a device at host:port can demonstrably
// reach: this host's address on the route to it. A connected UDP socket is how
// the kernel is asked for that address — nothing is sent. Resolves "" when it
// cannot be told.
export function seedURLTowards(deps, host, port) {
  const brokerPort = deps.cfg?.server?.port || 0;
  if (!brokerPort) return Promise.resolve("");
  return new Promise((resolve) => {
    let sock;
    const done = (v) => {
      try { sock?.close(); } catch {}
      resolve(v);
    };
    try {
      sock = createSocket("udp4");
      sock.on("error", () => done(""));
      sock.connect(port, host, (err) => {
        if (err) return done("");
        let ip = "";
        try { ip = sock.address().address; } catch {}
        done(ip && ip !== "0.0.0.0" ? `http://${ip}:${brokerPort}` : "");
      });
    } catch {
      done("");
    }
  });
}

// seedURLFromHint picks the broker URL for a cable-attached device, whose
// route nobody can observe: the provision hint, but only when it is
// unambiguous. Returns { url } or { error }.
export function seedURLFromHint(fw, candidates) {
  if (candidates.length === 1) return { url: candidates[0] };
  return { error: errNoSeedUSB(fw || "unknown version", candidates.length) };
}

// mirrorToRegistry records a just-applied enrolment. A new device is
// registered; a known one is converged in place (replaceActive).
//
// One case writes nothing: the device is already in the registry, the PSK
// pushed is the one the registry holds (whether it was reused or the caller
// passed that same key), and the caller gave no broker_url (converge=false; an
// auto-seeded address does not count — nobody asked for a converge). The
// record is correct as it stands, and replacing it would reset the config
// version to 1 under a live device still at version N — after which every
// pending the broker stages is numbered below what the device already has and
// is ignored. That is the headline "point it at my WiFi" call.
//
// Returns { registered, reregistered, enrolled, note }.
export function mirrorToRegistry(deps, deviceID, regPayload, converge) {
  if (!converge) {
    try {
      if (deps.registry.load(deviceID)?.active?.payload?.psk_hex === regPayload.psk_hex) {
        return { registered: false, reregistered: false, enrolled: true, note: "" };
      }
    } catch {
      /* not there, or unreadable → let register() decide */
    }
  }
  try {
    deps.registry.register(deviceID, regPayload);
    return { registered: true, reregistered: false, enrolled: true, note: "" };
  } catch (e) {
    if (/already exists/.test(e.message)) {
      // Re-provision (device wiped + re-paired): converge active config in
      // place — the device already applied it and proved presence. Queueing a
      // pending left a stuck, undecryptable update. Preserves device
      // metadata. See #8.
      try {
        deps.registry.replaceActive(deviceID, regPayload);
        return { registered: false, reregistered: true, enrolled: true, note: "" };
      } catch (e2) {
        return { registered: false, reregistered: false, enrolled: false, note: `device provisioned but registry re-register failed: ${e2.message}` };
      }
    }
    return { registered: false, reregistered: false, enrolled: false, note: `device provisioned but registry write failed: ${e.message}` };
  }
}
