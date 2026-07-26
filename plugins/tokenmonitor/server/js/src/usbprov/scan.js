// Port classification + registry-match resolution (compat/PROVISION_WIRE.md §5).
// Mirrors go/internal/usbprov/scan.go. Never opens a port (no HELLO here; the
// scan tool decides whether to probe based on tier).

import { classifyVIDPID, labelFor, TIER_REGISTRY_MATCH, TIER_PROBE, TIER_SHARED } from "./usbids.js";
import { deviceIDFromSerial } from "./enum.js";

// resolve classifies enumerated ports and resolves registry-match. `registered`
// is a Map (or plain object) from a registered device_id to its hardware SKU
// (SKU may be "" if unknown). Results are sorted by descending trust
// (registry-match first, then probe, then shared) then by path.
// Returns [{ path, vid, pid, serial, serialNorm, tier, label, deviceID, registered, sku }].
export function resolve(ports, registered) {
  const reg = registered instanceof Map ? registered : new Map(Object.entries(registered || {}));
  const out = [];
  for (const p of ports) {
    const { tier } = classifyVIDPID(p.vid, p.pid);
    const r = {
      path: p.path,
      vid: p.vid,
      pid: p.pid,
      serial: p.serial || "",
      serialNorm: p.serialNorm || "",
      tier,
      label: labelFor(p.vid, p.pid),
      deviceID: "",
      registered: false,
      sku: "",
    };
    const { id: candidate, ok } = deviceIDFromSerial(p.serialNorm || "");
    if (ok) {
      if (reg.has(candidate)) {
        // Registry-match: the strongest identity signal. Auto-selectable.
        r.tier = TIER_REGISTRY_MATCH;
        r.registered = true;
        r.deviceID = candidate;
        r.sku = reg.get(candidate) || "";
      } else if (tier === TIER_PROBE) {
        // A factory-fresh Espressif unit: surface the candidate id so the user
        // can tell two of them apart, but it stays a probe.
        r.deviceID = candidate;
      }
      // A shared bridge with an accidentally-hex serial is NOT given a
      // device_id — its iSerial is not a device MAC.
    }
    out.push(r);
  }

  out.sort((a, b) => {
    const ra = tierRank(a.tier);
    const rb = tierRank(b.tier);
    if (ra !== rb) return ra - rb;
    return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
  });
  return out;
}

function tierRank(t) {
  switch (t) {
    case TIER_REGISTRY_MATCH:
      return 0;
    case TIER_PROBE:
      return 1;
    default:
      return 2; // shared and anything unknown
  }
}

// registryMatches returns the subset that resolved to a registry-match — the
// only tier the usb_provision tool may auto-select when the caller omits an
// explicit port.
export function registryMatches(results) {
  return results.filter((r) => r.tier === TIER_REGISTRY_MATCH);
}
