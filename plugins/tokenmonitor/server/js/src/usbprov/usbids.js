// USB device-identity table (compat/PROVISION_WIRE.md §5, compat/usb-ids.json).
//
// This table is HARDCODED here, not loaded from a data file at runtime, so no
// configuration edit can widen the set of devices the tool is willing to write
// to. compat/usb-ids.json exists purely as the specification and test fixture;
// test/usbids.test.js asserts this hardcoded copy matches it byte-for-value.
//
// This is NOT a security boundary against someone who can edit the installed
// source — they already control serial writes. It guards against accidental
// config edits, corrupted vendoring and unreviewed data changes.

// Tier classifies how confidently a port is a TokenMonitor.
export const TIER_REGISTRY_MATCH = "registry-match";
export const TIER_PROBE = "probe";
export const TIER_SHARED = "shared";

// deviceTable is the authoritative hardcoded copy. Keep it in sync with
// compat/usb-ids.json (the parity test enforces it). Only probe and shared
// entries live here; registry-match is resolved at runtime.
export const deviceTable = [
  { vid: 0x303a, pid: 0x1001, tier: TIER_PROBE, label: "Espressif USB-Serial/JTAG (ESP32-S3 / C3 / C6)" },
  { vid: 0x1a86, pid: 0x7523, tier: TIER_SHARED, label: "CH340 USB-UART bridge" },
  { vid: 0x10c4, pid: 0xea60, tier: TIER_SHARED, label: "CP210x USB-UART bridge" },
  { vid: 0x0403, pid: 0x6001, tier: TIER_SHARED, label: "FTDI FT232 USB-UART bridge" },
];

// classifyVIDPID returns { tier, found } for a (vid, pid). An unrecognised
// serial device degrades to the most restrictive tier (shared): never
// auto-selected, and written to ONLY after the user names the port explicitly.
// Callers MUST keep the tier (and found) and gate on it.
export function classifyVIDPID(vid, pid) {
  for (const e of deviceTable) {
    if (e.vid === vid && e.pid === pid) return { tier: e.tier, found: true };
  }
  return { tier: TIER_SHARED, found: false };
}

// labelFor returns the human label for a (vid, pid), or "" if unknown.
export function labelFor(vid, pid) {
  for (const e of deviceTable) {
    if (e.vid === vid && e.pid === pid) return e.label;
  }
  return "";
}
