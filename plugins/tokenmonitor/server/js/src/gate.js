// The broker's copy of the device's manifest gate. Mirror of Go
// internal/ota/gate.go and py/src/tmon_mcp/gate.py.
//
// The device runs tmon_ota_gate_decide()
// (firmware/components/ota/src/ota_gate.c) before it installs anything. The
// broker has to reach the same verdict BEFORE it stages, because a manifest the
// device refuses is not merely a wasted cycle: the refusal is silent.
// tmon_ota.c clears the pending, poisons nothing and reports nothing, so from
// here it looks exactly like a device that keeps running the old version. The
// auto-discovery loop then re-stages, five times, and tombstones a release that
// was never broken — while every arm costs the device a reboot.
//
// That is not hypothetical. The published 1.0.0 index declared
// min_secure_version = packed(0.11.4) instead of the packed(version) default,
// so every unit whose anti-rollback floor had climbed past 0.11.4 — which
// includes any unit re-flashed over USB with NVS preserved, since tmon_min_sv
// is monotonic and survives even a factory reset — refused it forever.
//
// The rows in compat/ota/gate_manifest.json are the shared contract; this file
// and firmware/components/ota/src/ota_gate.c must agree on every one marked
// "broker".

import { packSemver } from "./ota.js";
import { serialIsDev } from "./registry/store.js";

// Verdicts name why a manifest cannot be installed on a given device, or "" when
// it can. These strings are the `expect` values in
// compat/ota/gate_manifest.json and are shared with tmon_ota_gate_verdict_str()
// on the device — they are contract, not log text.
export const GATE_OK = "";
export const GATE_SHA_MISMATCH = "sha-mismatch";
export const GATE_VERSION_MISMATCH = "version-mismatch";
export const GATE_SKU = "sku";
export const GATE_PRERELEASE_NOT_DEV = "prerelease-not-dev-channel";
export const GATE_UNKNOWN_CHANNEL = "unknown-channel";
export const GATE_DEV_CHANNEL_ON_PROD = "dev-channel-on-production";
export const GATE_MIN_SV_BELOW_FLOOR = "min-sv-below-floor";
export const GATE_UNPACKABLE = "unpackable-version";
export const GATE_VERSION_BELOW = "version-below-floor";

// gateDeviceOf reads the policy inputs out of a registry record. A plain object
// rather than a class so the shared vectors can drive predictDeviceGate
// directly, with no registry on disk.
export function gateDeviceOf(dev) {
  return {
    floor: Number(dev.active.payload.min_secure_version || 0),
    sku: dev.hwSku || "",
    isDev: serialIsDev(dev.serialNumber),
  };
}

// predictDeviceGate returns [verdict, why]: the verdict the DEVICE will reach
// for this manifest, plus an operator-readable explanation. GATE_OK means "the
// device will accept it"; anything else means staging it can only burn a
// reboot.
//
// It deliberately covers ONLY the gates whose inputs the broker actually holds.
// Transient conditions the device defers on — the battery/USB gate, an
// unfinished PENDING_VERIFY window, an unreachable download host — are NOT
// predicted here: those retry on their own and pre-skipping them would turn a
// delay into a refusal.
//
// The check order matches ota_gate.c so both sides name the same reason when a
// manifest trips several gates at once; compat/ota/gate_manifest.json pins it.
export function predictDeviceGate(mf, dev) {
  const version = String(mf.version || "");
  const channel = String(mf.channel || "");
  const minSV = Number(mf.min_secure_version || 0);
  const floor = Number(dev.floor || 0);
  const devSku = String(dev.sku || "");
  const mfSku = String(mf.sku || "");

  // SKU. The auto-discovery path fetches update-<HWSku>.json, so a mismatch
  // here means a hand-staged manifest for the wrong hardware. The device warns
  // rather than refuses on a non-factory unit, but the broker has no reliable
  // read on that bit and an operator typo is worth failing closed on — the
  // message names exactly what to fix.
  if (devSku && mfSku !== devSku) {
    return [GATE_SKU, `manifest is for sku ${mfSku} but the device reports ${devSku}`];
  }

  // A "-dev.<ts>" prerelease is a dev-channel artifact by definition; one that
  // omits channel:"dev" is a signer bug, and the device refuses it on every
  // unit so a prerelease can never masquerade as stable.
  if (version.includes("-") && !channel) {
    return [GATE_PRERELEASE_NOT_DEV,
      `${version} is a prerelease but the manifest declares no channel; ` +
      "the device refuses these on every unit"];
  }
  if (channel) {
    if (channel !== "dev") {
      return [GATE_UNKNOWN_CHANNEL,
        `manifest declares channel "${channel}"; the firmware only understands ` +
        '"dev" and refuses any other'];
    }
    if (!dev.isDev) {
      return [GATE_DEV_CHANNEL_ON_PROD,
        "dev-channel firmware never installs on a production unit " +
        "(the device gates on the serial's FAC field, not on config)"];
    }
  }

  // Anti-rollback (a): the signer-declared floor. This is the one the broker
  // never used to check, and the one that stranded 1.0.0.
  if (minSV < floor) {
    return [GATE_MIN_SV_BELOW_FLOOR,
      `manifest ${version} declares min_secure_version=${minSV} but the device's ` +
      `anti-rollback floor is ${floor}, so it will refuse the install and report ` +
      `nothing. Republish ${version} with min_secure_version >= ${floor} — the ` +
      "tmtools default, packed(version), is always correct; lowering it can only " +
      "lock devices out"];
  }

  // Anti-rollback (b): the image itself.
  const packed = packSemver(version);
  if (packed === null) {
    return [GATE_UNPACKABLE, `manifest version "${version}" does not pack`];
  }
  if (packed < floor) {
    return [GATE_VERSION_BELOW,
      `${version} packs to ${packed}, below the device's anti-rollback floor ` +
      `${floor}; a device can never be moved backwards over OTA`];
  }

  return [GATE_OK, ""];
}

// predictPendingCrossCheck mirrors the device's gate step 2: the signed
// manifest must describe the very image the pending blob points at. The device
// compares the manifest's sha256/version against the pending's
// firmware_sha256/firmware_version and refuses on any disagreement, silently —
// the classic shape being a manifest left over from the previous build.
//
// Separate from predictDeviceGate because the two have different inputs: the
// auto-discovery path derives the pending FROM the manifest, so it cannot
// disagree with itself, while a hand-staged pending carries operator-typed
// fields that can.
export function predictPendingCrossCheck(mf, shaHex, version) {
  const mfSha = String(mf.sha256 || "");
  const mfVer = String(mf.version || "");
  if (shaHex && mfSha.toLowerCase() !== String(shaHex).toLowerCase()) {
    return [GATE_SHA_MISMATCH,
      `the signed manifest covers sha256=${mfSha} but the pending points at ` +
      `${shaHex}; they must describe the same image (a manifest left over from ` +
      "an earlier build is the usual cause)"];
  }
  if (version && mfVer !== version) {
    return [GATE_VERSION_MISMATCH,
      `the signed manifest declares version ${mfVer} but the pending says ${version}`];
  }
  return [GATE_OK, ""];
}
