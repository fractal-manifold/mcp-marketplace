package ota

// The broker's copy of the device's manifest gate.
//
// The device runs tmon_ota_gate_decide() (firmware/components/ota/src/ota_gate.c)
// before it installs anything. The broker has to reach the same verdict BEFORE
// it stages, because a manifest the device refuses is not merely a wasted
// cycle: the refusal is silent. tmon_ota.c clears the pending, poisons nothing
// and reports nothing, so from here it looks exactly like a device that keeps
// running the old version. decide() then re-stages, five times, and tombstones
// a release that was never broken — while every arm costs the device a reboot.
//
// That is not hypothetical. The published 1.0.0 index declared
// min_secure_version = packed(0.11.4) instead of the packed(version) default,
// so every unit whose anti-rollback floor had climbed past 0.11.4 — which
// includes any unit re-flashed over USB with NVS preserved, since tmon_min_sv
// is monotonic and survives even a factory reset — refused it forever.
//
// The rows in compat/ota/gate_manifest.json are the shared contract; this file
// and firmware/components/ota/src/ota_gate.c must agree on every one marked
// "broker". Mirrored in py/src/tmon_mcp/ota.py and js/src/ota.js.

import (
	"fmt"
	"strings"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

// GateVerdict names why a manifest cannot be installed on a given device, or
// "" when it can. The strings are the `expect` values in
// compat/ota/gate_manifest.json and are shared with tmon_ota_gate_verdict_str()
// on the device — they are contract, not log text.
type GateVerdict string

const (
	GateOK               GateVerdict = ""
	GateSHAMismatch      GateVerdict = "sha-mismatch"
	GateVersionMismatch  GateVerdict = "version-mismatch"
	GateSKU              GateVerdict = "sku"
	GatePrereleaseNotDev GateVerdict = "prerelease-not-dev-channel"
	GateUnknownChannel   GateVerdict = "unknown-channel"
	GateDevChannelOnProd GateVerdict = "dev-channel-on-production"
	GateMinSVBelowFloor  GateVerdict = "min-sv-below-floor"
	GateUnpackable       GateVerdict = "unpackable-version"
	GateVersionBelow     GateVerdict = "version-below-floor"
)

// GateDevice is what the policy needs to know about the target. It is a
// separate type from registry.Device so the shared vectors can drive it
// directly, without a registry on disk.
type GateDevice struct {
	// Floor is the device's reported anti-rollback floor (packed 8.8.16),
	// active.min_secure_version — mirrored from X-Tmon-Min-Sv on /sync.
	Floor uint32
	// SKU is the device's hardware SKU. Empty means "not known yet", in
	// which case the SKU check is skipped rather than guessed at.
	SKU string
	// IsDev is tmon_serial_is_dev() — the serial's FAC field is "DEV". It
	// selects the dev release channel, nothing else.
	IsDev bool
}

// GateDeviceOf reads the policy inputs out of a registry record.
func GateDeviceOf(dev *registry.Device) GateDevice {
	return GateDevice{
		Floor: dev.Active.MinSecureVersion,
		SKU:   dev.HWSku,
		IsDev: registry.SerialIsDev(dev.SerialNumber),
	}
}

// PredictDeviceGate returns the verdict the DEVICE will reach for this
// manifest, plus an operator-readable explanation. GateOK means "the device
// will accept it"; anything else means staging it can only burn a reboot.
//
// It deliberately covers ONLY the gates whose inputs the broker actually
// holds. Transient conditions the device defers on — the battery/USB gate, an
// unfinished PENDING_VERIFY window, an unreachable download host — are NOT
// predicted here: those retry on their own and pre-skipping them would turn a
// delay into a refusal.
//
// The check order matches ota_gate.c so both sides name the same reason when a
// manifest trips several gates at once; compat/ota/gate_manifest.json pins it.
func PredictDeviceGate(mf ManifestFields, dev GateDevice) (GateVerdict, string) {
	// SKU. The auto-discovery path fetches update-<HWSku>.json, so a mismatch
	// here means a hand-staged manifest for the wrong hardware. The device
	// warns rather than refuses on a non-factory unit, but the broker has no
	// reliable read on that bit and an operator typo is worth failing closed
	// on — the message names exactly what to fix.
	if dev.SKU != "" && mf.SKU != dev.SKU {
		return GateSKU, fmt.Sprintf(
			"manifest is for sku %s but the device reports %s", mf.SKU, dev.SKU)
	}

	// A "-dev.<ts>" prerelease is a dev-channel artifact by definition; one
	// that omits channel:"dev" is a signer bug, and the device refuses it on
	// every unit so a prerelease can never masquerade as stable.
	if strings.Contains(mf.Version, "-") && mf.Channel == "" {
		return GatePrereleaseNotDev, fmt.Sprintf(
			"%s is a prerelease but the manifest declares no channel; "+
				"the device refuses these on every unit", mf.Version)
	}
	if mf.Channel != "" {
		if mf.Channel != "dev" {
			return GateUnknownChannel, fmt.Sprintf(
				"manifest declares channel %q; the firmware only understands \"dev\" "+
					"and refuses any other", mf.Channel)
		}
		if !dev.IsDev {
			return GateDevChannelOnProd, "dev-channel firmware never installs on a " +
				"production unit (the device gates on the serial's FAC field, not on config)"
		}
	}

	// Anti-rollback (a): the signer-declared floor. This is the one the broker
	// never used to check, and the one that stranded 1.0.0.
	if mf.MinSecureVersion < dev.Floor {
		return GateMinSVBelowFloor, fmt.Sprintf(
			"manifest %s declares min_secure_version=%d but the device's anti-rollback "+
				"floor is %d, so it will refuse the install and report nothing. "+
				"Republish %s with min_secure_version >= %d — the tmtools default, "+
				"packed(version), is always correct; lowering it can only lock devices out",
			mf.Version, mf.MinSecureVersion, dev.Floor, mf.Version, dev.Floor)
	}

	// Anti-rollback (b): the image itself.
	packed, ok := PackSemver(mf.Version)
	if !ok {
		return GateUnpackable, fmt.Sprintf("manifest version %q does not pack", mf.Version)
	}
	if packed < dev.Floor {
		return GateVersionBelow, fmt.Sprintf(
			"%s packs to %d, below the device's anti-rollback floor %d; "+
				"a device can never be moved backwards over OTA",
			mf.Version, packed, dev.Floor)
	}

	return GateOK, ""
}

// PredictPendingCrossCheck mirrors the device's gate step 2: the signed
// manifest must describe the very image the pending blob points at. The device
// compares the manifest's sha256/version against the pending's
// firmware_sha256/firmware_version and refuses on any disagreement, silently —
// the classic shape being a manifest left over from the previous build.
//
// It is separate from PredictDeviceGate because the two have different inputs:
// the auto-discovery path derives the pending FROM the manifest, so it cannot
// disagree with itself, while a hand-staged pending carries operator-typed
// fields that can. The verdict strings are the same contract
// (compat/ota/gate_manifest.json rows marked device-only, since only a caller
// holding both halves can reach them).
func PredictPendingCrossCheck(mf ManifestFields, shaHex, version string) (GateVerdict, string) {
	if shaHex != "" && !strings.EqualFold(mf.SHA256, shaHex) {
		return GateSHAMismatch, fmt.Sprintf(
			"the signed manifest covers sha256=%s but the pending points at %s; "+
				"they must describe the same image (a manifest left over from an "+
				"earlier build is the usual cause)", mf.SHA256, shaHex)
	}
	if version != "" && mf.Version != version {
		return GateVersionMismatch, fmt.Sprintf(
			"the signed manifest declares version %s but the pending says %s",
			mf.Version, version)
	}
	return GateOK, ""
}
