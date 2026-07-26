package usbprov

import "sort"

// ScanResult is one classified, resolved serial port — what tokenmonitor_usb_scan
// returns per entry. It layers tier classification and registry-match resolution
// on top of a raw enumerated Port, WITHOUT opening the port (no HELLO here; the
// scan tool decides whether to probe based on Tier).
type ScanResult struct {
	Port
	// Tier is the trust classification after registry resolution: a port whose
	// serial-derived device_id is registered is promoted to TierRegistryMatch
	// regardless of its VID/PID.
	Tier Tier
	// Label is a human-readable device description from the VID/PID table.
	Label string
	// DeviceID is the resolved (registry-match) or candidate (probe) device_id,
	// or "" when none can be trusted (an unregistered shared bridge). For a
	// registry-match it is authoritative; for a bare probe it is only a
	// candidate derived from the iSerial and must be confirmed by a HELLO_RESP
	// before any write.
	DeviceID string
	// Registered is true only when DeviceID is present in the local registry.
	Registered bool
	// SKU is the registry's hardware SKU for a registered device, else "".
	SKU string
}

// Resolve classifies enumerated ports and resolves registry-match. `registered`
// maps a registered device_id to its hardware SKU (SKU may be "" if unknown);
// pass the local registry's contents. It never opens a port. Results are sorted
// by descending trust (registry-match first, then probe, then shared) and then
// by path, so the caller can present the safest auto-selectable candidates first.
func Resolve(ports []Port, registered map[string]string) []ScanResult {
	out := make([]ScanResult, 0, len(ports))
	for _, p := range ports {
		tier, _ := ClassifyVIDPID(p.VID, p.PID)
		r := ScanResult{Port: p, Tier: tier, Label: LabelFor(p.VID, p.PID)}

		// A serial that looks like a device MAC yields a candidate device_id — but
		// ONLY for a probe-tier Espressif port. A `shared` bridge (CH340 / CP210x
		// / FTDI) whose iSerial happens to be hex is NOT a device MAC; promoting it
		// to registry-match would let a foreign gadget be auto-selected and written
		// to. usbids.go's invariant is explicit: the scan only ever upgrades a
		// `probe` entry, never a `shared` one.
		if candidate, ok := DeviceIDFromSerial(p.SerialNorm); ok && tier == TierProbe {
			if sku, isReg := registered[candidate]; isReg {
				// Registry-match: the strongest identity signal — the iSerial
				// (MAC-derived) matches an enrolled device. Auto-selectable.
				r.Tier = TierRegistryMatch
				r.Registered = true
				r.DeviceID = candidate
				r.SKU = sku
			} else {
				// A factory-fresh Espressif unit: surface the candidate id so the
				// user can tell two of them apart, but it stays a probe (must be
				// confirmed by HELLO before any write).
				r.DeviceID = candidate
			}
		}
		out = append(out, r)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := tierRank(out[i].Tier), tierRank(out[j].Tier); ri != rj {
			return ri < rj
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// tierRank orders tiers by descending trust for presentation.
func tierRank(t Tier) int {
	switch t {
	case TierRegistryMatch:
		return 0
	case TierProbe:
		return 1
	default: // TierShared and anything unknown
		return 2
	}
}

// RegistryMatches returns the subset that resolved to a registry-match — the
// only tier the usb_provision tool may auto-select when the caller omits an
// explicit port.
func RegistryMatches(results []ScanResult) []ScanResult {
	var m []ScanResult
	for _, r := range results {
		if r.Tier == TierRegistryMatch {
			m = append(m, r)
		}
	}
	return m
}
