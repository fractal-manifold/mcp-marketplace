package usbprov

import (
	"errors"
	"strings"
)

// ErrEnumerateUnsupported is returned by Enumerate on an OS whose serial
// enumeration is not yet implemented. Linux is the reference/primary path
// (the dev + rescue workflow this feature targets); macOS and Windows
// enumeration are deliberately deferred rather than shipped untested — a scan
// on those platforms reports this error instead of silently finding nothing.
var ErrEnumerateUnsupported = errors.New("usbprov: serial enumeration not implemented on this OS yet")

// Port is one enumerated serial port with its USB identity. Serial is the raw
// iSerial string as the OS reported it; SerialNorm is the normalised form used
// for comparison (see NormalizeSerial).
type Port struct {
	Path       string // OS path: /dev/ttyACM0, /dev/cu.usbmodemXXXX, COM3
	VID        uint16
	PID        uint16
	Serial     string
	SerialNorm string
}

// Enumerate lists candidate serial ports with their USB VID/PID/iSerial. It is
// implemented per-OS (enum_linux.go, enum_darwin.go, enum_windows.go). It only
// enumerates — classification, HELLO probing and registry-match resolution are
// layered on top by the scan, never here. It must never open a port.
func Enumerate() ([]Port, error) {
	return enumerate()
}

// NormalizeSerial lower-cases an iSerial and strips the separators different
// stacks insert into a MAC-derived serial (colons, dashes, underscores,
// spaces), so "84:F7:03:AB:CD:EF" and "84f703abcdef" compare equal. Other
// characters are left intact — a bridge's iSerial need not be hex.
func NormalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '_', ' ':
			return -1
		}
		return r
	}, s)
}

// DeviceIDFromSerial derives the 8-hex device_id from a normalised iSerial,
// mirroring the firmware: device_id = the last 4 bytes of the MAC printed as
// "%02x%02x%02x%02x" (firmware/components/core/src/identity.c). The USB
// iSerial on a factory-fused unit is the full 6-byte MAC, so the device_id is
// its last 8 hex characters.
//
// Returns ("", false) when the normalised serial is not at least 8 trailing
// hex characters — i.e. not a MAC-derived serial we can map to a device_id.
// The MATCH itself is still gated on the registry (a coincidental 8-hex tail
// is not identity); this only produces the candidate key to look up. The
// iSerial format is verified on production-fused units per
// compat/PROVISION_WIRE.md; treat a mismatch as "no registry match", never as
// an identity claim.
func DeviceIDFromSerial(serialNorm string) (string, bool) {
	if len(serialNorm) < 8 {
		return "", false
	}
	tail := serialNorm[len(serialNorm)-8:]
	for i := 0; i < len(tail); i++ {
		c := tail[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			return "", false
		}
	}
	return tail, true
}
