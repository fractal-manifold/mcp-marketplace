package usbprov

// USB device-identity table.
//
// This table is HARDCODED here, not loaded from a data file at runtime, so no
// configuration edit can widen the set of devices the tool is willing to
// write to. compat/usb-ids.json exists purely as the specification and test
// fixture; usbids_test.go asserts this hardcoded copy matches it byte-for-
// value (the same pattern tool_schemas_test.go uses for the MCP registrations).
//
// This is NOT a security boundary against someone who can edit the installed
// source — they already control serial writes. It guards against accidental
// config edits, corrupted vendoring and unreviewed data changes.
//
// See compat/PROVISION_WIRE.md §5 and compat/usb-ids.json for the tier
// semantics.

// Tier classifies how confidently a port is a TokenMonitor and therefore what
// the tool may do with it.
type Tier string

const (
	// TierRegistryMatch: a `probe` (Espressif) device whose iSerial
	// (MAC-derived id) matches a device already enrolled in the local
	// registry. Unambiguous identity WITHOUT writing anything;
	// auto-selection allowed. Resolved at runtime against the registry, so it
	// is NOT keyed by VID/PID and does not appear in deviceTable. The scan
	// only ever upgrades a `probe` entry to registry-match — never a `shared`
	// or unknown device, so a foreign serial gadget reporting an iSerial that
	// happens to collide with an enrolled id cannot be auto-selected.
	TierRegistryMatch Tier = "registry-match"

	// TierProbe: an Espressif USB-Serial/JTAG VID/PID — enumerable but burned
	// into the ROM of every ESP32-S3/C3/C6 (every devkit, every unrelated ESP
	// project, the stock firmware on this same board). One bounded HELLO is
	// allowed, ONLY during a user-initiated scan, never in the background; if
	// several candidates enumerate, list and ask — never auto-pick. No config
	// write without a valid HELLO_RESP.
	TierProbe Tier = "probe"

	// TierShared: a generic USB-UART bridge VID/PID shared with thousands of
	// unrelated products (3D printers, radios, dev boards). NEVER auto-select
	// and NEVER write until the user names the port explicitly. Writing blind
	// here is how you send bytes to someone's 3D printer.
	TierShared Tier = "shared"
)

// USBID is one hardcoded VID/PID → tier mapping.
type USBID struct {
	VID   uint16
	PID   uint16
	Tier  Tier
	Label string
}

// deviceTable is the authoritative hardcoded copy. Keep it in sync with
// compat/usb-ids.json (the parity test enforces it). Only probe and shared
// entries live here; registry-match is resolved at runtime.
var deviceTable = []USBID{
	{0x303a, 0x1001, TierProbe, "Espressif USB-Serial/JTAG (ESP32-S3 / C3 / C6)"},
	{0x1a86, 0x7523, TierShared, "CH340 USB-UART bridge"},
	{0x10c4, 0xea60, TierShared, "CP210x USB-UART bridge"},
	{0x0403, 0x6001, TierShared, "FTDI FT232 USB-UART bridge"},
}

// ClassifyVIDPID returns the base tier for a (vid, pid) and whether it was
// found in the hardcoded table. An unrecognised serial device degrades to the
// most restrictive tier (shared): never auto-selected, and written to ONLY
// after the user names the port explicitly — because a serial port that is
// not a known TokenMonitor bridge might be anything (a 3D printer, a radio).
//
// What the hardcoded table bounds is the set of devices the tool will
// touch AUTOMATICALLY or PROBE unprompted: only `probe` entries get an
// unprompted HELLO, and only a `probe` entry can be upgraded to
// registry-match and auto-selected. It does NOT bound every conceivable
// write — a `shared`/unknown port the user names by hand is still writable,
// by design (that is how a legitimate but unrecognised bridge is used). So
// callers MUST keep the tier (and the returned `found`) and gate on it:
// dropping them would make an unknown device indistinguishable from an
// approved shared bridge.
func ClassifyVIDPID(vid, pid uint16) (Tier, bool) {
	for _, e := range deviceTable {
		if e.VID == vid && e.PID == pid {
			return e.Tier, true
		}
	}
	return TierShared, false
}

// LabelFor returns the human label for a (vid, pid), or "" if unknown.
func LabelFor(vid, pid uint16) string {
	for _, e := range deviceTable {
		if e.VID == vid && e.PID == pid {
			return e.Label
		}
	}
	return ""
}
