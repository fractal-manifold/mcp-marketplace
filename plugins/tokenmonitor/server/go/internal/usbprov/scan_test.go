package usbprov

import "testing"

func TestResolve_RegistryMatchWinsOverProbe(t *testing.T) {
	ports := []Port{
		// Espressif VID/PID, serial = a MAC whose last 8 hex is a registered id.
		{Path: "/dev/ttyACM0", VID: 0x303a, PID: 0x1001, SerialNorm: "84f703abcdef"},
	}
	reg := map[string]string{"03abcdef": "S1"}
	got := Resolve(ports, reg)
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d", len(got))
	}
	r := got[0]
	if r.Tier != TierRegistryMatch || !r.Registered {
		t.Errorf("registered device must be TierRegistryMatch: %+v", r)
	}
	if r.DeviceID != "03abcdef" || r.SKU != "S1" {
		t.Errorf("resolved id/sku wrong: %+v", r)
	}
}

func TestResolve_ProbeCandidateNotRegistered(t *testing.T) {
	ports := []Port{
		{Path: "/dev/ttyACM0", VID: 0x303a, PID: 0x1001, SerialNorm: "84f70311112222"},
	}
	got := Resolve(ports, map[string]string{}) // empty registry
	r := got[0]
	if r.Tier != TierProbe {
		t.Errorf("unregistered Espressif unit must stay TierProbe, got %s", r.Tier)
	}
	if r.Registered {
		t.Error("must not be marked registered")
	}
	// A probe still surfaces its candidate id (so two fresh units are
	// distinguishable) but it is NOT authoritative.
	if r.DeviceID != "11112222" {
		t.Errorf("probe candidate id = %q, want 11112222", r.DeviceID)
	}
}

func TestResolve_SharedBridgeGetsNoDeviceID(t *testing.T) {
	ports := []Port{
		// CH340 with a serial that happens to end in 8 hex chars: must NOT be
		// given a device_id, because a bridge iSerial is not a device MAC.
		{Path: "/dev/ttyUSB0", VID: 0x1a86, PID: 0x7523, SerialNorm: "0000deadbeef"},
	}
	r := Resolve(ports, map[string]string{})[0]
	if r.Tier != TierShared {
		t.Errorf("CH340 must be TierShared, got %s", r.Tier)
	}
	if r.DeviceID != "" {
		t.Errorf("a shared bridge must get no device_id, got %q", r.DeviceID)
	}
}

func TestResolve_SharedBridgeIsNeverPromotedByAColldingSerial(t *testing.T) {
	// A shared bridge (here FTDI) whose iSerial happens to collide with an
	// enrolled device_id must STAY shared. Its iSerial is not a device MAC, so
	// the collision is meaningless — and promoting it would make a foreign
	// gadget auto-selectable by usb_provision and get HELLO bytes written to it
	// without the user ever naming the port. This is the documented invariant in
	// usbids.go / PROVISION_WIRE §5: only a `probe` entry is ever upgraded.
	ports := []Port{
		{Path: "/dev/ttyUSB0", VID: 0x0403, PID: 0x6001, SerialNorm: "84f703abcdef"},
	}
	r := Resolve(ports, map[string]string{"03abcdef": ""})[0]
	if r.Tier != TierShared {
		t.Errorf("a shared bridge must stay shared despite a colliding serial: %+v", r)
	}
	if r.Registered || r.DeviceID != "" {
		t.Errorf("a shared bridge must get no identity: %+v", r)
	}
}

func TestResolve_SortsByTrustThenPath(t *testing.T) {
	ports := []Port{
		{Path: "/dev/ttyUSB9", VID: 0x1a86, PID: 0x7523},                             // shared
		{Path: "/dev/ttyACM5", VID: 0x303a, PID: 0x1001, SerialNorm: "84f7aaaaaaaa"}, // probe
		{Path: "/dev/ttyACM0", VID: 0x303a, PID: 0x1001, SerialNorm: "84f703abcdef"}, // registry-match
		{Path: "/dev/ttyACM1", VID: 0x303a, PID: 0x1001, SerialNorm: "84f7bbbbbbbb"}, // probe
	}
	reg := map[string]string{"03abcdef": "S1"}
	got := Resolve(ports, reg)
	wantOrder := []string{"/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyACM5", "/dev/ttyUSB9"}
	for i, w := range wantOrder {
		if got[i].Path != w {
			t.Errorf("position %d = %s, want %s (order: %v)", i, got[i].Path, w, paths(got))
		}
	}
	m := RegistryMatches(got)
	if len(m) != 1 || m[0].Path != "/dev/ttyACM0" {
		t.Errorf("RegistryMatches wrong: %v", paths(m))
	}
}

func paths(rs []ScanResult) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Path
	}
	return out
}
