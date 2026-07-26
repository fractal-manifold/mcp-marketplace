package usbprov

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// findUSBIDs walks up to the repo-root compat/usb-ids.json — the spec + test
// fixture. Like the framing vectors it is NOT vendored into server/compat/
// (it is never read at runtime; each runtime hardcodes its own copy), so this
// walks all the way to the monorepo root. Skips on a standalone checkout.
func findUSBIDs(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 9; i++ {
		candidate := filepath.Join(dir, "compat", "usb-ids.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("compat/usb-ids.json not found upward from %s (standalone checkout)", wd)
	return ""
}

type usbIDsDoc struct {
	Devices []struct {
		VID   string `json:"vid"`
		PID   string `json:"pid"`
		Tier  string `json:"tier"`
		Label string `json:"label"`
	} `json:"devices"`
}

// TestUSBIDs_MatchFixture asserts the hardcoded deviceTable is byte-for-value
// identical to compat/usb-ids.json — same VID/PID (parsed), tier and label, in
// the same order and with the same count. This is what makes "hardcoded, not
// loaded at runtime" honest: an unreviewed change to the fixture (or a
// corrupted vendoring) that widened the set of writable devices would fail
// here rather than silently taking effect.
func TestUSBIDs_MatchFixture(t *testing.T) {
	raw, err := os.ReadFile(findUSBIDs(t))
	if err != nil {
		t.Fatalf("read usb-ids.json: %v", err)
	}
	var doc usbIDsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse usb-ids.json: %v", err)
	}

	if len(doc.Devices) != len(deviceTable) {
		t.Fatalf("device count: hardcoded %d, fixture %d", len(deviceTable), len(doc.Devices))
	}
	for i, fd := range doc.Devices {
		vid, err := strconv.ParseUint(fd.VID, 0, 16)
		if err != nil {
			t.Errorf("fixture[%d] vid %q not 16-bit hex: %v", i, fd.VID, err)
			continue
		}
		pid, err := strconv.ParseUint(fd.PID, 0, 16)
		if err != nil {
			t.Errorf("fixture[%d] pid %q not 16-bit hex: %v", i, fd.PID, err)
			continue
		}
		hc := deviceTable[i]
		if uint16(vid) != hc.VID || uint16(pid) != hc.PID {
			t.Errorf("entry %d id: hardcoded %04x:%04x, fixture %04x:%04x",
				i, hc.VID, hc.PID, vid, pid)
		}
		if string(hc.Tier) != fd.Tier {
			t.Errorf("entry %d (%04x:%04x) tier: hardcoded %q, fixture %q",
				i, hc.VID, hc.PID, hc.Tier, fd.Tier)
		}
		if hc.Label != fd.Label {
			t.Errorf("entry %d (%04x:%04x) label:\n  hardcoded %q\n  fixture   %q",
				i, hc.VID, hc.PID, hc.Label, fd.Label)
		}
	}
}

// TestUSBIDs_NoDuplicates enforces the fixture's "duplicate_or_contradictory
// fail closed" rule on the hardcoded table: two entries for the same (vid,pid)
// are contradictory and must never ship.
func TestUSBIDs_NoDuplicates(t *testing.T) {
	seen := map[uint32]int{}
	for i, e := range deviceTable {
		key := uint32(e.VID)<<16 | uint32(e.PID)
		if j, dup := seen[key]; dup {
			t.Errorf("duplicate (vid,pid) %04x:%04x at entries %d and %d", e.VID, e.PID, j, i)
		}
		seen[key] = i
	}
}

// TestUSBIDs_KnownTiers enforces the fixture's "unknown_tier degrades to
// shared" spirit on the hardcoded table: every hardcoded tier must be one of
// the two VID/PID-keyed tiers (registry-match is never in the table).
func TestUSBIDs_KnownTiers(t *testing.T) {
	for _, e := range deviceTable {
		switch e.Tier {
		case TierProbe, TierShared:
			// ok
		case TierRegistryMatch:
			t.Errorf("%04x:%04x is registry-match — that tier is runtime-resolved, never in the table", e.VID, e.PID)
		default:
			t.Errorf("%04x:%04x has unknown tier %q", e.VID, e.PID, e.Tier)
		}
	}
}

func TestClassifyVIDPID(t *testing.T) {
	if tier, found := ClassifyVIDPID(0x303a, 0x1001); !found || tier != TierProbe {
		t.Errorf("Espressif should classify as probe/found, got %q/%v", tier, found)
	}
	if tier, found := ClassifyVIDPID(0x1a86, 0x7523); !found || tier != TierShared {
		t.Errorf("CH340 should classify as shared/found, got %q/%v", tier, found)
	}
	// An unknown serial device degrades to the most restrictive tier and
	// reports found=false.
	if tier, found := ClassifyVIDPID(0xdead, 0xbeef); tier != TierShared || found {
		t.Errorf("unknown device must be shared/not-found, got %q/%v", tier, found)
	}
}
