package ota

// Parity tests for the broker's copy of the device manifest gate.
//
// These drive compat/ota/gate_manifest.json — the same rows
// firmware/test/host/test_ota_gate.c runs against the shipping
// tmon_ota_gate_decide(). Two implementations of one policy only stay honest
// if something checks them against the same table; without it the drift is
// invisible, because a device that refuses a manifest says nothing at all.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type gateCase struct {
	Name     string   `json:"name"`
	Manifest string   `json:"manifest"`
	Expect   string   `json:"expect"`
	Sides    []string `json:"sides"`
	Why      string   `json:"why"`
	Device   struct {
		Floor     uint32 `json:"floor"`
		SKU       string `json:"sku"`
		IsFactory bool   `json:"is_factory"`
		IsDev     bool   `json:"is_dev"`
	} `json:"device"`
}

func findGateVectors(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 9; i++ {
		candidate := filepath.Join(dir, "compat", "ota", "gate_manifest.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("compat/ota/gate_manifest.json not found upward from %s (standalone checkout)", wd)
	return ""
}

func TestPredictDeviceGateVectors(t *testing.T) {
	raw, err := os.ReadFile(findGateVectors(t))
	if err != nil {
		t.Fatalf("read gate vectors: %v", err)
	}
	var doc struct {
		Cases []gateCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse gate vectors: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("gate vectors carry no cases")
	}

	ran := 0
	for _, c := range doc.Cases {
		applies := len(c.Sides) == 0
		for _, s := range c.Sides {
			if s == "broker" {
				applies = true
			}
		}
		if !applies {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			// The row's manifest is the byte-exact canonical form the signer
			// emits; the broker reads fields out of it exactly as it does from
			// a real index, never re-encoding.
			var mf ManifestFields
			if err := json.Unmarshal([]byte(c.Manifest), &mf); err != nil {
				t.Fatalf("manifest does not parse: %v", err)
			}
			dev := GateDevice{Floor: c.Device.Floor, SKU: c.Device.SKU, IsDev: c.Device.IsDev}
			got, why := PredictDeviceGate(mf, dev)
			want := c.Expect
			if want == "ok" {
				want = ""
			}
			if string(got) != want {
				t.Fatalf("expected %q, got %q (%s)", want, string(got), why)
			}
			if got != GateOK && strings.TrimSpace(why) == "" {
				t.Fatal("a refusal must carry an explanation an operator can act on")
			}
		})
	}
	if ran == 0 {
		t.Fatal("no broker-side cases ran")
	}
}

// The regression proper: a release the device WANTS (newer than its floor)
// whose manifest floor locks it out must be reported loudly and must not touch
// the install-loop streak. Before this, the broker staged it, the device
// refused it in silence, and five rounds later the release was tombstoned for
// that device — the shape the published 1.0.0 index put every unit at or past
// 0.12.0 into.
func TestDecideRefusesManifestBelowDeviceFloor(t *testing.T) {
	v := loadVectors(t)

	// Same manifest shape as the published 1.0.0 index: a 1.0.1 release whose
	// declared floor was lowered to packed(0.11.4).
	lowFloor, _ := PackSemver("0.11.4")
	canonical, sigB64 := signedManifest(t, "ed25519-2026-q2", "S1", "1.0.1", "", lowFloor)
	idx := Index{
		Version:      "1.0.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-1.0.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()
	cfg := otaConfigForVectors(t, v, srv.URL)

	// A unit that has confirmed 1.0.0 and was then re-flashed down over USB:
	// tmon_min_sv is monotonic and survives the flash, so it reports an old
	// running version behind a 1.0.0 floor.
	floor, _ := PackSemver("1.0.0")
	reg := newRegistryWithDevice(t, testDevice, "S1", floor)

	// Staging five times in a row is what tombstones a version. Prove that a
	// manifest the device would refuse never gets that far, no matter how
	// often the loop runs.
	checker := NewChecker(cfg, reg, nil)
	for i := 0; i < maxAutoStages+2; i++ {
		rep, err := checker.Check(t.Context(), false, "", "")
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		got := rep.Devices[0]
		if got.Action != "skipped:min-sv-below-floor" {
			t.Fatalf("round %d: got action=%s reason=%q, want skipped:min-sv-below-floor",
				i, got.Action, got.Reason)
		}
		if !strings.Contains(got.Reason, "min_secure_version") {
			t.Fatalf("round %d: reason must name the field to fix, got %q", i, got.Reason)
		}
		if rep.Staged != 0 {
			t.Fatalf("round %d: staged %d, want 0", i, rep.Staged)
		}
	}

	dev, err := reg.Load(testDevice)
	if err != nil {
		t.Fatalf("load device: %v", err)
	}
	if dev.BlockedFirmwareVersion != "" {
		t.Fatalf("a publishing mistake must never tombstone the release; got %q",
			dev.BlockedFirmwareVersion)
	}
	if dev.Pending != nil {
		t.Fatalf("nothing should have been staged; got pending %+v", dev.Pending)
	}
}

// The same release with the floor tmtools would have picked stages normally —
// same binary, same device, only the signed floor differs. This is the pair
// that makes the invariant concrete: lowering the floor subtracts devices and
// buys nothing.
func TestDecideStagesConformantManifestAtSameFloor(t *testing.T) {
	v := loadVectors(t)
	idx := conformantIndex(t, "ed25519-2026-q2", "S1", "1.0.1", "")
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()
	cfg := otaConfigForVectors(t, v, srv.URL)

	floor, _ := PackSemver("1.0.0")
	reg := newRegistryWithDevice(t, testDevice, "S1", floor)
	checker := NewChecker(cfg, reg, nil)

	rep, err := checker.Check(t.Context(), false, "", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Devices[0].Action != "staged" {
		t.Fatalf("got action=%s reason=%q, want staged",
			rep.Devices[0].Action, rep.Devices[0].Reason)
	}
}

// Why the fix ships as 1.0.1 and not as a re-signed 1.0.0.
//
// By the time the bad index is noticed a device carries three pieces of state
// keyed on the string "1.0.0": the broker's install-loop tombstone
// (BlockedFirmwareVersion), the device's own tmon_ota_bad poison record, and
// possibly a stale pending. Re-signing 1.0.0 clears none of them — the
// tombstone is only cleared by a report of a STRICTLY NEWER version, and the
// device refuses to re-arm a poisoned version string at all. A genuine 1.0.1
// steps past all three at once. This test pins the broker half.
func TestPublishingANewerVersionRecoversATombstonedDevice(t *testing.T) {
	v := loadVectors(t)
	idx := conformantIndex(t, "ed25519-2026-q2", "S1", "1.0.1", "")
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()
	cfg := otaConfigForVectors(t, v, srv.URL)

	floor, _ := PackSemver("1.0.0")
	reg := newRegistryWithDevice(t, testDevice, "S1", floor)
	// The state the incident leaves behind: five refused arms tombstoned 1.0.0,
	// and a pending for it is still sitting there.
	if err := reg.SetBlockedFirmwareVersion(testDevice, "1.0.0"); err != nil {
		t.Fatalf("SetBlockedFirmwareVersion: %v", err)
	}

	checker := NewChecker(cfg, reg, nil)
	rep, err := checker.Check(t.Context(), false, "", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Devices[0].Action != "staged" {
		t.Fatalf("a tombstone on 1.0.0 must not block 1.0.1; got action=%s reason=%q",
			rep.Devices[0].Action, rep.Devices[0].Reason)
	}
	dev, err := reg.Load(testDevice)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if dev.Pending == nil || dev.Pending.FirmwareVersion != "1.0.1" {
		t.Fatalf("expected 1.0.1 staged; got %+v", dev.Pending)
	}

	// The tombstone itself is cleared by the /sync handler on the first report
	// of a strictly newer version (broker/server.go, CompareSemver > 0), so a
	// device that installs this pending drops it on its next poll. What matters
	// here is that the tombstone never had to be cleared to make progress.
	if dev.BlockedFirmwareVersion != "1.0.0" {
		t.Fatalf("the tombstone should still be untouched at this point; got %q",
			dev.BlockedFirmwareVersion)
	}
}
