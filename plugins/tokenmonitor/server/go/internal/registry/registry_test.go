package registry

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const (
	testID  = "ab12cd34"
	testPSK = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	newPSK  = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
)

func newReg(t *testing.T) *Registry {
	t.Helper()
	r, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func u8ptr(v uint8) *uint8 { return &v }

// findGolden walks up to the repo's compat/registry/golden fixture shared
// across the three runtimes. Returns "" when run from a standalone checkout
// without the compat tree (the caller skips).
func findGolden(t *testing.T, name string) string {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, "compat", "registry", "golden", name)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// TestGolden_LegacyProvidersMigrateToModes loads the shared golden fixture
// (which still uses the legacy [providers] bool table) and asserts the Go
// reader migrates it to provider_modes identically to the JS/Python readers.
func TestGolden_LegacyProvidersMigrateToModes(t *testing.T) {
	src := findGolden(t, "ab12cd34.toml")
	if src == "" {
		t.Skip("compat/registry/golden unavailable (standalone checkout)")
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	r := newReg(t)
	if err := os.WriteFile(filepath.Join(r.dir, "ab12cd34.toml"), raw, 0o644); err != nil {
		t.Fatalf("seed golden: %v", err)
	}
	dev, err := r.Load("ab12cd34")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if dev.Active.Providers != nil {
		t.Fatalf("legacy Providers should be dropped after migration, got %+v", dev.Active.Providers)
	}
	wantActive := ProviderModeSet{Claude: "auto", Codex: "disabled", Gemini: "disabled"}
	if dev.Active.ProviderModes == nil || *dev.Active.ProviderModes != wantActive {
		t.Fatalf("active provider_modes = %+v, want %+v", dev.Active.ProviderModes, wantActive)
	}
	wantPending := ProviderModeSet{Claude: "auto", Codex: "auto", Gemini: "disabled"}
	if dev.Pending == nil || dev.Pending.ProviderModes == nil || *dev.Pending.ProviderModes != wantPending {
		t.Fatalf("pending provider_modes = %+v, want %+v", dev.Pending, wantPending)
	}
}

// TestGolden_NoVol loads the shared ab12cd34_novol.toml fixture (no `vol`
// key in [active] or [pending]) and asserts the Go reader treats absent vol
// as nil ("never set"), not 0 (explicit mute), and that a save/reload
// round-trip keeps it nil. Mirrors the JS/Python novol tests.
func TestGolden_NoVol(t *testing.T) {
	src := findGolden(t, "ab12cd34_novol.toml")
	if src == "" {
		t.Skip("compat/registry/golden unavailable (standalone checkout)")
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	r := newReg(t)
	if err := os.WriteFile(filepath.Join(r.dir, "ab12cd34.toml"), raw, 0o644); err != nil {
		t.Fatalf("seed golden: %v", err)
	}
	dev, err := r.Load("ab12cd34")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if dev.Active.Vol != nil {
		t.Fatalf("active vol absent on disk should parse as nil, got %v", *dev.Active.Vol)
	}
	if dev.Pending == nil {
		t.Fatal("pending missing")
	}
	if dev.Pending.Vol != nil {
		t.Fatalf("pending vol absent on disk should parse as nil, got %v", *dev.Pending.Vol)
	}
	// Round-trip: a partial update to the pending (no vol) must not
	// materialise vol=0.
	dev2, err := r.SetPending("ab12cd34", ConfigPayload{City: "Sevilla"})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev2.Pending.Vol != nil {
		t.Fatalf("pending vol should stay nil after partial update, got %v", *dev2.Pending.Vol)
	}
	reloaded, err := r.Load("ab12cd34")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Pending.Vol != nil {
		t.Fatalf("pending vol should stay nil after reload, got %v", *reloaded.Pending.Vol)
	}
}

func TestValidDeviceID(t *testing.T) {
	cases := map[string]bool{
		"ab12cd34": true,
		"00000000": true,
		"AB12CD34": false, // uppercase rejected
		"ab12cd":   false, // too short
		"ab12cd345": false,
		"zzzzzzzz": false,
		"":         false,
	}
	for id, want := range cases {
		if got := ValidDeviceID(id); got != want {
			t.Errorf("ValidDeviceID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestRegister_RequiresPSKAndURL(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{BrokerURL: "x"}); err == nil {
		t.Fatal("expected error without psk")
	}
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK}); err == nil {
		t.Fatal("expected error without broker_url")
	}
	if _, err := r.Register(testID, ConfigPayload{PSKHex: "short", BrokerURL: "x"}); err == nil {
		t.Fatal("expected error on bad psk length")
	}
}

func TestRegister_DuplicateRejected(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "u"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "u"}); err == nil {
		t.Fatal("expected error on duplicate register")
	}
}

func TestLoad_NotFound(t *testing.T) {
	r := newReg(t)
	_, err := r.Load(testID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestSetBlockedFirmwareVersion: the revert tombstone setter persists and
// round-trips through disk, is only-on-change, clears on empty, and ignores
// unknown devices.
func TestSetBlockedFirmwareVersion(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://x"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.SetBlockedFirmwareVersion(testID, "0.9.1"); err != nil {
		t.Fatalf("SetBlockedFirmwareVersion: %v", err)
	}
	dev, _ := r.Load(testID)
	if dev.BlockedFirmwareVersion != "0.9.1" {
		t.Fatalf("blocked = %q, want 0.9.1", dev.BlockedFirmwareVersion)
	}
	// Clear with empty string.
	if err := r.SetBlockedFirmwareVersion(testID, ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	dev, _ = r.Load(testID)
	if dev.BlockedFirmwareVersion != "" {
		t.Fatalf("blocked = %q, want cleared", dev.BlockedFirmwareVersion)
	}
	// Unknown device is a silent no-op.
	if err := r.SetBlockedFirmwareVersion("ffffffff", "0.9.1"); err != nil {
		t.Fatalf("unknown device should be a no-op, got %v", err)
	}
}

func TestRegister_ForcesVersion1(t *testing.T) {
	r := newReg(t)
	dev, err := r.Register(testID, ConfigPayload{
		PSKHex:    testPSK,
		BrokerURL: "http://x",
		Version:   99, // should be overridden
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if dev.Active.Version != 1 {
		t.Errorf("Active.Version = %d, want 1", dev.Active.Version)
	}
	if dev.Pending != nil {
		t.Errorf("Pending = %+v, want nil", dev.Pending)
	}
}

func TestReportSettings_UpdatesActiveAndPendingNoVersionBump(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", ThemeMode: "day",
		BrDay: u8ptr(80), BrNight: u8ptr(20), Vol: u8ptr(60),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Queue an unrelated pending (e.g. an OTA) that inherited the old theme.
	if _, err := r.SetPending(testID, ConfigPayload{City: "Madrid"}); err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	dev, _ := r.Load(testID)
	activeVer := dev.Active.Version
	pendingVer := dev.Pending.Version
	if dev.Pending.ThemeMode != "day" {
		t.Fatalf("precondition: pending theme = %q, want day", dev.Pending.ThemeMode)
	}

	// Device reports the user switched to night + bumped night brightness.
	night := "night"
	dev, err := r.ReportSettings(testID, ReportedSettings{ThemeMode: &night, BrNight: u8ptr(45)})
	if err != nil {
		t.Fatalf("ReportSettings: %v", err)
	}
	// Active mirrors the device, version unchanged (converging, not pushing).
	if dev.Active.ThemeMode != "night" {
		t.Errorf("Active.ThemeMode = %q, want night", dev.Active.ThemeMode)
	}
	if dev.Active.BrNight == nil || *dev.Active.BrNight != 45 {
		t.Errorf("Active.BrNight not applied: %+v", dev.Active.BrNight)
	}
	if dev.Active.Version != activeVer {
		t.Errorf("Active.Version bumped %d -> %d, want unchanged", activeVer, dev.Active.Version)
	}
	// Queued pending also converges so its promotion won't revert the theme.
	if dev.Pending == nil || dev.Pending.ThemeMode != "night" {
		t.Errorf("Pending.ThemeMode not updated: %+v", dev.Pending)
	}
	if dev.Pending.Version != pendingVer {
		t.Errorf("Pending.Version bumped %d -> %d, want unchanged", pendingVer, dev.Pending.Version)
	}
	// Operator-owned field on the pending is untouched.
	if dev.Pending.City != "Madrid" {
		t.Errorf("Pending.City clobbered: %q", dev.Pending.City)
	}

	// Out-of-range clamps; unknown theme ignored.
	dev, err = r.ReportSettings(testID, ReportedSettings{ThemeMode: sptr("rainbow"), BrDay: u8ptr(200), Vol: u8ptr(255)})
	if err != nil {
		t.Fatalf("ReportSettings clamp: %v", err)
	}
	if dev.Active.ThemeMode != "night" {
		t.Errorf("unknown theme should be ignored, got %q", dev.Active.ThemeMode)
	}
	if *dev.Active.BrDay != 100 || *dev.Active.Vol != 100 {
		t.Errorf("clamp failed: BrDay=%d Vol=%d", *dev.Active.BrDay, *dev.Active.Vol)
	}

	// Survives reload from disk.
	dev, _ = r.Load(testID)
	if dev.Active.ThemeMode != "night" || *dev.Active.BrNight != 45 {
		t.Errorf("not persisted: %+v", dev.Active.ConfigPayload)
	}
}

func sptr(s string) *string { return &s }

// TestReportSettings_PetFields mirrors the display-settings report-back for the
// device-owned virtual-pet fields: pet_enabled (bool), pet_species (clamped
// 0..9), pet_name (truncated to 15). Absence of pet_species must leave the
// stored value untouched (no sentinel). See compat/SETTINGS_REPORT.md.
func TestReportSettings_PetFields(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	enabled := true
	name := "Sparky the very long pet name"
	dev, err := r.ReportSettings(testID, ReportedSettings{
		PetEnabled: &enabled, PetSpecies: u8ptr(2), PetName: &name,
	})
	if err != nil {
		t.Fatalf("ReportSettings: %v", err)
	}
	if dev.Active.PetEnabled == nil || !*dev.Active.PetEnabled {
		t.Errorf("PetEnabled not applied: %+v", dev.Active.PetEnabled)
	}
	if dev.Active.PetSpecies == nil || *dev.Active.PetSpecies != 2 {
		t.Errorf("PetSpecies not applied: %+v", dev.Active.PetSpecies)
	}
	if dev.Active.PetName != "Sparky the very" {
		t.Errorf("PetName not truncated to 15: %q", dev.Active.PetName)
	}

	// Out-of-range species is clamped to 9.
	dev, err = r.ReportSettings(testID, ReportedSettings{PetSpecies: u8ptr(42)})
	if err != nil {
		t.Fatalf("ReportSettings clamp: %v", err)
	}
	if dev.Active.PetSpecies == nil || *dev.Active.PetSpecies != 9 {
		t.Errorf("PetSpecies clamp failed: %+v", dev.Active.PetSpecies)
	}

	// Absent pet_species (nil) leaves the stored value untouched.
	dev, err = r.ReportSettings(testID, ReportedSettings{PetName: sptr("Rex")})
	if err != nil {
		t.Fatalf("ReportSettings absence: %v", err)
	}
	if dev.Active.PetSpecies == nil || *dev.Active.PetSpecies != 9 {
		t.Errorf("absent pet_species mutated stored value: %+v", dev.Active.PetSpecies)
	}
	if dev.Active.PetName != "Rex" {
		t.Errorf("PetName not updated: %q", dev.Active.PetName)
	}

	// Survives reload from disk.
	dev, _ = r.Load(testID)
	if dev.Active.PetSpecies == nil || *dev.Active.PetSpecies != 9 || dev.Active.PetName != "Rex" {
		t.Errorf("not persisted: %+v", dev.Active.ConfigPayload)
	}
}

func TestSetPending_BumpsVersionAndMerges(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", City: "Madrid", BrDay: u8ptr(80), BrNight: u8ptr(20), Vol: u8ptr(60),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Partial update: just City.
	dev, err := r.SetPending(testID, ConfigPayload{City: "Barcelona"})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev.Pending == nil {
		t.Fatal("Pending nil after change")
	}
	if dev.Pending.Version != 2 {
		t.Errorf("Pending.Version = %d, want 2", dev.Pending.Version)
	}
	if dev.Pending.City != "Barcelona" {
		t.Errorf("Pending.City = %q, want Barcelona", dev.Pending.City)
	}
	// Untouched fields come from active.
	if dev.Pending.BrokerURL != "http://a" {
		t.Errorf("Pending.BrokerURL = %q, want http://a", dev.Pending.BrokerURL)
	}
	if *dev.Pending.BrDay != 80 || *dev.Pending.BrNight != 20 || *dev.Pending.Vol != 60 {
		t.Errorf("Pending non-changed fields not preserved: %+v", dev.Pending.ConfigPayload)
	}

	// Second partial: change PSK on top of pending. Version becomes 3, City stays.
	dev, err = r.SetPending(testID, ConfigPayload{PSKHex: newPSK})
	if err != nil {
		t.Fatalf("SetPending #2: %v", err)
	}
	if dev.Pending.Version != 3 {
		t.Errorf("Pending.Version = %d, want 3", dev.Pending.Version)
	}
	if dev.Pending.City != "Barcelona" {
		t.Errorf("City lost across SetPending calls: %q", dev.Pending.City)
	}
	if dev.Pending.PSKHex != newPSK {
		t.Errorf("PSK not applied: %q", dev.Pending.PSKHex)
	}
}

// TestReplaceActive_ConvergesAndPreservesMetadata covers issue #8: a physical
// re-provision must overwrite the active config (not queue a stuck pending),
// clear any existing pending, reset version to 1, and preserve device-level
// metadata (here: the OTA channel). A subsequent pending then resumes at v2.
func TestReplaceActive_ConvergesAndPreservesMetadata(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://old", City: "Madrid",
	}, "dev"); err != nil { // channel=dev is device-level metadata
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.SetPending(testID, ConfigPayload{City: "Barcelona"}); err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	// Device-reported OTA state that a re-provision must NOT discard.
	if err := r.SetActiveFirmwareVersion(testID, "1.2.3", nil); err != nil {
		t.Fatalf("SetActiveFirmwareVersion: %v", err)
	}
	if err := r.BumpMinSV(testID, 7); err != nil {
		t.Fatalf("BumpMinSV: %v", err)
	}

	dev, err := r.ReplaceActive(testID, ConfigPayload{
		PSKHex: newPSK, BrokerURL: "http://new", City: "Sevilla",
	})
	if err != nil {
		t.Fatalf("ReplaceActive: %v", err)
	}
	if dev.Pending != nil {
		t.Fatalf("Pending not cleared: %+v", dev.Pending)
	}
	if dev.Active.FirmwareVersion != "1.2.3" {
		t.Errorf("firmware_version lost: %q, want 1.2.3", dev.Active.FirmwareVersion)
	}
	if dev.Active.MinSecureVersion != 7 {
		t.Errorf("min_secure_version reset: %d, want 7 (anti-rollback weakened)", dev.Active.MinSecureVersion)
	}
	if dev.Active.PSKHex != newPSK || dev.Active.BrokerURL != "http://new" || dev.Active.City != "Sevilla" {
		t.Errorf("Active not replaced: %+v", dev.Active.ConfigPayload)
	}
	if dev.Active.Version != 1 {
		t.Errorf("Active.Version = %d, want 1", dev.Active.Version)
	}
	if dev.Channel != "dev" {
		t.Errorf("device metadata (channel) lost: %q, want dev", dev.Channel)
	}

	dev, err = r.SetPending(testID, ConfigPayload{City: "Bilbao"})
	if err != nil {
		t.Fatalf("SetPending after replace: %v", err)
	}
	if dev.Pending == nil || dev.Pending.Version != 2 {
		t.Errorf("post-replace pending version wrong: %+v", dev.Pending)
	}
}

func TestReplaceActive_RequiresExisting(t *testing.T) {
	r := newReg(t)
	if _, err := r.ReplaceActive(testID, ConfigPayload{PSKHex: newPSK, BrokerURL: "http://new"}); err == nil {
		t.Fatal("ReplaceActive on missing device should error")
	}
}

func TestSetPending_NoOpDropsPending(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", City: "Madrid", BrDay: u8ptr(80), BrNight: u8ptr(20), Vol: u8ptr(60),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Update that matches active exactly = no-op = no pending written.
	dev, err := r.SetPending(testID, ConfigPayload{City: "Madrid"})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev.Pending != nil {
		t.Errorf("expected no pending after no-op update, got %+v", dev.Pending)
	}
}

func TestMaybePromote_RequiresPendingPSKAndExactVersion(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.SetPending(testID, ConfigPayload{PSKHex: newPSK, City: "Tokyo"}); err != nil {
		t.Fatalf("SetPending: %v", err)
	}

	// Wrong: signed with active.
	promoted, err := r.MaybePromote(testID, 2, false)
	if err != nil || promoted {
		t.Fatalf("promote with active PSK: promoted=%v err=%v", promoted, err)
	}
	// Wrong: signed with pending but version off.
	promoted, err = r.MaybePromote(testID, 1, true)
	if err != nil || promoted {
		t.Fatalf("promote with wrong version: promoted=%v err=%v", promoted, err)
	}
	// Right: signed with pending AND version matches.
	promoted, err = r.MaybePromote(testID, 2, true)
	if err != nil || !promoted {
		t.Fatalf("legit promote rejected: promoted=%v err=%v", promoted, err)
	}

	dev, err := r.Load(testID)
	if err != nil {
		t.Fatalf("Load post-promote: %v", err)
	}
	if dev.Pending != nil {
		t.Errorf("Pending still present after promote: %+v", dev.Pending)
	}
	if dev.Active.Version != 2 || dev.Active.PSKHex != newPSK || dev.Active.City != "Tokyo" {
		t.Errorf("Active not updated: %+v", dev.Active)
	}
	if dev.Active.LastSeen.IsZero() {
		t.Errorf("Active.LastSeen not set on promote")
	}
}


func TestMaybePromote_ThemeOnlyPromotesWithActivePSK(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", ThemeMode: "day",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.SetPending(testID, ConfigPayload{ThemeMode: "night"}); err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	// Active PSK signature (usedPendingPSK=false) MUST promote because
	// the rotation does not change the PSK.
	promoted, err := r.MaybePromote(testID, 2, false)
	if err != nil || !promoted {
		t.Fatalf("theme-only promote with active PSK: promoted=%v err=%v", promoted, err)
	}
	dev, err := r.Load(testID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if dev.Pending != nil {
		t.Errorf("Pending still set after theme-only promote: %+v", dev.Pending)
	}
	if dev.Active.ThemeMode != "night" {
		t.Errorf("Active.ThemeMode = %q, want night", dev.Active.ThemeMode)
	}
}

func TestMaybePromote_RotationStillRequiresPendingPSK(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.SetPending(testID, ConfigPayload{PSKHex: newPSK}); err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	// Active-PSK signature against a rotation pending must NOT promote.
	promoted, err := r.MaybePromote(testID, 2, false)
	if err != nil || promoted {
		t.Fatalf("PSK-rotation promote with active sig: promoted=%v err=%v", promoted, err)
	}
}

func TestMaybePromote_NoPending(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	promoted, err := r.MaybePromote(testID, 1, true)
	if err != nil || promoted {
		t.Fatalf("no-pending promote: promoted=%v err=%v", promoted, err)
	}
}

func TestPSKsFor(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	active, pending, err := r.PSKsFor(testID)
	if err != nil {
		t.Fatalf("PSKsFor: %v", err)
	}
	if len(active) != 32 || pending != nil {
		t.Errorf("active=%d pending=%v", len(active), pending)
	}

	// Pending without PSK change => still only active PSK exposed.
	if _, err := r.SetPending(testID, ConfigPayload{City: "X"}); err != nil {
		t.Fatalf("SetPending city: %v", err)
	}
	active, pending, err = r.PSKsFor(testID)
	if err != nil || len(active) != 32 || pending != nil {
		t.Errorf("after city-only pending: active=%d pending=%v err=%v", len(active), pending, err)
	}

	// Pending with PSK change => both surface.
	if _, err := r.SetPending(testID, ConfigPayload{PSKHex: newPSK}); err != nil {
		t.Fatalf("SetPending psk: %v", err)
	}
	active, pending, err = r.PSKsFor(testID)
	if err != nil || len(active) != 32 || len(pending) != 32 {
		t.Errorf("after psk pending: active=%d pending=%d err=%v", len(active), len(pending), err)
	}
}

func TestTouch_NoOpsForUnknown(t *testing.T) {
	r := newReg(t)
	if err := r.Touch(testID); err != nil {
		t.Errorf("Touch unknown should be nil, got %v", err)
	}
}

func TestList_SortedAndIgnoresJunk(t *testing.T) {
	r := newReg(t)
	for _, id := range []string{"bb000000", "aa000000", "cc000000"} {
		if _, err := r.Register(id, ConfigPayload{PSKHex: testPSK, BrokerURL: "u"}); err != nil {
			t.Fatalf("Register %s: %v", id, err)
		}
	}
	// junk files that List must skip
	for _, name := range []string{"junk.toml", "ZZ000000.toml", "ab.toml", "notes.txt"} {
		if err := writeFile(r.Dir(), name, "garbage"); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	out, err := r.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	if out[0].DeviceID != "aa000000" || out[2].DeviceID != "cc000000" {
		t.Errorf("not sorted: %s, %s, %s", out[0].DeviceID, out[1].DeviceID, out[2].DeviceID)
	}
}

func TestSetPending_ThemeModeOnlyBumpsVersion(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", ThemeMode: "day",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	dev, err := r.SetPending(testID, ConfigPayload{ThemeMode: "night"})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev.Pending == nil {
		t.Fatal("Pending nil after theme-only change")
	}
	if dev.Pending.Version != 2 {
		t.Errorf("Pending.Version = %d, want 2", dev.Pending.Version)
	}
	if dev.Pending.ThemeMode != "night" {
		t.Errorf("Pending.ThemeMode = %q, want night", dev.Pending.ThemeMode)
	}
	// No-op when pending matches active.
	if _, err := r.Register("cc000000", ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://b", ThemeMode: "auto",
	}); err != nil {
		t.Fatalf("Register cc: %v", err)
	}
	dev2, err := r.SetPending("cc000000", ConfigPayload{ThemeMode: "auto"})
	if err != nil {
		t.Fatalf("SetPending cc: %v", err)
	}
	if dev2.Pending != nil {
		t.Errorf("Pending should be nil for theme no-op, got %+v", dev2.Pending)
	}
}

func TestConcurrentSetPending_VersionsMonotonic(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{PSKHex: testPSK, BrokerURL: "http://a", City: "Madrid"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	const N = 20
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each goroutine writes a distinct city so SetPending never decides "no-op".
			city := "City" + strings.Repeat("X", i+1)
			if _, err := r.SetPending(testID, ConfigPayload{City: city}); err != nil {
				t.Errorf("SetPending %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	dev, err := r.Load(testID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if dev.Pending == nil {
		t.Fatal("Pending nil after concurrent updates")
	}
	// Active = 1, so pending must be > 1 and ≤ N+1.
	if dev.Pending.Version <= 1 || dev.Pending.Version > N+1 {
		t.Errorf("Pending.Version = %d, want between 2 and %d", dev.Pending.Version, N+1)
	}
}

func TestSetPending_VolZero(t *testing.T) {
	r := newReg(t)
	if _, err := r.Register(testID, ConfigPayload{
		PSKHex: testPSK, BrokerURL: "http://a", Vol: u8ptr(60),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Update Vol to 0.
	dev, err := r.SetPending(testID, ConfigPayload{Vol: u8ptr(0)})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev.Pending == nil {
		t.Fatal("Pending nil after Vol change to 0")
	}
	if dev.Pending.Vol == nil || *dev.Pending.Vol != 0 {
		t.Errorf("Pending.Vol = %v, want 0", dev.Pending.Vol)
	}

	// Another partial update (City) should preserve Vol=0.
	dev, err = r.SetPending(testID, ConfigPayload{City: "Berlin"})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if dev.Pending.Vol == nil || *dev.Pending.Vol != 0 {
		t.Errorf("Pending.Vol = %v after partial update, want 0", dev.Pending.Vol)
	}
}

func writeFile(dir, name, body string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
}

// findCompatFile walks up from the test working directory to the
// authoritative monorepo compat/<rel>. Skips on a standalone checkout.
func findCompatFile(t *testing.T, rel ...string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 9; i++ {
		candidate := filepath.Join(append([]string{dir, "compat"}, rel...)...)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("compat/%s not found upward from %s (standalone checkout)", filepath.Join(rel...), wd)
	return ""
}

// TestChannelRoutingVectors checks SerialIsDev + CandidateChannels against the
// shared cross-runtime contract (compat/registry/channel_routing.json).
func TestChannelRoutingVectors(t *testing.T) {
	path := findCompatFile(t, "registry", "channel_routing.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var vectors struct {
		SerialIsDev []struct {
			Serial   string `json:"serial"`
			Expected bool   `json:"expected"`
		} `json:"serial_is_dev"`
		CandidateChannels []struct {
			Channel  string   `json:"channel"`
			Serial   string   `json:"serial"`
			Expected []string `json:"expected"`
		} `json:"candidate_channels"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	for _, c := range vectors.SerialIsDev {
		if got := SerialIsDev(c.Serial); got != c.Expected {
			t.Errorf("SerialIsDev(%q) = %v, want %v", c.Serial, got, c.Expected)
		}
	}
	for _, c := range vectors.CandidateChannels {
		dev := &Device{SerialNumber: c.Serial, Channel: c.Channel}
		if got := CandidateChannels(dev); !reflect.DeepEqual(got, c.Expected) {
			t.Errorf("CandidateChannels(channel=%q, serial=%q) = %v, want %v", c.Channel, c.Serial, got, c.Expected)
		}
	}
}
