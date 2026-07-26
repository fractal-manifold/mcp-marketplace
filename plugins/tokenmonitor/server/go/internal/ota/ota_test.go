package ota

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

func TestPackSemver(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"0.0.0", 0, true},
		{"0.5.1", 0<<24 | 5<<16 | 1, true},
		{"1.2.3", 1<<24 | 2<<16 | 3, true},
		{"255.255.65535", 255<<24 | 255<<16 | 65535, true},
		// Malformed shapes.
		{"", 0, false},
		{"1.2", 0, false},
		{"1.2.3.4", 0, false},
		{"1.2.x", 0, false},
		{"v1.2.3", 0, false},
		{"1..3", 0, false},
		{" 1.2.3", 0, false},
		// Leading zeros rejected (strict semver), but a lone "0" is fine.
		{"01.2.3", 0, false},
		{"1.02.3", 0, false},
		{"1.2.03", 0, false},
		// Out of range for the 8.8.16 packing.
		{"256.0.0", 0, false},
		{"0.256.0", 0, false},
		{"0.0.65536", 0, false},
	}
	for _, c := range cases {
		got, ok := PackSemver(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("PackSemver(%q) = (%d,%t), want (%d,%t)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// semverOrderVectors mirrors compat/ota/semver_order.json — the shared
// contract for the version-packing and prerelease-ordering helpers.
type semverOrderVectors struct {
	Pack []struct {
		Version string `json:"version"`
		Packed  uint32 `json:"packed"`
		OK      bool   `json:"ok"`
	} `json:"pack"`
	Compare []struct {
		A    string `json:"a"`
		B    string `json:"b"`
		Sign int    `json:"sign"`
	} `json:"compare"`
	CompareUnparseable []struct {
		A string `json:"a"`
		B string `json:"b"`
	} `json:"compare_unparseable"`
	Valid []struct {
		Version string `json:"version"`
		Valid   bool   `json:"valid"`
	} `json:"valid"`
}

// findCompatFile walks up from the test working directory looking for a file
// under compat/. Skips (standalone checkout) if not found.
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

// TestSemverVectors drives PackSemver + CompareSemver from the shared
// cross-runtime contract so Go, JS and Python stay byte-for-byte aligned.
func TestSemverVectors(t *testing.T) {
	raw, err := os.ReadFile(findCompatFile(t, "ota", "semver_order.json"))
	if err != nil {
		t.Fatalf("read semver_order.json: %v", err)
	}
	var v semverOrderVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse semver_order.json: %v", err)
	}
	for _, c := range v.Pack {
		got, ok := PackSemver(c.Version)
		if ok != c.OK || (ok && got != c.Packed) {
			t.Errorf("PackSemver(%q) = (%d,%t), want (%d,%t)", c.Version, got, ok, c.Packed, c.OK)
		}
	}
	for _, c := range v.Compare {
		got, ok := CompareSemver(c.A, c.B)
		if !ok || got != c.Sign {
			t.Errorf("CompareSemver(%q,%q) = (%d,%t), want (%d,true)", c.A, c.B, got, ok, c.Sign)
		}
	}
	for _, c := range v.CompareUnparseable {
		if _, ok := CompareSemver(c.A, c.B); ok {
			t.Errorf("CompareSemver(%q,%q) should be unparseable", c.A, c.B)
		}
	}
	for _, c := range v.Valid {
		if got := ValidVersion(c.Version); got != c.Valid {
			t.Errorf("ValidVersion(%q) = %t, want %t", c.Version, got, c.Valid)
		}
	}
}

// compatVectors is the subset of compat/ed25519/vectors.json the OTA
// verifier cares about.
type compatVectors struct {
	TestKeypair struct {
		PubHex string `json:"pub_hex"`
	} `json:"test_keypair"`
	Manifests []struct {
		Name            string `json:"name"`
		CanonicalString string `json:"canonical_string"`
		SignatureHex    string `json:"signature_hex"`
		SignatureB64    string `json:"signature_b64"`
	} `json:"manifests"`
	Tamper []struct {
		Name string `json:"name"`
	} `json:"tamper_cases_must_not_verify"`
}

// findVectors walks up from the test working directory looking for the
// authoritative compat/ed25519/vectors.json. The Go source lives inside the
// tokenmonitor plugin, so the monorepo root is several levels up; the server
// slice ships only tool-schemas.json (no ed25519/), so we probe the specific
// file and skip in a standalone plugin checkout.
func findVectors(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 9; i++ {
		candidate := filepath.Join(dir, "compat", "ed25519", "vectors.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("compat/ed25519/vectors.json not found upward from %s (standalone checkout)", wd)
	return ""
}

func loadVectors(t *testing.T) compatVectors {
	t.Helper()
	raw, err := os.ReadFile(findVectors(t))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v compatVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(v.Manifests) == 0 {
		t.Fatal("vectors carry no OTA manifests")
	}
	return v
}

// TestVerifyManifestVectors asserts the Go verifier accepts every signed
// canonical manifest in the shared suite, and rejects a tampered byte and a
// wrong key. This is the byte-exact contract the Python and JS brokers must
// also satisfy.
func TestVerifyManifestVectors(t *testing.T) {
	v := loadVectors(t)
	pub, err := hex.DecodeString(v.TestKeypair.PubHex)
	if err != nil {
		t.Fatalf("decode pub_hex: %v", err)
	}
	for _, m := range v.Manifests {
		if m.SignatureHex == "" {
			t.Fatalf("%s: vector is missing signature_hex", m.Name)
		}
		sig, err := hex.DecodeString(m.SignatureHex)
		if err != nil {
			t.Fatalf("%s: decode signature_hex: %v", m.Name, err)
		}
		body := []byte(m.CanonicalString)
		if !VerifyManifest(pub, body, sig) {
			t.Errorf("%s: signature should verify but did not", m.Name)
		}
		// signature_b64 must decode to the same 64 bytes.
		sigB64, err := base64.StdEncoding.DecodeString(m.SignatureB64)
		if err != nil || hex.EncodeToString(sigB64) != m.SignatureHex {
			t.Errorf("%s: signature_b64 does not match signature_hex", m.Name)
		}
		// Flip one byte of the manifest → must fail.
		tampered := append([]byte(nil), body...)
		tampered[0] ^= 0x01
		if VerifyManifest(pub, tampered, sig) {
			t.Errorf("%s: tampered manifest must not verify", m.Name)
		}
		// Wrong key → must fail.
		wrong := append([]byte(nil), pub...)
		wrong[0] ^= 0x01
		if VerifyManifest(wrong, body, sig) {
			t.Errorf("%s: wrong key must not verify", m.Name)
		}
	}
}

// s1Vector returns the S1 manifest vector (key_id ed25519-2026-q2,
// version 0.5.1) used to build a mock release index.
func s1Vector(t *testing.T, v compatVectors) (canonical, sigB64 string) {
	t.Helper()
	for _, m := range v.Manifests {
		if strings.Contains(m.Name, "S1") {
			return m.CanonicalString, m.SignatureB64
		}
	}
	t.Fatal("no S1 manifest vector found")
	return "", ""
}

// otaConfigForVectors builds an [ota] config whose keyring carries the
// shared test pubkey under the S1 manifest's key_id (ed25519-2026-q2), and
// whose releases_repo points at the supplied mock server URL.
func otaConfigForVectors(t *testing.T, v compatVectors, repoURL string) *config.Config {
	t.Helper()
	pub, err := hex.DecodeString(v.TestKeypair.PubHex)
	if err != nil {
		t.Fatalf("decode pub_hex: %v", err)
	}
	return &config.Config{
		OTA: config.OTAConfig{
			Enabled:             true,
			ReleasesRepo:        repoURL,
			PollIntervalMinutes: 60,
			Keys: []config.OTAKey{{
				KeyID:     "ed25519-2026-q2",
				PubkeyB64: base64.StdEncoding.EncodeToString(pub),
			}},
		},
	}
}

// mockReleases serves update-<SKU>.json for the SKUs in idxBySKU. SKUs not
// in the map 404, mimicking GitHub's "no such asset" for a never-released
// SKU.
func mockReleases(t *testing.T, idxBySKU map[string]Index) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/releases/latest/download/update-"
		if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, ".json") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		sku := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), ".json")
		idx, ok := idxBySKU[sku]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(idx)
	}))
}

func newRegistryWithDevice(t *testing.T, deviceID, sku string, minSV uint32) *registry.Registry {
	t.Helper()
	reg, err := registry.New(t.TempDir())
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if _, err := reg.Register(deviceID, registry.ConfigPayload{
		PSKHex:    testPSK,
		BrokerURL: "https://broker.example",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// A production (non-DEV) serial keeps these staging tests on a single
	// channel (stable). Dual-channel dev routing has its own test.
	if err := reg.SetSerial(deviceID, "CWM-S1-MAD-2620-000001-0", sku); err != nil {
		t.Fatalf("SetSerial: %v", err)
	}
	if minSV > 0 {
		if err := reg.BumpMinSV(deviceID, minSV); err != nil {
			t.Fatalf("BumpMinSV: %v", err)
		}
	}
	return reg
}

const (
	testPSK    = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	testDevice = "ab12cd34"
)

func TestCheckStagesUpdate(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	reg := newRegistryWithDevice(t, testDevice, "S1", 0)
	checker := NewChecker(cfg, reg, nil)

	// Dry run reports would_stage and writes nothing.
	rep, err := checker.Check(context.Background(), true, "", "")
	if err != nil {
		t.Fatalf("dry-run Check: %v", err)
	}
	if rep.Staged != 0 || len(rep.Devices) != 1 || rep.Devices[0].Action != "would_stage" {
		t.Fatalf("dry-run: got staged=%d devices=%+v, want 1 would_stage", rep.Staged, rep.Devices)
	}
	if len(rep.PerSKU) != 1 || !rep.PerSKU[0].Verified || rep.PerSKU[0].LatestVersion != "0.5.1" {
		t.Fatalf("dry-run per-sku: %+v", rep.PerSKU)
	}
	if dev, _ := reg.Load(testDevice); dev.Pending != nil {
		t.Fatal("dry-run must not write a pending")
	}

	// Real run stages the pending with the firmware fields.
	rep, err = checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Staged != 1 || rep.Devices[0].Action != "staged" {
		t.Fatalf("got staged=%d devices=%+v, want 1 staged", rep.Staged, rep.Devices)
	}
	dev, err := reg.Load(testDevice)
	if err != nil || dev.Pending == nil {
		t.Fatalf("expected a pending after staging, got %+v (err=%v)", dev, err)
	}
	p := dev.Pending.ConfigPayload
	if p.FirmwareVersion != "0.5.1" || p.FirmwareURL != idx.BinURL ||
		p.FirmwareSHA256 != "abc123" ||
		p.FirmwareManifestB64 != idx.ManifestB64 || p.FirmwareManifestSigB64 != sigB64 {
		t.Fatalf("staged firmware fields wrong: %+v", p)
	}

	// Idempotence: a second pass sees the pending already carries 0.5.1.
	rep, err = checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("second Check: %v", err)
	}
	if rep.Staged != 0 || rep.Devices[0].Action != "skipped:already-pending" {
		t.Fatalf("idempotence: got staged=%d action=%s", rep.Staged, rep.Devices[0].Action)
	}
}

func TestCheckUpToDate(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	// Device floor is STRICTLY ABOVE packed(0.5.1) → the device would refuse
	// this release (packed < floor), so the broker must not stage it. (Floor
	// EQUAL to the release is installable on-device and is covered by
	// TestCheckStagesWhenReleaseAtFloor.)
	packed, _ := PackSemver("0.5.2")
	reg := newRegistryWithDevice(t, testDevice, "S1", packed)
	checker := NewChecker(cfg, reg, nil)

	rep, err := checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Staged != 0 || rep.Devices[0].Action != "up_to_date" {
		t.Fatalf("got staged=%d action=%s, want up_to_date", rep.Staged, rep.Devices[0].Action)
	}
}

// TestCheckStagesWhenReleaseAtFloor locks the floor-comparison fix: a release
// whose packed version EQUALS the device's anti-rollback floor is INSTALLABLE
// on-device (tmon_ota.c refuses only packed < floor), so the broker must mirror
// that with `<` and stage it — not treat floor==release as up_to_date. The
// real-world case is a dev canary: after the 24 h floor matures to base X.Y.Z,
// a newer X.Y.Z-dev.<ts> packs to the same base (== floor) and must still
// stage. Here we use a fresh device (no running version) at floor==release.
func TestCheckStagesWhenReleaseAtFloor(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	floor, _ := PackSemver("0.5.1") // floor EQUALS the release base
	reg := newRegistryWithDevice(t, testDevice, "S1", floor)
	checker := NewChecker(cfg, reg, nil)

	rep, err := checker.Check(context.Background(), true /*dryRun*/, "", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Devices[0].Action != "would_stage" {
		t.Fatalf("got action=%s, want would_stage (release packed == floor is installable)",
			rep.Devices[0].Action)
	}
}

// TestCheckNoStageWhenRunningEqualsRelease guards the anti-churn fix: a device
// whose RUNNING firmware (Active.FirmwareVersion) already equals the release
// must report up_to_date even when its anti-rollback FLOOR
// (Active.MinSecureVersion) sits a patch below that version — which is the
// normal case, since a manifest sets a conservative floor, not one equal to
// its own version. Comparing the release to the floor alone (the pre-fix
// behaviour) would re-stage 0.5.1 forever and the device would re-download
// and reject it every cycle.
func TestCheckNoStageWhenRunningEqualsRelease(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	// Floor is 0.5.0, one patch BELOW the release...
	floor, _ := PackSemver("0.5.0")
	reg := newRegistryWithDevice(t, testDevice, "S1", floor)
	// ...but the device is already running 0.5.1. Promote a 0.5.1 firmware
	// into Active so Active.FirmwareVersion == release without moving the
	// floor (mirrors a normal install: tmon_min_sv tracks the manifest's
	// conservative floor, not the running version).
	dev, err := reg.SetPending(testDevice, registry.ConfigPayload{
		FirmwareURL:     idx.BinURL,
		FirmwareSHA256:  "00",
		FirmwareVersion: "0.5.1",
	})
	if err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if _, err := reg.MaybePromote(testDevice, dev.Pending.Version, false); err != nil {
		t.Fatalf("MaybePromote: %v", err)
	}

	checker := NewChecker(cfg, reg, nil)
	rep, err := checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Staged != 0 || rep.Devices[0].Action != "up_to_date" {
		t.Fatalf("got staged=%d action=%s, want up_to_date (running==release, floor below)",
			rep.Staged, rep.Devices[0].Action)
	}
}

// TestCheckSkipsBlockedVersion locks the revert tombstone: when a device has
// BlockedFirmwareVersion set to the exact version of the newest release, the
// AUTO-discovery loop must NOT re-stage it (a canary that was just rolled back
// must stay rolled back). A NEWER release over a blocked one still stages.
func TestCheckSkipsBlockedVersion(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()
	cfg := otaConfigForVectors(t, v, srv.URL)

	// Fresh device (no running version), tombstone == the release version.
	reg := newRegistryWithDevice(t, testDevice, "S1", 0)
	if err := reg.SetBlockedFirmwareVersion(testDevice, "0.5.1"); err != nil {
		t.Fatalf("SetBlockedFirmwareVersion: %v", err)
	}
	checker := NewChecker(cfg, reg, nil)
	rep, err := checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Staged != 0 || rep.Devices[0].Action != "skipped:blocked-version" {
		t.Fatalf("blocked: got staged=%d action=%s, want skipped:blocked-version",
			rep.Staged, rep.Devices[0].Action)
	}
}

// TestCheckStagesNewerThanBlocked: the tombstone must match on version equality
// ONLY — a fixed release NEWER than the blocked version must still go out.
func TestCheckStagesNewerThanBlocked(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()
	cfg := otaConfigForVectors(t, v, srv.URL)

	reg := newRegistryWithDevice(t, testDevice, "S1", 0)
	// Block an OLDER version than the release — release 0.5.1 must still stage.
	if err := reg.SetBlockedFirmwareVersion(testDevice, "0.5.0"); err != nil {
		t.Fatalf("SetBlockedFirmwareVersion: %v", err)
	}
	checker := NewChecker(cfg, reg, nil)
	rep, err := checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Staged != 1 || rep.Devices[0].Action != "staged" {
		t.Fatalf("newer-than-blocked: got staged=%d action=%s, want 1 staged",
			rep.Staged, rep.Devices[0].Action)
	}
}

func TestCheckRejectsTamperedSignature(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	// Flip one base64 char in the signature so verify fails.
	bad := []byte(sigB64)
	if bad[0] == 'A' {
		bad[0] = 'B'
	} else {
		bad[0] = 'A'
	}
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: string(bad),
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	reg := newRegistryWithDevice(t, testDevice, "S1", 0)
	checker := NewChecker(cfg, reg, nil)

	rep, err := checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Staged != 0 {
		t.Fatalf("tampered signature must not stage, staged=%d", rep.Staged)
	}
	if len(rep.PerSKU) != 1 || rep.PerSKU[0].Verified || rep.PerSKU[0].Error == "" {
		t.Fatalf("expected unverified per-sku with error, got %+v", rep.PerSKU)
	}
	if rep.Devices[0].Action != "skipped:no-release" {
		t.Fatalf("device action = %s, want skipped:no-release", rep.Devices[0].Action)
	}
}

func TestCheckInertWhenUnconfigured(t *testing.T) {
	reg := newRegistryWithDevice(t, testDevice, "S1", 0)
	// Enabled but no keys → not Configured.
	cfg := &config.Config{OTA: config.OTAConfig{
		Enabled:      true,
		ReleasesRepo: "https://github.com/x/y",
	}}
	checker := NewChecker(cfg, reg, nil)
	rep, err := checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Configured || rep.Staged != 0 || rep.Note == "" {
		t.Fatalf("unconfigured check should be inert: %+v", rep)
	}
	if len(rep.Devices) != 0 {
		t.Fatalf("unconfigured check must not inspect devices: %+v", rep.Devices)
	}
}

// TestCheckDevUnitConsidersBothChannels verifies that a DEV-serial unit
// consumes BOTH stable and dev (CandidateChannels), and that when only the
// stable channel has a release (the dev asset 404s), the device still stages
// the stable build. Exercises the per-device multi-channel gather + bestChannel
// selection in the OTA loop.
func TestCheckDevUnitConsidersBothChannels(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	// Mock serves stable only; the dev asset is absent (404).
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	reg := newRegistryWithDevice(t, testDevice, "S1", 0)
	// Flip to a DEV serial so the unit tracks stable + dev.
	if err := reg.SetSerial(testDevice, "CWM-S1-DEV-2620-000001-0", "S1"); err != nil {
		t.Fatalf("SetSerial: %v", err)
	}
	checker := NewChecker(cfg, reg, nil)

	rep, err := checker.Check(context.Background(), true, "", "")
	if err != nil {
		t.Fatalf("dry-run Check: %v", err)
	}
	// Both channels were queried: a verified stable entry and a failed dev entry.
	var stableSeen, devSeen bool
	for _, s := range rep.PerSKU {
		switch s.Channel {
		case "stable":
			if !s.Verified || s.LatestVersion != "0.5.1" {
				t.Errorf("stable per-sku not verified at 0.5.1: %+v", s)
			}
			stableSeen = true
		case "dev":
			if s.Verified || s.Error == "" {
				t.Errorf("dev per-sku should have failed (no asset): %+v", s)
			}
			devSeen = true
		}
	}
	if !stableSeen || !devSeen {
		t.Fatalf("expected both stable and dev per-sku entries, got %+v", rep.PerSKU)
	}
	// Stable wins (dev absent): the device would stage 0.5.1 on the stable track.
	if len(rep.Devices) != 1 || rep.Devices[0].Action != "would_stage" {
		t.Fatalf("device result: %+v, want 1 would_stage", rep.Devices)
	}
	if rep.Devices[0].Channel != "stable" || rep.Devices[0].To != "0.5.1" {
		t.Errorf("device channel/to = %q/%q, want stable/0.5.1", rep.Devices[0].Channel, rep.Devices[0].To)
	}
}

// TestApiReleasesURL pins the repo-URL → GitHub-API mapping (and the
// test-server passthrough used by mockReleasesFull).
func TestApiReleasesURL(t *testing.T) {
	cases := []struct{ repo, want string }{
		{"https://github.com/fractal-manifold/tokenmonitor-ota-releases",
			"https://api.github.com/repos/fractal-manifold/tokenmonitor-ota-releases/releases?per_page=100"},
		{"https://github.com/fractal-manifold/tokenmonitor-ota-releases/",
			"https://api.github.com/repos/fractal-manifold/tokenmonitor-ota-releases/releases?per_page=100"},
		{"http://127.0.0.1:5000", "http://127.0.0.1:5000/releases?per_page=100"},
	}
	for _, c := range cases {
		if got := apiReleasesURL(c.repo); got != c.want {
			t.Errorf("apiReleasesURL(%q) = %q, want %q", c.repo, got, c.want)
		}
	}
}

// TestPickDevAsset exercises the newest-prerelease-with-asset selection: a
// newer -dev.<ts> wins; non-prerelease, plain-version and draft tags are
// ignored; and the choice is per-SKU (a release missing the SKU asset is
// skipped). It returns the release TAG (the caller builds the URL).
func TestPickDevAsset(t *testing.T) {
	a := func(sku string) ghAsset { return ghAsset{Name: "update-" + sku + ".json", URL: "u/" + sku} }
	rels := []ghRelease{
		// Newest first (as GitHub returns), but selection must not rely on order.
		{TagName: "v0.6.8-dev.202606022100", Prerelease: true, Assets: []ghAsset{a("S1")}},
		{TagName: "v0.9.0-dev.202609090000", Prerelease: true, Draft: true, Assets: []ghAsset{a("S1")}}, // draft → ignored
		{TagName: "v0.7.0", Prerelease: false, Assets: []ghAsset{a("S1")}},                              // not prerelease → ignored
		{TagName: "v0.6.8-dev.202606021930", Prerelease: true, Assets: []ghAsset{a("S1"), a("S2")}},
		{TagName: "v0.6.7", Prerelease: true, Assets: []ghAsset{a("S1")}}, // plain version → not a dev build → ignored
	}
	if ver, tag, ok := pickDevAsset(rels, "S1"); !ok || ver != "0.6.8-dev.202606022100" || tag != "v0.6.8-dev.202606022100" {
		t.Errorf("S1 pick = (%q,%q,%t), want newest dev ts (draft excluded)", ver, tag, ok)
	}
	// S2 only appears on the older dev release → that one is chosen for S2.
	if ver, tag, ok := pickDevAsset(rels, "S2"); !ok || ver != "0.6.8-dev.202606021930" || tag != "v0.6.8-dev.202606021930" {
		t.Errorf("S2 pick = (%q,%q,%t), want v0.6.8-dev.202606021930", ver, tag, ok)
	}
	// A SKU with no dev asset anywhere → not found.
	if _, _, ok := pickDevAsset(rels, "S9"); ok {
		t.Errorf("S9 should not be found")
	}
	if _, _, ok := pickDevAsset(nil, "S1"); ok {
		t.Errorf("empty listing should not be found")
	}
}

// devVector returns the named dev manifest vector (channel:"dev").
func devVector(t *testing.T, v compatVectors, name string) (canonical, sigB64 string) {
	t.Helper()
	for _, m := range v.Manifests {
		if m.Name == name {
			return m.CanonicalString, m.SignatureB64
		}
	}
	t.Fatalf("no manifest vector named %q", name)
	return "", ""
}

// devReleaseFixture is one immutable dev prerelease the mock advertises via
// the GitHub releases API, with its per-SKU index assets.
type devReleaseFixture struct {
	version string
	idx     map[string]Index
}

// mockReleasesFull serves the stable latest/download redirect AND the dev
// surface: the GitHub releases-list API at /releases plus each dev release's
// per-SKU asset at /releases/download/v<version>/update-<SKU>.json. Asset
// URLs are absolute and point back at this same server.
func mockReleasesFull(t *testing.T, stable map[string]Index, devs []devReleaseFixture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		base := "http://" + r.Host
		switch {
		case path == "/releases":
			out := make([]map[string]any, 0, len(devs))
			for _, d := range devs {
				assets := make([]map[string]string, 0, len(d.idx))
				for sku := range d.idx {
					assets = append(assets, map[string]string{
						"name":                 "update-" + sku + ".json",
						"browser_download_url": base + "/releases/download/v" + d.version + "/update-" + sku + ".json",
					})
				}
				out = append(out, map[string]any{
					"tag_name":   "v" + d.version,
					"prerelease": true,
					"assets":     assets,
				})
			}
			_ = json.NewEncoder(w).Encode(out)
		case strings.HasPrefix(path, "/releases/download/v") && strings.HasSuffix(path, ".json"):
			rest := strings.TrimPrefix(path, "/releases/download/v")
			slash := strings.Index(rest, "/")
			if slash < 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			version := rest[:slash]
			sku := strings.TrimSuffix(strings.TrimPrefix(rest[slash+1:], "update-"), ".json")
			for _, d := range devs {
				if d.version == version {
					if idx, ok := d.idx[sku]; ok {
						_ = json.NewEncoder(w).Encode(idx)
						return
					}
				}
			}
			w.WriteHeader(http.StatusNotFound)
		case strings.HasPrefix(path, "/releases/latest/download/update-") && strings.HasSuffix(path, ".json"):
			sku := strings.TrimSuffix(strings.TrimPrefix(path, "/releases/latest/download/update-"), ".json")
			if idx, ok := stable[sku]; ok {
				_ = json.NewEncoder(w).Encode(idx)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestCheckDevUnitStagesDevPrerelease drives the full dev path: a DEV unit,
// the API listing advertises an immutable vX.Y.Z-dev.<ts> prerelease, and the
// broker resolves + verifies its signed manifest and stages it on the dev
// channel.
func TestCheckDevUnitStagesDevPrerelease(t *testing.T) {
	v := loadVectors(t)
	const devVer = "0.6.8-dev.202606021930"
	canonical, sigB64 := devVector(t, v, "ota-S1-dev-v"+devVer)
	devIdx := Index{
		Version:      devVer,
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-" + devVer + ".bin",
	}
	srv := mockReleasesFull(t, nil, []devReleaseFixture{
		{version: devVer, idx: map[string]Index{"S1": devIdx}},
	})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	// The dev manifest is signed under key_id "ed25519-dev" (same test key).
	cfg.OTA.Keys = append(cfg.OTA.Keys, config.OTAKey{
		KeyID:     "ed25519-dev",
		PubkeyB64: cfg.OTA.Keys[0].PubkeyB64,
	})
	reg := newRegistryWithDevice(t, testDevice, "S1", 0)
	if err := reg.SetSerial(testDevice, "CWM-S1-DEV-2620-000001-0", "S1"); err != nil {
		t.Fatalf("SetSerial: %v", err)
	}
	checker := NewChecker(cfg, reg, nil)

	rep, err := checker.Check(context.Background(), true, "", "")
	if err != nil {
		t.Fatalf("dry-run Check: %v", err)
	}
	var devVerified bool
	for _, s := range rep.PerSKU {
		if s.Channel == "dev" {
			if !s.Verified || s.LatestVersion != devVer {
				t.Errorf("dev per-sku not verified at %s: %+v", devVer, s)
			}
			devVerified = true
		}
	}
	if !devVerified {
		t.Fatalf("expected a verified dev per-sku entry, got %+v", rep.PerSKU)
	}
	if len(rep.Devices) != 1 || rep.Devices[0].Action != "would_stage" ||
		rep.Devices[0].Channel != "dev" || rep.Devices[0].To != devVer {
		t.Fatalf("device result = %+v, want 1 would_stage dev %s", rep.Devices, devVer)
	}
}

// devSelectFixture mirrors compat/ota/dev_release_select.json — the shared
// contract for pickDevAsset. The releases use the real GitHub API field
// names, so they unmarshal straight into []ghRelease.
type devSelectFixture struct {
	Cases []struct {
		Name     string      `json:"name"`
		Releases []ghRelease `json:"releases"`
		Queries  []struct {
			SKU    string `json:"sku"`
			Expect *struct {
				Version string `json:"version"`
				Tag     string `json:"tag"`
			} `json:"expect"`
		} `json:"queries"`
	} `json:"cases"`
}

// TestDevReleaseSelectVectors drives pickDevAsset from the shared
// cross-runtime contract so Go, JS and Python pick the identical dev release.
func TestDevReleaseSelectVectors(t *testing.T) {
	raw, err := os.ReadFile(findCompatFile(t, "ota", "dev_release_select.json"))
	if err != nil {
		t.Fatalf("read dev_release_select.json: %v", err)
	}
	var fx devSelectFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse dev_release_select.json: %v", err)
	}
	if len(fx.Cases) == 0 {
		t.Fatal("fixture carries no cases")
	}
	for _, c := range fx.Cases {
		for _, q := range c.Queries {
			ver, tag, ok := pickDevAsset(c.Releases, q.SKU)
			if q.Expect == nil {
				if ok {
					t.Errorf("%s/%s: expected no pick, got (%q,%q)", c.Name, q.SKU, ver, tag)
				}
				continue
			}
			if !ok || ver != q.Expect.Version || tag != q.Expect.Tag {
				t.Errorf("%s/%s: pick = (%q,%q,%t), want (%q,%q)",
					c.Name, q.SKU, ver, tag, ok, q.Expect.Version, q.Expect.Tag)
			}
		}
	}
}

// simulateRollback replays what a device does with a staged pending it cannot
// boot: it applies the config (pending → active, which optimistically sets
// Active.FirmwareVersion to the staged version), downloads and installs the
// image, panics before self-confirming, and the bootloader rolls it back — so
// on the next sync it reports the OLD version again and the broker writes that
// back over Active.FirmwareVersion. That reversion is what re-opens decide()'s
// newer-than-running guard and drives the loop.
func simulateRollback(t *testing.T, reg *registry.Registry, deviceID, runningVersion string) {
	t.Helper()
	dev, err := reg.Load(deviceID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if dev.Pending == nil {
		t.Fatal("simulateRollback: no pending to consume")
	}
	promoted, err := reg.MaybePromote(deviceID, dev.Pending.Version, false)
	if err != nil || !promoted {
		t.Fatalf("MaybePromote: promoted=%v err=%v", promoted, err)
	}
	if err := reg.SetActiveFirmwareVersion(deviceID, runningVersion, nil); err != nil {
		t.Fatalf("SetActiveFirmwareVersion: %v", err)
	}
}

// A device that downloads a release, fails to boot it and rolls back gets
// exactly maxAutoStages attempts before the broker gives up and tombstones the
// version. Without the streak counter this loops forever, one full firmware
// download per cycle.
func TestCheckBlocksInstallLoop(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	reg := newRegistryWithDevice(t, testDevice, "S1", 0)
	if err := reg.SetActiveFirmwareVersion(testDevice, "0.5.0", nil); err != nil {
		t.Fatalf("seed running version: %v", err)
	}
	checker := NewChecker(cfg, reg, nil)

	for i := 1; i <= maxAutoStages; i++ {
		rep, err := checker.Check(context.Background(), false, "", "")
		if err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
		if rep.Devices[0].Action != "staged" {
			t.Fatalf("check %d: got %q, want staged", i, rep.Devices[0].Action)
		}
		simulateRollback(t, reg, testDevice, "0.5.0")
	}

	// The (maxAutoStages+1)-th visit is where the breaker fires: the device
	// consumed every pending and came back still running the old version.
	rep, err := checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("breaker check: %v", err)
	}
	if rep.Devices[0].Action != "skipped:install-loop" {
		t.Fatalf("got %q, want skipped:install-loop", rep.Devices[0].Action)
	}
	if rep.Staged != 0 {
		t.Fatalf("breaker staged %d, want 0", rep.Staged)
	}
	dev, err := reg.Load(testDevice)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if dev.BlockedFirmwareVersion != "0.5.1" {
		t.Fatalf("tombstone = %q, want 0.5.1", dev.BlockedFirmwareVersion)
	}
	if dev.Pending != nil {
		t.Fatalf("breaker must not leave a pending, got %+v", dev.Pending)
	}

	// And it stays blocked on subsequent polls, now via the persisted
	// tombstone rather than the in-memory streak — so a broker restart does
	// not resume the loop.
	rep, err = checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("post-block check: %v", err)
	}
	if rep.Devices[0].Action != "skipped:blocked-version" {
		t.Fatalf("got %q, want skipped:blocked-version", rep.Devices[0].Action)
	}
}

// The breaker must not fire on a device that simply takes its time: as long as
// each stage is a different version, or the device actually lands on one, the
// streak resets and staging continues normally.
func TestCheckStreakResetsOnSuccessfulInstall(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	reg := newRegistryWithDevice(t, testDevice, "S1", 0)
	if err := reg.SetActiveFirmwareVersion(testDevice, "0.5.0", nil); err != nil {
		t.Fatalf("seed running version: %v", err)
	}
	checker := NewChecker(cfg, reg, nil)

	// Two failed installs, then it boots: report the new version as running.
	for i := 0; i < 2; i++ {
		if _, err := checker.Check(context.Background(), false, "", ""); err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
		simulateRollback(t, reg, testDevice, "0.5.0")
	}
	if err := reg.SetActiveFirmwareVersion(testDevice, "0.5.1", nil); err != nil {
		t.Fatalf("report success: %v", err)
	}
	rep, err := checker.Check(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("post-success check: %v", err)
	}
	if rep.Devices[0].Action != "up_to_date" {
		t.Fatalf("got %q, want up_to_date", rep.Devices[0].Action)
	}
	if streak, ok := checker.streaks[testDevice]; ok {
		t.Fatalf("streak survived a successful install: %+v", streak)
	}
	if dev, _ := reg.Load(testDevice); dev.BlockedFirmwareVersion != "" {
		t.Fatalf("a device that installed the release must not be tombstoned, got %q",
			dev.BlockedFirmwareVersion)
	}
}

// A dry run answers a question; it never causes a download, so it must never
// advance the streak toward the breaker.
func TestCheckDryRunDoesNotAdvanceStreak(t *testing.T) {
	v := loadVectors(t)
	canonical, sigB64 := s1Vector(t, v)
	idx := Index{
		Version:      "0.5.1",
		ManifestB64:  base64.StdEncoding.EncodeToString([]byte(canonical)),
		SignatureB64: sigB64,
		BinURL:       "https://downloads.example/tmon-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	reg := newRegistryWithDevice(t, testDevice, "S1", 0)
	checker := NewChecker(cfg, reg, nil)

	for i := 0; i < maxAutoStages*3; i++ {
		rep, err := checker.Check(context.Background(), true, "", "")
		if err != nil {
			t.Fatalf("dry check %d: %v", i, err)
		}
		if rep.Devices[0].Action != "would_stage" {
			t.Fatalf("dry check %d: got %q, want would_stage", i, rep.Devices[0].Action)
		}
	}
	if len(checker.streaks) != 0 {
		t.Fatalf("dry runs recorded streaks: %+v", checker.streaks)
	}
	if dev, _ := reg.Load(testDevice); dev.BlockedFirmwareVersion != "" {
		t.Fatalf("dry runs wrote a tombstone: %q", dev.BlockedFirmwareVersion)
	}
}
