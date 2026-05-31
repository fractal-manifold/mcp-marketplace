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

	"github.com/fractal-manifold/cwm-mcp/internal/config"
	"github.com/fractal-manifold/cwm-mcp/internal/registry"
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
// cwallmonitor plugin, so the monorepo root is several levels up; the server
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
	if err := reg.SetSerial(deviceID, "CWM-S1-DEV-2620-000001-0", sku); err != nil {
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
		BinURL:       "https://downloads.example/cwm-S1-0.5.1.bin",
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
		BinURL:       "https://downloads.example/cwm-S1-0.5.1.bin",
	}
	srv := mockReleases(t, map[string]Index{"S1": idx})
	defer srv.Close()

	cfg := otaConfigForVectors(t, v, srv.URL)
	// Device already at or above packed(0.5.1) → no staging.
	packed, _ := PackSemver("0.5.1")
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
		BinURL:       "https://downloads.example/cwm-S1-0.5.1.bin",
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
