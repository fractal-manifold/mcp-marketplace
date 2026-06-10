package broker

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/fractal-manifold/cwm-mcp/internal/auth"
	"github.com/fractal-manifold/cwm-mcp/internal/registry"
	"github.com/fractal-manifold/cwm-mcp/internal/usage"
)

// signedSyncRequestFW is signedSyncRequest with an X-Cwm-Fw-Version header,
// to drive the AES-GCM gate and the firmware-version persistence path.
func signedSyncRequestFW(t *testing.T, ts *httptest.Server, psk []byte, deviceID string, version uint32, fw string) *http.Response {
	t.Helper()
	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := mustHex(t, 16)
	path := "/device/" + deviceID + "/sync"
	versionStr := strconv.FormatUint(uint64(version), 10)
	sig := auth.ComputeSignature(psk, "GET", path, now, nonce, deviceID, versionStr)

	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("X-Cwm-Timestamp", now)
	req.Header.Set("X-Cwm-Nonce", nonce)
	req.Header.Set("X-Cwm-Signature", sig)
	req.Header.Set("X-Cwm-Device", deviceID)
	req.Header.Set("X-Cwm-Config-Version", versionStr)
	if fw != "" {
		req.Header.Set("X-Cwm-Fw-Version", fw)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestFwSupportsGCM_GateComparator pins the numeric maj.min.patch prefix
// comparison: pre-0.9.0 / absent / garbage → CTR (false); >=0.9.0,
// including a -dev.* prerelease that carries the same decrypt code → GCM.
func TestFwSupportsGCM_GateComparator(t *testing.T) {
	// Cross-impl edge-case table. MUST stay byte-identical to GCM_GATE_CASES
	// (js test/crypto.test.js) and test_gcm_fw_gate_comparator (py) so the
	// three brokers never diverge on which firmware gets GCM vs CTR. Rule is
	// strict ota.PackSemver: exactly MAJOR.MINOR.PATCH numeric (no leading
	// zeros, in range), optional "-suffix" ignored; anything else → CTR.
	cases := []struct {
		fw   string
		want bool
	}{
		// At/above the floor → GCM.
		{"0.9.0", true},
		{"0.9.1", true},
		{"1.0.0", true},
		{"0.10.0", true},
		{"255.255.65535", true},
		// Suffix of the floor still counts (same source tree).
		{"0.9.0-dev.202606091938", true},
		{"0.9.0-rc1", true},
		// Below the floor → CTR.
		{"0.8.0", false},
		{"0.8.99", false},
		{"0.8.0-dev.1", false},
		{"0.0.0", false},
		// Loose forms go/py REJECT (js used to accept these) → CTR.
		{"0.9", false},             // too few components
		{"v0.9.0", false},          // leading "v" not stripped
		{"0.9.0+build", false},     // "+build" not stripped (split on "-" only)
		{"00.9.0", false},          // leading zero
		{"0.09.0", false},          // leading zero
		{"0.9junk.0", false},       // non-digit component
		{"256.0.0", false},         // major out of 8-bit range
		{"0.0.65536", false},       // patch out of 16-bit range
		{"999999999999.0.0", false}, // huge component
		{"0.9.0.0", false},         // too many components
		// Absent / unparseable → CTR.
		{"", false},
		{"garbage", false},
		{"not.a.version", false},
	}
	for _, c := range cases {
		if got := fwSupportsGCM(c.fw); got != c.want {
			t.Errorf("fwSupportsGCM(%q) = %v, want %v", c.fw, got, c.want)
		}
	}
}

// TestDeviceSync_LegacyFwGetsCTR: a device below the GCM floor receives the
// legacy 16-byte-IV CTR blob with no "enc" field, still decryptable.
func TestDeviceSync_LegacyFwGetsCTR(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x", City: "Madrid"})
	reg.SetPending(syncTestID, registry.ConfigPayload{City: "Paris"})

	pskBytes, _ := hex.DecodeString(activePSK)
	resp := signedSyncRequestFW(t, ts, pskBytes, syncTestID, 1, "0.8.5")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var r syncResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	if r.Pending == nil {
		t.Fatal("pending nil")
	}
	if r.Pending.Enc != "" {
		t.Errorf("enc = %q, want empty (CTR)", r.Pending.Enc)
	}
	nonce := mustDecode(t, r.Pending.NonceB64)
	if len(nonce) != registry.PendingNonceLen {
		t.Errorf("nonce length = %d, want %d (CTR IV)", len(nonce), registry.PendingNonceLen)
	}
	ct := mustDecode(t, r.Pending.PayloadB64)
	pt, err := registry.DecryptPending(pskBytes, nonce, ct)
	if err != nil {
		t.Fatalf("decrypt CTR: %v", err)
	}
	var payload map[string]any
	json.Unmarshal(pt, &payload)
	if payload["city"] != "Paris" {
		t.Errorf("city = %v, want Paris", payload["city"])
	}
}

// TestDeviceSync_GCMFwGetsGCM: a device at/above the floor (here a dev
// prerelease) receives enc="gcm" with a 12-byte nonce, decryptable only
// with the matching version AAD.
func TestDeviceSync_GCMFwGetsGCM(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x", City: "Madrid"})
	reg.SetPending(syncTestID, registry.ConfigPayload{City: "Paris"})

	pskBytes, _ := hex.DecodeString(activePSK)
	resp := signedSyncRequestFW(t, ts, pskBytes, syncTestID, 1, "0.9.0-dev.202606")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var r syncResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	if r.Pending == nil {
		t.Fatal("pending nil")
	}
	if r.Pending.Enc != "gcm" {
		t.Errorf("enc = %q, want gcm", r.Pending.Enc)
	}
	nonce := mustDecode(t, r.Pending.NonceB64)
	if len(nonce) != registry.PendingGCMNonceLen {
		t.Errorf("nonce length = %d, want %d (GCM)", len(nonce), registry.PendingGCMNonceLen)
	}
	ct := mustDecode(t, r.Pending.PayloadB64)
	pt, err := registry.DecryptPendingGCM(pskBytes, r.Pending.Version, nonce, ct)
	if err != nil {
		t.Fatalf("decrypt GCM: %v", err)
	}
	var payload map[string]any
	json.Unmarshal(pt, &payload)
	if payload["city"] != "Paris" {
		t.Errorf("city = %v, want Paris", payload["city"])
	}
	// Wrong AAD (version) must fail — bound to pending.version.
	if _, err := registry.DecryptPendingGCM(pskBytes, r.Pending.Version+1, nonce, ct); err == nil {
		t.Error("decrypt with wrong version (AAD) succeeded")
	}
}

// TestDeviceSync_PersistsFwVersionOnChange: the reported X-Cwm-Fw-Version
// lands in Active.FirmwareVersion, only updates on change, and a revert to
// an older string is recorded (so OTA auto-discovery stops re-staging the
// release the device just rolled back from).
func TestDeviceSync_PersistsFwVersionOnChange(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x"})
	pskBytes, _ := hex.DecodeString(activePSK)

	// First sync reports 0.9.0 → persisted.
	resp := signedSyncRequestFW(t, ts, pskBytes, syncTestID, 0, "0.9.0")
	resp.Body.Close()
	dev, _ := reg.Load(syncTestID)
	if dev.Active.FirmwareVersion != "0.9.0" {
		t.Fatalf("active fw = %q, want 0.9.0", dev.Active.FirmwareVersion)
	}

	// No-change sync stays 0.9.0 and doesn't error.
	resp = signedSyncRequestFW(t, ts, pskBytes, syncTestID, 0, "0.9.0")
	if resp.StatusCode != 200 {
		t.Fatalf("no-change status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	dev, _ = reg.Load(syncTestID)
	if dev.Active.FirmwareVersion != "0.9.0" {
		t.Fatalf("after no-change active fw = %q, want 0.9.0", dev.Active.FirmwareVersion)
	}

	// A canary revert to an older version is recorded.
	resp = signedSyncRequestFW(t, ts, pskBytes, syncTestID, 0, "0.8.5")
	resp.Body.Close()
	dev, _ = reg.Load(syncTestID)
	if dev.Active.FirmwareVersion != "0.8.5" {
		t.Fatalf("after revert active fw = %q, want 0.8.5", dev.Active.FirmwareVersion)
	}
}

// TestDeviceSync_ClearsBlockedVersionWhenNewer: a revert tombstone is cleared
// once the device reports a version STRICTLY NEWER than the blocked one (a
// fixed release landed). A report <= the tombstone leaves it in place.
func TestDeviceSync_ClearsBlockedVersionWhenNewer(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x"})
	pskBytes, _ := hex.DecodeString(activePSK)

	if err := reg.SetBlockedFirmwareVersion(syncTestID, "0.9.1"); err != nil {
		t.Fatalf("SetBlockedFirmwareVersion: %v", err)
	}

	// Device still on the blocked version → tombstone stays.
	resp := signedSyncRequestFW(t, ts, pskBytes, syncTestID, 0, "0.9.1")
	resp.Body.Close()
	dev, _ := reg.Load(syncTestID)
	if dev.BlockedFirmwareVersion != "0.9.1" {
		t.Fatalf("tombstone = %q, want 0.9.1 (report == blocked must not clear)", dev.BlockedFirmwareVersion)
	}

	// Device reaches a newer version (the fix) → tombstone cleared.
	resp = signedSyncRequestFW(t, ts, pskBytes, syncTestID, 0, "0.9.2")
	resp.Body.Close()
	dev, _ = reg.Load(syncTestID)
	if dev.BlockedFirmwareVersion != "" {
		t.Fatalf("tombstone = %q, want cleared after newer report", dev.BlockedFirmwareVersion)
	}
}

// TestWriteUsageError_RetryAfterHeader: a *usage.RateLimitedError carries
// its Retry-After hint into the 429 response header (rounded up to whole
// seconds, min 1); other errors set no Retry-After.
func TestWriteUsageError_RetryAfterHeader(t *testing.T) {
	t.Run("rate-limited sets header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		writeUsageError(rec, &usage.RateLimitedError{RetryAfter: 42 * time.Second})
		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("status = %d, want 429", rec.Code)
		}
		if got := rec.Header().Get("Retry-After"); got != "42" {
			t.Errorf("Retry-After = %q, want 42", got)
		}
	})
	t.Run("sub-second hint clamps to 1", func(t *testing.T) {
		rec := httptest.NewRecorder()
		writeUsageError(rec, &usage.RateLimitedError{RetryAfter: 200 * time.Millisecond})
		if got := rec.Header().Get("Retry-After"); got != "1" {
			t.Errorf("Retry-After = %q, want 1", got)
		}
	})
	t.Run("zero hint sets no header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		writeUsageError(rec, &usage.RateLimitedError{RetryAfter: 0})
		if got := rec.Header().Get("Retry-After"); got != "" {
			t.Errorf("Retry-After = %q, want empty", got)
		}
	})
	t.Run("non-rate-limit error sets no header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		writeUsageError(rec, usage.ErrCredsMissing)
		if got := rec.Header().Get("Retry-After"); got != "" {
			t.Errorf("Retry-After = %q, want empty for non-429", got)
		}
	})
}

// TestSnapshotSlots_AlwaysArray: a nil Slots slice marshals to "slots":[]
// (never null, never omitted) — byte parity with the py/js brokers.
func TestSnapshotSlots_AlwaysArray(t *testing.T) {
	blob, err := json.Marshal(usage.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}
	raw, ok := m["slots"]
	if !ok {
		t.Fatalf("slots field omitted from %s", blob)
	}
	if string(raw) != "[]" {
		t.Errorf("slots = %s, want []", raw)
	}
}
