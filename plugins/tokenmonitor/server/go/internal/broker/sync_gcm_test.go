package broker

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/usage"
)

// signedSyncRequestFW is signedSyncRequest with an X-Tmon-Fw-Version header,
// to drive the AES-GCM gate and the firmware-version persistence path.
func signedSyncRequestFW(t *testing.T, ts *httptest.Server, psk []byte, deviceID string, version uint32, fw string) *http.Response {
	t.Helper()
	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := mustHex(t, 16)
	path := "/device/" + deviceID + "/sync"
	versionStr := strconv.FormatUint(uint64(version), 10)
	sig := auth.ComputeSignature(psk, "GET", path, now, nonce, deviceID, versionStr)

	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("X-Tmon-Timestamp", now)
	req.Header.Set("X-Tmon-Nonce", nonce)
	req.Header.Set("X-Tmon-Signature", sig)
	req.Header.Set("X-Tmon-Device", deviceID)
	req.Header.Set("X-Tmon-Config-Version", versionStr)
	if fw != "" {
		req.Header.Set("X-Tmon-Fw-Version", fw)
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
		{"0.8.1", true},
		{"0.8.99", true},
		{"0.9.0", true},
		{"0.9.1", true},
		{"1.0.0", true},
		{"0.10.0", true},
		{"255.255.65535", true},
		// Suffix of the floor still counts (same source tree).
		{"0.8.1-dev.202606091938", true},
		{"0.8.1-rc1", true},
		// Below the floor → CTR.
		{"0.8.0", false},
		{"0.7.99", false},
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
	resp := signedSyncRequestFW(t, ts, pskBytes, syncTestID, 1, "0.8.0")
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

// TestDeviceSync_PersistsFwVersionOnChange: the reported X-Tmon-Fw-Version
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

// signedSyncRequestOTAFail is signedSyncRequestFW plus the X-Tmon-Ota-Fail
// header, which carries the device's own verdict on an image it installed but
// could not boot.
func signedSyncRequestOTAFail(t *testing.T, ts *httptest.Server, psk []byte, deviceID, fw, otaFail string) *http.Response {
	t.Helper()
	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := mustHex(t, 16)
	path := "/device/" + deviceID + "/sync"
	sig := auth.ComputeSignature(psk, "GET", path, now, nonce, deviceID, "0")

	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("X-Tmon-Timestamp", now)
	req.Header.Set("X-Tmon-Nonce", nonce)
	req.Header.Set("X-Tmon-Signature", sig)
	req.Header.Set("X-Tmon-Device", deviceID)
	req.Header.Set("X-Tmon-Config-Version", "0")
	if fw != "" {
		req.Header.Set("X-Tmon-Fw-Version", fw)
	}
	if otaFail != "" {
		req.Header.Set("X-Tmon-Ota-Fail", otaFail)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestParseOTAFail pins the header grammar. Everything that is not an
// unambiguous report of a definitively-failed install must return nil: this
// value is unsigned, so it fails closed by construction.
func TestParseOTAFail(t *testing.T) {
	cases := []struct {
		in       string
		want     bool
		version  string
		installs int
		why      string
	}{
		{in: "0.10.5:2:panic", want: true, version: "0.10.5", installs: 2, why: "the canonical report"},
		{in: "0.10.5:3:wdt", want: true, version: "0.10.5", installs: 3, why: "any count at or above the threshold"},
		{in: " 0.10.5:2:panic ", want: true, version: "0.10.5", installs: 2, why: "surrounding whitespace is tolerated"},
		{in: "0.10.5-dev.202607181200:2:panic", want: true, version: "0.10.5-dev.202607181200", installs: 2, why: "dev prereleases are real versions"},

		{in: "", why: "absent header"},
		{in: "none", why: "the firmware's explicit no-failure sentinel"},
		{in: "0.10.5:1:panic", why: "one failure may be a brownout; two is evidence"},
		{in: "0.10.5:0:panic", why: "zero failures"},
		{in: "0.10.5:2:pending", why: "still in flight — the install may yet succeed"},
		{in: "0.10.5:2:", why: "empty state"},
		{in: "0.10.5:2", why: "too few fields"},
		{in: "0.10.5:2:panic:extra", why: "too many fields"},
		{in: "garbage:2:panic", why: "an unparseable version would poison the tombstone forever"},
		{in: "0.10:2:panic", why: "not MAJOR.MINOR.PATCH"},
		{in: "0.10.5:two:panic", why: "non-numeric count"},
		{in: "0.10.5:-3:panic", why: "negative count"},
		{in: strings.Repeat("9", 100) + ":2:panic", why: "over the length cap"},
	}
	for _, c := range cases {
		got := parseOTAFail(c.in)
		if c.want {
			if got == nil {
				t.Errorf("parseOTAFail(%q) = nil, want a report (%s)", c.in, c.why)
				continue
			}
			if got.version != c.version || got.installs != c.installs {
				t.Errorf("parseOTAFail(%q) = %+v, want version=%s installs=%d",
					c.in, *got, c.version, c.installs)
			}
			continue
		}
		if got != nil {
			t.Errorf("parseOTAFail(%q) = %+v, want nil (%s)", c.in, *got, c.why)
		}
	}
}

// A device reporting that it failed to install a version twice gets that
// version tombstoned, so auto-discovery stops offering it. This is the
// device-driven half of the install-loop breaker.
func TestDeviceSync_BlocksVersionOnReportedInstallFailure(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x"})
	pskBytes, _ := hex.DecodeString(activePSK)

	resp := signedSyncRequestOTAFail(t, ts, pskBytes, syncTestID, "0.10.3", "0.10.5:2:panic")
	resp.Body.Close()

	dev, _ := reg.Load(syncTestID)
	if dev.BlockedFirmwareVersion != "0.10.5" {
		t.Fatalf("tombstone = %q, want 0.10.5", dev.BlockedFirmwareVersion)
	}
}

// The reports that must NOT block: still-pending installs, a count below the
// threshold, garbage, and — importantly — a device reporting a failure for the
// version it is now actually running, which means it recovered.
func TestDeviceSync_DoesNotBlockOnWeakOTAFailReports(t *testing.T) {
	cases := []struct {
		name, fw, otaFail string
	}{
		{"still pending", "0.10.3", "0.10.5:2:pending"},
		{"below hard threshold", "0.10.3", "0.10.5:1:panic"},
		// The soft states take minFailedInstallsSoft. Tombstoning these at 2
		// would silently shorten the DEVICE's own 4-attempt budget.
		{"brownout below soft threshold", "0.10.3", "0.10.5:2:brownout"},
		{"noconfirm below soft threshold", "0.10.3", "0.10.5:3:noconfirm"},
		{"unknown below soft threshold", "0.10.3", "0.10.5:3:unknown"},
		{"unrecognised state gets the soft threshold", "0.10.3", "0.10.5:2:someday"},
		// installs is 0..255 on-device; anything else is not a record we wrote.
		{"count above the firmware range", "0.10.3", "0.10.5:256:panic"},
		{"malformed", "0.10.3", "not-a-version:5:panic"},
		{"sentinel", "0.10.3", "none"},
		{"absent", "0.10.3", ""},
		{"empty state", "0.10.3", "0.10.5:4:"},
		{"wrong field count", "0.10.3", "0.10.5:4"},
		{"extra field", "0.10.3", "0.10.5:2:panic:extra"},
		// Count-parsing cases that a laxer runtime would accept: Python's
		// int() takes "1_0" and padded values, JS parseInt takes "2abc" and
		// Number() takes "0x2". All three parsers reject them, and these
		// cases exist in the py/js suites too so the agreement is enforced
		// from both ends rather than assumed.
		{"underscored count", "0.10.3", "0.10.5:1_0:panic"},
		{"trailing garbage in count", "0.10.3", "0.10.5:2abc:panic"},
		{"padded count", "0.10.3", "0.10.5: 2 :panic"},
		{"hex count", "0.10.3", "0.10.5:0x2:panic"},
		// The stale-record case: the device eventually booted the version it
		// once failed on, so the record describes history, not a live problem.
		{"failure names the running version", "0.10.5", "0.10.5:2:panic"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts, reg := newDeviceSyncServer(t)
			activePSK := mustHex(t, 32)
			reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x"})
			pskBytes, _ := hex.DecodeString(activePSK)

			resp := signedSyncRequestOTAFail(t, ts, pskBytes, syncTestID, c.fw, c.otaFail)
			resp.Body.Close()

			dev, _ := reg.Load(syncTestID)
			if dev.BlockedFirmwareVersion != "" {
				t.Fatalf("tombstoned %q on a report that proves nothing", dev.BlockedFirmwareVersion)
			}
		})
	}
}
