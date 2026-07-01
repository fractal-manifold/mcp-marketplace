package broker

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/state"
)

const syncTestID = "ab12cd34"

// TestPendingPayloadJSON_VolOmittedWhenNil pins the wire contract: a nil Vol
// (never set) must NOT emit a "vol" key, so a device is never silently muted;
// an explicit Vol=0 (mute) must emit "vol":0.
func TestPendingPayloadJSON_VolOmittedWhenNil(t *testing.T) {
	u8 := func(v uint8) *uint8 { return &v }

	nilJSON, err := pendingPayloadJSON(registry.ConfigPayload{Version: 8, City: "Barcelona"})
	if err != nil {
		t.Fatalf("pendingPayloadJSON (nil vol): %v", err)
	}
	var nilMap map[string]any
	if err := json.Unmarshal(nilJSON, &nilMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := nilMap["vol"]; ok {
		t.Fatalf("nil Vol must omit the vol key, got %s", nilJSON)
	}

	zeroJSON, err := pendingPayloadJSON(registry.ConfigPayload{Version: 8, Vol: u8(0)})
	if err != nil {
		t.Fatalf("pendingPayloadJSON (vol=0): %v", err)
	}
	var zeroMap map[string]any
	if err := json.Unmarshal(zeroJSON, &zeroMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := zeroMap["vol"]; !ok || v.(float64) != 0 {
		t.Fatalf("explicit Vol=0 must emit vol:0, got %s", zeroJSON)
	}
}

func mustHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

func newDeviceSyncServer(t *testing.T) (*httptest.Server, *registry.Registry) {
	t.Helper()
	cfg := newTestConfig(t, writeCredsFile(t, time.Now().Add(time.Hour).UnixMilli()))
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	logger := log.New(io.Discard, "", 0)
	reg, err := registry.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(NewMux(cfg, cache, state.New(), logger, nil, reg, nil, nil))
	t.Cleanup(ts.Close)
	return ts, reg
}

func signedSyncRequest(t *testing.T, ts *httptest.Server, psk []byte, deviceID string, version uint32) *http.Response {
	t.Helper()
	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := mustHex(t, 16) // 32 hex chars
	path := "/device/" + deviceID + "/sync"
	versionStr := strconv.FormatUint(uint64(version), 10)
	sig := auth.ComputeSignature(psk, "GET", path, now, nonce, deviceID, versionStr)

	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("X-Tmon-Timestamp", now)
	req.Header.Set("X-Tmon-Nonce", nonce)
	req.Header.Set("X-Tmon-Signature", sig)
	req.Header.Set("X-Tmon-Device", deviceID)
	req.Header.Set("X-Tmon-Config-Version", versionStr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func mustDecode(t *testing.T, b64 string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDeviceSync_NoPending_ReturnsActiveVersionOnly(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	if _, err := reg.Register(syncTestID, registry.ConfigPayload{
		PSKHex: activePSK, BrokerURL: "http://x",
	}); err != nil {
		t.Fatal(err)
	}
	pskBytes, _ := hex.DecodeString(activePSK)
	resp := signedSyncRequest(t, ts, pskBytes, syncTestID, 1)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var r syncResponse
	json.NewDecoder(resp.Body).Decode(&r)
	if r.ActiveVersion != 1 || r.Pending != nil {
		t.Errorf("response = %+v, want {ActiveVersion:1, Pending:nil}", r)
	}
}

func TestDeviceSync_PendingDelivered_DecryptsWithActivePSK(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	newPSK := mustHex(t, 32)
	if _, err := reg.Register(syncTestID, registry.ConfigPayload{
		PSKHex: activePSK, BrokerURL: "http://x",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.SetPending(syncTestID, registry.ConfigPayload{
		PSKHex: newPSK, City: "Tokyo",
	}); err != nil {
		t.Fatal(err)
	}

	activeBytes, _ := hex.DecodeString(activePSK)
	resp := signedSyncRequest(t, ts, activeBytes, syncTestID, 1)
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
	if r.Pending.Version != 2 {
		t.Errorf("pending version = %d, want 2", r.Pending.Version)
	}

	nonce := mustDecode(t, r.Pending.NonceB64)
	ct := mustDecode(t, r.Pending.PayloadB64)
	pt, err := registry.DecryptPending(activeBytes, nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(pt, &payload); err != nil {
		t.Fatalf("payload decrypt produced invalid JSON: %v\n%s", err, pt)
	}
	if payload["city"] != "Tokyo" {
		t.Errorf("payload city = %v, want Tokyo", payload["city"])
	}
	if payload["psk_hex"] != newPSK {
		t.Errorf("payload psk_hex = %v, want %s", payload["psk_hex"], newPSK)
	}
}

// newDeviceSyncServerWithState is like newDeviceSyncServer but hands back the
// *state.State so a test can seed the broker self-version verdict.
func newDeviceSyncServerWithState(t *testing.T) (*httptest.Server, *registry.Registry, *state.State) {
	t.Helper()
	cfg := newTestConfig(t, writeCredsFile(t, time.Now().Add(time.Hour).UnixMilli()))
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	logger := log.New(io.Discard, "", 0)
	reg, err := registry.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := state.New()
	ts := httptest.NewServer(NewMux(cfg, cache, st, logger, nil, reg, nil, nil))
	t.Cleanup(ts.Close)
	return ts, reg, st
}

func TestDeviceSync_BrokerUpdateFields_PresentWhenKnown(t *testing.T) {
	ts, reg, st := newDeviceSyncServerWithState(t)
	st.SetUpdate(state.UpdateInfo{Known: true, Outdated: true, Current: "0.9.2", Latest: "0.9.4"})
	activePSK := mustHex(t, 32)
	if _, err := reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x"}); err != nil {
		t.Fatal(err)
	}
	pskBytes, _ := hex.DecodeString(activePSK)
	resp := signedSyncRequest(t, ts, pskBytes, syncTestID, 1)
	defer resp.Body.Close()
	var r syncResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	if r.BrokerUpdateAvailable == nil || !*r.BrokerUpdateAvailable {
		t.Errorf("broker_update_available = %v, want true", r.BrokerUpdateAvailable)
	}
	if r.BrokerVersion != "0.9.2" || r.BrokerLatest != "0.9.4" {
		t.Errorf("broker version/latest = %q/%q, want 0.9.2/0.9.4", r.BrokerVersion, r.BrokerLatest)
	}
}

func TestDeviceSync_BrokerUpdateFields_AbsentWhenUnknown(t *testing.T) {
	ts, reg, _ := newDeviceSyncServerWithState(t) // verdict left unknown
	activePSK := mustHex(t, 32)
	if _, err := reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x"}); err != nil {
		t.Fatal(err)
	}
	pskBytes, _ := hex.DecodeString(activePSK)
	resp := signedSyncRequest(t, ts, pskBytes, syncTestID, 1)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// Raw-body check: the fields must be entirely absent (omitempty), not just
	// zero-valued, so an old-firmware/JSON-strict device never misreads them.
	for _, key := range []string{"broker_update_available", "broker_version", "broker_latest"} {
		if strings.Contains(string(body), key) {
			t.Errorf("unknown verdict leaked %q into /sync body: %s", key, body)
		}
	}
}

func TestDeviceSync_PromotesOnPendingPSKAndMatchingVersion(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	newPSK := mustHex(t, 32)
	reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x"})
	reg.SetPending(syncTestID, registry.ConfigPayload{PSKHex: newPSK, City: "Tokyo"})

	newBytes, _ := hex.DecodeString(newPSK)
	// Device signs with the NEW key and reports version 2 → promote.
	resp := signedSyncRequest(t, ts, newBytes, syncTestID, 2)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var r syncResponse
	json.NewDecoder(resp.Body).Decode(&r)
	if r.ActiveVersion != 2 || r.Pending != nil {
		t.Errorf("after promote: %+v want active=2, no pending", r)
	}
	dev, err := reg.Load(syncTestID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Active.PSKHex != newPSK || dev.Active.City != "Tokyo" {
		t.Errorf("active not updated: %+v", dev.Active)
	}
}

func TestDeviceSync_RejectsUnknownDevice(t *testing.T) {
	ts, _ := newDeviceSyncServer(t)
	resp := signedSyncRequest(t, ts, make([]byte, 32), "ff000000", 0)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestDeviceSync_RejectsBadDeviceID(t *testing.T) {
	ts, _ := newDeviceSyncServer(t)
	// Path-level: doesn't match the 8-hex shape.
	resp := signedSyncRequest(t, ts, make([]byte, 32), "ZZZZZZZZ", 0)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestDeviceSync_WrongPSKReturns401(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x"})

	resp := signedSyncRequest(t, ts, []byte("wrong-32-bytes-key-padding-zzzzz"), syncTestID, 1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestCredentials_PerDeviceLookup(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x"})
	pskBytes, _ := hex.DecodeString(activePSK)

	// Signed /credentials with X-Tmon-Device should succeed even though
	// the device PSK differs from the global cfg.PSK().
	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := mustHex(t, 16)
	sig := auth.ComputeSignature(pskBytes, "GET", "/credentials", now, nonce, syncTestID, "1")

	req, _ := http.NewRequest("GET", ts.URL+"/credentials", nil)
	req.Header.Set("X-Tmon-Timestamp", now)
	req.Header.Set("X-Tmon-Nonce", nonce)
	req.Header.Set("X-Tmon-Signature", sig)
	req.Header.Set("X-Tmon-Device", syncTestID)
	req.Header.Set("X-Tmon-Config-Version", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200 (per-device lookup should accept device PSK)", resp.StatusCode)
	}
}
