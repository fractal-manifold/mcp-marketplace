package broker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Size coverage for /device/{id}/settings (compat/SETTINGS_REPORT.md §body cap).
//
// This cap had NO test in any of the three runtimes, and the value it carried —
// 512 bytes — was under the size of a perfectly ordinary report. A device that
// remembered ~7 networks had every report rejected, and because the firmware's
// dirty flag only clears on a 2xx, the rejection permanently vetoed every
// broker-pushed display setting. TestDeviceSettings_FullReportWithEightNetworks
// is the regression that would have caught it.

// fullReportBody renders a settings report shaped exactly like the firmware's
// (config_sync.c: the flat device-owned fields plus wifi_known), with n
// remembered networks whose SSIDs are ssidLen characters long.
func fullReportBody(t *testing.T, n, ssidLen int) []byte {
	t.Helper()
	type net struct {
		SSID     string `json:"ssid"`
		Verified bool   `json:"verified"`
		Open     bool   `json:"open"`
	}
	nets := make([]net, 0, n)
	for i := 0; i < n; i++ {
		// Distinct SSIDs of the requested length; 32 is the 802.11 maximum.
		s := fmt.Sprintf("%02d", i) + strings.Repeat("w", ssidLen-2)
		nets = append(nets, net{SSID: s, Verified: i%2 == 0, Open: i%3 == 0})
	}
	body := map[string]any{
		"theme_mode":            "night",
		"br_day":                100,
		"br_night":              30,
		"vol":                   80,
		"autorotate_enabled":    true,
		"autorotate_interval_s": 30,
		"pet_enabled":           true,
		"panel_enabled":         true,
		"pet_species":           2,
		"pet_name":              "Mochi",
		"wifi_known":            nets,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The regression. Eight networks is what the store holds (TMON_WIFI_MAX_NETS)
// and 32 characters is the longest SSID 802.11 allows, so this is the largest
// report real firmware can produce from real inputs — it must be accepted, and
// the fields in it must actually land in the registry.
func TestDeviceSettings_FullReportWithEightNetworks(t *testing.T) {
	ts, reg, psk := newBodyDigestServer(t)
	body := fullReportBody(t, 8, 32)
	if len(body) <= 512 {
		t.Fatalf("test body is %d bytes — it no longer exercises the old cap", len(body))
	}
	resp := signedBodyPost(t, ts, psk, "/device/"+syncTestID+"/settings", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body %d bytes)", resp.StatusCode, len(body))
	}
	dev, err := reg.Load(syncTestID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Active.Vol == nil || *dev.Active.Vol != 80 {
		t.Errorf("vol not persisted: %+v", dev.Active.Vol)
	}
	if dev.Active.WiFiKnown == nil || len(*dev.Active.WiFiKnown) != 8 {
		t.Errorf("wifi_known not persisted in full: %+v", dev.Active.WiFiKnown)
	}
}

// A body sitting exactly on the cap is inside it, not over it — and must be
// APPLIED, not merely "not 413". Asserting 204 is what makes this test fail
// against the old 512-byte broker, which answered 400 here.
func TestDeviceSettings_AtCapAccepted(t *testing.T) {
	ts, reg, psk := newBodyDigestServer(t)
	// Pad pet_name so the whole document is exactly maxSettingsBodyBytes.
	// pet_name is length-clamped downstream, not rejected, so an at-cap body
	// built this way is a perfectly valid report.
	const prefix = `{"vol":42,"pet_name":"`
	const suffix = `"}`
	body := []byte(prefix + strings.Repeat("p", maxSettingsBodyBytes-len(prefix)-len(suffix)) + suffix)
	if len(body) != maxSettingsBodyBytes {
		t.Fatalf("padding wrong: %d bytes, want %d", len(body), maxSettingsBodyBytes)
	}
	resp := signedBodyPost(t, ts, psk, "/device/"+syncTestID+"/settings", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("body of exactly %d bytes: status = %d, want 204", maxSettingsBodyBytes, resp.StatusCode)
	}
	dev, err := reg.Load(syncTestID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Active.Vol == nil || *dev.Active.Vol != 42 {
		t.Errorf("at-cap body was not applied: vol = %+v", dev.Active.Vol)
	}
}

// One byte over is 413 — a distinct answer from 400, because the device
// downgrades its own wifi_known budget on 413 and retries, whereas 400 means
// the bytes were unreadable and a shorter list would not help.
func TestDeviceSettings_OverCapRejected413(t *testing.T) {
	ts, reg, psk := newBodyDigestServer(t)
	// EXACTLY one byte over. A body of cap+10 would still pass against an
	// implementation that let cap+1 through, which is the off-by-one this test
	// is here to catch.
	payload := []byte(`{"vol":25}`)
	body := append(bytes.Repeat([]byte(" "), maxSettingsBodyBytes+1-len(payload)), payload...)
	if len(body) != maxSettingsBodyBytes+1 {
		t.Fatalf("test body is %d bytes, want %d", len(body), maxSettingsBodyBytes+1)
	}
	resp := signedBodyPost(t, ts, psk, "/device/"+syncTestID+"/settings", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	dev, err := reg.Load(syncTestID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Active.Vol != nil {
		t.Errorf("oversize body persisted vol=%d", *dev.Active.Vol)
	}
}

// The size gate runs before signature verification (the v3 canonical covers
// sha256(body), so the raw bytes are needed either way) — an oversize body from
// an unauthenticated peer must cost a size check, not a PSK comparison.
func TestDeviceSettings_OversizeRejectedBeforeAuth(t *testing.T) {
	ts, _, _ := newBodyDigestServer(t)
	body := bytes.Repeat([]byte("x"), maxSettingsBodyBytes+1)
	req, _ := http.NewRequest("POST", ts.URL+"/device/"+syncTestID+"/settings", bytes.NewReader(body))
	req.Header.Set("X-Tmon-Device", syncTestID)
	req.Header.Set("X-Tmon-Signature", strings.Repeat("0", 64))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (size checked before auth)", resp.StatusCode)
	}
}

// The three runtimes must not drift: py and js carry the same number under
// _MAX_SETTINGS_BODY_BYTES / MAX_SETTINGS_BODY_BYTES, and the firmware picks a
// smaller budget for itself so neither side depends on the other's value.
func TestDeviceSettings_CapMatchesCrossRuntimeConstant(t *testing.T) {
	if maxSettingsBodyBytes != 4<<10 {
		t.Fatalf("maxSettingsBodyBytes = %d; py/js pin 4096 — update all three together", maxSettingsBodyBytes)
	}
}
