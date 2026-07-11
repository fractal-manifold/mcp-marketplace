package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/devlog"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

// Endpoint coverage for the HMAC v3 body digest (compat/HMAC_CANONICAL.md):
// /device/{id}/settings and /logs must accept a correctly-digested body,
// reject a tampered or malformed digest with 401, keep accepting legacy v2
// (no header) requests, and keep the oversize behavior intact.

// signedBodyPost signs a POST under the v3 canonical (digest of body) unless
// digestOverride is set — pass "" to send NO X-Tmon-Body-Sha256 header and a
// legacy v2 signature instead.
func signedBodyPost(t *testing.T, ts *httptest.Server, psk []byte, path string, body []byte, digestOverride *string) *http.Response {
	t.Helper()
	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := mustHex(t, 16)
	deviceID := syncTestID

	var sig, digest string
	if digestOverride == nil {
		sum := sha256.Sum256(body)
		digest = hex.EncodeToString(sum[:])
		sig = auth.ComputeSignatureBody(psk, "POST", path, now, nonce, deviceID, "1", digest)
	} else if *digestOverride == "" {
		sig = auth.ComputeSignature(psk, "POST", path, now, nonce, deviceID, "1")
	} else {
		digest = *digestOverride
		sig = auth.ComputeSignatureBody(psk, "POST", path, now, nonce, deviceID, "1", digest)
	}

	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(body))
	req.Header.Set("X-Tmon-Timestamp", now)
	req.Header.Set("X-Tmon-Nonce", nonce)
	req.Header.Set("X-Tmon-Signature", sig)
	req.Header.Set("X-Tmon-Device", deviceID)
	req.Header.Set("X-Tmon-Config-Version", "1")
	if digest != "" {
		req.Header.Set("X-Tmon-Body-Sha256", digest)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func newBodyDigestServer(t *testing.T) (*httptest.Server, *registry.Registry, []byte) {
	t.Helper()
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	if _, err := reg.Register(syncTestID, registry.ConfigPayload{PSKHex: activePSK, BrokerURL: "http://x"}); err != nil {
		t.Fatal(err)
	}
	pskBytes, _ := hex.DecodeString(activePSK)
	return ts, reg, pskBytes
}

func TestDeviceSettings_V3DigestAcceptsAndPersists(t *testing.T) {
	ts, reg, psk := newBodyDigestServer(t)
	resp := signedBodyPost(t, ts, psk, "/device/"+syncTestID+"/settings", []byte(`{"vol":25}`), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	dev, err := reg.Load(syncTestID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Active.Vol == nil || *dev.Active.Vol != 25 {
		t.Errorf("vol not persisted: %+v", dev.Active.Vol)
	}
}

func TestDeviceSettings_TamperedBodyRejected401(t *testing.T) {
	ts, reg, psk := newBodyDigestServer(t)
	// Digest of {"vol":25}, but the wire body says vol:99 — on-path tamper.
	sum := sha256.Sum256([]byte(`{"vol":25}`))
	digest := hex.EncodeToString(sum[:])
	resp := signedBodyPost(t, ts, psk, "/device/"+syncTestID+"/settings", []byte(`{"vol":99}`), &digest)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	dev, err := reg.Load(syncTestID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Active.Vol != nil {
		t.Errorf("tampered body persisted vol=%d", *dev.Active.Vol)
	}
}

func TestDeviceSettings_MalformedDigestRejected401(t *testing.T) {
	ts, _, psk := newBodyDigestServer(t)
	for _, bad := range []string{
		strings.ToUpper(strings.Repeat("a", 64)), // uppercase
		strings.Repeat("a", 63),                  // short
		strings.Repeat("g", 64),                  // non-hex
	} {
		bad := bad
		resp := signedBodyPost(t, ts, psk, "/device/"+syncTestID+"/settings", []byte(`{"vol":25}`), &bad)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("digest %q: status = %d, want 401", bad, resp.StatusCode)
		}
	}
}

func TestDeviceSettings_NoHeaderLegacyV2Accepted(t *testing.T) {
	ts, reg, psk := newBodyDigestServer(t)
	legacy := ""
	resp := signedBodyPost(t, ts, psk, "/device/"+syncTestID+"/settings", []byte(`{"vol":30}`), &legacy)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("legacy v2 status = %d, want 204", resp.StatusCode)
	}
	dev, err := reg.Load(syncTestID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Active.Vol == nil || *dev.Active.Vol != 30 {
		t.Errorf("legacy vol not persisted: %+v", dev.Active.Vol)
	}
}

func TestDeviceLogs_V3DigestAccepted(t *testing.T) {
	ts, _, psk := newBodyDigestServer(t)
	resp := signedBodyPost(t, ts, psk, "/device/"+syncTestID+"/logs", []byte("I (123) tmon: boot\n"), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
}

func TestDeviceLogs_OversizeBodyStill413(t *testing.T) {
	ts, _, psk := newBodyDigestServer(t)
	big := bytes.Repeat([]byte("x"), int(devlog.MaxBodyBytes)+1)
	resp := signedBodyPost(t, ts, psk, "/device/"+syncTestID+"/logs", big, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}
