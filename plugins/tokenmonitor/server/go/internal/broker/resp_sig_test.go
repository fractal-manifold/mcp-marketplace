package broker

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

// The response signature is what lets the DEVICE authenticate the BROKER. It
// is the adoption gate for an mDNS-discovered address (compat/mdns.md): the
// device_id in the TXT `devs=` list is public, so anything on the LAN can
// advertise itself as our broker, and only holding the PSK proves the pairing.
//
// syncWithNonce is signedSyncRequest with the nonce handed back, because the
// response tag is bound to it — that binding is what makes this a
// challenge-response rather than a replayable stamp.
func syncWithNonce(t *testing.T, ts *httptest.Server, psk []byte, deviceID string, version uint32) (*http.Response, string, string) {
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp, nonce, path
}

func TestDeviceSync_ResponseSignatureVerifiesWithDevicePSK(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	activePSK := mustHex(t, 32)
	if _, err := reg.Register(syncTestID, registry.ConfigPayload{
		PSKHex: activePSK, BrokerURL: "http://x",
	}); err != nil {
		t.Fatal(err)
	}
	pskBytes, _ := hex.DecodeString(activePSK)

	resp, nonce, path := syncWithNonce(t, ts, pskBytes, syncTestID, 1)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	got := resp.Header.Get(RespSigHeader)
	if got == "" {
		t.Fatal("no " + RespSigHeader + " on an authenticated /sync — the device cannot adopt this address")
	}
	// The device computes HOST from the authority it dialled; the broker takes
	// it from its own end of the socket. They agree only when nothing is
	// relaying in between.
	authority := strings.TrimPrefix(ts.URL, "http://")
	want := auth.ComputeResponseSignature(pskBytes, syncTestID, nonce, authority, path, 200, auth.BodySHA256Hex(body))
	if got != want {
		t.Errorf("resp signature = %s, want %s", got, want)
	}

	// Bound to THIS request's nonce: the same body under a different nonce
	// must not verify, or a captured tag could be replayed by an impostor.
	other := auth.ComputeResponseSignature(pskBytes, syncTestID, mustHex(t, 16), authority, path, 200, auth.BodySHA256Hex(body))
	if got == other {
		t.Error("response signature is not bound to the request nonce")
	}

	// Bound to the address that answered. This is the anti-relay property: an
	// impostor advertising itself on the LAN can forward our request to the
	// real broker and hand back this very tag, and the ONLY thing that stops
	// the device adopting the relay is that the tag names the broker's address
	// and not the relay's.
	elsewhere := auth.ComputeResponseSignature(pskBytes, syncTestID, nonce, "192.168.1.99:8765", path, 200, auth.BodySHA256Hex(body))
	if got == elsewhere {
		t.Error("response signature is not bound to the address that answered — a relay would pass the adoption gate")
	}
}

func TestDeviceSync_ResponseSignatureAbsentOnUnauthorized(t *testing.T) {
	ts, reg := newDeviceSyncServer(t)
	if _, err := reg.Register(syncTestID, registry.ConfigPayload{
		PSKHex: mustHex(t, 32), BrokerURL: "http://x",
	}); err != nil {
		t.Fatal(err)
	}
	wrong, _ := hex.DecodeString(mustHex(t, 32))

	resp, _, _ := syncWithNonce(t, ts, wrong, syncTestID, 1)
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if sig := resp.Header.Get(RespSigHeader); sig != "" {
		t.Errorf("401 carried a response signature (%s); an impostor that cannot verify a request must not be able to emit a tag either", sig)
	}
}

// An impostor broker that knows the (public) device_id but not the PSK cannot
// produce a tag the device accepts. This is the property the whole mDNS-first
// model rests on.
func TestResponseSignature_WrongPSKDoesNotVerify(t *testing.T) {
	real, _ := hex.DecodeString(mustHex(t, 32))
	impostor, _ := hex.DecodeString(mustHex(t, 32))
	body := []byte(`{"active_version":3}`)

	honest := auth.ComputeResponseSignature(real, syncTestID, "0123456789abcdef0123456789abcdef",
		"192.168.1.28:8765", "/device/"+syncTestID+"/sync", 200, auth.BodySHA256Hex(body))
	forged := auth.ComputeResponseSignature(impostor, syncTestID, "0123456789abcdef0123456789abcdef",
		"192.168.1.28:8765", "/device/"+syncTestID+"/sync", 200, auth.BodySHA256Hex(body))
	if honest == forged {
		t.Fatal("a different PSK produced the same tag")
	}
}

// broker_url travels in a pending under two conditions at once: an operator
// staged it (it differs from the active record's address — the registry's own
// value is never echoed), and the device asking reports firmware older than
// 1.0.1, the release where the address stopped being configuration.
func TestPendingPayloadJSON_BrokerURLIsALegacyRepoint(t *testing.T) {
	const staged, recorded = "http://192.168.1.50:8765", "http://192.168.1.28:8765"
	for _, tc := range []struct {
		name          string
		pendingURL    string
		activeURL, fw string
		want          bool
	}{
		{"legacy 0.12.0", staged, recorded, "0.12.0", true},
		{"legacy 1.0.0", staged, recorded, "1.0.0", true},
		{"legacy dev build", staged, recorded, "1.0.0-dev.202609011200", true},
		{"legacy, registry had no address", staged, "", "0.10.3", true},
		{"1.0.1", staged, recorded, "1.0.1", false},
		{"1.0.1 dev build", staged, recorded, "1.0.1-dev.202609181200", false},
		{"2.0.0", staged, recorded, "2.0.0", false},
		{"no version reported", staged, recorded, "", false},
		{"unparseable version", staged, recorded, "dev", false},
		{"legacy, but only the registry's own address", recorded, recorded, "0.12.0", false},
		{"legacy, nothing staged", "", recorded, "0.12.0", false},
	} {
		out, err := pendingPayloadJSON(registry.ConfigPayload{Version: 9, BrokerURL: tc.pendingURL, City: "Barcelona"}, tc.activeURL, tc.fw)
		if err != nil {
			t.Fatalf("%s: pendingPayloadJSON: %v", tc.name, err)
		}
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.name, err)
		}
		if _, got := m["broker_url"]; got != tc.want {
			t.Errorf("%s: broker_url present = %v, want %v (%s)", tc.name, got, tc.want, out)
		}
		if tc.want && m["broker_url"] != staged {
			t.Errorf("%s: broker_url = %v", tc.name, m["broker_url"])
		}
		if m["city"] != "Barcelona" {
			t.Errorf("%s: other fields must still travel, got %s", tc.name, out)
		}
	}
}
