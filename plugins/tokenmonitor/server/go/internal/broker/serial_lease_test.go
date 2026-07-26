package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/state"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/usbprov"
)

// recordController records suspend/resume so the test can prove — through the
// full HTTP round trip — that Grant suspended the tailer and Release resumed it.
type recordController struct {
	suspend, resume int
}

func (c *recordController) SuspendPort(string) error { c.suspend++; return nil }
func (c *recordController) ResumePort(string)        { c.resume++ }

func newLeaseServer(t *testing.T, lease *usbprov.LeaseManager) (*httptest.Server, *config.Config) {
	t.Helper()
	cfg := newTestConfig(t, writeCredsFile(t, time.Now().Add(time.Hour).UnixMilli()))
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	logger := log.New(io.Discard, "", 0)
	ts := httptest.NewServer(NewMux(cfg, cache, state.New(), logger, nil, nil, nil, nil, lease))
	t.Cleanup(ts.Close)
	return ts, cfg
}

// leasePOST signs a JSON body the way the follower client does (v3
// body-covering canonical) and posts it. nonce must be unique per call (the
// broker's replay cache rejects a repeat).
func leasePOST(t *testing.T, ts *httptest.Server, cfg *config.Config, path string, v any, nonce string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(v)
	sum := sha256.Sum256(body)
	bodySHA := hex.EncodeToString(sum[:])
	now := strconv.FormatInt(time.Now().Unix(), 10)
	sig := auth.ComputeSignatureBody(cfg.PSK(), "POST", path, now, nonce, "", "", bodySHA)
	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tmon-Timestamp", now)
	req.Header.Set("X-Tmon-Nonce", nonce)
	req.Header.Set("X-Tmon-Signature", sig)
	req.Header.Set("X-Tmon-Body-Sha256", bodySHA)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func TestSerialLease_RoundTripGrantsRenewsReleases(t *testing.T) {
	ctrl := &recordController{}
	lease := usbprov.NewLeaseManager(ctrl, 10*time.Second)
	ts, cfg := newLeaseServer(t, lease)

	// Grant over HTTP. The port need not exist for the manager to lease it, but
	// the handler canonicalises via EvalSymlinks — so use a path that resolves.
	port := "/dev/null"
	resp := leasePOST(t, ts, cfg, usbprov.LeasePath, usbprov.LeaseRequest{Port: port, TTLMillis: 5000}, "11111111111111111111111111111111")
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("grant status = %d (%s)", resp.StatusCode, b)
	}
	var gr usbprov.LeaseResponse
	json.NewDecoder(resp.Body).Decode(&gr)
	resp.Body.Close()
	if gr.LeaseID == "" || gr.TTLMillis != 5000 {
		t.Fatalf("bad grant response: %+v", gr)
	}
	// PROVISION_WIRE §6: the grant echoes the canonical port it keyed the lease on.
	if gr.Port == "" {
		t.Errorf("grant response must echo the canonical port: %+v", gr)
	}
	if ctrl.suspend != 1 {
		t.Fatalf("suspend count = %d, want 1", ctrl.suspend)
	}

	// A second grant on the same (canonical) port is busy.
	busy := leasePOST(t, ts, cfg, usbprov.LeasePath, usbprov.LeaseRequest{Port: port, TTLMillis: 5000}, "22222222222222222222222222222222")
	if busy.StatusCode != http.StatusConflict {
		t.Fatalf("second grant status = %d, want 409", busy.StatusCode)
	}
	busy.Body.Close()

	// Renew carries ONLY the lease id; the leader re-applies the original TTL.
	rn := leasePOST(t, ts, cfg, usbprov.LeaseRenewPath, usbprov.RenewRequest{LeaseID: gr.LeaseID}, "33333333333333333333333333333333")
	if rn.StatusCode != http.StatusOK {
		t.Fatalf("renew status = %d, want 200", rn.StatusCode)
	}
	var rr usbprov.RenewResponse
	json.NewDecoder(rn.Body).Decode(&rr)
	rn.Body.Close()
	if rr.TTLMillis != 5000 {
		t.Fatalf("renew re-granted %d ms, want the original 5000", rr.TTLMillis)
	}

	// Release resumes the owner.
	rel := leasePOST(t, ts, cfg, usbprov.LeaseReleasePath, usbprov.ReleaseRequest{LeaseID: gr.LeaseID}, "44444444444444444444444444444444")
	if rel.StatusCode != http.StatusOK {
		t.Fatalf("release status = %d, want 200", rel.StatusCode)
	}
	rel.Body.Close()
	if ctrl.resume != 1 {
		t.Fatalf("resume count = %d, want 1 after release", ctrl.resume)
	}

	// Renewing a released lease is 410 Gone (the client must then abort).
	gone := leasePOST(t, ts, cfg, usbprov.LeaseRenewPath, usbprov.RenewRequest{LeaseID: gr.LeaseID}, "55555555555555555555555555555555")
	if gone.StatusCode != http.StatusGone {
		t.Fatalf("renew-after-release status = %d, want 410", gone.StatusCode)
	}
	gone.Body.Close()
}

func TestSerialLease_MissingBodyDigestRejected(t *testing.T) {
	lease := usbprov.NewLeaseManager(&recordController{}, 10*time.Second)
	ts, cfg := newLeaseServer(t, lease)

	body, _ := json.Marshal(usbprov.LeaseRequest{Port: "/dev/null", TTLMillis: 5000})
	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "0123456789abcdef0123456789abcdef"
	// Sign the v2 canonical (no body digest) and omit X-Tmon-Body-Sha256: these
	// port-mutating endpoints must refuse an unsigned body, not downgrade.
	sig := auth.ComputeSignature(cfg.PSK(), "POST", usbprov.LeasePath, now, nonce, "", "")
	req, _ := http.NewRequest("POST", ts.URL+usbprov.LeasePath, bytes.NewReader(body))
	req.Header.Set("X-Tmon-Timestamp", now)
	req.Header.Set("X-Tmon-Nonce", nonce)
	req.Header.Set("X-Tmon-Signature", sig)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing body digest: status = %d, want 401", resp.StatusCode)
	}
}

func TestIsLoopbackPeer(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:5555", true},
		{"[::1]:5555", true},
		{"127.0.0.1", true}, // bare host (some transports)
		{"8.8.8.8:1234", false},
		{"192.168.1.5:80", false},
		{"[2001:db8::1]:443", false},
		{"", false},
		{"garbage", false},
	}
	for _, c := range cases {
		if got := isLoopbackPeer(c.addr); got != c.want {
			t.Errorf("isLoopbackPeer(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

// TestSerialLease_NonLoopbackPeerRejected drives handleSerialLease directly with
// a forged non-loopback RemoteAddr (httptest always connects via loopback, so a
// direct call is the only way to exercise the guard) and asserts 403 BEFORE any
// auth/body work.
func TestSerialLease_NonLoopbackPeerRejected(t *testing.T) {
	lease := usbprov.NewLeaseManager(&recordController{}, 10*time.Second)
	cfg := newTestConfig(t, writeCredsFile(t, time.Now().Add(time.Hour).UnixMilli()))
	cache := auth.NewNonceCache(time.Minute)
	logger := log.New(io.Discard, "", 0)

	req := httptest.NewRequest("POST", usbprov.LeasePath, bytes.NewReader([]byte(`{}`)))
	req.RemoteAddr = "203.0.113.7:44444" // documentation-range public IP
	rec := httptest.NewRecorder()
	handleSerialLease(cfg, cache, logger, lease, rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback peer: status = %d, want 403", rec.Code)
	}
}

func TestSerialLease_NilManagerIs503(t *testing.T) {
	ts, cfg := newLeaseServer(t, nil) // no serial device configured on this host
	resp := leasePOST(t, ts, cfg, usbprov.LeasePath, usbprov.LeaseRequest{Port: "/dev/null", TTLMillis: 5000}, "66666666666666666666666666666666")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("nil manager: status = %d, want 503", resp.StatusCode)
	}
}
