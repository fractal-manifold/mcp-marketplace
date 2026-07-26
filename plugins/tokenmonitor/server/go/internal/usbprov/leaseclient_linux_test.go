//go:build linux

package usbprov

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
)

// leaseTestServer stands up an HTTP handler that validates the client's real
// signatures (via auth.VerifyMultiBody) and drives a real LeaseManager, so the
// test proves OpenLeased signs correctly AND that grant/renew/release wire up.
// renewGate, when non-nil and returning false, makes /serial/lease/renew answer
// 410 — modelling a reaped lease so the client's Lost channel must fire.
func leaseTestServer(t *testing.T, psk []byte, mgr *LeaseManager, renewOK func() bool) *httptest.Server {
	t.Helper()
	cache := auth.NewNonceCache(5 * time.Minute)
	mux := http.NewServeMux()
	verify := func(w http.ResponseWriter, r *http.Request, path string) ([]byte, bool) {
		raw := make([]byte, 0, 256)
		buf := make([]byte, 256)
		for {
			n, err := r.Body.Read(buf)
			raw = append(raw, buf[:n]...)
			if err != nil {
				break
			}
		}
		if _, err := auth.VerifyMultiBody(
			[][]byte{psk}, "POST", path,
			r.Header.Get("X-Tmon-Timestamp"), r.Header.Get("X-Tmon-Nonce"),
			r.Header.Get("X-Tmon-Signature"), "", "",
			r.Header.Get("X-Tmon-Body-Sha256"), raw, cache, time.Minute, time.Now(),
		); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return nil, false
		}
		return raw, true
	}
	mux.HandleFunc(LeasePath, func(w http.ResponseWriter, r *http.Request) {
		raw, ok := verify(w, r, LeasePath)
		if !ok {
			return
		}
		var req LeaseRequest
		json.Unmarshal(raw, &req)
		canonical, _ := CanonicalPort(req.Port)
		id, granted, expires, err := mgr.Grant(canonical, time.Duration(req.TTLMillis)*time.Millisecond)
		if err == ErrLeaseBusy {
			w.WriteHeader(http.StatusConflict)
			return
		} else if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(LeaseResponse{LeaseID: id, Port: canonical, TTLMillis: granted.Milliseconds(), ExpiresUnixMillis: expires.UnixMilli()})
	})
	mux.HandleFunc(LeaseRenewPath, func(w http.ResponseWriter, r *http.Request) {
		raw, ok := verify(w, r, LeaseRenewPath)
		if !ok {
			return
		}
		if renewOK != nil && !renewOK() {
			w.WriteHeader(http.StatusGone)
			return
		}
		var req RenewRequest
		json.Unmarshal(raw, &req)
		granted, expires, err := mgr.Renew(req.LeaseID)
		if err != nil {
			w.WriteHeader(http.StatusGone)
			return
		}
		json.NewEncoder(w).Encode(RenewResponse{TTLMillis: granted.Milliseconds(), ExpiresUnixMillis: expires.UnixMilli()})
	})
	mux.HandleFunc(LeaseReleasePath, func(w http.ResponseWriter, r *http.Request) {
		raw, ok := verify(w, r, LeaseReleasePath)
		if !ok {
			return
		}
		var req ReleaseRequest
		json.Unmarshal(raw, &req)
		mgr.Release(req.LeaseID)
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestOpenLeased_HeldPathOpensRenewsReleases(t *testing.T) {
	master, slave := openPtyUsb(t)
	defer master.Close()

	psk := []byte("client-test-psk")
	ctrl := newFakeController()
	mgr := NewLeaseManager(ctrl, 10*time.Second)
	ts := leaseTestServer(t, psk, mgr, nil)

	client := &LeaseClient{BaseURL: ts.URL, PSK: psk, HTTP: ts.Client()}
	lp, err := client.OpenLeased(context.Background(), slave)
	if err != nil {
		t.Fatalf("OpenLeased: %v", err)
	}
	if lp.Handle == nil {
		t.Fatal("nil handle on a granted lease")
	}
	// The lease was granted → the controller was suspended for this port.
	canonical, _ := CanonicalPort(slave)
	if s, _ := ctrl.counts(canonical); s != 1 {
		t.Fatalf("suspend count = %d, want 1", s)
	}
	// Lost must NOT fire while the lease is healthy.
	select {
	case <-lp.Lost:
		t.Fatal("Lost fired on a healthy lease")
	case <-time.After(200 * time.Millisecond):
	}
	// Close releases the lease → controller resumed, port freed.
	if err := lp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, r := ctrl.counts(canonical); r != 1 {
		t.Fatalf("resume count = %d, want 1 after Close", r)
	}
	// The port lock is free again.
	rel, err := AcquirePortLock(canonical)
	if err != nil {
		t.Fatalf("port lock not free after Close: %v", err)
	}
	_ = rel()
}

func TestOpenLeased_LostFiresWhenRenewFails(t *testing.T) {
	master, slave := openPtyUsb(t)
	defer master.Close()

	psk := []byte("client-test-psk")
	mgr := NewLeaseManager(newFakeController(), 10*time.Second)
	var allow atomic.Bool
	allow.Store(true)
	ts := leaseTestServer(t, psk, mgr, allow.Load)

	// Use a short renew cadence by requesting a small TTL via a custom client.
	client := &LeaseClient{BaseURL: ts.URL, PSK: psk, HTTP: ts.Client()}
	lp, err := client.OpenLeased(context.Background(), slave)
	if err != nil {
		t.Fatalf("OpenLeased: %v", err)
	}
	defer lp.Close()

	// Start refusing renewals; the client's renewLoop must close Lost.
	allow.Store(false)
	select {
	case <-lp.Lost:
		// good
	case <-time.After(15 * time.Second):
		t.Fatal("Lost did not fire after renew began failing")
	}
}

func TestOpenLeased_DirectOpenWhenNoBroker(t *testing.T) {
	master, slave := openPtyUsb(t)
	defer master.Close()

	// BaseURL points nowhere → acquire's dial fails → direct open fallback.
	client := &LeaseClient{BaseURL: "http://127.0.0.1:1", PSK: []byte("x"), HTTP: &http.Client{Timeout: time.Second}}
	lp, err := client.OpenLeased(context.Background(), slave)
	if err != nil {
		t.Fatalf("direct-open fallback: %v", err)
	}
	if lp.Handle == nil {
		t.Fatal("nil handle on direct open")
	}
	// Direct opens never lose a lease.
	select {
	case <-lp.Lost:
		t.Fatal("Lost fired on a direct open")
	case <-time.After(100 * time.Millisecond):
	}
	lp.Close()
}
