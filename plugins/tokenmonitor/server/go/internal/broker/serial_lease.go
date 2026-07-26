package broker

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/usbprov"
)

// maxLeaseBodyBytes bounds a lease request body. Lease JSON is a port path or a
// 32-hex id plus a TTL — tiny; the cap just stops a malformed peer streaming.
const maxLeaseBodyBytes = 4 << 10

// handleSerialLease services the three leader-mediated serial-lease endpoints
// (compat/PROVISION_WIRE.md §6): a follower that wants to open the USB port asks
// the leader to suspend its tailer. A nil `lease` answers 503 so the follower
// falls back to a direct open — that is the contract for a broker built without
// a lease manager (and what a non-leader/older peer effectively presents). The
// Go leader itself always wires one up, using usbprov.NopController when no
// serial device is configured, so every port is simply free to grant there.
// Auth is the shared-PSK loopback HMAC with a MANDATORY body
// digest (the body carries the port/id, so it must be signed) — an absent
// X-Tmon-Body-Sha256 is rejected rather than silently downgraded to v2.
func handleSerialLease(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, lease *usbprov.LeaseManager, w http.ResponseWriter, r *http.Request) {
	if lease == nil {
		writeError(w, http.StatusServiceUnavailable, "serial port not configured on this host")
		return
	}
	// Loopback-only, INDEPENDENT of the broker's bind address. The lease grants
	// control of a HOST-LOCAL resource (the USB port / log tailer); the PSK is
	// the credential the device uses for broker access and must not implicitly
	// confer remote serial-ownership control. A follower always dials 127.0.0.1,
	// so a non-loopback peer is never legitimate. RemoteAddr is the real TCP peer
	// — never a spoofable Host/X-Forwarded-For header.
	if !isLoopbackPeer(r.RemoteAddr) {
		logger.Printf("lease %s rejected: non-loopback peer %s", r.URL.Path, r.RemoteAddr)
		writeError(w, http.StatusForbidden, "serial lease is loopback-only")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Body FIRST (bounded), then body-aware auth — the v3 signature covers
	// sha256(body). Reading before auth is safe: the cap bounds memory and
	// nothing is acted on until the signature checks out.
	r.Body = http.MaxBytesReader(w, r.Body, maxLeaseBodyBytes)
	raw, rerr := io.ReadAll(r.Body)
	if rerr != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}

	bodySHA := r.Header.Get("X-Tmon-Body-Sha256")
	if bodySHA == "" {
		// These endpoints mutate port ownership; refuse an unsigned body rather
		// than fall back to the v2 (body-blind) canonical.
		logger.Printf("lease %s from %s: missing body digest", r.URL.Path, r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if _, verr := auth.VerifyMultiBody(
		[][]byte{cfg.PSK()},
		"POST", r.URL.Path,
		r.Header.Get("X-Tmon-Timestamp"),
		r.Header.Get("X-Tmon-Nonce"),
		r.Header.Get("X-Tmon-Signature"),
		r.Header.Get("X-Tmon-Device"),
		r.Header.Get("X-Tmon-Config-Version"),
		bodySHA,
		raw,
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	); verr != nil {
		logger.Printf("auth rejected %s from %s: %v", r.URL.Path, r.RemoteAddr, verr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	switch r.URL.Path {
	case usbprov.LeasePath:
		handleLeaseGrant(logger, lease, raw, w)
	case usbprov.LeaseRenewPath:
		handleLeaseRenew(logger, lease, raw, w)
	case usbprov.LeaseReleasePath:
		handleLeaseRelease(lease, raw, w)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

// isLoopbackPeer reports whether remoteAddr (r.RemoteAddr, "host:port") is a
// loopback IP. A missing/unparseable host fails closed (not loopback).
func isLoopbackPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // some transports report a bare host
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func handleLeaseGrant(logger *log.Logger, lease *usbprov.LeaseManager, raw []byte, w http.ResponseWriter) {
	var req usbprov.LeaseRequest
	if err := json.Unmarshal(raw, &req); err != nil || req.Port == "" {
		writeError(w, http.StatusBadRequest, "bad lease request")
		return
	}
	// Canonicalise on the leader (Abs + EvalSymlinks) so the lease slot key
	// matches what the tailer and the follower's OpenExclusive both compute.
	canonical, err := usbprov.CanonicalPort(req.Port)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unresolvable port")
		return
	}
	id, granted, expires, err := lease.Grant(canonical, time.Duration(req.TTLMillis)*time.Millisecond)
	if errors.Is(err, usbprov.ErrLeaseBusy) {
		// PROVISION_WIRE §6: 409 body is {"error":"busy","holder":...}. The port
		// is always busy on a competing lease here (Grant suspends the tailer
		// before recording), so the holder is "lease".
		writeJSON(w, http.StatusConflict, map[string]string{"error": "busy", "holder": "lease"})
		return
	} else if err != nil {
		logger.Printf("lease grant %s: %v", canonical, err)
		writeError(w, http.StatusServiceUnavailable, "cannot yield port")
		return
	}
	writeJSON(w, http.StatusOK, usbprov.LeaseResponse{
		LeaseID:           id,
		Port:              canonical,
		TTLMillis:         granted.Milliseconds(),
		ExpiresUnixMillis: expires.UnixMilli(),
	})
}

func handleLeaseRenew(logger *log.Logger, lease *usbprov.LeaseManager, raw []byte, w http.ResponseWriter) {
	var req usbprov.RenewRequest
	if err := json.Unmarshal(raw, &req); err != nil || req.LeaseID == "" {
		writeError(w, http.StatusBadRequest, "bad renew request")
		return
	}
	granted, expires, err := lease.Renew(req.LeaseID)
	if errors.Is(err, usbprov.ErrLeaseUnknown) {
		// 410 Gone: the lease lapsed or never existed → the follower MUST abort
		// its session (the port may already be back with the tailer). This is a
		// KNOWN route with an unknown lease, distinct from the grant path's 404
		// (an old leader that lacks the route entirely → direct-open fallback).
		writeError(w, http.StatusGone, "lease unknown or expired")
		return
	} else if err != nil {
		logger.Printf("lease renew: %v", err)
		writeError(w, http.StatusInternalServerError, "renew error")
		return
	}
	writeJSON(w, http.StatusOK, usbprov.RenewResponse{
		TTLMillis:         granted.Milliseconds(),
		ExpiresUnixMillis: expires.UnixMilli(),
	})
}

func handleLeaseRelease(lease *usbprov.LeaseManager, raw []byte, w http.ResponseWriter) {
	var req usbprov.ReleaseRequest
	if err := json.Unmarshal(raw, &req); err != nil || req.LeaseID == "" {
		writeError(w, http.StatusBadRequest, "bad release request")
		return
	}
	// Idempotent: an unknown/expired id is still a success so a follower that
	// releases after its lease already lapsed sees ok and stops retrying.
	lease.Release(req.LeaseID)
	writeJSON(w, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}
