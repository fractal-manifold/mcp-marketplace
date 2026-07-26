package usbprov

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
)

// LeaseClient is the follower side of the serial-lease contract
// (compat/PROVISION_WIRE.md §6). A follower that wants to provision over USB
// asks the local leader — which owns the log tailer — to yield the port, holds
// the lease (renewing before it lapses) for the session, then releases it.
//
// The lease is the authority between cooperating tokenmonitor-mcp processes; the
// OS-exclusive open (OpenExclusive) is the second fence, for everything the
// lease cannot see. So even the "no lease needed" fallbacks still open
// exclusively.
type LeaseClient struct {
	BaseURL string // e.g. http://127.0.0.1:8765 (no trailing slash)
	PSK     []byte
	HTTP    *http.Client
	now     func() time.Time // injectable for tests; defaults to time.Now
}

// DefaultLeaseTTL is the TTL a follower requests. The leader clamps it; the
// client renews at half this cadence, so a single missed renewal still leaves
// margin before the leader reaps the lease and resumes tailing.
const DefaultLeaseTTL = 20 * time.Second

// maxLeaseRespBytes bounds a lease response body the client will read — the JSON
// is a short id + two integers; the cap just stops a rogue peer streaming.
const maxLeaseRespBytes = 4 << 10

func (c *LeaseClient) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *LeaseClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 4 * time.Second}
}

// LeasedPort is a serial port acquired for exclusive use. Handle is the open
// port. Lost is closed if the lease can no longer be held (the leader reaped it,
// or the broker became unreachable) — the caller MUST treat that as the port
// possibly reclaimed by the tailer and abort any in-flight session (derive the
// provisioning context from it). For a direct open (no leader tailing), Lost is
// never closed. Close releases the lease and the port; it is idempotent.
type LeasedPort struct {
	Handle   *Handle
	Lost     <-chan struct{}
	stopOnce sync.Once
	stop     func()
}

// Close releases the lease (if any) and the underlying port. Idempotent AND
// concurrency-safe: a cancellation path and a cleanup path may both call it.
func (p *LeasedPort) Close() error {
	p.stopOnce.Do(func() {
		if p.stop != nil {
			p.stop()
		}
	})
	return nil
}

var neverClosed = make(chan struct{}) // a Lost channel that never fires (direct opens)

// OpenLeased acquires port for exclusive provisioning use. It first asks the
// local leader for a lease; on 200 it opens the (now-yielded) port and renews
// the lease in the background until Close. If the leader has no such endpoint
// (404, older broker) or no serial device configured (503), or no broker is
// running at all (dial error), it falls back to a direct OS-exclusive open —
// the flock still fences foreign and follower processes.
//
// Returns ErrLeaseBusy if another follower already holds the lease, and
// ErrPortBusy if the direct open loses the flock race.
func (c *LeaseClient) OpenLeased(ctx context.Context, port string) (*LeasedPort, error) {
	id, granted, needLease, err := c.acquire(ctx, port, DefaultLeaseTTL)
	if err != nil {
		return nil, err
	}
	if !needLease {
		// No leader is tailing this port: open directly. The flock is still the
		// cross-process fence.
		h, oerr := openWithRetry(ctx, port)
		if oerr != nil {
			return nil, oerr
		}
		p := &LeasedPort{Handle: h, Lost: neverClosed}
		p.stop = func() { _ = h.Release() }
		return p, nil
	}

	// Lease held: the leader's tailer has already released the port (Grant
	// suspends synchronously before answering 200), so the open should succeed
	// promptly; retry briefly to cover an election-gap or foreign holder.
	h, oerr := openWithRetry(ctx, port)
	if oerr != nil {
		c.releaseBounded(id) // hand the port back to the tailer
		return nil, oerr
	}

	lost := make(chan struct{})
	stopRenew := make(chan struct{})
	go c.renewLoop(id, granted, lost, stopRenew)

	p := &LeasedPort{Handle: h, Lost: lost}
	p.stop = func() {
		close(stopRenew) // stop renewing
		_ = h.Release()  // close the port
		c.releaseBounded(id)
	}
	return p, nil
}

// acquire posts a lease request. needLease is false when no lease is required
// (no broker, or a leader without this endpoint / without a serial device): the
// caller then opens the port directly. It is true only on a 200 grant.
func (c *LeaseClient) acquire(ctx context.Context, port string, ttl time.Duration) (id string, granted time.Duration, needLease bool, err error) {
	body, _ := json.Marshal(LeaseRequest{Port: port, TTLMillis: ttl.Milliseconds()})
	resp, derr := c.do(ctx, LeasePath, body)
	if derr != nil {
		// A cancelled/expired caller context must surface, NOT silently fall
		// through to a direct open (which would ignore the cancellation).
		if ctx.Err() != nil {
			return "", 0, false, ctx.Err()
		}
		// No broker reachable → nobody is tailing the port → direct open.
		return "", 0, false, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxLeaseRespBytes))

	switch resp.StatusCode {
	case http.StatusOK:
		var lr LeaseResponse
		if uerr := json.Unmarshal(raw, &lr); uerr != nil || lr.LeaseID == "" || lr.TTLMillis <= 0 {
			return "", 0, false, fmt.Errorf("usbprov: malformed lease response")
		}
		return lr.LeaseID, time.Duration(lr.TTLMillis) * time.Millisecond, true, nil
	case http.StatusConflict:
		return "", 0, false, ErrLeaseBusy
	case http.StatusNotFound, http.StatusServiceUnavailable:
		// Leader too old to know the endpoint, or no serial device configured on
		// it: no tailer contends this port → direct open.
		return "", 0, false, nil
	default:
		return "", 0, false, fmt.Errorf("usbprov: lease request failed: %s", resp.Status)
	}
}

// renewLoop renews the lease at half the granted cadence until stopRenew. On the
// first renewal failure it closes lost and returns — the caller's session must
// then abort (the tailer may reclaim the port).
func (c *LeaseClient) renewLoop(id string, granted time.Duration, lost chan struct{}, stopRenew <-chan struct{}) {
	interval := granted / 2
	if interval < 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stopRenew:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := c.renew(ctx, id)
			cancel()
			if err != nil {
				close(lost) // lease is gone → signal the session to abort
				return
			}
		}
	}
}

func (c *LeaseClient) renew(ctx context.Context, id string) error {
	body, _ := json.Marshal(RenewRequest{LeaseID: id})
	resp, err := c.do(ctx, LeaseRenewPath, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxLeaseRespBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("usbprov: renew failed: %s", resp.Status)
	}
	return nil
}

// releaseBounded releases best-effort with its OWN bounded context, so a
// cleanup path never blocks indefinitely even when LeaseClient.HTTP was
// supplied without a timeout. The leader reaps the lease on TTL expiry anyway.
func (c *LeaseClient) releaseBounded(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c.release(ctx, id)
}

func (c *LeaseClient) release(ctx context.Context, id string) {
	body, _ := json.Marshal(ReleaseRequest{LeaseID: id})
	resp, err := c.do(ctx, LeaseReleasePath, body)
	if err != nil {
		return // best-effort; the leader reaps the lease on TTL expiry anyway
	}
	// Drain the small body so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxLeaseRespBytes))
	resp.Body.Close()
}

// do signs and sends one POST with a mandatory body digest (v3 canonical).
func (c *LeaseClient) do(ctx context.Context, path string, body []byte) (*http.Response, error) {
	sum := sha256.Sum256(body)
	bodySHA := hex.EncodeToString(sum[:])
	ts := strconv.FormatInt(c.clock().Unix(), 10)
	nonce := freshLeaseNonce()
	sig := auth.ComputeSignatureBody(c.PSK, "POST", path, ts, nonce, "", "", bodySHA)

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tmon-Timestamp", ts)
	req.Header.Set("X-Tmon-Nonce", nonce)
	req.Header.Set("X-Tmon-Signature", sig)
	req.Header.Set("X-Tmon-Body-Sha256", bodySHA)
	return c.httpClient().Do(req)
}

// openWithRetry opens the port exclusively, retrying on ErrPortBusy for a short
// bounded window (the previous holder — the tailer or a lapsing lease — may take
// a moment to fully release the flock). Honours ctx cancellation.
func openWithRetry(ctx context.Context, port string) (*Handle, error) {
	const attempts = 20
	var lastErr error
	for i := 0; i < attempts; i++ {
		h, err := OpenExclusive(port)
		if err == nil {
			return h, nil
		}
		if !errors.Is(err, ErrPortBusy) {
			return nil, err // a real open error (missing device, perms) — don't spin
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil, lastErr
}

func freshLeaseNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
