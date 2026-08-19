// Package mdns advertises the tokenmonitor-mcp broker on the local network so
// firmware devices can locate it when their cached broker URL stops
// working (DHCP renew, broker host change). The service type is
// `_tmon-broker._tcp` and the TXT record carries:
//
//	v=1
//	runtime=go|python|js
//	devs=<id1>,<id2>,...     (registered device_ids, lowercase 8 hex)
//
// device_id is public — it travels in the X-Tmon-Device HTTP header on
// every poll — so listing them in TXT only lets devices filter "is my
// broker on this LAN?" without leaking secrets. Authentication is still
// HMAC against the per-device PSK held by the registry.
//
// When bind is loopback (127.0.0.1 / ::1) we skip publication entirely:
// the device can't reach the broker anyway, and pretending otherwise
// would just generate spurious hits in the discovery scan.
package mdns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

// ServiceType is the mDNS service the firmware queries for.
const ServiceType = "_tmon-broker._tcp"

// virtualIfacePrefixes mirrors the list in internal/mcp/server.go. We
// must skip them on mDNS publication too: a device on the WiFi LAN can't
// reach a Docker bridge / VPN tunnel address, but if we announce on that
// interface zeroconf advertises every interface's IP — including the
// unreachable ones — and the firmware's discovery code picks the first
// match by device_id, which lands on the wrong IP.
var virtualIfacePrefixes = []string{
	"docker", "br-", "veth", "virbr", "vnet", "tun", "tap",
	"vmnet", "tailscale", "wg", "zt",
}

func isVirtualIface(name string) bool {
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// physicalMulticastIfaces returns the multicast-capable, non-loopback,
// non-virtual interfaces zeroconf should advertise on. Returning nil
// would make zeroconf fall back to ALL multicast interfaces, which is
// what we are explicitly trying to avoid.
func physicalMulticastIfaces() []net.Interface {
	all, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.Interface
	for _, iface := range all {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		if isVirtualIface(iface.Name) {
			continue
		}
		out = append(out, iface)
	}
	return out
}

// Runtime is the value used in the TXT `runtime=` field. The Python and
// JS impls publish the same record format with their own runtime tag so
// a single TXT can disambiguate which binary won the bind race.
const Runtime = "go"

// devIDLister is the slice of the registry the publisher needs. Kept
// minimal so tests can inject a fake without dragging the whole package.
type devIDLister interface {
	ListDeviceIDs() ([]string, error)
}

// Publisher owns the zeroconf server and a goroutine that re-announces
// the TXT record whenever the device list changes and re-registers the
// whole service whenever the interface addresses change (DHCP renew,
// network switch) — zeroconf snapshots the A/AAAA records *and* binds
// its multicast sockets at Register time, so both go stale otherwise.
// Construct via Start; stop with Close (or by cancelling the context
// passed to Start).
// mdnsServer is the sliver of *zeroconf.Server the publisher actually uses.
// It exists so tick() can be driven in a test without opening multicast
// sockets; production always holds a real *zeroconf.Server.
type mdnsServer interface {
	Shutdown()
	SetText(text []string)
}

// registerService is the seam the tests replace. It must never hand back a
// typed nil: a (*zeroconf.Server)(nil) parked in the interface would make
// `srv == nil` false, and that comparison is the only thing that retries a
// failed republish (on failure tick() also advances lastIfp, so the
// address-changed term will not fire again).
var registerService = func(instance, service, domain string, port int,
	text []string, ifaces []net.Interface) (mdnsServer, error) {
	srv, err := zeroconf.Register(instance, service, domain, port, text, ifaces)
	if err != nil {
		return nil, err
	}
	return srv, nil
}

type Publisher struct {
	server   mdnsServer
	mu       sync.Mutex
	lastTxt  string
	lastIfp  string // fingerprint of the advertised interface addresses
	instance string
	port     int
	closed   bool

	// Idle-liveness watchdog. If no device has hit us for idleThreshold we
	// re-announce, on the theory that our own advertisement is what went
	// stale — an interface that flapped, a zeroconf server that wedged, an
	// announcement lost in a lossy multicast domain. Bounded by a doubling
	// backoff so a device that is simply switched off does not have us
	// multicasting every 30 s forever.
	lastReq        func() time.Time // when a device last hit the broker
	startedAt      time.Time        // stands in for lastReq before the first hit
	lastSeenReq    time.Time        // lastReq as of the previous check
	idleAttempts   int
	lastReannounce time.Time
}

// Idle-liveness constants. The threshold matches the refresh tick, so an idle
// broker re-announces on the first tick that notices. The backoff mirrors the
// device's own discovery backoff (see
// firmware/components/core/src/tmon_discovery.c) — same shape, so the two
// sides of this recovery are read the same way.
const (
	idleThreshold = 30 * time.Second
	reannounceMin = 30 * time.Second
	reannounceMax = 5 * time.Minute
)

// reannounceGap is the wait after `attempts` idle re-announcements: the floor
// for the first, doubling to the ceiling thereafter.
func reannounceGap(attempts int) time.Duration {
	gap := reannounceMin
	for i := 1; i < attempts; i++ {
		if gap >= reannounceMax/2 {
			return reannounceMax
		}
		gap *= 2
	}
	return gap
}

// shouldReannounce is the pure decision behind the watchdog. `lastReq` must
// already be normalised by the caller (the broker's start time stands in
// before any device has ever hit us).
//
// devs == 0 means no device is registered here, so there is nobody our
// advertisement could help and no reason to put packets on the LAN.
func shouldReannounce(now, lastReq, lastReannounce time.Time, attempts, devs int) bool {
	if devs == 0 {
		return false
	}
	if now.Sub(lastReq) < idleThreshold {
		return false
	}
	if lastReannounce.IsZero() {
		return true
	}
	return now.Sub(lastReannounce) >= reannounceGap(attempts)
}

// takeIdleReannounce answers "is an idle re-announce due right now?" and, when
// it is, consumes it: the caller must go on to republish. Returns how long we
// have been idle, for the log line. Any request seen since the previous call
// resets the backoff to the floor, however old that request is by now.
func (p *Publisher) takeIdleReannounce(now time.Time, devs int) (bool, time.Duration) {
	if p.lastReq == nil {
		return false, 0
	}
	lastReq := p.lastReq()

	p.mu.Lock()
	defer p.mu.Unlock()
	if lastReq.IsZero() {
		lastReq = p.startedAt
	}
	// Reset on a request we had not seen before, not on "the request we can
	// see is recent". The loop ticks at the same 30 s as the threshold, so a
	// request landing just after a tick is already 30 s old by the next one:
	// keying the reset on freshness would miss it to scheduling jitter and
	// leave the backoff out at five minutes.
	if !lastReq.Equal(p.lastSeenReq) {
		p.lastSeenReq = lastReq
		p.idleAttempts = 0
		p.lastReannounce = time.Time{}
	}
	if !shouldReannounce(now, lastReq, p.lastReannounce, p.idleAttempts, devs) {
		return false, 0
	}
	p.idleAttempts++
	p.lastReannounce = now
	return true, now.Sub(lastReq)
}

// ifaceFingerprint condenses the advertised interfaces + their addresses
// into a comparable string so refreshLoop can detect address churn.
func ifaceFingerprint(ifaces []net.Interface) string {
	var parts []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			parts = append(parts, iface.Name+"/"+a.String())
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// hostShort derives a 6-hex tag from the OS hostname so two laptops on
// the same LAN don't collide on `tmon-broker.local`. Falling back to
// "anon" rather than randomising — a stable name across reboots is
// friendlier to the device's cached resolution.
func hostShort() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "anon00"
	}
	sum := sha256.Sum256([]byte(h))
	return hex.EncodeToString(sum[:3])
}

// isLoopback returns true when bind targets only the loopback interface.
// "" / "0.0.0.0" / "::" are treated as "all interfaces" — publishable.
func isLoopback(bind string) bool {
	if bind == "" || bind == "0.0.0.0" || bind == "::" {
		return false
	}
	ip := net.ParseIP(bind)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// buildTXT renders the TXT record body. Length cap: a single TXT chunk
// is bounded at 255 bytes by the DNS RR encoding; we trim the devs list
// from the right when we exceed that so the most-recently-discovered
// devices stay visible (alphabetical order means lowest IDs win, which
// is fine for the small home/lab fleets we target).
func buildTXT(devs []string) []string {
	out := []string{"v=1", "runtime=" + Runtime}
	if len(devs) == 0 {
		out = append(out, "devs=")
		return out
	}
	sort.Strings(devs)
	const maxLen = 255 - len("devs=")
	joined := strings.Join(devs, ",")
	if len(joined) > maxLen {
		// Walk back until we fit. Each id is 8 chars + 1 comma = 9.
		// This is a worst-case truncation; we don't expect to hit it.
		joined = joined[:maxLen]
		if cut := strings.LastIndex(joined, ","); cut > 0 {
			joined = joined[:cut]
		}
	}
	out = append(out, "devs="+joined)
	return out
}

// Start advertises the broker and keeps the TXT record fresh. Returns
// nil + a no-op publisher when the bind is loopback (publication
// suppressed by design). Errors during initial Register are returned;
// later refresh failures are logged, not propagated, since the broker
// keeps serving regardless.
//
// lastReq reports when a device last hit the broker; it drives the idle
// re-announce watchdog and may be nil to disable it.
func Start(ctx context.Context, bind string, port int, lister devIDLister, lastReq func() time.Time, logger *log.Logger) (*Publisher, error) {
	if isLoopback(bind) {
		if logger != nil {
			logger.Printf("mdns: bind=%s is loopback, skipping broker advertisement", bind)
		}
		return &Publisher{}, nil
	}
	if lister == nil {
		return nil, fmt.Errorf("mdns: nil registry")
	}

	devs, err := lister.ListDeviceIDs()
	if err != nil {
		// Non-fatal: empty list still lets the device discover by
		// runtime tag, and the next refresh tick will retry.
		if logger != nil {
			logger.Printf("mdns: initial device list: %v", err)
		}
		devs = nil
	}
	txt := buildTXT(devs)

	instance := "tmon-broker-" + hostShort()
	ifaces := physicalMulticastIfaces()
	srv, err := registerService(instance, ServiceType, "local.", port, txt, ifaces)
	if err != nil {
		return nil, fmt.Errorf("mdns register: %w", err)
	}
	if logger != nil {
		names := make([]string, 0, len(ifaces))
		for _, i := range ifaces {
			names = append(names, i.Name)
		}
		logger.Printf("mdns: published %s.%s.local. port=%d devs=%d ifaces=%v",
			instance, ServiceType, port, len(devs), names)
	}

	p := &Publisher{
		server:    srv,
		lastTxt:   strings.Join(txt, ";"),
		lastIfp:   ifaceFingerprint(ifaces),
		instance:  instance,
		port:      port,
		lastReq:   lastReq,
		startedAt: time.Now(),
	}

	go p.refreshLoop(ctx, lister, logger)
	return p, nil
}

// refreshLoop polls the registry every 30s and pushes an updated TXT if
// the device list changed. Cheap (a single readdir) and bounded — we
// don't watch the filesystem to avoid bringing in inotify just for this.
// The same tick runs the idle-liveness watchdog (takeIdleReannounce).
func (p *Publisher) refreshLoop(ctx context.Context, lister devIDLister, logger *log.Logger) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			p.Close()
			return
		case <-t.C:
		}
		if !p.tick(lister, logger) {
			return
		}
	}
}

// tick runs one refresh pass, extracted from the loop so a test can drive it
// without opening multicast sockets. Each of the three causes folded into
// needRepub below must independently produce a republish; an `|| idle`
// quietly dropped from that expression is invisible to a test that only
// exercises takeIdleReannounce.
//
// Returns false when the publisher has been closed and the loop should stop.
func (p *Publisher) tick(lister devIDLister, logger *log.Logger) bool {
	devs, err := lister.ListDeviceIDs()
	if err != nil {
		if logger != nil {
			logger.Printf("mdns: refresh device list: %v", err)
		}
		return true
	}
	txt := buildTXT(devs)
	joined := strings.Join(txt, ";")

	// Interface addresses changed (DHCP renew, network switch): the
	// registered A records and the multicast sockets are both stale —
	// re-register from scratch. This is what lets a device rediscover
	// the broker after the host moves LANs. A nil server (previous
	// re-register failed, or initial addrs vanished) retries here too.
	ifaces := physicalMulticastIfaces()
	ifp := ifaceFingerprint(ifaces)
	// Liveness: nobody has talked to us in a while, so re-announce in
	// case it is our own advertisement that went stale. Consumed here
	// (not inside the branch below) so the backoff advances exactly once
	// per tick whatever the republish does.
	idle, idleFor := p.takeIdleReannounce(time.Now(), len(devs))
	if idle && logger != nil {
		logger.Printf("mdns: no device traffic for %ds, re-announcing", int(idleFor.Seconds()))
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return false
	}
	srv := p.server
	needRepub := ifp != p.lastIfp || srv == nil || idle
	p.mu.Unlock()

	if needRepub {
		if srv != nil {
			srv.Shutdown()
		}
		newSrv, err := registerService(p.instance, ServiceType, "local.", p.port, txt, ifaces)
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			if newSrv != nil {
				newSrv.Shutdown()
			}
			return false
		}
		if err != nil {
			// server == nil keeps needRepub true next tick.
			p.server = nil
			p.lastIfp = ifp
			p.mu.Unlock()
			if logger != nil {
				logger.Printf("mdns: republish: %v", err)
			}
			return true
		}
		p.server = newSrv
		p.lastIfp = ifp
		p.lastTxt = joined
		p.mu.Unlock()
		if logger != nil {
			why := "addresses changed"
			if idle {
				why = "idle"
			}
			logger.Printf("mdns: %s, republished %s.%s.local. port=%d devs=%d",
				why, p.instance, ServiceType, p.port, len(devs))
		}
		return true
	}

	p.mu.Lock()
	changed := joined != p.lastTxt
	if changed {
		p.lastTxt = joined
	}
	srv = p.server
	p.mu.Unlock()
	if changed && srv != nil {
		srv.SetText(txt)
		if logger != nil {
			logger.Printf("mdns: TXT updated, devs=%d", len(devs))
		}
	}
	return true
}

// Close releases the zeroconf server (idempotent). Safe to call after
// Start returned the loopback no-op publisher.
func (p *Publisher) Close() {
	p.mu.Lock()
	srv := p.server
	p.server = nil
	p.closed = true
	p.mu.Unlock()
	if srv != nil {
		srv.Shutdown()
	}
}
