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
type Publisher struct {
	server   *zeroconf.Server
	mu       sync.Mutex
	lastTxt  string
	lastIfp  string // fingerprint of the advertised interface addresses
	instance string
	port     int
	closed   bool
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
func Start(ctx context.Context, bind string, port int, lister devIDLister, logger *log.Logger) (*Publisher, error) {
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
	srv, err := zeroconf.Register(instance, ServiceType, "local.", port, txt, ifaces)
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
		server:   srv,
		lastTxt:  strings.Join(txt, ";"),
		lastIfp:  ifaceFingerprint(ifaces),
		instance: instance,
		port:     port,
	}

	go p.refreshLoop(ctx, lister, logger)
	return p, nil
}

// refreshLoop polls the registry every 30s and pushes an updated TXT if
// the device list changed. Cheap (a single readdir) and bounded — we
// don't watch the filesystem to avoid bringing in inotify just for this.
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
		devs, err := lister.ListDeviceIDs()
		if err != nil {
			if logger != nil {
				logger.Printf("mdns: refresh device list: %v", err)
			}
			continue
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
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		srv := p.server
		needRepub := ifp != p.lastIfp || srv == nil
		p.mu.Unlock()

		if needRepub {
			if srv != nil {
				srv.Shutdown()
			}
			newSrv, err := zeroconf.Register(p.instance, ServiceType, "local.", p.port, txt, ifaces)
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				if newSrv != nil {
					newSrv.Shutdown()
				}
				return
			}
			if err != nil {
				// server == nil keeps needRepub true next tick.
				p.server = nil
				p.lastIfp = ifp
				p.mu.Unlock()
				if logger != nil {
					logger.Printf("mdns: republish: %v", err)
				}
				continue
			}
			p.server = newSrv
			p.lastIfp = ifp
			p.lastTxt = joined
			p.mu.Unlock()
			if logger != nil {
				logger.Printf("mdns: addresses changed, republished %s.%s.local. port=%d devs=%d",
					p.instance, ServiceType, p.port, len(devs))
			}
			continue
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
	}
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
