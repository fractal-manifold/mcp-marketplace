package mdns

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildTXTDedupSortAndRuntime(t *testing.T) {
	txt := buildTXT([]string{"bb", "aa"})
	if txt[0] != "v=1" || txt[1] != "runtime=go" {
		t.Fatalf("header entries wrong: %v", txt)
	}
	if txt[2] != "devs=aa,bb" {
		t.Fatalf("devs entry wrong: %v", txt[2])
	}
}

func TestBuildTXTEmpty(t *testing.T) {
	txt := buildTXT(nil)
	if txt[len(txt)-1] != "devs=" {
		t.Fatalf("empty list must still publish devs=: %v", txt)
	}
}

func TestBuildTXTCapsAtWholeIDBoundary(t *testing.T) {
	var ids []string
	for i := 0; i < 40; i++ { // 40×9 bytes joined > 250 cap
		ids = append(ids, fmt.Sprintf("%08x", i))
	}
	txt := buildTXT(ids)
	devs := strings.TrimPrefix(txt[len(txt)-1], "devs=")
	if len(devs) > 255-len("devs=") {
		t.Fatalf("devs over cap: %d", len(devs))
	}
	if strings.HasSuffix(devs, ",") {
		t.Fatalf("devs ends mid-boundary: %q", devs)
	}
	for _, id := range strings.Split(devs, ",") {
		if len(id) != 8 {
			t.Fatalf("truncated id survived: %q", id)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for bind, want := range map[string]bool{
		"":              false,
		"0.0.0.0":       false,
		"::":            false,
		"127.0.0.1":     true,
		"::1":           true,
		"192.168.1.142": false,
	} {
		if got := isLoopback(bind); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", bind, got, want)
		}
	}
}

func TestIfaceFingerprintEmptyAndDeterministic(t *testing.T) {
	if got := ifaceFingerprint(nil); got != "" {
		t.Fatalf("nil ifaces must fingerprint to empty, got %q", got)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("no interfaces: %v", err)
	}
	a := ifaceFingerprint(ifaces)
	b := ifaceFingerprint(ifaces)
	if a != b {
		t.Fatalf("fingerprint not deterministic: %q vs %q", a, b)
	}
}

// --- idle-liveness watchdog -------------------------------------------
//
// The device recovers from a moved broker by querying us (see
// firmware/components/net/src/cred_client.c). This watchdog covers the other
// failure: our own advertisement went stale — flapping interface, wedged
// zeroconf server, an announcement lost in a lossy multicast domain — so no
// query of theirs is answered. Everything below is about not turning that
// into a permanent multicast beacon aimed at a device that is simply off.

func TestReannounceGapFloorDoublesToCeiling(t *testing.T) {
	want := []time.Duration{
		30 * time.Second, 30 * time.Second, 60 * time.Second,
		120 * time.Second, 240 * time.Second, 5 * time.Minute, 5 * time.Minute,
	}
	for attempts, w := range want {
		if got := reannounceGap(attempts); got != w {
			t.Errorf("reannounceGap(%d) = %v, want %v", attempts, got, w)
		}
	}
}

func TestShouldReannounceNeedsAnIdleBrokerWithDevices(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var never time.Time

	if shouldReannounce(now, now.Add(-time.Hour), never, 0, 0) {
		t.Error("no registered device: nobody our advertisement could help")
	}
	if shouldReannounce(now, now.Add(-29*time.Second), never, 0, 1) {
		t.Error("29 s of quiet is not idle yet")
	}
	if !shouldReannounce(now, now.Add(-30*time.Second), never, 0, 1) {
		t.Error("30 s with a registered device must re-announce")
	}
}

func TestShouldReannounceRespectsTheBackoff(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	idle := now.Add(-time.Hour)

	if shouldReannounce(now, idle, now.Add(-29*time.Second), 1, 1) {
		t.Error("29 s after the first re-announce is inside the 30 s floor")
	}
	if !shouldReannounce(now, idle, now.Add(-30*time.Second), 1, 1) {
		t.Error("30 s after the first re-announce is due")
	}
	// Third re-announce onwards the gap doubles: 60 s, not 30.
	if shouldReannounce(now, idle, now.Add(-59*time.Second), 2, 1) {
		t.Error("gap must have widened to 60 s after two re-announces")
	}
	if !shouldReannounce(now, idle, now.Add(-60*time.Second), 2, 1) {
		t.Error("60 s after two re-announces is due")
	}
}

func TestTakeIdleReannounceBacksOffThenResetsOnTraffic(t *testing.T) {
	lastReq := time.Unix(1_700_000_000, 0)
	p := &Publisher{lastReq: func() time.Time { return lastReq }, startedAt: lastReq}

	now := lastReq
	if fired, _ := p.takeIdleReannounce(now.Add(29*time.Second), 1); fired {
		t.Fatal("fired before the idle threshold")
	}

	// Walk the backoff: the first re-announce is immediate, then 30, 60, 120,
	// 240 and a 300 s ceiling.
	now = now.Add(30 * time.Second)
	fired, idleFor := p.takeIdleReannounce(now, 1)
	if !fired {
		t.Fatal("first idle re-announce did not fire")
	}
	if idleFor != 30*time.Second {
		t.Fatalf("idleFor = %v, want 30s", idleFor)
	}
	for _, gap := range []time.Duration{30, 60, 120, 240, 300, 300} {
		gap *= time.Second
		if fired, _ := p.takeIdleReannounce(now.Add(gap-time.Second), 1); fired {
			t.Fatalf("fired one second early inside a %v gap", gap)
		}
		now = now.Add(gap)
		if fired, _ := p.takeIdleReannounce(now, 1); !fired {
			t.Fatalf("did not fire at the end of a %v gap", gap)
		}
	}

	// A device comes back: the next tick must find the watchdog disarmed and
	// back at the floor, not still out at five minutes.
	lastReq = now.Add(time.Second)
	if fired, _ := p.takeIdleReannounce(now.Add(2*time.Second), 1); fired {
		t.Fatal("fired while traffic was flowing")
	}
	if fired, _ := p.takeIdleReannounce(now.Add(32*time.Second), 1); !fired {
		t.Fatal("after traffic stopped again the floor must be 30 s, not the old ceiling")
	}
}

func TestTakeIdleReannounceNeverFiresWithoutDevicesOrAReader(t *testing.T) {
	lastReq := time.Unix(1_700_000_000, 0)
	p := &Publisher{lastReq: func() time.Time { return lastReq }, startedAt: lastReq}
	if fired, _ := p.takeIdleReannounce(lastReq.Add(time.Hour), 0); fired {
		t.Error("no registered devices: must stay quiet")
	}

	// The loopback no-op publisher has no reader at all.
	noop := &Publisher{}
	if fired, _ := noop.takeIdleReannounce(time.Now(), 3); fired {
		t.Error("a publisher with no lastReq reader must never re-announce")
	}
}

func TestTakeIdleReannounceUsesStartTimeBeforeAnyRequest(t *testing.T) {
	// A broker that has never been hit still has registered devices — one may
	// be booting right now with a stale URL. Idle is measured from start.
	started := time.Unix(1_700_000_000, 0)
	p := &Publisher{lastReq: func() time.Time { return time.Time{} }, startedAt: started}

	if fired, _ := p.takeIdleReannounce(started.Add(29*time.Second), 1); fired {
		t.Error("fired before the threshold elapsed since start")
	}
	if fired, _ := p.takeIdleReannounce(started.Add(30*time.Second), 1); !fired {
		t.Error("must re-announce 30 s after start with no device ever seen")
	}
}

func TestTakeIdleReannounceResetsOnTrafficSeenOnlyBetweenTicks(t *testing.T) {
	// The loop ticks at the same 30 s as the idle threshold, so a request that
	// lands just after a tick is already ~30 s old when the next one looks at
	// it. Resetting on "is this request recent?" would miss it to scheduling
	// jitter and leave the backoff out at its five-minute ceiling.
	lastReq := time.Unix(1_700_000_000, 0)
	p := &Publisher{lastReq: func() time.Time { return lastReq }, startedAt: lastReq}

	// Drive the backoff out to the ceiling.
	now := lastReq.Add(30 * time.Second)
	for _, gap := range []time.Duration{0, 30, 60, 120, 240, 300} {
		now = now.Add(gap * time.Second)
		if fired, _ := p.takeIdleReannounce(now, 1); !fired {
			t.Fatalf("setup: expected a re-announce at +%v", gap)
		}
	}

	// A device hits us, and the next tick lands 31 s later — never inside the
	// threshold, so only the "have I seen this request before?" test catches it.
	lastReq = now.Add(5 * time.Second)
	if fired, _ := p.takeIdleReannounce(lastReq.Add(31*time.Second), 1); !fired {
		t.Fatal("traffic seen only between ticks must reset the backoff to the floor")
	}
}

// --- the refresh tick actually republishes -------------------------------
// takeIdleReannounce returning true proves nothing on its own: tick() has to
// go on and republish. Each of the three causes folded into needRepub is
// exercised alone, so an `|| idle` dropped from it fails exactly one of them.
// Mirrors py test_tick_republishes_* and js "tick republishes when ...".

type fakeServer struct {
	shutdowns int
	setTexts  int
}

func (f *fakeServer) Shutdown()          { f.shutdowns++ }
func (f *fakeServer) SetText(_ []string) { f.setTexts++ }

type oneDeviceLister struct{}

func (oneDeviceLister) ListDeviceIDs() ([]string, error) { return []string{"aa11bb22"}, nil }

// tickHarness builds a Publisher whose republish is a counter rather than a
// multicast socket. `staleIfp` picks whether the interface fingerprint looks
// changed; everything else is held steady so exactly one cause can fire.
func tickHarness(t *testing.T, srv mdnsServer, staleIfp bool, lastReq func() time.Time) (*Publisher, *int) {
	t.Helper()
	registers := 0
	orig := registerService
	registerService = func(_, _, _ string, _ int, _ []string, _ []net.Interface) (mdnsServer, error) {
		registers++
		return &fakeServer{}, nil
	}
	t.Cleanup(func() { registerService = orig })

	ifp := ifaceFingerprint(physicalMulticastIfaces())
	if staleIfp {
		ifp = "stale-fingerprint"
	}
	p := &Publisher{
		server:   srv,
		lastTxt:  strings.Join(buildTXT([]string{"aa11bb22"}), ";"),
		lastIfp:  ifp,
		instance: "tmon-broker-test",
		port:     8765,
		lastReq:  lastReq,
	}
	return p, &registers
}

func TestTickRepublishesWhenIdle(t *testing.T) {
	srv := &fakeServer{}
	p, registers := tickHarness(t, srv, false, func() time.Time { return time.Now().Add(-60 * time.Second) })
	if !p.tick(oneDeviceLister{}, nil) {
		t.Fatal("tick must keep the loop running")
	}
	if *registers != 1 {
		t.Fatalf("an idle tick must republish: registers=%d", *registers)
	}
	if srv.shutdowns != 1 {
		t.Fatalf("and tear the old advertisement down first: shutdowns=%d", srv.shutdowns)
	}
}

func TestTickRepublishesWhenAddressesChanged(t *testing.T) {
	p, registers := tickHarness(t, &fakeServer{}, true, time.Now)
	p.tick(oneDeviceLister{}, nil)
	if *registers != 1 {
		t.Fatalf("a changed fingerprint must republish: registers=%d", *registers)
	}
}

func TestTickRepublishesWhenServerIsDown(t *testing.T) {
	p, registers := tickHarness(t, nil, false, time.Now)
	p.tick(oneDeviceLister{}, nil)
	if *registers != 1 {
		t.Fatalf("a down publisher must be retried: registers=%d", *registers)
	}
}

func TestTickIsQuietWhenNothingChanged(t *testing.T) {
	srv := &fakeServer{}
	p, registers := tickHarness(t, srv, false, time.Now)
	p.tick(oneDeviceLister{}, nil)
	if *registers != 0 {
		t.Fatalf("a quiet tick must not republish: registers=%d", *registers)
	}
	if srv.shutdowns != 0 || srv.setTexts != 0 {
		t.Fatalf("a quiet tick must not touch the server: %+v", *srv)
	}
}

// A failed republish must leave the publisher retryable: tick() advances
// lastIfp on failure, so `srv == nil` is the only term left that can fire.
func TestTickRetriesAfterAFailedRepublish(t *testing.T) {
	p, _ := tickHarness(t, &fakeServer{}, true, time.Now)
	registerService = func(_, _, _ string, _ int, _ []string, _ []net.Interface) (mdnsServer, error) {
		return nil, fmt.Errorf("register refused")
	}
	p.tick(oneDeviceLister{}, nil)
	if p.server != nil {
		t.Fatal("a failed republish must leave the server nil, not a typed nil")
	}

	retries := 0
	registerService = func(_, _, _ string, _ int, _ []string, _ []net.Interface) (mdnsServer, error) {
		retries++
		return &fakeServer{}, nil
	}
	p.tick(oneDeviceLister{}, nil)
	if retries != 1 {
		t.Fatalf("the next tick must retry the republish: retries=%d", retries)
	}
}
