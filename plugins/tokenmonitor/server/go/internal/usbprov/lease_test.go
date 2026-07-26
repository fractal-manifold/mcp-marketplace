package usbprov

import (
	"sync"
	"testing"
	"time"
)

// fakeController records suspend/resume calls per port.
type fakeController struct {
	mu       sync.Mutex
	suspend  map[string]int
	resume   map[string]int
	failPort string // SuspendPort returns an error for this port
}

func newFakeController() *fakeController {
	return &fakeController{suspend: map[string]int{}, resume: map[string]int{}}
}

func (c *fakeController) SuspendPort(p string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p == c.failPort {
		return errTimeout // any non-nil error
	}
	c.suspend[p]++
	return nil
}

func (c *fakeController) ResumePort(p string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resume[p]++
}

func (c *fakeController) counts(p string) (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.suspend[p], c.resume[p]
}

// newTestManager builds a manager with a controllable clock, deterministic ids.
func newTestManager(ctrl SerialController) (*LeaseManager, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	var n int
	m := NewLeaseManager(ctrl, 10*time.Second)
	m.now = clk.now
	m.newID = func() string { n++; return "lease" + string(rune('0'+n)) }
	return m, clk
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestLease_GrantSuspendsAndReleaseResumes(t *testing.T) {
	ctrl := newFakeController()
	m, _ := newTestManager(ctrl)

	id, granted, _, err := m.Grant("/dev/ttyACM0", 5*time.Second)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if granted != 5*time.Second {
		t.Errorf("granted = %v, want 5s", granted)
	}
	if s, r := ctrl.counts("/dev/ttyACM0"); s != 1 || r != 0 {
		t.Errorf("after grant suspend=%d resume=%d, want 1/0", s, r)
	}
	m.Release(id)
	if s, r := ctrl.counts("/dev/ttyACM0"); s != 1 || r != 1 {
		t.Errorf("after release suspend=%d resume=%d, want 1/1", s, r)
	}
	// Release is idempotent.
	m.Release(id)
	if _, r := ctrl.counts("/dev/ttyACM0"); r != 1 {
		t.Errorf("double release resumed twice: resume=%d", r)
	}
}

func TestLease_SecondGrantOnSamePortIsBusy(t *testing.T) {
	ctrl := newFakeController()
	m, _ := newTestManager(ctrl)
	if _, _, _, err := m.Grant("/dev/ttyACM0", time.Second); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := m.Grant("/dev/ttyACM0", time.Second); err != ErrLeaseBusy {
		t.Fatalf("second grant: want ErrLeaseBusy, got %v", err)
	}
	// A different port is free.
	if _, _, _, err := m.Grant("/dev/ttyACM1", time.Second); err != nil {
		t.Fatalf("distinct port grant: %v", err)
	}
}

func TestLease_TTLClamped(t *testing.T) {
	m, _ := newTestManager(newFakeController())
	if _, granted, _, _ := m.Grant("/dev/ttyACM0", time.Hour); granted != 10*time.Second {
		t.Errorf("over-max ttl not clamped: %v", granted)
	}
	if _, granted, _, _ := m.Grant("/dev/ttyACM1", time.Millisecond); granted != defaultLeaseMinTTL {
		t.Errorf("under-min ttl not clamped: %v", granted)
	}
}

func TestLease_RenewExtendsAndRejectsExpired(t *testing.T) {
	ctrl := newFakeController()
	m, clk := newTestManager(ctrl)
	id, _, _, _ := m.Grant("/dev/ttyACM0", 5*time.Second)

	clk.advance(3 * time.Second) // still alive
	// Renew carries no TTL: the lease re-applies its ORIGINAL granted 5s.
	if got, _, err := m.Renew(id); err != nil {
		t.Fatalf("renew while alive: %v", err)
	} else if got != 5*time.Second {
		t.Fatalf("renew re-granted %v, want the original 5s", got)
	}
	// Now deadline is +5s from t=3s → t=8s. Advance past it.
	clk.advance(6 * time.Second) // t=9s > 8s
	if _, _, err := m.Renew(id); err != ErrLeaseUnknown {
		t.Fatalf("renew after expiry: want ErrLeaseUnknown, got %v", err)
	}
	// A failed renew must have freed the port (resumed the owner).
	if _, r := ctrl.counts("/dev/ttyACM0"); r != 1 {
		t.Errorf("expired renew did not resume owner: resume=%d", r)
	}
}

func TestLease_ReapExpiredResumesOwner(t *testing.T) {
	ctrl := newFakeController()
	m, clk := newTestManager(ctrl)
	m.Grant("/dev/ttyACM0", 2*time.Second)
	m.Grant("/dev/ttyACM1", 8*time.Second)

	clk.advance(3 * time.Second) // ACM0 expired, ACM1 alive
	if n := m.ReapExpired(); n != 1 {
		t.Fatalf("reaped %d, want 1", n)
	}
	if _, r0 := ctrl.counts("/dev/ttyACM0"); r0 != 1 {
		t.Errorf("expired port not resumed: %d", r0)
	}
	if _, r1 := ctrl.counts("/dev/ttyACM1"); r1 != 0 {
		t.Errorf("live port wrongly resumed: %d", r1)
	}
	// The reaped port is grantable again.
	if _, _, _, err := m.Grant("/dev/ttyACM0", time.Second); err != nil {
		t.Errorf("re-grant after reap: %v", err)
	}
}

func TestLease_GrantFailsIfControllerCannotYield(t *testing.T) {
	ctrl := newFakeController()
	ctrl.failPort = "/dev/ttyACM0"
	m, _ := newTestManager(ctrl)
	if _, _, _, err := m.Grant("/dev/ttyACM0", time.Second); err == nil {
		t.Fatal("grant must fail when the owner cannot yield the port")
	}
	// No lease recorded, so the port is not marked busy.
	ctrl.failPort = ""
	if _, _, _, err := m.Grant("/dev/ttyACM0", time.Second); err != nil {
		t.Fatalf("port should be free after a failed grant: %v", err)
	}
}

// gateController blocks SuspendPort(gatedPort) on a channel until the test
// releases it, modelling a slow tailer yield. It must NOT hold a lock while
// blocking, or ResumePort/counts on other ports would wedge.
type gateController struct {
	mu         sync.Mutex
	suspend    map[string]int
	resume     map[string]int
	gatedPort  string
	gate       chan struct{}
	suspending chan struct{} // closed-style signal: one send when the gated suspend is entered
}

func newGateController(gated string) *gateController {
	return &gateController{
		suspend:    map[string]int{},
		resume:     map[string]int{},
		gatedPort:  gated,
		gate:       make(chan struct{}),
		suspending: make(chan struct{}, 1),
	}
}

func (c *gateController) SuspendPort(p string) error {
	if p == c.gatedPort {
		select {
		case c.suspending <- struct{}{}:
		default:
		}
		<-c.gate // block until the test releases us — no lock held
	}
	c.mu.Lock()
	c.suspend[p]++
	c.mu.Unlock()
	return nil
}

func (c *gateController) ResumePort(p string) {
	c.mu.Lock()
	c.resume[p]++
	c.mu.Unlock()
}

// TestLease_SlowSuspendDoesNotBlockOtherPorts proves Grant no longer holds the
// manager mutex across the (blocking) SuspendPort: a stuck suspend on ACM0 must
// not stall a Grant/Release on ACM1, and a concurrent Grant on ACM0 must fail
// busy while the first is mid-suspend.
func TestLease_SlowSuspendDoesNotBlockOtherPorts(t *testing.T) {
	ctrl := newGateController("/dev/ttyACM0")
	m := NewLeaseManager(ctrl, 10*time.Second) // real clock + random ids: this is a concurrency test

	// Start a Grant on the gated port; it blocks inside SuspendPort.
	grantDone := make(chan error, 1)
	go func() {
		_, _, _, err := m.Grant("/dev/ttyACM0", 5*time.Second)
		grantDone <- err
	}()
	select {
	case <-ctrl.suspending:
	case <-time.After(2 * time.Second):
		t.Fatal("gated Grant never entered SuspendPort")
	}

	// While ACM0's suspend is stuck, an unrelated port must lease + release fast.
	other := make(chan error, 1)
	go func() {
		id, _, _, err := m.Grant("/dev/ttyACM1", time.Second)
		if err == nil {
			m.Release(id)
		}
		other <- err
	}()
	select {
	case err := <-other:
		if err != nil {
			t.Fatalf("unrelated port grant blocked/failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unrelated port grant stalled behind a slow suspend — m.mu held across SuspendPort")
	}

	// A concurrent Grant on the still-reserving port must report busy, not block.
	if _, _, _, err := m.Grant("/dev/ttyACM0", time.Second); err != ErrLeaseBusy {
		t.Fatalf("concurrent same-port grant during suspend: want ErrLeaseBusy, got %v", err)
	}

	// Release the gate; the first Grant now commits.
	close(ctrl.gate)
	select {
	case err := <-grantDone:
		if err != nil {
			t.Fatalf("gated Grant failed after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gated Grant never completed after gate release")
	}
}

func TestRandomLeaseID_UniqueAndHex(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := randomLeaseID()
		if len(id) != 32 {
			t.Fatalf("id len = %d, want 32", len(id))
		}
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("non-hex char in id %q", id)
			}
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}
