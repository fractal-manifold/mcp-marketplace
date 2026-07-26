package usbprov

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Lease arbitration (leader side). The serial tailer runs only in the leader,
// so a follower that wants to open the port asks the leader — over the signed
// loopback endpoints in compat/PROVISION_WIRE.md §6 — to stop tailing it. The
// lease is the authority BETWEEN cooperating tokenmonitor-mcp processes; the
// OS-exclusive open (serial_linux.go) is the fence for everything the lease
// cannot see (election gaps, overrun leases, foreign programs).
//
// This type is the in-leader table. It is transport-agnostic (the broker mux
// wraps it) and clock-injectable (deadlines are monotonic — an NTP step must
// not expire a lease early or extend it; Go's time.Time carries a monotonic
// reading, and tests inject a fake clock).

// Defaults for TTL clamping.
const (
	defaultLeaseMaxTTL = 60 * time.Second
	defaultLeaseMinTTL = 1 * time.Second
)

// ErrLeaseBusy is returned by Grant when the canonical port is already leased.
var ErrLeaseBusy = errors.New("usbprov: port is already leased")

// ErrLeaseUnknown is returned by Renew for an unknown or expired lease — the
// client MUST then treat the port as lost and abort its session.
var ErrLeaseUnknown = errors.New("usbprov: lease is unknown or expired")

// SerialController is the leader's owner of the physical port(s) — in practice
// the firmware-log tailer. The lease manager calls it to hand a port to a
// lessee and to take it back. Both calls are keyed by canonical path; the
// controller no-ops for a port it does not own.
type SerialController interface {
	// SuspendPort stops reading canonical and releases its fd, blocking until
	// the port is free for a lessee to open. A no-op (nil) for an unowned port.
	SuspendPort(canonical string) error
	// ResumePort allows the owner to reacquire canonical (via its own
	// OS-exclusive open, which retries if a lessee still holds it).
	ResumePort(canonical string)
}

// NopController is a SerialController for a leader that tails no port (the
// serial device is unconfigured): every port is free, so Grant never has to
// suspend anything.
type NopController struct{}

func (NopController) SuspendPort(string) error { return nil }
func (NopController) ResumePort(string)        {}

type leaseEntry struct {
	id       string
	port     string        // canonical path
	granted  time.Duration // the clamped TTL granted; re-applied on a (ttl-less) renew
	deadline time.Time     // monotonic; the lease is dead once now >= deadline
}

// LeaseManager is the leader's per-port lease table.
type LeaseManager struct {
	mu     sync.Mutex
	ctrl   SerialController
	now    func() time.Time
	newID  func() string
	maxTTL time.Duration
	minTTL time.Duration
	byPort map[string]*leaseEntry
	byID   map[string]*leaseEntry
	// reserving holds ports with an in-flight Grant that has released m.mu to
	// call the (possibly blocking) SuspendPort. It reserves the port slot for the
	// duration of that call so a concurrent Grant on the same port fails busy,
	// without holding m.mu across the blocking suspend (which would stall every
	// other lease op — see the reservation dance in Grant).
	reserving map[string]bool
}

// NewLeaseManager builds a manager over ctrl. maxTTL<=0 uses the default.
func NewLeaseManager(ctrl SerialController, maxTTL time.Duration) *LeaseManager {
	if maxTTL <= 0 {
		maxTTL = defaultLeaseMaxTTL
	}
	return &LeaseManager{
		ctrl:      ctrl,
		now:       time.Now,
		newID:     randomLeaseID,
		maxTTL:    maxTTL,
		minTTL:    defaultLeaseMinTTL,
		byPort:    map[string]*leaseEntry{},
		byID:      map[string]*leaseEntry{},
		reserving: map[string]bool{},
	}
}

// Grant leases canonical for up to ttl. On success it has already suspended the
// controller's tailer on that port, so the caller may open it. Returns the
// lease id, the granted (clamped) ttl, and the informational wall-clock expiry.
func (m *LeaseManager) Grant(canonical string, ttl time.Duration) (id string, granted time.Duration, expires time.Time, err error) {
	// Phase 1 (under m.mu): reap lapsed leases, reject if the port is already
	// leased or being reserved by a concurrent Grant, then reserve the slot.
	m.mu.Lock()
	m.reapLocked()
	if _, held := m.byPort[canonical]; held || m.reserving[canonical] {
		m.mu.Unlock()
		return "", 0, time.Time{}, ErrLeaseBusy
	}
	m.reserving[canonical] = true
	m.mu.Unlock()

	// Phase 2 (WITHOUT m.mu): hand the port to the lessee. SuspendPort blocks
	// until the tailer's fd + port lock are freed; holding m.mu across it would
	// stall Renew/Release/reap for every port. The `reserving` slot keeps this
	// port exclusive meanwhile.
	suspendErr := m.ctrl.SuspendPort(canonical)

	// Phase 3 (under m.mu): commit the lease, or roll back on suspend failure.
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.reserving, canonical)
	if suspendErr != nil {
		// The owner could not fully yield the port: undo any partial suspend so
		// the tailer resumes, and create no lease.
		m.ctrl.ResumePort(canonical)
		return "", 0, time.Time{}, suspendErr
	}
	granted = m.clampTTL(ttl)
	now := m.now()
	e := &leaseEntry{id: m.newID(), port: canonical, granted: granted, deadline: now.Add(granted)}
	m.byPort[canonical] = e
	m.byID[e.id] = e
	return e.id, granted, now.Add(granted), nil
}

// Renew extends an existing lease by re-applying its original granted TTL. The
// renew request carries no TTL of its own (PROVISION_WIRE §6) — the lease
// remembers what it was granted — so a {lease_id}-only renew can never
// accidentally clamp the window down to the floor. Returns ErrLeaseUnknown if
// the lease is gone or already expired (the client must then abort).
func (m *LeaseManager) Renew(id string) (granted time.Duration, expires time.Time, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.byID[id]
	if !ok || !m.now().Before(e.deadline) {
		// Unknown, or lapsed: reap it so the port frees, and refuse.
		if ok {
			m.dropLocked(e)
		}
		return 0, time.Time{}, ErrLeaseUnknown
	}
	now := m.now()
	e.deadline = now.Add(e.granted)
	return e.granted, now.Add(e.granted), nil
}

// Release drops a lease and resumes the owner. Idempotent — an unknown id is a
// success (a client releasing after its lease already expired must still see ok).
func (m *LeaseManager) Release(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.byID[id]; ok {
		m.dropLocked(e)
	}
}

// ReapExpired drops every lapsed lease (resuming the owner for each). The
// leader runs this on a ticker so a crashed follower's lease cannot wedge the
// tailer forever. Returns how many were reclaimed.
func (m *LeaseManager) ReapExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reapLocked()
}

func (m *LeaseManager) reapLocked() int {
	now := m.now()
	n := 0
	for _, e := range m.byID {
		if !now.Before(e.deadline) {
			m.dropLocked(e)
			n++
		}
	}
	return n
}

// dropLocked removes a lease from both indices and resumes the owner. Caller
// holds m.mu.
func (m *LeaseManager) dropLocked(e *leaseEntry) {
	delete(m.byID, e.id)
	// Only resume the owner if this entry still owns the port slot (a lease
	// could have been superseded on the same port by a reap+regrant, though the
	// mutex makes that impossible here — defensive).
	if cur, ok := m.byPort[e.port]; ok && cur == e {
		delete(m.byPort, e.port)
	}
	m.ctrl.ResumePort(e.port)
}

func (m *LeaseManager) clampTTL(ttl time.Duration) time.Duration {
	if ttl > m.maxTTL {
		return m.maxTTL
	}
	if ttl < m.minTTL {
		return m.minTTL
	}
	return ttl
}

// randomLeaseID returns 16 bytes of crypto entropy as 32 lowercase hex chars.
func randomLeaseID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is catastrophic and unrecoverable; a predictable
		// id would let another local process guess it, so panic rather than
		// hand out a weak token.
		panic("usbprov: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
