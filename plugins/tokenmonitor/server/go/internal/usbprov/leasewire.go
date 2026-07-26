package usbprov

// Wire types and paths for the leader-mediated serial lease
// (compat/PROVISION_WIRE.md §6). A follower POSTs these, signed with the shared
// PSK, to the leader's loopback broker; the leader's LeaseManager services them.
// Kept in one place so all three runtimes — and the Go broker handler and Go
// follower client — serialise byte-identically.

// Lease endpoint paths (exact, no trailing slash). Signed over verbatim.
const (
	LeasePath        = "/serial/lease"
	LeaseRenewPath   = "/serial/lease/renew"
	LeaseReleasePath = "/serial/lease/release"
)

// LeaseRequest asks the leader to suspend its tailer on Port and grant a lease.
// Port is the raw device path as the follower sees it; the leader canonicalises
// it (Abs + EvalSymlinks) so an alias and the real node share one lease slot.
type LeaseRequest struct {
	Port      string `json:"port"`
	TTLMillis int64  `json:"ttl_ms"`
}

// LeaseResponse is the granted lease (PROVISION_WIRE §6). Port echoes the
// canonical path the leader keyed the lease on. TTLMillis is the (clamped) TTL
// the follower must renew within; ExpiresUnixMillis is informational wall-clock
// only (the leader tracks expiry on a monotonic clock, so a client clock skew
// cannot extend or shorten the real deadline).
type LeaseResponse struct {
	LeaseID           string `json:"lease_id"`
	Port              string `json:"port"`
	TTLMillis         int64  `json:"ttl_ms"`
	ExpiresUnixMillis int64  `json:"expires_unix_ms"`
}

// RenewRequest extends an existing lease before it lapses. It carries ONLY the
// lease id (PROVISION_WIRE §6): the leader re-applies the lease's original
// granted TTL, so a renew can never accidentally shrink the window (an omitted
// ttl_ms must not clamp to the floor).
type RenewRequest struct {
	LeaseID string `json:"lease_id"`
}

// RenewResponse mirrors LeaseResponse minus the id/port (both unchanged).
type RenewResponse struct {
	TTLMillis         int64 `json:"ttl_ms"`
	ExpiresUnixMillis int64 `json:"expires_unix_ms"`
}

// ReleaseRequest ends a lease early so the leader resumes tailing. Release is
// idempotent — an unknown or already-expired id still returns success.
type ReleaseRequest struct {
	LeaseID string `json:"lease_id"`
}
