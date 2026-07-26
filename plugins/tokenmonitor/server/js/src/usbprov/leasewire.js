// Wire paths for the leader-mediated serial lease (compat/PROVISION_WIRE.md §6).
// A follower POSTs these, signed with the shared PSK, to the leader's loopback
// broker; the leader's LeaseManager services them. Kept in one place so all
// three runtimes serialise byte-identically.

// Lease endpoint paths (exact, no trailing slash). Signed over verbatim.
export const LEASE_PATH = "/serial/lease";
export const LEASE_RENEW_PATH = "/serial/lease/renew";
export const LEASE_RELEASE_PATH = "/serial/lease/release";

// JSON field shapes (mirror of go/internal/usbprov/leasewire.go — these names
// ARE the contract):
//   LeaseRequest:   { port, ttl_ms }
//   LeaseResponse:  { lease_id, port, ttl_ms, expires_unix_ms }
//   RenewRequest:   { lease_id }
//   RenewResponse:  { ttl_ms, expires_unix_ms }
//   ReleaseRequest: { lease_id }
//
// LeaseResponse.port echoes the CANONICAL path the leader keyed the lease on
// (the follower may have asked with an alias such as /dev/esp32s3).
// expires_unix_ms is informational wall-clock only — the leader tracks expiry
// on a monotonic clock, so client clock skew cannot move the real deadline.
//
// RenewRequest deliberately carries no ttl_ms: the leader re-applies the TTL it
// originally granted, so a renew can never shrink the window.
