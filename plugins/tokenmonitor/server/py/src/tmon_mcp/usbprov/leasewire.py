"""Wire types and paths for the leader-mediated serial lease
(compat/PROVISION_WIRE.md §6). A follower POSTs these, signed with the shared
PSK, to the leader's loopback broker; the leader's LeaseManager services them.
Port of tokenmonitor-mcp/internal/usbprov/leasewire.go. What is contractual is
the FIELD shape below, not the exact bytes: Python's encoder emits `{"a": 1}`
where Go and JS emit `{"a":1}`. That is harmless because a request is signed over
the bytes it actually sends and a response body is not signed at all — but it
does mean a test may never compare raw JSON across runtimes."""

from __future__ import annotations

# Lease endpoint paths (exact, no trailing slash). Signed over verbatim.
LEASE_PATH = "/serial/lease"
LEASE_RENEW_PATH = "/serial/lease/renew"
LEASE_RELEASE_PATH = "/serial/lease/release"

# JSON field shapes (mirror of leasewire.go — these names ARE the contract).
#   LeaseRequest:  {"port": str, "ttl_ms": int}
#   LeaseResponse: {"lease_id": str, "port": str, "ttl_ms": int,
#                   "expires_unix_ms": int}
#   RenewRequest:  {"lease_id": str}
#   RenewResponse: {"ttl_ms": int, "expires_unix_ms": int}
#   ReleaseRequest:{"lease_id": str}
#
# LeaseResponse.port echoes the CANONICAL path the leader keyed the lease on
# (the follower may have asked with an alias such as /dev/esp32s3).
# expires_unix_ms is informational wall-clock only — the leader tracks expiry on
# a monotonic clock, so client clock skew cannot move the real deadline.
#
# RenewRequest deliberately carries no ttl_ms: the leader re-applies the TTL it
# originally granted, so a renew can never shrink the window. A leader that read
# a ttl_ms here would see 0 from a conforming follower and clamp the lease to
# the 1 s floor mid-session.
