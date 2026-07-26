"""Lease arbitration (leader side).

Port of tokenmonitor-mcp/internal/usbprov/lease.go. The serial tailer runs only
in the leader, so a follower that wants to open the port asks the leader — over
the signed loopback endpoints in compat/PROVISION_WIRE.md §6 — to stop tailing
it. The lease is the authority BETWEEN cooperating tokenmonitor-mcp processes;
the OS-exclusive open (serial_port.py) is the fence for everything the lease
cannot see.

Deadlines are monotonic (time.monotonic) — an NTP step must not expire a lease
early or extend it; a fake clock is injectable for tests.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from typing import Callable, Protocol

# Defaults for TTL clamping (seconds).
DEFAULT_LEASE_MAX_TTL = 60.0
DEFAULT_LEASE_MIN_TTL = 1.0


class LeaseBusy(Exception):
    """Raised by grant() when the canonical port is already leased."""


class LeaseUnknown(Exception):
    """Raised by renew() for an unknown or expired lease — the client MUST then
    treat the port as lost and abort its session."""


class SerialController(Protocol):
    """The leader's owner of the physical port(s) — in practice the
    firmware-log tailer. Both calls are keyed by canonical path; the controller
    no-ops for a port it does not own."""

    def suspend_port(self, canonical: str) -> None:
        """Stop reading canonical and release its fd, blocking until the port is
        free for a lessee to open. A no-op for an unowned port. Raises on a
        failure to yield."""

    def resume_port(self, canonical: str) -> None:
        """Allow the owner to reacquire canonical."""


class NopController:
    """A SerialController for a leader that tails no port (the serial device is
    unconfigured): every port is free, so grant never has to suspend
    anything."""

    def suspend_port(self, canonical: str) -> None:
        return None

    def resume_port(self, canonical: str) -> None:
        return None


@dataclass
class _LeaseEntry:
    id: str
    port: str  # canonical path
    deadline: float  # monotonic; the lease is dead once now >= deadline
    granted: float  # the clamped TTL this lease was granted; renew re-applies it


class LeaseManager:
    """The leader's per-port lease table."""

    def __init__(
        self,
        ctrl: SerialController,
        max_ttl: float = 0.0,
        *,
        now: Callable[[], float] | None = None,
        new_id: Callable[[], str] | None = None,
    ) -> None:
        self._ctrl = ctrl
        self._mu = threading.Lock()
        self._now = now or __import__("time").monotonic
        self._new_id = new_id or random_lease_id
        self._max_ttl = max_ttl if max_ttl > 0 else DEFAULT_LEASE_MAX_TTL
        self._min_ttl = DEFAULT_LEASE_MIN_TTL
        self._by_port: dict[str, _LeaseEntry] = {}
        self._by_id: dict[str, _LeaseEntry] = {}
        # ports with an in-flight grant that has released the lock to call the
        # (possibly blocking) suspend_port — reserves the slot without holding
        # the lock across the blocking suspend.
        self._reserving: set[str] = set()

    def grant(self, canonical: str, ttl: float) -> tuple[str, float, float]:
        """Lease canonical for up to ttl seconds. On success it has already
        suspended the controller's tailer on that port. Returns
        (lease_id, granted_ttl, expires_monotonic). Raises LeaseBusy if the port
        is already leased/reserved, or re-raises a suspend failure."""
        # Phase 1 (under lock): reap, reject if held/reserved, then reserve.
        with self._mu:
            self._reap_locked()
            if canonical in self._by_port or canonical in self._reserving:
                raise LeaseBusy("usbprov: port is already leased")
            self._reserving.add(canonical)

        # Phase 2 (WITHOUT lock): hand the port to the lessee. suspend_port
        # blocks until the tailer's fd + port lock are freed; holding the lock
        # across it would stall renew/release/reap for every port. The reserving
        # slot keeps this port exclusive meanwhile.
        suspend_err: Exception | None = None
        try:
            self._ctrl.suspend_port(canonical)
        except Exception as e:  # noqa: BLE001
            suspend_err = e

        # Phase 3 (under lock): commit the lease, or roll back on suspend failure.
        with self._mu:
            self._reserving.discard(canonical)
            if suspend_err is not None:
                # The owner could not fully yield the port: undo any partial
                # suspend so the tailer resumes, and create no lease.
                self._ctrl.resume_port(canonical)
                raise suspend_err
            granted = self._clamp_ttl(ttl)
            now = self._now()
            e = _LeaseEntry(id=self._new_id(), port=canonical,
                            deadline=now + granted, granted=granted)
            self._by_port[canonical] = e
            self._by_id[e.id] = e
            return e.id, granted, now + granted

    def renew(self, lease_id: str) -> tuple[float, float]:
        """Extend an existing lease by RE-APPLYING the TTL it was originally
        granted. Returns (granted_ttl, expires_monotonic). Raises LeaseUnknown
        if the lease is gone or already expired (the client must then abort).

        The renew carries no TTL of its own, per PROVISION_WIRE §6: "a renew can
        never shrink the window". Taking one from the request is not merely
        untidy, it is a cross-runtime break — a Go follower sends only
        {"lease_id"}, so a leader that read ttl_ms would see 0 and clamp to the
        1 s FLOOR, then reclaim the port a second later while the follower is
        still mid-session. That is the byte-splitting this lease exists to
        prevent. Mirror of Go LeaseManager.Renew."""
        with self._mu:
            e = self._by_id.get(lease_id)
            if e is None or not (self._now() < e.deadline):
                # Unknown, or lapsed: reap it so the port frees, and refuse.
                if e is not None:
                    self._drop_locked(e)
                raise LeaseUnknown("usbprov: lease is unknown or expired")
            now = self._now()
            e.deadline = now + e.granted
            return e.granted, now + e.granted

    def release(self, lease_id: str) -> None:
        """Drop a lease and resume the owner. Idempotent — an unknown id is a
        success."""
        with self._mu:
            e = self._by_id.get(lease_id)
            if e is not None:
                self._drop_locked(e)

    def reap_expired(self) -> int:
        """Drop every lapsed lease (resuming the owner for each). Returns how
        many were reclaimed."""
        with self._mu:
            return self._reap_locked()

    # --- internals (caller holds self._mu) ---

    def _reap_locked(self) -> int:
        now = self._now()
        n = 0
        for e in list(self._by_id.values()):
            if not (now < e.deadline):
                self._drop_locked(e)
                n += 1
        return n

    def _drop_locked(self, e: _LeaseEntry) -> None:
        self._by_id.pop(e.id, None)
        cur = self._by_port.get(e.port)
        if cur is e:
            self._by_port.pop(e.port, None)
        self._ctrl.resume_port(e.port)

    def _clamp_ttl(self, ttl: float) -> float:
        if ttl > self._max_ttl:
            return self._max_ttl
        if ttl < self._min_ttl:
            return self._min_ttl
        return ttl


def random_lease_id() -> str:
    """16 bytes of crypto entropy as 32 lowercase hex chars."""
    return secrets.token_bytes(16).hex()
