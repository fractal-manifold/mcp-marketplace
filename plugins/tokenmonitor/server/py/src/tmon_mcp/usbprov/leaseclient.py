"""Follower side of the serial-lease contract (compat/PROVISION_WIRE.md §6).

Port of tokenmonitor-mcp/internal/usbprov/leaseclient.go. A follower that wants
to provision over USB asks the local leader — which owns the log tailer — to
yield the port, holds the lease (renewing before it lapses) for the session,
then releases it. Requests are signed with the v3 body-covering canonical and
carry X-Tmon-Body-Sha256.

The lease is the authority between cooperating tokenmonitor-mcp processes; the
OS-exclusive open (open_exclusive) is the second fence — so even the "no lease
needed" fallbacks still open exclusively.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from .. import auth
from .leasewire import LEASE_PATH, LEASE_RELEASE_PATH, LEASE_RENEW_PATH
from .lease import LeaseBusy
from .serial_port import Handle, PortBusy, open_exclusive

# The TTL a follower requests. The leader clamps it; the client renews at half
# this cadence, so a single missed renewal still leaves margin.
DEFAULT_LEASE_TTL = 20.0  # seconds

# Bounds a lease response body the client will read.
_MAX_LEASE_RESP_BYTES = 4 << 10


@dataclass
class LeasedPort:
    """A serial port acquired for exclusive use. handle is the open port. lost
    is set if the lease can no longer be held (the leader reaped it, or the
    broker became unreachable) — the caller MUST treat that as the port possibly
    reclaimed and abort any in-flight session. For a direct open, lost is never
    set. close releases the lease and the port; idempotent."""

    handle: Handle
    lost: threading.Event
    _stop: Callable[[], None]
    _once: threading.Lock = None  # type: ignore[assignment]
    _closed: bool = False

    def __post_init__(self) -> None:
        self._once = threading.Lock()

    def close(self) -> None:
        """Release the lease (if any) and the underlying port. Idempotent and
        concurrency-safe: exactly one caller runs _stop (check-and-set under a
        lock, so two concurrent closers can't both fire it)."""
        with self._once:
            if self._closed:
                return
            self._closed = True
        self._stop()


class LeaseClient:
    """The follower's lease client. base_url is e.g. http://127.0.0.1:8765 (no
    trailing slash)."""

    def __init__(
        self,
        base_url: str,
        psk: bytes,
        *,
        http_timeout: float = 4.0,
        now: Callable[[], float] | None = None,
    ) -> None:
        self.base_url = base_url
        self.psk = psk
        self._http_timeout = http_timeout
        self._now = now or time.time

    def open_leased(self, port: str, cancel: threading.Event | None = None) -> LeasedPort:
        """Acquire port for exclusive provisioning use. First asks the local
        leader for a lease; on 200 opens the (now-yielded) port and renews in the
        background until close. On a leader without the endpoint (404), no serial
        device (503), or no broker running (dial error), falls back to a direct
        OS-exclusive open. Raises LeaseBusy if another follower holds the lease,
        PortBusy if the direct open loses the flock race."""
        lease_id, granted, need_lease = self._acquire(port, DEFAULT_LEASE_TTL, cancel)
        if not need_lease:
            h = _open_with_retry(port, cancel)
            never = threading.Event()
            return LeasedPort(handle=h, lost=never, _stop=lambda: h.release())

        # Lease held: the leader's tailer has already released the port, so the
        # open should succeed promptly; retry briefly to cover an election-gap.
        try:
            h = _open_with_retry(port, cancel)
        except Exception:
            self._release_bounded(lease_id)  # hand the port back to the tailer
            raise

        lost = threading.Event()
        stop_renew = threading.Event()
        renew_thread = threading.Thread(
            target=self._renew_loop,
            args=(lease_id, granted, lost, stop_renew),
            daemon=True,
            name="usbprov-lease-renew",
        )
        renew_thread.start()

        def _stop() -> None:
            stop_renew.set()
            h.release()
            self._release_bounded(lease_id)

        return LeasedPort(handle=h, lost=lost, _stop=_stop)

    # --- HTTP steps -------------------------------------------------------

    def _acquire(
        self, port: str, ttl: float, cancel: threading.Event | None
    ) -> tuple[str, float, bool]:
        """POST a lease request. need_lease is False when no lease is required
        (no broker, or a leader without this endpoint / without a serial device):
        the caller then opens the port directly. True only on a 200 grant."""
        body = json.dumps({"port": port, "ttl_ms": int(ttl * 1000)}).encode("utf-8")
        try:
            status, raw = self._do(LEASE_PATH, body)
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            # Any transport failure — dial refused, connect timeout, or a
            # read-timeout mid-response (raised as TimeoutError, NOT wrapped in
            # URLError) — is treated as "no broker reachable", matching Go. A
            # cancelled caller must surface, not silently fall through.
            if cancel is not None and cancel.is_set():
                raise
            # No broker reachable → nobody is tailing the port → direct open.
            return "", 0.0, False

        if status == 200:
            try:
                lr = json.loads(raw)
                lease_id = lr["lease_id"]
                # "ttl_ms", not "granted_ms" — PROVISION_WIRE §6. The field name
                # is part of the cross-runtime contract: a Go leader emits
                # ttl_ms, and reading the wrong key here would make every grant
                # look malformed against it.
                ttl_ms = lr["ttl_ms"]
            except (ValueError, KeyError, TypeError):
                raise RuntimeError("usbprov: malformed lease response")
            # bool is an int subclass, so exclude it explicitly; Go would not
            # accept `true` for an int64 either.
            if (
                not isinstance(lease_id, str)
                or not lease_id
                or isinstance(ttl_ms, bool)
                or not isinstance(ttl_ms, int)
                or ttl_ms <= 0
            ):
                raise RuntimeError("usbprov: malformed lease response")
            return lease_id, ttl_ms / 1000.0, True
        if status == 409:
            raise LeaseBusy("usbprov: port is already leased")
        if status in (404, 503):
            # Leader too old to know the endpoint, or no serial device
            # configured: no tailer contends this port → direct open.
            return "", 0.0, False
        raise RuntimeError(f"usbprov: lease request failed: {status}")

    def _renew_loop(
        self,
        lease_id: str,
        granted: float,
        lost: threading.Event,
        stop_renew: threading.Event,
    ) -> None:
        """Renew at half the granted cadence until stop_renew. On the first
        failure, set lost and return — the caller's session must then abort."""
        interval = granted / 2.0
        if interval < 0.25:
            interval = 0.25
        while True:
            if stop_renew.wait(interval):
                return
            try:
                self._renew(lease_id)
            except Exception:  # noqa: BLE001
                lost.set()  # lease is gone → signal the session to abort
                return

    def _renew(self, lease_id: str) -> None:
        # Body carries ONLY the lease id (PROVISION_WIRE §6): the leader
        # re-applies the TTL it originally granted, so a renew can never shrink
        # the window. Sending a ttl_ms here is not just redundant — against a
        # leader that honoured it, an omitted or small value would clamp the
        # lease down to the 1 s floor mid-session.
        body = json.dumps({"lease_id": lease_id}).encode("utf-8")
        status, _ = self._do(LEASE_RENEW_PATH, body)
        if status != 200:
            raise RuntimeError(f"usbprov: renew failed: {status}")

    def _release_bounded(self, lease_id: str) -> None:
        """Release best-effort. The leader reaps the lease on TTL expiry
        anyway."""
        try:
            self._release(lease_id)
        except Exception:  # noqa: BLE001
            pass

    def _release(self, lease_id: str) -> None:
        body = json.dumps({"lease_id": lease_id}).encode("utf-8")
        try:
            self._do(LEASE_RELEASE_PATH, body)
        except urllib.error.URLError:
            return  # best-effort

    def _do(self, path: str, body: bytes) -> tuple[int, bytes]:
        """Sign and send one POST with a mandatory body digest (v3 canonical).
        Returns (status, body_bytes). Raises URLError only on a dial/transport
        failure (an HTTP error status is returned, not raised)."""
        body_sha = hashlib.sha256(body).hexdigest()
        ts = str(int(self._now()))
        nonce = secrets.token_hex(16)
        sig = auth.compute_signature_body(self.psk, "POST", path, ts, nonce, "", "", body_sha)
        req = urllib.request.Request(self.base_url + path, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Tmon-Timestamp", ts)
        req.add_header("X-Tmon-Nonce", nonce)
        req.add_header("X-Tmon-Signature", sig)
        req.add_header("X-Tmon-Body-Sha256", body_sha)
        try:
            with urllib.request.urlopen(req, timeout=self._http_timeout) as resp:
                return resp.status, resp.read(_MAX_LEASE_RESP_BYTES)
        except urllib.error.HTTPError as e:
            # A non-2xx status is a normal outcome here (409/404/503), not a
            # transport failure — surface the code.
            data = b""
            try:
                data = e.read(_MAX_LEASE_RESP_BYTES)
            except Exception:  # noqa: BLE001
                pass
            return e.code, data


def _open_with_retry(port: str, cancel: threading.Event | None) -> Handle:
    """Open the port exclusively, retrying on PortBusy for a short bounded
    window (the previous holder may take a moment to fully release the flock).
    Honours cancel."""
    attempts = 20
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return open_exclusive(port)
        except PortBusy as e:
            last_exc = e
            if cancel is not None and cancel.is_set():
                raise
            time.sleep(0.05)
        # A real open error (missing device, perms) is NOT retried — propagates.
    assert last_exc is not None
    raise last_exc
