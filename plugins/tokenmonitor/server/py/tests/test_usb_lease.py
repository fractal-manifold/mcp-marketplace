"""LeaseManager parity with go/internal/usbprov/lease_test.go: grant suspends /
release resumes, second grant on same port is busy, TTL clamp, renew
extends/rejects-expired, reap resumes owner, grant fails if controller cannot
yield, and a slow suspend does not block other ports (the reservation dance)."""

from __future__ import annotations

import contextlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tmon_mcp.usbprov.leaseclient import LeaseClient
from tmon_mcp.usbprov.leasewire import LEASE_PATH, LEASE_RENEW_PATH
from tmon_mcp.usbprov.lease import (
    DEFAULT_LEASE_MIN_TTL,
    LeaseBusy,
    LeaseManager,
    LeaseUnknown,
    random_lease_id,
)


class _FakeController:
    def __init__(self, fail_port: str = "") -> None:
        self.suspend: dict[str, int] = {}
        self.resume: dict[str, int] = {}
        self.fail_port = fail_port
        self._mu = threading.Lock()

    def suspend_port(self, p: str) -> None:
        if p == self.fail_port:
            raise RuntimeError("cannot yield")
        with self._mu:
            self.suspend[p] = self.suspend.get(p, 0) + 1

    def resume_port(self, p: str) -> None:
        with self._mu:
            self.resume[p] = self.resume.get(p, 0) + 1

    def counts(self, p: str) -> tuple[int, int]:
        with self._mu:
            return self.suspend.get(p, 0), self.resume.get(p, 0)


class _FakeClock:
    def __init__(self, t: float = 1_700_000.0) -> None:
        self.t = t
        self._mu = threading.Lock()

    def now(self) -> float:
        with self._mu:
            return self.t

    def advance(self, d: float) -> None:
        with self._mu:
            self.t += d


def _mgr(ctrl):
    clk = _FakeClock()
    n = [0]

    def _id() -> str:
        n[0] += 1
        return f"lease{n[0]}"

    return LeaseManager(ctrl, 10.0, now=clk.now, new_id=_id), clk


def test_grant_suspends_and_release_resumes():
    ctrl = _FakeController()
    m, _ = _mgr(ctrl)
    lid, granted, _ = m.grant("/dev/ttyACM0", 5.0)
    assert granted == 5.0
    assert ctrl.counts("/dev/ttyACM0") == (1, 0)
    m.release(lid)
    assert ctrl.counts("/dev/ttyACM0") == (1, 1)
    m.release(lid)  # idempotent
    assert ctrl.counts("/dev/ttyACM0")[1] == 1


def test_second_grant_same_port_busy():
    ctrl = _FakeController()
    m, _ = _mgr(ctrl)
    m.grant("/dev/ttyACM0", 1.0)
    with pytest.raises(LeaseBusy):
        m.grant("/dev/ttyACM0", 1.0)
    m.grant("/dev/ttyACM1", 1.0)  # a different port is free


def test_ttl_clamped():
    m, _ = _mgr(_FakeController())
    _, g1, _ = m.grant("/dev/ttyACM0", 3600.0)
    assert g1 == 10.0  # over-max
    _, g2, _ = m.grant("/dev/ttyACM1", 0.001)
    assert g2 == DEFAULT_LEASE_MIN_TTL  # under-min


def test_renew_extends_and_rejects_expired():
    ctrl = _FakeController()
    m, clk = _mgr(ctrl)
    lid, _, _ = m.grant("/dev/ttyACM0", 5.0)
    clk.advance(3.0)
    # Renew carries no TTL: the lease re-applies its ORIGINAL granted 5 s.
    assert m.renew(lid)[0] == 5.0  # alive
    clk.advance(6.0)  # deadline is now t=8; t=9 is past it
    with pytest.raises(LeaseUnknown):
        m.renew(lid)
    assert ctrl.counts("/dev/ttyACM0")[1] == 1  # freed the port


def test_renew_reapplies_the_clamped_grant():
    """A renew must re-apply the TTL the lease was GRANTED, not the TTL that was
    asked for — the request that was clamped down (or up) must stay clamped, and
    a renew must never be able to shrink the window. Mirrors Go's
    TestLease_RenewExtendsAndRejectsExpired."""
    ctrl = _FakeController()
    m, clk = _mgr(ctrl)
    lid, granted, _ = m.grant("/dev/ttyACM0", 3600.0)
    assert granted == 10.0  # clamped to the fake manager's max
    clk.advance(9.0)
    assert m.renew(lid)[0] == 10.0  # the clamped grant, not 3600
    clk.advance(9.0)  # deadline is t=19; still alive at t=18
    assert m.renew(lid)[0] == 10.0


def test_reap_expired_resumes_owner():
    ctrl = _FakeController()
    m, clk = _mgr(ctrl)
    m.grant("/dev/ttyACM0", 2.0)
    m.grant("/dev/ttyACM1", 8.0)
    clk.advance(3.0)
    assert m.reap_expired() == 1
    assert ctrl.counts("/dev/ttyACM0")[1] == 1
    assert ctrl.counts("/dev/ttyACM1")[1] == 0
    m.grant("/dev/ttyACM0", 1.0)  # grantable again


def test_grant_fails_if_controller_cannot_yield():
    ctrl = _FakeController(fail_port="/dev/ttyACM0")
    m, _ = _mgr(ctrl)
    with pytest.raises(RuntimeError):
        m.grant("/dev/ttyACM0", 1.0)
    ctrl.fail_port = ""
    m.grant("/dev/ttyACM0", 1.0)  # free after a failed grant


def test_slow_suspend_does_not_block_other_ports():
    """Grant must not hold the manager lock across the blocking suspend_port."""

    gate = threading.Event()
    entered = threading.Event()

    class _GateController:
        def __init__(self) -> None:
            self.resume: dict[str, int] = {}
            self._mu = threading.Lock()

        def suspend_port(self, p: str) -> None:
            if p == "/dev/ttyACM0":
                entered.set()
                gate.wait(2.0)

        def resume_port(self, p: str) -> None:
            with self._mu:
                self.resume[p] = self.resume.get(p, 0) + 1

    m = LeaseManager(_GateController(), 10.0)  # real clock + random ids

    grant_done: list = []

    def _grant0():
        try:
            grant_done.append(m.grant("/dev/ttyACM0", 5.0))
        except Exception as e:  # noqa: BLE001
            grant_done.append(e)

    threading.Thread(target=_grant0, daemon=True).start()
    assert entered.wait(2.0), "gated grant never entered suspend_port"

    # While ACM0's suspend is stuck, ACM1 must lease+release fast.
    other: list = []

    def _other():
        try:
            lid, _, _ = m.grant("/dev/ttyACM1", 1.0)
            m.release(lid)
            other.append(None)
        except Exception as e:  # noqa: BLE001
            other.append(e)

    t = threading.Thread(target=_other, daemon=True)
    t.start()
    t.join(2.0)
    assert other and other[0] is None, "unrelated port stalled behind a slow suspend"

    # A concurrent grant on the still-reserving port must report busy.
    with pytest.raises(LeaseBusy):
        m.grant("/dev/ttyACM0", 1.0)

    gate.set()
    time.sleep(0.2)
    assert grant_done and not isinstance(grant_done[0], Exception)


def test_random_lease_id_unique_and_hex():
    seen = set()
    for _ in range(100):
        lid = random_lease_id()
        assert len(lid) == 32 and all(c in "0123456789abcdef" for c in lid)
        assert lid not in seen
        seen.add(lid)


# --- follower client wire shape ------------------------------------------
#
# The endpoint tests drive the leader side; these drive the client side against
# a bare HTTP server that records the raw bytes. Both halves are ours, so an
# end-to-end round trip would still pass with a field neither side reads — only
# the serialized body proves what a GO leader would actually parse.


class _RecordingLeader(BaseHTTPRequestHandler):
    """Answers any lease POST with a canned 200 and records the raw body."""

    seen: list = []
    grant_body = b'{"lease_id":"' + b"a" * 32 + b'","port":"/dev/ttyFAKE0",' \
                 b'"ttl_ms":10000,"expires_unix_ms":1}'
    renew_body = b'{"ttl_ms":10000,"expires_unix_ms":1}'

    def do_POST(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        type(self).seen.append((self.path, raw))
        body = self.grant_body if self.path == LEASE_PATH else self.renew_body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence the default stderr access log
        return


@contextlib.contextmanager
def _recording_leader():
    _RecordingLeader.seen = []
    srv = HTTPServer(("127.0.0.1", 0), _RecordingLeader)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}", _RecordingLeader
    finally:
        srv.shutdown()
        srv.server_close()


def test_client_reads_ttl_ms_from_the_grant():
    with _recording_leader() as (base, rec):
        c = LeaseClient(base, b"psk")
        lease_id, granted, need = c._acquire("/dev/ttyFAKE0", 20.0, None)
        assert need is True
        assert lease_id == "a" * 32
        assert granted == 10.0  # ttl_ms, in seconds — NOT the requested 20
        path, raw = rec.seen[0]
        assert path == LEASE_PATH
        assert json.loads(raw) == {"port": "/dev/ttyFAKE0", "ttl_ms": 20000}


def test_client_renew_body_carries_only_lease_id():
    """A stray ttl_ms here is exactly the bug that clamps a lease to the 1 s
    floor mid-session against a leader that honours it (PROVISION_WIRE §6)."""
    with _recording_leader() as (base, rec):
        c = LeaseClient(base, b"psk")
        c._renew("a" * 32)
        path, raw = rec.seen[0]
        assert path == LEASE_RENEW_PATH
        assert json.loads(raw) == {"lease_id": "a" * 32}


def test_client_rejects_a_grant_without_ttl_ms():
    """A leader still emitting the old granted_ms is malformed, not tolerated:
    silently defaulting the TTL would desynchronise the renew cadence from the
    real deadline."""

    class _Old(_RecordingLeader):
        grant_body = b'{"lease_id":"' + b"a" * 32 + b'","granted_ms":10000}'

    _Old.seen = []
    srv = HTTPServer(("127.0.0.1", 0), _Old)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = LeaseClient(f"http://127.0.0.1:{srv.server_port}", b"psk")
        with pytest.raises(RuntimeError, match="malformed"):
            c._acquire("/dev/ttyFAKE0", 20.0, None)
    finally:
        srv.shutdown()
        srv.server_close()
