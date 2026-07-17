"""429 back-off (multi-instance incident regression).

Once a provider fetch raises RateLimited, the cache must NOT re-hit upstream
until the Retry-After window elapses: it serves the last snapshot stale-200
when one exists, else surfaces RateLimited with the remaining wait. Retry-After
used to be parsed but never honored, so a transient 429 got re-triggered on
every device poll.
"""

from __future__ import annotations

from tmon_mcp import usage
from tmon_mcp.usage import Cache, RateLimited, Snapshot, Upstream


class _Stub:
    def __init__(self, seq):
        self.seq = seq
        self.calls = 0

    async def fetch(self, session):  # noqa: ANN001
        step = self.seq[min(self.calls, len(self.seq) - 1)]
        self.calls += 1
        if isinstance(step, Exception):
            raise step
        return step


def _cache(seq, ttl=30):
    c = Cache(ttl, {"x": _Stub(seq)})
    return c, c._fetchers["x"]


async def test_cold_429_suppresses_upstream_during_window():
    c, f = _cache([RateLimited(600)])
    t = [1_000_000.0]
    c._now = lambda: t[0]

    for _ in range(1):
        try:
            await c.get(None, "x")
            assert False, "expected RateLimited"
        except RateLimited:
            pass
    assert f.calls == 1

    t[0] += 30
    try:
        await c.get(None, "x")
        assert False
    except RateLimited as e:
        assert e.retry_after > 0
    t[0] += 300
    try:
        await c.get(None, "x")
        assert False
    except RateLimited:
        pass
    assert f.calls == 1  # no upstream re-hit during cooldown

    t[0] += 600
    try:
        await c.get(None, "x")
        assert False
    except RateLimited:
        pass
    assert f.calls == 2  # window elapsed → one fresh attempt


async def test_429_after_good_snapshot_serves_stale():
    c, f = _cache([Snapshot(session_pct=42), RateLimited(600)])
    t = [1_000_000.0]
    c._now = lambda: t[0]

    first = await c.get(None, "x")
    assert first.session_pct == 42
    assert f.calls == 1

    t[0] += 31
    try:
        await c.get(None, "x")
        assert False
    except RateLimited as e:
        assert e.stale_snapshot is not None and e.stale_snapshot.session_pct == 42
    assert f.calls == 2

    t[0] += 5
    stale = await c.get(None, "x")
    assert stale.session_pct == 42
    assert f.calls == 2  # served stale-200 without re-hitting upstream


async def test_success_clears_cooldown():
    c, f = _cache([RateLimited(600), Snapshot(session_pct=7)])
    t = [1_000_000.0]
    c._now = lambda: t[0]

    try:
        await c.get(None, "x")
        assert False
    except RateLimited:
        pass
    t[0] += 601
    ok = await c.get(None, "x")
    assert ok.session_pct == 7
    assert f.calls == 2


async def test_plain_upstream_error_does_not_arm_cooldown():
    c, f = _cache([Snapshot(session_pct=11), Upstream("500"), Upstream("500")], ttl=1)
    t = [1_000_000.0]
    c._now = lambda: t[0]

    await c.get(None, "x")
    t[0] += 2
    try:
        await c.get(None, "x")
        assert False
    except Upstream:
        pass
    t[0] += 2
    try:
        await c.get(None, "x")
        assert False
    except Upstream:
        pass
    assert f.calls == 3  # no cooldown → retried each poll
