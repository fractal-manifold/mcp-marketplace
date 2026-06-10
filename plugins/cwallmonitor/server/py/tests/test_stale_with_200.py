"""Stale-with-200 behaviour for /usage and /spend (Go/JS parity).

When an upstream refresh fails but the TTL cache still holds a last-good
snapshot, the broker answers 200 + the cached body + an X-Cwm-Stale-Reason
header instead of surfacing the error. The cache attaches the last-good
snapshot to the raised error (err.stale_snapshot); the broker's
_stale_response renders it. With NO last-good snapshot the error maps to the
normal HTTP status.

These tests drive the cache error paths directly with fake fetchers (a first
success seeds the cache, a controlled clock expires the TTL, a second call
raises) and exercise the broker's _stale_response helper.
"""

from __future__ import annotations

from dataclasses import asdict

import pytest

from cwm_mcp import spend, usage
from cwm_mcp.broker import server as broker_server


# ---------------------------------------------------------------------------
# /usage cache: stale_snapshot attaches only when a last-good exists
# ---------------------------------------------------------------------------


class _FlakyUsageFetcher:
    """First fetch succeeds, every later fetch raises Upstream."""

    def __init__(self) -> None:
        self.calls = 0

    async def fetch(self, session):  # noqa: ANN001 - session unused
        self.calls += 1
        if self.calls == 1:
            return usage.Snapshot(session_pct=42.0, tier="pro")
        raise usage.Upstream("upstream 500")


class _NeverGoodUsageFetcher:
    async def fetch(self, session):  # noqa: ANN001
        raise usage.Upstream("upstream 500")


async def test_usage_error_with_cache_attaches_stale_snapshot():
    fetcher = _FlakyUsageFetcher()
    cache = usage.Cache(ttl_seconds=10, fetchers={"claude": fetcher})
    clock = {"t": 1000.0}
    cache._now = lambda: clock["t"]  # type: ignore[attr-defined]

    # First call seeds the last-good snapshot.
    good = await cache.get(None, "claude")
    assert good.session_pct == 42.0

    # Advance past the TTL so the next get refreshes (and fails).
    clock["t"] = 1100.0
    with pytest.raises(usage.UsageError) as exc:
        await cache.get(None, "claude")
    snap = getattr(exc.value, "stale_snapshot", None)
    assert snap is not None, "last-good snapshot must attach to the error"
    assert snap.session_pct == 42.0
    assert snap.stale_seconds >= 100


async def test_usage_error_without_cache_has_no_stale_snapshot():
    cache = usage.Cache(ttl_seconds=10, fetchers={"claude": _NeverGoodUsageFetcher()})
    with pytest.raises(usage.UsageError) as exc:
        await cache.get(None, "claude")
    assert getattr(exc.value, "stale_snapshot", None) is None


# ---------------------------------------------------------------------------
# /spend cache: same contract
# ---------------------------------------------------------------------------


class _FlakySpendFetcher:
    def __init__(self) -> None:
        self.calls = 0

    def fetch(self, now: float):
        self.calls += 1
        if self.calls == 1:
            return spend.Snapshot(today_usd=1.23, has_subscription=True)
        raise spend.SpendUnavailable("logs unreadable")


class _NeverGoodSpendFetcher:
    def fetch(self, now: float):
        raise spend.SpendUnavailable("logs unreadable")


async def test_spend_error_with_cache_attaches_stale_snapshot():
    fetcher = _FlakySpendFetcher()
    cache = spend.Cache(ttl_seconds=10, fetchers={"claude": fetcher})
    clock = {"t": 2000.0}
    cache._now = lambda: clock["t"]  # type: ignore[attr-defined]

    good = await cache.get("claude")
    assert good.today_usd == 1.23

    clock["t"] = 2100.0
    with pytest.raises(spend.SpendError) as exc:
        await cache.get("claude")
    snap = getattr(exc.value, "stale_snapshot", None)
    assert snap is not None
    assert snap.today_usd == 1.23
    assert snap.stale_seconds >= 100


async def test_spend_error_without_cache_has_no_stale_snapshot():
    cache = spend.Cache(ttl_seconds=10, fetchers={"claude": _NeverGoodSpendFetcher()})
    with pytest.raises(spend.SpendError) as exc:
        await cache.get("claude")
    assert getattr(exc.value, "stale_snapshot", None) is None


# ---------------------------------------------------------------------------
# Broker _stale_response: 200 + body + X-Cwm-Stale-Reason
# ---------------------------------------------------------------------------


def test_stale_response_sets_header_and_200():
    snap = usage.Snapshot(session_pct=42.0, tier="pro", fetched_at_unix=0)
    resp = broker_server._stale_response(snap, "upstream 500")
    assert resp.status == 200
    assert resp.headers["X-Cwm-Stale-Reason"] == "upstream 500"
    assert resp.headers["Cache-Control"] == "no-store"
    # The body is the serialised snapshot, with a backfilled fetched_at_unix.
    assert snap.fetched_at_unix != 0
