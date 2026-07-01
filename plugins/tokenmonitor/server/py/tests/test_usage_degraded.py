"""Antigravity degraded marker (bug 12).

loadCodeAssist OK but the quota sub-RPC failed → snapshot.degraded=True and the
key is present in the wire body; on quota success the key is absent (the broker
pops it when falsy so only-when-true is emitted, matching Go omitempty / JS).
"""

from __future__ import annotations

import time

from tmon_mcp import usage
from tmon_mcp.broker.server import _snapshot_body


class _FakeResp:
    def __init__(self, status: int, data: dict):
        self.status = status
        self._data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def json(self, content_type=None):  # noqa: ANN001
        return self._data


class _FakeSession:
    """Routes session.post by URL: loadCodeAssist always 200, quota configurable."""

    def __init__(self, quota_status: int, quota_body: dict):
        self._quota_status = quota_status
        self._quota_body = quota_body

    def post(self, url, **kwargs):  # noqa: ANN001
        if "loadCodeAssist" in url:
            return _FakeResp(200, {"cloudaicompanionProject": "proj-123", "currentTier": {"id": "free-tier"}})
        return _FakeResp(self._quota_status, self._quota_body)


def _seeded_fetcher() -> usage.AntigravityFetcher:
    f = usage.AntigravityFetcher()
    f._cached_token = ("seeded", int(time.time() * 1000) + 3_600_000)
    return f


async def test_degraded_when_quota_fails():
    f = _seeded_fetcher()
    snap = await f.fetch(_FakeSession(500, {"error": "boom"}))
    assert snap.degraded is True
    # Wire body carries degraded only when true.
    assert _snapshot_body(snap).get("degraded") is True


async def test_not_degraded_when_quota_ok():
    body = {
        "groups": [{
            "displayName": "Gemini Models",
            "buckets": [{
                "bucketId": "gemini-weekly", "window": "weekly",
                "resetTime": "2026-07-07T10:55:39Z", "remainingFraction": 0.5,
            }],
        }],
    }
    f = _seeded_fetcher()
    snap = await f.fetch(_FakeSession(200, body))
    assert snap.degraded is False
    # Falsy degraded is popped from the wire body entirely.
    assert "degraded" not in _snapshot_body(snap)
