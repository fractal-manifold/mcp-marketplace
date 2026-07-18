"""Codex usage-window mapping.

OpenAI collapsed Codex to a SINGLE weekly limit (2026-07): primary_window is
the 7d weekly window, secondary_window is null. The broker must render Codex
weekly-only (session hidden), like Antigravity, while still handling the legacy
two-window shape.
"""

from __future__ import annotations

from tmon_mcp import creds, usage


class _FakeResp:
    def __init__(self, data: dict):
        self.status = 200
        self._data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def json(self, content_type=None):  # noqa: ANN001
        return self._data


class _FakeSession:
    def __init__(self, data: dict):
        self._data = data

    def get(self, url, **kwargs):  # noqa: ANN001
        return _FakeResp(self._data)


def _fetcher(monkeypatch) -> usage.CodexFetcher:
    monkeypatch.setattr(
        creds,
        "load_codex",
        lambda _p: creds.CodexStored(access_token="tok", account_id="acct", expires_at_unix_ms=0),
    )
    # is_expired(now) → False regardless of the seeded expiry.
    monkeypatch.setattr(creds.CodexStored, "is_expired", lambda self, now_ms: False)
    return usage.CodexFetcher(auth_path="/dev/null")


async def test_codex_single_weekly_window(monkeypatch):
    body = {
        "plan_type": "plus",
        "rate_limit": {
            "allowed": True,
            "limit_reached": False,
            "primary_window": {
                "used_percent": 1,
                "limit_window_seconds": 604800,
                "reset_after_seconds": 602722,
                "reset_at": 1784812589,
            },
            "secondary_window": None,
        },
        "rate_limit_reset_credits": {"available_count": 4},
    }
    snap = await _fetcher(monkeypatch).fetch(_FakeSession(body))
    assert snap.weekly_pct == 1
    assert snap.weekly_window_seconds == 604800
    assert snap.weekly_reset_eta_seconds == 602722
    assert snap.session_window_seconds == 0  # session card hidden
    assert snap.session_pct == 0
    assert snap.tier == "plus"
    assert [(s.label, s.pct, s.window_seconds, s.reset_eta_seconds) for s in snap.slots] == [
        ("Weekly", 1, 604800, 602722)
    ]


async def test_codex_inverted_windows(monkeypatch):
    # Forward-looking: OpenAI may re-add the 5h limit as secondary_window while
    # keeping the weekly window in primary_window. Classifying by duration keeps
    # the labels right — 604800 is Weekly, 18000 is Session.
    body = {
        "plan_type": "pro",
        "rate_limit": {
            "primary_window": {"used_percent": 6, "limit_window_seconds": 604800, "reset_after_seconds": 582744},
            "secondary_window": {"used_percent": 33, "limit_window_seconds": 18000, "reset_after_seconds": 14007},
        },
    }
    snap = await _fetcher(monkeypatch).fetch(_FakeSession(body))
    assert snap.session_pct == 33
    assert snap.session_window_seconds == 18000
    assert snap.weekly_pct == 6
    assert snap.weekly_window_seconds == 604800
    assert [(s.label, s.pct, s.window_seconds, s.reset_eta_seconds) for s in snap.slots] == [
        ("Session", 33, 18000, 14007),
        ("Weekly", 6, 604800, 582744),
    ]


async def test_codex_monthly_window(monkeypatch):
    # A window longer than two weeks maps to a Monthly bucket, which has no
    # legacy scalar → it surfaces via slots only; the weekly card is hidden.
    body = {
        "plan_type": "pro",
        "rate_limit": {
            "primary_window": {"used_percent": 20, "limit_window_seconds": 18000, "reset_after_seconds": 3600},
            "secondary_window": {"used_percent": 42, "limit_window_seconds": 2592000, "reset_after_seconds": 1000000},
        },
    }
    snap = await _fetcher(monkeypatch).fetch(_FakeSession(body))
    assert snap.session_pct == 20
    assert snap.session_window_seconds == 18000
    assert snap.weekly_window_seconds == 0  # weekly card hidden
    assert snap.weekly_pct == 0
    assert [(s.label, s.pct, s.window_seconds, s.reset_eta_seconds) for s in snap.slots] == [
        ("Session", 20, 18000, 3600),
        ("Monthly", 42, 2592000, 1000000),
    ]


async def test_codex_fractional_window_floors(monkeypatch):
    # A fractional limit_window_seconds floors to an integer, matching go/js.
    body = {
        "plan_type": "plus",
        "rate_limit": {
            "primary_window": {"used_percent": 10, "limit_window_seconds": 18000.5, "reset_after_seconds": 100},
            "secondary_window": {"used_percent": 20, "limit_window_seconds": 604800, "reset_after_seconds": 200},
        },
    }
    snap = await _fetcher(monkeypatch).fetch(_FakeSession(body))
    assert snap.session_window_seconds == 18000
    assert snap.weekly_window_seconds == 604800


async def test_codex_legacy_two_window(monkeypatch):
    body = {
        "plan_type": "plus",
        "rate_limit": {
            "primary_window": {
                "used_percent": 33,
                "limit_window_seconds": 18000,
                "reset_after_seconds": 14007,
                "reset_at": 1779678515,
            },
            "secondary_window": {
                "used_percent": 6,
                "limit_window_seconds": 604800,
                "reset_after_seconds": 582744,
                "reset_at": 1780247253,
            },
        },
    }
    snap = await _fetcher(monkeypatch).fetch(_FakeSession(body))
    assert snap.session_pct == 33
    assert snap.session_window_seconds == 18000
    assert snap.weekly_pct == 6
    assert snap.weekly_window_seconds == 604800
    assert [(s.label, s.pct) for s in snap.slots] == [("Session", 33), ("Weekly", 6)]
