"""DST-correctness of the weekly spend window boundary (bug 10).

The week start must be local Monday 00:00 even when a DST transition falls
inside the week. The old `dow * 86400` arithmetic lands an hour off because a
spring-forward day is only 23 h long. Matches the Go reference impl.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

import pytest


@pytest.fixture()
def madrid_tz():
    prev = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Madrid"
    time.tzset()
    try:
        yield
    finally:
        if prev is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = prev
        time.tzset()


def test_week_start_across_spring_forward(madrid_tz):
    from tmon_mcp.spend import window_starts

    # Sunday 2026-03-29 12:00 CEST (UTC+2, just after the spring-forward that
    # happened at 02:00 that morning) == 10:00 UTC.
    now = datetime(2026, 3, 29, 10, 0, 0, tzinfo=timezone.utc).timestamp()
    w = window_starts(now)

    # Correct week start: Monday 2026-03-23 00:00 CET (UTC+1, still winter) ==
    # 2026-03-22 23:00 UTC. The buggy dow*86400 math would give 22:00 UTC.
    want = datetime(2026, 3, 22, 23, 0, 0, tzinfo=timezone.utc).timestamp()
    assert w.week == want
