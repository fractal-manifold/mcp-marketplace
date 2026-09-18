from __future__ import annotations

import asyncio
import os
import time

from tmon_mcp import session_life
from tmon_mcp.state import Role, State, load_shared_snapshot


def test_lease_lifecycle_is_visible_cross_process(tmp_path, monkeypatch):
    monkeypatch.setenv("TMON_RUNTIME_DIR", str(tmp_path))
    lease = session_life.SessionLease()
    assert session_life.live_session_count() == 1
    lease.close()
    assert session_life.live_session_count() == 0


def test_stale_lease_is_reaped(tmp_path, monkeypatch):
    monkeypatch.setenv("TMON_RUNTIME_DIR", str(tmp_path))
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    stale = sessions / "session-dead"
    stale.write_text("0\n")
    old = time.time() - 100
    os.utime(stale, (old, old))
    assert session_life.live_session_count(stale_after=1) == 0
    assert not stale.exists()


def test_daemon_lock_is_singleton_and_reacquirable(tmp_path, monkeypatch):
    monkeypatch.setenv("TMON_RUNTIME_DIR", str(tmp_path))
    first = session_life.acquire_daemon_lock()
    assert first.acquired
    second = session_life.acquire_daemon_lock()
    assert not second.acquired
    first.close()
    third = session_life.acquire_daemon_lock()
    assert third.acquired
    third.close()


def test_daemon_log_tail_is_shared(tmp_path, monkeypatch):
    monkeypatch.setenv("TMON_RUNTIME_DIR", str(tmp_path))
    (tmp_path / "broker.log").write_text("one\ntwo\nthree\n")
    assert session_life.daemon_log_tail(2) == {
        "total_available": 3,
        "lines": ["two", "three"],
    }


def test_daemon_state_snapshot_is_shared(tmp_path, monkeypatch):
    monkeypatch.setenv("TMON_RUNTIME_DIR", str(tmp_path))
    state = State()
    state.set_role(Role.LEADER)
    state.enable_shared()
    state.record_request("192.168.1.4:1234", 200, 1700000000)
    snap = load_shared_snapshot()
    assert snap.role == "leader"
    assert snap.requests_total == 1
    assert snap.last_request_status == 200


async def test_monitor_stops_after_last_session(tmp_path, monkeypatch):
    monkeypatch.setenv("TMON_RUNTIME_DIR", str(tmp_path))
    shutdown = asyncio.Event()
    await session_life.monitor_sessions(
        shutdown, poll_seconds=0.005, idle_grace=0.01, stale_after=0.1
    )
    assert shutdown.is_set()
