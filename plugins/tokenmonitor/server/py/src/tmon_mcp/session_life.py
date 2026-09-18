"""Cross-runtime MCP-session leases and single broker-daemon lifetime."""

from __future__ import annotations

import asyncio
from contextlib import suppress
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

HEARTBEAT_SECONDS = 5.0
STALE_AFTER_SECONDS = 30.0
IDLE_GRACE_SECONDS = 10.0
MAX_DAEMON_LOG_BYTES = 2 * 1024 * 1024


def runtime_dir() -> Path:
    if os.environ.get("TMON_RUNTIME_DIR", "").strip():
        return Path(os.environ["TMON_RUNTIME_DIR"].strip())
    if os.environ.get("XDG_RUNTIME_DIR", "").strip():
        return Path(os.environ["XDG_RUNTIME_DIR"].strip()) / "tokenmonitor"
    cache = os.environ.get("XDG_CACHE_HOME", "").strip()
    root = Path(cache) if cache else Path.home() / ".cache"
    return root / "tokenmonitor" / "runtime"


def _ensure_runtime_dir() -> Path:
    root = runtime_dir()
    sessions = root / "sessions"
    sessions.mkdir(parents=True, exist_ok=True, mode=0o700)
    with suppress(OSError):
        root.chmod(0o700)
    with suppress(OSError):
        sessions.chmod(0o700)
    return root


class SessionLease:
    def __init__(self) -> None:
        root = _ensure_runtime_dir()
        self.path = root / "sessions" / f"session-{os.getpid()}-{secrets.token_hex(12)}"
        self.path.write_text(f"{os.getpid()}\n")
        self.path.chmod(0o600)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._heartbeat, name="tmon-session-heartbeat", daemon=True)
        self._thread.start()
        self._closed = False

    def _heartbeat(self) -> None:
        while not self._stop.wait(HEARTBEAT_SECONDS):
            with suppress(OSError):
                self.path.touch()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        self._thread.join(timeout=HEARTBEAT_SECONDS + 1)
        with suppress(FileNotFoundError):
            self.path.unlink()


def _process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return False


def _lock_path() -> Path:
    return _ensure_runtime_dir() / "broker.lock"


def _read_lock_pid(path: Path) -> int:
    try:
        return int((path / "pid").read_text().strip())
    except (OSError, ValueError):
        return 0


def daemon_running() -> bool:
    path = _lock_path()
    return _process_alive(_read_lock_pid(path))


class DaemonLock:
    def __init__(self, path: Path, owner: str, acquired: bool) -> None:
        self.path = path
        self.owner = owner
        self.acquired = acquired
        self._closed = False

    def close(self) -> None:
        if self._closed or not self.acquired:
            return
        self._closed = True
        try:
            if (self.path / "pid").read_text().strip() == self.owner:
                with suppress(FileNotFoundError):
                    (runtime_dir() / "broker-state.json").unlink()
                shutil.rmtree(self.path)
        except FileNotFoundError:
            pass


def acquire_daemon_lock() -> DaemonLock:
    path = _lock_path()
    for attempt in range(3):
        try:
            path.mkdir(mode=0o700)
            owner = str(os.getpid())
            (path / "pid").write_text(owner + "\n")
            (path / "pid").chmod(0o600)
            return DaemonLock(path, owner, True)
        except FileExistsError:
            pass
        pid = _read_lock_pid(path)
        if _process_alive(pid):
            return DaemonLock(path, "", False)
        if pid == 0 and attempt == 0:
            time.sleep(0.05)
            continue
        with suppress(FileNotFoundError):
            shutil.rmtree(path)
    raise RuntimeError("could not acquire broker singleton lock")


def start_daemon(config_path: str = "") -> None:
    if daemon_running():
        return
    root = _ensure_runtime_dir()
    argv = [sys.executable, "-m", "tmon_mcp", "--daemon"]
    if config_path:
        argv += ["--config", config_path]
    log_path = root / "broker.log"
    try:
        if log_path.stat().st_size > MAX_DAEMON_LOG_BYTES:
            log_path.replace(log_path.with_name("broker.log.1"))
    except FileNotFoundError:
        pass
    log = open(log_path, "ab", buffering=0)
    kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": log,
        "stderr": subprocess.STDOUT,
        "close_fds": True,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    else:
        kwargs["start_new_session"] = True
    try:
        subprocess.Popen(argv, **kwargs)
    finally:
        log.close()


def daemon_log_tail(limit: int) -> dict:
    text = (runtime_dir() / "broker.log").read_text(errors="replace").rstrip("\r\n")
    lines = text.splitlines() if text else []
    return {"total_available": len(lines), "lines": lines[-limit:]}


async def supervise_daemon(stop: asyncio.Event, config_path: str = "", logger=None) -> None:
    """Keep one daemon alive while the owning MCP session exists."""
    while not stop.is_set():
        try:
            start_daemon(config_path)
        except Exception as exc:  # noqa: BLE001
            if logger:
                logger.error("sessions: start broker daemon: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=HEARTBEAT_SECONDS)
        except TimeoutError:
            pass


def live_session_count(now: float | None = None, stale_after: float = STALE_AFTER_SECONDS) -> int:
    now = time.time() if now is None else now
    sessions = _ensure_runtime_dir() / "sessions"
    live = 0
    for path in sessions.glob("session-*"):
        if not path.is_file():
            continue
        try:
            if now - path.stat().st_mtime > stale_after:
                path.unlink()
            else:
                live += 1
        except FileNotFoundError:
            pass
    return live


async def monitor_sessions(
    shutdown: asyncio.Event,
    logger=None,
    *,
    poll_seconds: float = 2.0,
    idle_grace: float = IDLE_GRACE_SECONDS,
    stale_after: float = STALE_AFTER_SECONDS,
) -> None:
    empty_since: float | None = None
    while not shutdown.is_set():
        try:
            count = live_session_count(stale_after=stale_after)
        except OSError as exc:
            if logger:
                logger.warning("sessions: %s", exc)
            await asyncio.sleep(poll_seconds)
            continue
        now = time.monotonic()
        if count:
            empty_since = None
        elif empty_since is None:
            empty_since = now
        elif now - empty_since >= idle_grace:
            if logger:
                logger.info("sessions: none remain; stopping broker daemon")
            shutdown.set()
            return
        try:
            await asyncio.wait_for(shutdown.wait(), timeout=poll_seconds)
        except TimeoutError:
            pass
