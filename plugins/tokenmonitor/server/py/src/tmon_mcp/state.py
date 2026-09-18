"""Runtime state snapshot exposed by tokenmonitor_status."""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from enum import Enum

from . import RUNTIME
from . import session_life


class Role(str, Enum):
    UNKNOWN = "unknown"
    LEADER = "leader"
    FOLLOWER = "follower"


@dataclass
class UpdateInfo:
    """Cached result of the broker self-version check: is a newer broker/plugin
    release published than the one running. ``known`` is False until the first
    successful fetch of the remote marketplace catalog; while unknown the broker
    advertises nothing (never a false "up to date" or "outdated"). Mirror of Go
    state.UpdateInfo."""

    known: bool = False
    outdated: bool = False
    current: str = ""
    latest: str = ""
    checked_at: str = ""  # RFC3339, empty until the first successful check


@dataclass
class Snapshot:
    runtime: str
    role: str
    role_since: str  # RFC3339
    last_request_at: str = ""
    last_request_remote: str = ""
    last_request_status: int = 0
    requests_total: int = 0
    # update_available is set only once the self-version check has succeeded;
    # None (omitted) means "not yet checked", distinct from False ("up to date").
    update_available: bool | None = None
    latest_version: str = ""

    def to_dict(self) -> dict:
        out = {
            "runtime": self.runtime,
            "role": self.role,
            "role_since": self.role_since,
            "requests_total": self.requests_total,
        }
        if self.last_request_at:
            out["last_request_at"] = self.last_request_at
        if self.last_request_remote:
            out["last_request_remote"] = self.last_request_remote
        if self.last_request_status:
            out["last_request_status"] = self.last_request_status
        if self.update_available is not None:
            out["update_available"] = self.update_available
        if self.latest_version:
            out["latest_version"] = self.latest_version
        return out


def _rfc3339(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


@dataclass
class State:
    _role: Role = Role.UNKNOWN
    _role_since: float = field(default_factory=time.time)
    _last_at: float = 0.0
    _last_remote: str = ""
    _last_status: int = 0
    _count: int = 0
    _update: UpdateInfo = field(default_factory=UpdateInfo)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _persist_lock: threading.Lock = field(default_factory=threading.Lock)
    _shared: bool = False

    def set_role(self, role: Role) -> None:
        with self._lock:
            if self._role == role:
                return
            self._role = role
            self._role_since = time.time()
            shared = self._shared
        if shared:
            self._persist()

    def record_request(self, remote: str, status: int, when: float | None = None) -> None:
        when = time.time() if when is None else when
        with self._lock:
            self._last_at = when
            self._last_remote = remote
            self._last_status = status
            self._count += 1
            shared = self._shared
        if shared:
            self._persist()

    def last_request_at_epoch(self) -> float:
        """When a device last hit the broker (epoch seconds), 0.0 if never.

        The mDNS publisher reads it to decide whether its advertisement has
        gone unheard and should be re-announced.
        """
        with self._lock:
            return self._last_at

    def set_update(self, info: UpdateInfo) -> None:
        """Record the latest broker self-version-check result. The update-check
        poller pokes this concurrently; the broker /sync handler and the MCP
        health/status tools read it back via ``update``."""
        with self._lock:
            self._update = info
            shared = self._shared
        if shared:
            self._persist()

    def update(self) -> UpdateInfo:
        """Return the last cached self-version-check result (default =
        known:False, i.e. no check has succeeded yet)."""
        with self._lock:
            return self._update

    def snapshot(self) -> Snapshot:
        with self._lock:
            u = self._update
            return Snapshot(
                runtime=RUNTIME,
                role=self._role.value,
                role_since=_rfc3339(self._role_since),
                last_request_at=_rfc3339(self._last_at) if self._last_at else "",
                last_request_remote=self._last_remote,
                last_request_status=self._last_status,
                requests_total=self._count,
                update_available=(u.outdated if u.known else None),
                latest_version=(u.latest if u.known else ""),
            )

    def enable_shared(self) -> None:
        """Publish this daemon's state for all lightweight MCP adapters."""
        with self._lock:
            self._shared = True
        self._persist()

    def _persist(self) -> None:
        path = session_life.runtime_dir() / "broker-state.json"
        tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}")
        try:
            with self._persist_lock:
                tmp.write_text(json.dumps(self.snapshot().to_dict()) + "\n")
                tmp.chmod(0o600)
                tmp.replace(path)
        except OSError:
            # Observability must never turn a successful device request into a
            # broker failure (read-only filesystem, disk full, etc.).
            with suppress(FileNotFoundError):
                tmp.unlink()


def load_shared_snapshot() -> Snapshot:
    raw = json.loads((session_life.runtime_dir() / "broker-state.json").read_text())
    if not raw.get("role"):
        raise ValueError("shared broker snapshot has no role")
    return Snapshot(
        runtime=str(raw.get("runtime", "")),
        role=str(raw["role"]),
        role_since=str(raw.get("role_since", "")),
        last_request_at=str(raw.get("last_request_at", "")),
        last_request_remote=str(raw.get("last_request_remote", "")),
        last_request_status=int(raw.get("last_request_status", 0)),
        requests_total=int(raw.get("requests_total", 0)),
        update_available=raw.get("update_available"),
        latest_version=str(raw.get("latest_version", "")),
    )
