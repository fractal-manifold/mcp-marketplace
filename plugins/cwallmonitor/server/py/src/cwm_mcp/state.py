"""Runtime state snapshot exposed by wall_monitor_status."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum

from . import RUNTIME


class Role(str, Enum):
    UNKNOWN = "unknown"
    LEADER = "leader"
    FOLLOWER = "follower"


@dataclass
class Snapshot:
    runtime: str
    role: str
    role_since: str  # RFC3339
    last_request_at: str = ""
    last_request_remote: str = ""
    last_request_status: int = 0
    requests_total: int = 0

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
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def set_role(self, role: Role) -> None:
        with self._lock:
            if self._role == role:
                return
            self._role = role
            self._role_since = time.time()

    def record_request(self, remote: str, status: int, when: float | None = None) -> None:
        when = time.time() if when is None else when
        with self._lock:
            self._last_at = when
            self._last_remote = remote
            self._last_status = status
            self._count += 1

    def snapshot(self) -> Snapshot:
        with self._lock:
            return Snapshot(
                runtime=RUNTIME,
                role=self._role.value,
                role_since=_rfc3339(self._role_since),
                last_request_at=_rfc3339(self._last_at) if self._last_at else "",
                last_request_remote=self._last_remote,
                last_request_status=self._last_status,
                requests_total=self._count,
            )
