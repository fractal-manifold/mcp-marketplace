"""Per-device diagnostic log storage.

The device uploads its scrubbed log ring to POST /device/<id>/logs; this
module appends it to ``<config>/device-logs/<id>.log``, capped to the most
recent MAX_LINES. The broker (leader) is the sole writer; any cwm-mcp
process reads the file for the wall_monitor_device_logs MCP tool. Writes
serialise on a sibling .lock flock and rewrite-then-rename so a reader
always sees a whole file.

Wire-compatible with cwm-mcp/internal/devlog (Go) and ../js devlog.
"""

from __future__ import annotations

import fcntl
import os
from datetime import datetime, timezone
from pathlib import Path

# Per-device retention cap; matches the wall_monitor_device_logs limit max.
MAX_LINES = 2000
# Truncate any single stamped line. The firmware's own lines are <=200
# chars, so this only bites a misbehaving/compromised device; it bounds
# total retention at ~MAX_LINES*MAX_LINE_BYTES regardless of input.
MAX_LINE_BYTES = 1024
_TRUNC_MARKER = " [truncated]"
# Single-upload byte cap (firmware sends <=3 KB per 60 s cycle).
MAX_BODY_BYTES = 128 * 1024


def dir_for(devices_dir: str) -> Path:
    """The device-logs dir, a sibling of the registry's devices dir."""
    return Path(devices_dir).parent / "device-logs"


def _log_path(d: Path, device_id: str) -> Path:
    return d / f"{device_id}.log"


def stamp_lines(body: str, recv: datetime | None = None) -> list[str]:
    """Split an uploaded body into lines, drop blanks, prefix each with the
    broker's receive time (whole batch shares one stamp)."""
    recv = (recv or datetime.now(tz=timezone.utc)).astimezone(timezone.utc)
    stamp = recv.strftime("[%Y-%m-%dT%H:%M:%SZ] ")
    out: list[str] = []
    for ln in body.split("\n"):
        ln = ln.rstrip("\r")
        if ln.strip() == "":
            continue
        line = stamp + ln
        raw = line.encode("utf-8")
        if len(raw) > MAX_LINE_BYTES:
            # Reserve the marker's bytes inside the cap so the final line is
            # <= MAX_LINE_BYTES; "ignore" drops a trailing partial rune.
            limit = MAX_LINE_BYTES - len(_TRUNC_MARKER.encode("utf-8"))
            line = raw[:limit].decode("utf-8", "ignore") + _TRUNC_MARKER
        out.append(line)
    return out


def read(devices_dir: str, device_id: str) -> list[str]:
    """Every retained line for the device ([] when no file yet)."""
    path = _log_path(dir_for(devices_dir), device_id)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []
    return [ln for ln in text.split("\n") if ln]


def append(devices_dir: str, device_id: str, lines: list[str]) -> None:
    """Append lines, keeping only the most recent MAX_LINES. flock-guarded."""
    if not lines:
        return
    d = dir_for(devices_dir)
    d.mkdir(parents=True, exist_ok=True)
    lock_path = _log_path(d, device_id).with_suffix(".log.lock")
    with open(lock_path, "a+") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            existing = read(devices_dir, device_id)
            alllines = (existing + lines)[-MAX_LINES:]
            path = _log_path(d, device_id)
            tmp = path.with_suffix(".log.tmp")
            data = "\n".join(alllines)
            if alllines:
                data += "\n"
            tmp.write_text(data, encoding="utf-8")
            os.replace(tmp, path)
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
