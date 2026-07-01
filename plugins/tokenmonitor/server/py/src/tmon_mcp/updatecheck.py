"""Broker self-version check — the one question the broker cannot otherwise see:
is a newer TokenMonitor broker/plugin release published than the one this
process is running? The broker does NOT auto-update, so over time it drifts
behind the firmware it feeds. This module periodically fetches the public
marketplace catalog, compares the tokenmonitor entry's version against the
installed release version, and stashes the verdict in the shared State so three
surfaces can advertise it: the /device/<id>/sync body (-> on-device banner),
tokenmonitor_health / tokenmonitor_status (-> Claude Code), and a stderr WARN.

Strictly best-effort: any network/parse failure leaves the cached verdict
unknown (never a false "up to date" or "outdated") and never blocks or errors
the broker. Wire-identical to go/internal/updatecheck.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.request
from pathlib import Path

from . import __version__
from .ota import compare_semver
from .state import State, UpdateInfo

# PLUGIN_NAME is the marketplace entry whose version tracks releases.
PLUGIN_NAME = "tokenmonitor"
# DEFAULT_MARKETPLACE_URL is the raw catalog on the marketplace repo's default
# branch — the single source of truth for "latest published". Overridable via
# TOKENMONITOR_MARKETPLACE_URL (used by tests).
DEFAULT_MARKETPLACE_URL = (
    "https://raw.githubusercontent.com/fractal-manifold/mcp-marketplace/"
    "main/.claude-plugin/marketplace.json"
)

_HTTP_TIMEOUT = 10.0  # seconds
_POLL_INTERVAL = 6 * 60 * 60  # seconds
_INITIAL_DELAY = 30.0  # seconds
_MAX_BODY = 1 * 1024 * 1024  # 1 MiB


def marketplace_url() -> str:
    """Return the catalog URL, honouring the test/CI override."""
    return os.environ.get("TOKENMONITOR_MARKETPLACE_URL") or DEFAULT_MARKETPLACE_URL


def installed_version(baked: str | None = None) -> str:
    """Resolve the running release version. Prefer the bundle's plugin.json (the
    release/marketplace axis, apples-to-apples with the catalog) found via
    CLAUDE_PLUGIN_ROOT; fall back to the packaged broker version when that file
    is absent or unreadable."""
    baked = baked if baked is not None else __version__
    root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if root:
        p = Path(root) / ".claude-plugin" / "plugin.json"
        try:
            m = json.loads(p.read_text())
            v = m.get("version")
            if isinstance(v, str) and v:
                return v
        except Exception:
            pass
    return baked


def fetch_latest() -> str:
    """GET the marketplace catalog and return the tokenmonitor entry's version.
    An empty string means the entry was absent. Raises on network/HTTP/parse
    errors (callers treat any exception as "unknown")."""
    req = urllib.request.Request(
        marketplace_url(),
        headers={
            "Accept": "application/json",
            "User-Agent": "tokenmonitor-mcp-updatecheck",
        },
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310
        status = getattr(resp, "status", 200)
        if status != 200:
            raise RuntimeError(f"marketplace fetch: HTTP {status}")
        body = resp.read(_MAX_BODY)
    doc = json.loads(body)
    for p in doc.get("plugins", []) or []:
        if isinstance(p, dict) and p.get("name") == PLUGIN_NAME:
            return str(p.get("version", ""))
    return ""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def check(current: str) -> UpdateInfo:
    """Perform one fetch+compare and return the verdict. On any failure it
    returns a known=False result (verdict unknown) — callers must treat that as
    "advertise nothing"."""
    try:
        latest = fetch_latest()
    except Exception:
        return UpdateInfo(known=False, current=current)
    if not latest:
        return UpdateInfo(known=False, current=current)
    cmp = compare_semver(latest, current)
    if cmp is None:
        # Either version is unparseable under the project's semver subset;
        # don't guess.
        return UpdateInfo(known=False, current=current)
    return UpdateInfo(
        known=True,
        outdated=cmp > 0,
        current=current,
        latest=latest,
        checked_at=_now_iso(),
    )


async def _sleep(seconds: float, stop: asyncio.Event | None) -> bool:
    """Sleep up to ``seconds``. Return True to keep polling, False if the poller
    should exit (stop set or cancelled)."""
    if stop is None:
        try:
            await asyncio.sleep(seconds)
        except asyncio.CancelledError:
            return False
        return True
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        return True  # slept the full interval; poll now
    except asyncio.CancelledError:
        return False
    return False  # stop was set


async def run(
    state: State,
    logger: logging.Logger | None = None,
    *,
    baked: str | None = None,
    initial_delay: float = _INITIAL_DELAY,
    interval: float = _POLL_INTERVAL,
    stop: asyncio.Event | None = None,
) -> None:
    """Poll the marketplace catalog on a slow cadence and publish each verdict
    into ``state``. Returns when ``stop`` is set or the task is cancelled. The
    blocking fetch runs in a thread so it never stalls the event loop. Wholly
    best-effort: a fetch failure is swallowed and retried next tick."""
    if state is None:
        return
    current = installed_version(baked)
    delay = initial_delay
    while True:
        if not await _sleep(delay, stop):
            return
        delay = interval
        try:
            info = await asyncio.get_running_loop().run_in_executor(None, check, current)
            state.set_update(info)
            if logger is not None:
                if info.known and info.outdated:
                    logger.warning(
                        "updatecheck: broker %s is behind published %s — update the tokenmonitor plugin",
                        info.current,
                        info.latest,
                    )
                elif info.known:
                    logger.info("updatecheck: broker %s is up to date", info.current)
        except Exception:  # noqa: BLE001 — best-effort; never break the loop
            pass
