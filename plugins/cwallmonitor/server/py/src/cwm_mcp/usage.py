"""Per-provider usage fetchers + TTL cache.

Wire-compatible with cwm-mcp Go internal/usage. See compat/USAGE_WIRE.md
for the JSON shape served at /usage/{claude,codex,gemini}.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Protocol

import aiohttp

from . import creds
from .gemini_oauth_client import resolve_gemini_oauth_client

log = logging.getLogger("cwm_mcp.usage")

PROVIDER_CLAUDE = "claude"
PROVIDER_CODEX = "codex"
PROVIDER_GEMINI = "gemini"


class UsageError(Exception):
    """Base class for usage errors. The broker maps subclasses to HTTP."""


class CredsMissing(UsageError):
    pass


class TokenExpired(UsageError):
    pass


class Unauthorized(UsageError):
    pass


class RateLimited(UsageError):
    def __init__(self, retry_after: int = 0):
        super().__init__("rate limited")
        self.retry_after = retry_after


class Upstream(UsageError):
    pass


class Transport(UsageError):
    pass


class ParseUpstream(UsageError):
    pass


class NotImplementedProvider(UsageError):
    pass


@dataclass
class Slot:
    """One entry in Snapshot.slots — see compat/USAGE_WIRE.md."""

    label: str = ""
    pct: float = 0.0
    window_seconds: int = 0
    reset_eta_seconds: int = 0


@dataclass
class Snapshot:
    session_pct: float = 0.0
    weekly_pct: float = 0.0
    design_pct: float = 0.0
    design_present: bool = False
    session_reset_eta_seconds: int = 0
    weekly_reset_eta_seconds: int = 0
    design_reset_eta_seconds: int = 0
    session_window_seconds: int = 0
    weekly_window_seconds: int = 0
    tier: str = "unknown"
    fetched_at_unix: int = 0
    stale_seconds: int = 0
    slots: list[Slot] = field(default_factory=list)


class Fetcher(Protocol):
    async def fetch(self, session: aiohttp.ClientSession) -> Snapshot: ...


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


@dataclass
class _Entry:
    snap: Snapshot
    fetched: float
    last_err: Exception | None = None


class Cache:
    """Per-provider TTL cache with singleflight.

    On upstream error we return the previous good snapshot AND raise — the
    broker decides whether to surface the stale-with-200 or the error.
    """

    def __init__(self, ttl_seconds: int, fetchers: dict[str, Fetcher]) -> None:
        self._ttl = max(0.001, float(ttl_seconds))
        self._fetchers = fetchers
        self._entries: dict[str, _Entry] = {}
        self._inflight: dict[str, asyncio.Task[Snapshot]] = {}
        self._lock = asyncio.Lock()
        self._now: Callable[[], float] = time.time

    def providers(self) -> list[str]:
        return sorted(self._fetchers.keys())

    def gemini_fetcher(self) -> "GeminiFetcher | None":
        """Return the wired GeminiFetcher for the per-device override
        path. None when Gemini is disabled or a different fetcher
        was injected (tests)."""
        f = self._fetchers.get(PROVIDER_GEMINI)
        return f if isinstance(f, GeminiFetcher) else None

    async def get(self, session: aiohttp.ClientSession, provider: str) -> Snapshot:
        fetcher = self._fetchers.get(provider)
        if fetcher is None:
            raise NotImplementedProvider(f"provider {provider!r} not enabled")

        async with self._lock:
            entry = self._entries.get(provider)
            now = self._now()
            if entry is not None and now - entry.fetched < self._ttl:
                snap = Snapshot(**asdict(entry.snap))
                snap.stale_seconds = int(now - entry.fetched)
                return snap

            task = self._inflight.get(provider)
            if task is None:
                task = asyncio.create_task(self._refresh(session, provider, fetcher))
                self._inflight[provider] = task

        try:
            return await task
        except UsageError:
            # On error, fall back to last-good if present.
            async with self._lock:
                entry = self._entries.get(provider)
                if entry is not None:
                    snap = Snapshot(**asdict(entry.snap))
                    snap.stale_seconds = int(self._now() - entry.fetched)
                    # Re-raise so the caller can decide; pass the snap via
                    # exception attribute for the broker's stale-with-200.
                    raise
            raise

    async def _refresh(self, session: aiohttp.ClientSession, provider: str, fetcher: Fetcher) -> Snapshot:
        try:
            snap = await fetcher.fetch(session)
            now = self._now()
            snap.fetched_at_unix = int(now)
            snap.stale_seconds = 0
            async with self._lock:
                self._entries[provider] = _Entry(snap=snap, fetched=now)
                self._inflight.pop(provider, None)
            return snap
        except Exception as e:
            async with self._lock:
                entry = self._entries.get(provider)
                if entry is not None:
                    entry.last_err = e
                self._inflight.pop(provider, None)
            raise


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seconds_until_iso(iso: str, now_unix: float) -> int:
    """Parse Anthropic-style ISO with microsecond precision into ETA seconds."""
    if not iso:
        return 0
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:
        return 0
    eta = t.astimezone(timezone.utc).timestamp() - now_unix
    return int(max(0, eta))


def _retry_after(resp: aiohttp.ClientResponse) -> int:
    v = resp.headers.get("Retry-After", "")
    if not v:
        return 0
    try:
        return max(0, int(v))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime

        t = parsedate_to_datetime(v)
        return max(0, int(t.timestamp() - time.time()))
    except Exception:
        return 0


async def _read_json(resp: aiohttp.ClientResponse) -> dict:
    try:
        return await resp.json(content_type=None)
    except Exception as e:
        raise ParseUpstream(f"json: {e}") from e


# ---------------------------------------------------------------------------
# Claude
# ---------------------------------------------------------------------------


CLAUDE_URL = "https://api.anthropic.com/api/oauth/usage"
CLAUDE_BETA = "oauth-2025-04-20"
CLAUDE_SESSION_WINDOW = 5 * 3600
CLAUDE_WEEKLY_WINDOW = 7 * 86400


@dataclass
class ClaudeFetcher:
    oauth_path: str

    async def fetch(self, session: aiohttp.ClientSession) -> Snapshot:
        try:
            c = creds.load(self.oauth_path)
        except creds.CredsFileMissing as e:
            raise CredsMissing(str(e)) from e
        except creds.CredsParse as e:
            raise ParseUpstream(str(e)) from e
        if c.is_expired(int(time.time() * 1000)):
            raise TokenExpired("token expired, refresh on laptop")

        headers = {
            "Authorization": f"Bearer {c.access_token}",
            "anthropic-beta": CLAUDE_BETA,
            "Accept": "application/json",
        }
        try:
            async with session.get(CLAUDE_URL, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 401:
                    raise Unauthorized("upstream rejected token")
                if resp.status == 429:
                    raise RateLimited(_retry_after(resp))
                if resp.status < 200 or resp.status >= 300:
                    raise Upstream(f"status={resp.status}")
                doc = await _read_json(resp)
        except aiohttp.ClientError as e:
            raise Transport(str(e)) from e

        now = time.time()
        snap = Snapshot(
            session_window_seconds=CLAUDE_SESSION_WINDOW,
            weekly_window_seconds=CLAUDE_WEEKLY_WINDOW,
        )
        five = doc.get("five_hour") or {}
        seven = doc.get("seven_day") or {}
        ome = doc.get("seven_day_omelette")
        if isinstance(five, dict):
            snap.session_pct = float(five.get("utilization") or 0)
            snap.session_reset_eta_seconds = _seconds_until_iso(five.get("resets_at") or "", now)
        if isinstance(seven, dict):
            snap.weekly_pct = float(seven.get("utilization") or 0)
            snap.weekly_reset_eta_seconds = _seconds_until_iso(seven.get("resets_at") or "", now)
        if isinstance(ome, dict):
            snap.design_present = True
            snap.design_pct = float(ome.get("utilization") or 0)
            snap.design_reset_eta_seconds = _seconds_until_iso(ome.get("resets_at") or "", now)
        extra = doc.get("extra_usage") or {}
        snap.tier = "paid" if extra.get("is_enabled") else "unknown"
        return snap


# ---------------------------------------------------------------------------
# Codex
# ---------------------------------------------------------------------------


CODEX_URL = "https://chatgpt.com/backend-api/wham/usage"
CODEX_SESSION_FALLBACK = 5 * 3600
CODEX_WEEKLY_FALLBACK = 7 * 86400


@dataclass
class CodexFetcher:
    auth_path: str

    async def fetch(self, session: aiohttp.ClientSession) -> Snapshot:
        try:
            c = creds.load_codex(self.auth_path)
        except creds.CredsFileMissing as e:
            raise CredsMissing(str(e)) from e
        except creds.CredsParse as e:
            raise ParseUpstream(str(e)) from e
        if c.is_expired(int(time.time() * 1000)):
            raise TokenExpired("token expired, refresh on laptop")

        headers = {
            "Authorization": f"Bearer {c.access_token}",
            "ChatGPT-Account-Id": c.account_id,
            "Accept": "application/json",
            "User-Agent": "cwm-mcp/usage",
            "OpenAI-Beta": "chatgpt-account=enabled",
        }
        try:
            async with session.get(CODEX_URL, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 401:
                    raise Unauthorized("upstream rejected token")
                if resp.status == 429:
                    raise RateLimited(_retry_after(resp))
                if resp.status < 200 or resp.status >= 300:
                    raise Upstream(f"status={resp.status}")
                doc = await _read_json(resp)
        except aiohttp.ClientError as e:
            raise Transport(str(e)) from e

        snap = Snapshot(
            session_window_seconds=CODEX_SESSION_FALLBACK,
            weekly_window_seconds=CODEX_WEEKLY_FALLBACK,
            tier=str(doc.get("plan_type") or "unknown"),
        )
        rl = doc.get("rate_limit") or {}
        primary = rl.get("primary_window") or {}
        secondary = rl.get("secondary_window") or {}
        if isinstance(primary, dict):
            snap.session_pct = float(primary.get("used_percent") or 0)
            lim = primary.get("limit_window_seconds")
            if isinstance(lim, (int, float)) and lim > 0:
                snap.session_window_seconds = int(lim)
            snap.session_reset_eta_seconds = _codex_eta(primary)
        if isinstance(secondary, dict):
            snap.weekly_pct = float(secondary.get("used_percent") or 0)
            lim = secondary.get("limit_window_seconds")
            if isinstance(lim, (int, float)) and lim > 0:
                snap.weekly_window_seconds = int(lim)
            snap.weekly_reset_eta_seconds = _codex_eta(secondary)
        return snap


def _codex_eta(win: dict) -> int:
    ra = win.get("reset_after_seconds")
    if isinstance(ra, (int, float)):
        return int(ra)
    at = win.get("reset_at")
    if isinstance(at, (int, float)):
        eta = int(at) - int(time.time())
        return max(0, eta)
    return 0


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------


GEMINI_CODE_ASSIST = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
GEMINI_USER_QUOTA = "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota"
GEMINI_TOKEN_URL = "https://oauth2.googleapis.com/token"
# Gemini only has a daily quota — no weekly window. We surface the
# Pro bucket (the headline model users care about most) as session
# (24h) and leave weekly empty so the device hides that card.
GEMINI_SESSION_FALLBACK = 86400
GEMINI_SESSION_MODEL = "gemini-2.5-pro"


@dataclass
class GeminiFetcher:
    creds_path: str
    projects_path: str
    # Ordered list of model IDs to expose as Snapshot.slots. Empty falls
    # back to the single Pro bucket; first matched model is mirrored
    # into session_pct for legacy firmware.
    models: list[str] = field(default_factory=list)
    # Optional per-request hook (e.g. honour a per-device override
    # stored in the registry). When set, supersedes `models`.
    models_for: Callable[[], list[str]] | None = None
    _cached_token: tuple[str, int] = field(default=("", 0))  # (token, expires_at_ms)

    def _models(self) -> list[str]:
        if self.models_for is not None:
            m = self.models_for()
            if m:
                return list(m)
        if self.models:
            return list(self.models)
        return [GEMINI_SESSION_MODEL]

    async def fetch_with_models(self, session: aiohttp.ClientSession, models: list[str]) -> Snapshot:
        """Like fetch() but uses the supplied model list (e.g. a per-device
        override) instead of self.models / self.models_for. Token cache is
        reused — concurrent-safe because the model list is passed through
        the call stack, not written onto the instance."""
        return await self._fetch_internal(session, models)

    async def fetch(self, session: aiohttp.ClientSession) -> Snapshot:
        return await self._fetch_internal(session, self._models())

    async def _fetch_internal(self, session: aiohttp.ClientSession, models: list[str]) -> Snapshot:
        token = await self._token(session)
        body: dict = {
            "metadata": {
                "ideType": "IDE_UNSPECIFIED",
                "platform": "PLATFORM_UNSPECIFIED",
                "pluginType": "GEMINI",
            },
        }
        proj = self._active_project()
        if proj:
            body["cloudaicompanionProject"] = proj
            body["metadata"]["duetProject"] = proj
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            async with session.post(GEMINI_CODE_ASSIST, json=body, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status == 401:
                    raise Unauthorized("upstream rejected token")
                if resp.status == 429:
                    raise RateLimited(_retry_after(resp))
                if resp.status < 200 or resp.status >= 300:
                    raise Upstream(f"status={resp.status}")
                doc = await _read_json(resp)
        except aiohttp.ClientError as e:
            raise Transport(str(e)) from e

        snap = Snapshot(
            session_window_seconds=GEMINI_SESSION_FALLBACK,
            weekly_window_seconds=0,
        )
        paid = doc.get("paidTier")
        current = doc.get("currentTier") or {}
        if isinstance(paid, dict):
            snap.tier = str(paid.get("id") or "paid")
        elif isinstance(current, dict):
            snap.tier = str(current.get("id") or "unknown")

        # retrieveUserQuota is the endpoint gemini-cli itself polls to
        # drive its usage UI: free and paid tiers both return per-model
        # buckets with remainingFraction + resetTime. Without this the
        # device was stuck at 0 % even on heavily-used accounts.
        quota_proj = str(doc.get("cloudaicompanionProject") or "") or self._active_project()
        try:
            quota = await self._fetch_quota(session, token, quota_proj)
        except Exception:
            quota = None
        if quota:
            _gemini_apply_quota(snap, quota, time.time(), models)
        return snap

    async def _fetch_quota(self, session: aiohttp.ClientSession, token: str, project: str) -> dict | None:
        body: dict = {}
        if project:
            body["project"] = project
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        async with session.post(GEMINI_USER_QUOTA, json=body, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status < 200 or resp.status >= 300:
                return None
            return await _read_json(resp)

    async def _token(self, session: aiohttp.ClientSession) -> str:
        cached_tok, cached_exp = self._cached_token
        now_ms = int(time.time() * 1000)
        if cached_tok and cached_exp - now_ms > 60_000:
            return cached_tok

        p = Path(self.creds_path)
        if not p.is_file():
            raise CredsMissing(f"gemini creds file missing: {self.creds_path}")
        try:
            disk = json.loads(p.read_text())
        except Exception as e:
            raise ParseUpstream(f"gemini creds parse error: {e}") from e

        access = disk.get("access_token") or ""
        refresh = disk.get("refresh_token") or ""
        expiry = int(disk.get("expiry_date") or 0)
        if access and expiry - now_ms > 60_000:
            self._cached_token = (access, expiry)
            return access
        if not refresh:
            raise TokenExpired("token expired and no refresh_token available")

        oauth = await resolve_gemini_oauth_client(session)
        form = {
            "client_id": oauth.client_id,
            "client_secret": oauth.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh,
        }
        try:
            async with session.post(GEMINI_TOKEN_URL, data=form, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status < 200 or resp.status >= 300:
                    body = await resp.text()
                    raise Unauthorized(f"refresh failed: status={resp.status} body={body[:200]}")
                out = await _read_json(resp)
        except aiohttp.ClientError as e:
            raise Transport(str(e)) from e

        new_tok = out.get("access_token") or ""
        if not new_tok:
            raise ParseUpstream("refresh returned empty access_token")
        new_exp = now_ms + int(out.get("expires_in") or 3600) * 1000
        self._cached_token = (new_tok, new_exp)
        return new_tok

    def _active_project(self) -> str:
        p = Path(self.projects_path)
        if not p.is_file():
            return ""
        try:
            doc = json.loads(p.read_text())
        except Exception:
            return ""
        projects = doc.get("projects") or {}
        for v in projects.values():
            return str(v)
        return ""


def _gemini_pick_bucket(buckets: list[dict], model_id: str) -> dict | None:
    for b in buckets:
        if b.get("modelId") == model_id:
            return b
    # Prefix fallback covers version drift (e.g. -flash → -flash-002).
    for b in buckets:
        mid = b.get("modelId") or ""
        if isinstance(mid, str) and mid.startswith(model_id):
            return b
    return None


def _gemini_used_pct(remaining_fraction: float) -> float:
    if remaining_fraction < 0:
        remaining_fraction = 0.0
    elif remaining_fraction > 1:
        remaining_fraction = 1.0
    return (1 - remaining_fraction) * 100


def _gemini_reset_eta(iso: str, now_unix: float) -> int:
    if not iso:
        return 0
    eta = _seconds_until_iso(iso, now_unix)
    return max(0, int(eta))


def _gemini_apply_quota(
    snap: Snapshot, quota: dict, now_unix: float, models: list[str]
) -> None:
    buckets = quota.get("buckets") or []
    if not isinstance(buckets, list):
        return
    if not models:
        models = [GEMINI_SESSION_MODEL]
    if len(models) > 3:
        models = models[:3]
    first = True
    for m in models:
        b = _gemini_pick_bucket(buckets, m)
        if b is None:
            continue
        pct = _gemini_used_pct(float(b.get("remainingFraction") or 0))
        eta = _gemini_reset_eta(str(b.get("resetTime") or ""), now_unix)
        snap.slots.append(Slot(
            label=_gemini_label(m),
            pct=pct,
            window_seconds=GEMINI_SESSION_FALLBACK,
            reset_eta_seconds=eta,
        ))
        if first:
            snap.session_pct = pct
            snap.session_reset_eta_seconds = eta
            first = False


def _gemini_label(model_id: str) -> str:
    """Pill text rendered on the card: 'gemini-2.5-pro' → 'Pro'."""
    tail = model_id
    if tail.startswith("gemini-"):
        tail = tail[len("gemini-"):]
        # Strip the version segment ("2.5-").
        if "-" in tail:
            tail = tail.split("-", 1)[1]
    if not tail:
        return model_id
    parts = [p[:1].upper() + p[1:] if p else p for p in tail.split("-")]
    out = "-".join(parts)
    return out[:15]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_cache(cfg) -> Cache | None:
    """Wire up Fetchers from cfg.* paths. Returns None if no provider enabled."""
    fetchers: dict[str, Fetcher] = {
        PROVIDER_CLAUDE: ClaudeFetcher(oauth_path=cfg.oauth_path_abs()),
    }
    if cfg.codex.enabled:
        fetchers[PROVIDER_CODEX] = CodexFetcher(auth_path=cfg.codex_auth_path_abs())
    if cfg.gemini.enabled:
        fetchers[PROVIDER_GEMINI] = GeminiFetcher(
            creds_path=cfg.gemini_creds_path_abs(),
            projects_path=cfg.gemini_projects_path_abs(),
            models=cfg.gemini_models(),
        )
    ttl = cfg.usage.cache_ttl_seconds or 30
    log.info("usage: providers=%s cache_ttl=%ss", sorted(fetchers.keys()), ttl)
    return Cache(ttl_seconds=ttl, fetchers=fetchers)
