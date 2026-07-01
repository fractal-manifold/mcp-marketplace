"""Per-provider usage fetchers + TTL cache.

Wire-compatible with tokenmonitor-mcp Go internal/usage. See compat/USAGE_WIRE.md
for the JSON shape served at /usage/{claude,codex,antigravity}. The deprecated
"gemini" path is still accepted as an alias (canonical_provider) for firmware
deployed before the Gemini CLI -> Antigravity CLI rename.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Protocol

import aiohttp

from . import creds

log = logging.getLogger("tmon_mcp.usage")

PROVIDER_CLAUDE = "claude"
PROVIDER_CODEX = "codex"
PROVIDER_ANTIGRAVITY = "antigravity"
# PROVIDER_GEMINI is the DEPRECATED pre-rename wire string for the Antigravity
# provider (Google retired the Gemini CLI 2026-06-18). Deployed firmware still
# polls /usage/gemini and signs that exact path, so the broker keeps it as an
# alias: canonical_provider() maps it to PROVIDER_ANTIGRAVITY AFTER the HMAC
# check, never before.
PROVIDER_GEMINI = "gemini"


def canonical_provider(p: str) -> str:
    """Fold the deprecated "gemini" wire alias onto the canonical
    "antigravity" provider key used for cache/fetcher lookup. Call only AFTER
    verifying the request signature against the original path."""
    return PROVIDER_ANTIGRAVITY if p == PROVIDER_GEMINI else p


class UsageError(Exception):
    """Base class for usage errors. The broker maps subclasses to HTTP.

    stale_snapshot, when set by the cache, carries the last-good Snapshot so
    the broker can answer 200 + X-Tmon-Stale-Reason instead of an error
    (matching Go/JS stale-with-200 semantics)."""

    stale_snapshot: "Snapshot | None" = None


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
    # True when the broker reached the provider but the quota sub-RPC failed,
    # so the *_pct fields are placeholders. Emitted on the wire ONLY when true
    # (the broker pops it when falsy) — see compat/USAGE_WIRE.md.
    degraded: bool = False
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

    def antigravity_fetcher(self) -> "AntigravityFetcher | None":
        """Return the wired AntigravityFetcher for the per-device override
        path. None when Antigravity is disabled or a different fetcher
        was injected (tests)."""
        f = self._fetchers.get(PROVIDER_ANTIGRAVITY)
        return f if isinstance(f, AntigravityFetcher) else None

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
        except UsageError as err:
            # On error, fall back to last-good if present. Re-raise so the
            # caller can map the error to HTTP, but attach the last-good
            # snapshot to the exception so the broker can answer
            # stale-with-200 (matching Go/JS: 200 + X-Tmon-Stale-Reason).
            async with self._lock:
                entry = self._entries.get(provider)
                if entry is not None:
                    snap = Snapshot(**asdict(entry.snap))
                    snap.stale_seconds = int(self._now() - entry.fetched)
                    err.stale_snapshot = snap
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
            "User-Agent": "tokenmonitor-mcp/usage",
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
# Antigravity (agy, successor to the retired Gemini CLI)
# ---------------------------------------------------------------------------


# Antigravity's grouped weekly quota is served from the `daily-` CANARY host,
# not prod cloudcode-pa (prod 403s the quota RPC). Verified end-to-end via a
# mitmproxy capture of agy 1.0.13 (2026-06-30) — see the project memory
# "agy-antigravity-cli-format" for the full recipe.
ANTIGRAVITY_HOST = "https://daily-cloudcode-pa.googleapis.com/v1internal:"
GEMINI_CODE_ASSIST = ANTIGRAVITY_HOST + "loadCodeAssist"
GEMINI_USER_QUOTA = ANTIGRAVITY_HOST + "retrieveUserQuotaSummary"
# retrieveUserQuotaSummary is a PRIVATE API gated on the registered client
# User-Agent: without it Google returns 403 PERMISSION_DENIED; with agy's exact
# UA it returns 200. Send it on every call.
ANTIGRAVITY_UA = "antigravity/cli/1.0.13 (aidev_client; os_type=linux; arch=amd64)"
# Antigravity quota is a WEEKLY per-group limit (Gemini Models / Claude+GPT);
# there is no daily/session window, so the device hides the session card.
ANTIGRAVITY_WEEKLY = 604800
# OS keyring service under which agy stores its consumer OAuth token. The token
# is a JSON value {token:{access_token,refresh_token,expiry},…}; only the
# access_token is read here (agy keeps it fresh while it runs).
ANTIGRAVITY_KEYRING_SERVICE = "gemini"


def _read_keyring_token(service: str) -> dict | None:
    """Pull agy's consumer OAuth token from the OS keyring (libsecret) via
    `secret-tool`. The quota RPC requires THIS token — the gemini-cli token in
    oauth_creds.json authenticates loadCodeAssist but is rejected (403) by the
    quota endpoint. Returns the inner token object, or None on any failure (no
    secret-tool, locked/empty keyring, bad JSON) so the fetcher degrades to "--"
    rather than crashing. Verified via live capture 2026-06-30."""
    try:
        proc = subprocess.run(
            ["secret-tool", "lookup", "service", service],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    try:
        d = json.loads(proc.stdout)
    except Exception:
        return None
    tok = d.get("token") if isinstance(d, dict) else None
    return tok if isinstance(tok, dict) else None


def _parse_iso_ms(iso: str) -> int:
    """Parse an RFC3339 timestamp to epoch milliseconds, or 0 if unparseable
    (mirrors JS Date.parse(...) || 0)."""
    if not iso:
        return 0
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:
        return 0
    return int(t.astimezone(timezone.utc).timestamp() * 1000)


@dataclass
class AntigravityFetcher:
    keyring_service: str = ANTIGRAVITY_KEYRING_SERVICE
    # models/models_for are retained for call-site compatibility with the
    # per-device override path; the quota is now grouped (Gemini Models /
    # Claude+GPT), not per-model, so they no longer affect the result.
    models: list[str] = field(default_factory=list)
    models_for: Callable[[], list[str]] | None = None
    _cached_token: tuple[str, int] = field(default=("", 0))  # (token, expires_at_ms)

    async def fetch_with_models(self, session: aiohttp.ClientSession, models: list[str]) -> Snapshot:
        """Grouped quota ignores the per-device model slice; kept for call-site
        compat with the per-device override path in the broker."""
        return await self._fetch_internal(session)

    async def fetch(self, session: aiohttp.ClientSession) -> Snapshot:
        return await self._fetch_internal(session)

    async def _fetch_internal(self, session: aiohttp.ClientSession) -> Snapshot:
        token = self._token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": ANTIGRAVITY_UA,
        }
        # agy sends exactly this: ideType ANTIGRAVITY, no pluginType. The
        # response carries cloudaicompanionProject, used for the quota call.
        body = {"metadata": {"ideType": "ANTIGRAVITY"}}
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
            # Weekly-only quota: hide the session/daily card, surface weekly.
            session_window_seconds=0,
            weekly_window_seconds=ANTIGRAVITY_WEEKLY,
        )
        paid = doc.get("paidTier")
        current = doc.get("currentTier") or {}
        if isinstance(paid, dict):
            snap.tier = str(paid.get("id") or "paid")
        elif isinstance(current, dict):
            snap.tier = str(current.get("id") or "unknown")

        project = str(doc.get("cloudaicompanionProject") or "")
        try:
            quota = await self._fetch_quota(session, token, project)
        except Exception as e:
            # Quota sub-RPC failed: keep the tier-only snapshot but log the
            # error (previously swallowed) and mark it degraded below.
            log.warning("usage: antigravity quota sub-RPC failed (degraded): %s", e)
            quota = None
        if quota:
            _antigravity_apply_quota(snap, quota, time.time())
        else:
            # Reached the provider but no usable quota → placeholder pct fields.
            # Mark degraded so the device shows "usage unavailable" rather than
            # a bogus 0% (compat/USAGE_WIRE.md).
            snap.degraded = True
        return snap

    async def _fetch_quota(self, session: aiohttp.ClientSession, token: str, project: str) -> dict | None:
        # retrieveUserQuotaSummary requires a top-level `project` (empty body →
        # 403) and rejects loadCodeAssist-style metadata fields. Verified
        # 2026-06-30.
        body: dict = {}
        if project:
            body["project"] = project
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": ANTIGRAVITY_UA,
        }
        async with session.post(GEMINI_USER_QUOTA, json=body, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status < 200 or resp.status >= 300:
                return None
            return await _read_json(resp)

    def _token(self) -> str:
        """Read-only: agy's consumer token from the keyring. Per the maintainer's
        choice we do NOT refresh it here — agy keeps it fresh while it runs. A
        missing/expired token surfaces as CredsMissing/TokenExpired, which the
        broker maps to 404/503 and the device renders as "--"."""
        now_ms = int(time.time() * 1000)
        cached_tok, cached_exp = self._cached_token
        if cached_tok and cached_exp - now_ms > 60_000:
            return cached_tok
        t = _read_keyring_token(self.keyring_service)
        if not t or not t.get("access_token"):
            raise CredsMissing(
                f'antigravity keyring token not found (service="{self.keyring_service}"; sign in with agy)'
            )
        exp_ms = _parse_iso_ms(t.get("expiry") or "")
        if exp_ms and exp_ms - now_ms < 60_000:
            raise TokenExpired("antigravity keyring token expired (run agy to refresh it)")
        self._cached_token = (t["access_token"], exp_ms or (now_ms + 300_000))
        return t["access_token"]


def _gemini_used_pct(remaining_fraction) -> float:
    try:
        r = float(remaining_fraction)
    except (TypeError, ValueError):
        r = 0.0
    if not math.isfinite(r) or r < 0:
        r = 0.0
    elif r > 1:
        r = 1.0
    return (1 - r) * 100


def _gemini_reset_eta(iso: str, now_unix: float) -> int:
    if not iso:
        return 0
    return max(0, int(_seconds_until_iso(iso, now_unix)))


def _antigravity_apply_quota(snap: Snapshot, quota: dict, now_unix: float) -> None:
    """Map the real retrieveUserQuotaSummary response —
    {groups:[{displayName,description,buckets:[{window,resetTime,remainingFraction}]}]}
    — onto the device snapshot. Each group becomes one weekly slot; the
    "Gemini Models" group drives the headline weekly bar (maintainer's choice),
    falling back to the first group if no Gemini group is present. Verified
    against a live capture (agy 1.0.13, 2026-06-30)."""
    groups = quota.get("groups") if isinstance(quota, dict) else None
    if not isinstance(groups, list):
        groups = []
    headline_set = False
    for g in groups:
        if not isinstance(g, dict):
            continue
        gbuckets = g.get("buckets")
        if not isinstance(gbuckets, list):
            gbuckets = []
        b = next((x for x in gbuckets if isinstance(x, dict) and x.get("window") == "weekly"), None)
        if b is None:
            b = gbuckets[0] if gbuckets and isinstance(gbuckets[0], dict) else None
        if b is None:
            continue
        pct = _gemini_used_pct(b.get("remainingFraction"))
        eta = _gemini_reset_eta(str(b.get("resetTime") or ""), now_unix)
        snap.slots.append(Slot(
            label=_antigravity_group_label(g.get("displayName")),
            pct=pct,
            window_seconds=ANTIGRAVITY_WEEKLY,
            reset_eta_seconds=eta,
        ))
        is_gemini = "gemini" in str(g.get("displayName") or "").lower() or str(
            b.get("bucketId") or ""
        ).lower().startswith("gemini")
        if is_gemini and not headline_set:
            snap.weekly_pct = pct
            snap.weekly_reset_eta_seconds = eta
            headline_set = True
    if not headline_set and snap.slots:
        snap.weekly_pct = snap.slots[0].pct
        snap.weekly_reset_eta_seconds = snap.slots[0].reset_eta_seconds


def _antigravity_group_label(display_name) -> str:
    """Group pill label: "Gemini Models" → "Gemini", "Claude and GPT models" →
    "Claude and GPT". Capped to the device's 15-char slot label budget."""
    s = re.sub(r"\s+models$", "", str(display_name or "").strip(), flags=re.IGNORECASE)
    if not s:
        return "Quota"
    return s[:15] if len(s) > 15 else s


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
    if cfg.antigravity.enabled:
        # Registered under the canonical "antigravity" key. The broker folds the
        # deprecated /usage/gemini alias onto it AFTER HMAC verification. The
        # quota RPC needs agy's keyring token, not the on-disk oauth_creds.json.
        fetchers[PROVIDER_ANTIGRAVITY] = AntigravityFetcher(
            keyring_service=cfg.antigravity.keyring_service or "gemini",
            models=cfg.antigravity_models(),
        )
    ttl = cfg.usage.cache_ttl_seconds or 30
    log.info("usage: providers=%s cache_ttl=%ss", sorted(fetchers.keys()), ttl)
    return Cache(ttl_seconds=ttl, fetchers=fetchers)
