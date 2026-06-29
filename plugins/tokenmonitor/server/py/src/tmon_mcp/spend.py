"""Per-provider token cost computed locally from the CLI logs on this host.

Served at /spend/{claude,codex,gemini}. No admin key, account-local only.
Wire-compatible with js/src/spend.js and go/internal/spend. See
compat/SPEND_WIRE.md for the JSON shape and per-provider mapping.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from .pricing import Pricing, PriceTable

PROVIDER_CLAUDE = "claude"
PROVIDER_CODEX = "codex"
PROVIDER_GEMINI = "gemini"

MAX_MODELS = 8  # mirrors TMON_SPEND_MAX_MODELS


class SpendError(Exception):
    """Base class for spend errors.

    stale_snapshot, when set by the cache, carries the last-good Snapshot so
    the broker can answer 200 + X-Tmon-Stale-Reason (Go/JS parity)."""

    stale_snapshot: "Snapshot | None" = None


class NotImplementedProvider(SpendError):
    pass


class SpendUnavailable(SpendError):
    pass


@dataclass
class ModelSpend:
    model: str
    label: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_creation_tokens: int
    usd: float


@dataclass
class Snapshot:
    currency: str = "USD"
    has_subscription: bool = False
    today_usd: float = 0.0
    week_usd: float = 0.0
    month_usd: float = 0.0
    today_tokens: int = 0
    week_tokens: int = 0
    month_tokens: int = 0
    pricing_source: str = "none"
    pricing_stale: bool = False
    models: list[ModelSpend] = field(default_factory=list)
    fetched_at_unix: int = 0
    stale_seconds: int = 0


@dataclass
class Bundle:
    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_creation: int = 0

    def add(self, r: "Record") -> None:
        self.input += r.input
        self.output += r.output
        self.cache_read += r.cache_read
        self.cache_creation += r.cache_creation

    def total(self) -> int:
        return self.input + self.output + self.cache_read + self.cache_creation


@dataclass
class Record:
    model: str
    ts: float  # epoch seconds; 0 == unknown (dropped)
    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_creation: int = 0


# ---------------------------------------------------------------------------
# Time windows (local)
# ---------------------------------------------------------------------------


@dataclass
class _Windows:
    today: float
    week: float
    month: float


def window_starts(now: float) -> _Windows:
    d = datetime.fromtimestamp(now)
    today = d.replace(hour=0, minute=0, second=0, microsecond=0)
    dow = today.weekday()  # Monday=0
    week = today.timestamp() - dow * 86400
    month = today.replace(day=1).timestamp()
    return _Windows(today.timestamp(), week, month)


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------

_RE_CLAUDE = re.compile(r"^claude-(opus|sonnet|haiku)-(\d+)-(\d+)")
_RE_GEMINI = re.compile(r"^gemini-[\d.]+-([a-z]+)")


def _clip15(s: str) -> str:
    return s[:15] if len(s) > 15 else s


def label_for(model: str) -> str:
    m = model or ""
    mm = _RE_CLAUDE.match(m)
    if mm:
        fam = mm.group(1).capitalize()
        return _clip15(f"{fam} {mm.group(2)}.{mm.group(3)}")
    if m.lower().startswith("gpt-"):
        s = "GPT-" + m[4:]
        s = s.replace("-codex", " Codex").replace("-", " ")
        return _clip15(s)
    mm = _RE_GEMINI.match(m)
    if mm:
        return _clip15(mm.group(1).capitalize())
    return _clip15(m)


# ---------------------------------------------------------------------------
# Accumulation
# ---------------------------------------------------------------------------


class _Acc:
    def __init__(self, w: _Windows) -> None:
        self.w = w
        self.today: dict[str, Bundle] = {}
        self.week: dict[str, Bundle] = {}
        self.month: dict[str, Bundle] = {}

    @staticmethod
    def _add_to(m: dict[str, Bundle], r: Record) -> None:
        b = m.get(r.model)
        if b is None:
            b = Bundle()
            m[r.model] = b
        b.add(r)

    def add(self, r: Record) -> None:
        if not r.model or not r.ts or r.ts < self.w.month:
            return
        self._add_to(self.month, r)
        if r.ts >= self.w.week:
            self._add_to(self.week, r)
        if r.ts >= self.w.today:
            self._add_to(self.today, r)


# ---------------------------------------------------------------------------
# File walking + per-file record cache (incremental)
# ---------------------------------------------------------------------------


def _list_files(root: str, match) -> list[tuple[str, float, int]]:
    out: list[tuple[str, float, int]] = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if not match(name):
                continue
            p = os.path.join(dirpath, name)
            try:
                st = os.stat(p)
            except OSError:
                continue
            out.append((p, st.st_mtime, st.st_size))
    return out


class _FileRecordCache:
    def __init__(self) -> None:
        self._entries: dict[str, tuple[float, int, list[Record]]] = {}

    def get(self, path: str, mtime: float, size: int, parse) -> list[Record]:
        hit = self._entries.get(path)
        if hit is not None and hit[0] == mtime and hit[1] == size:
            return hit[2]
        recs = parse(path)
        self._entries[path] = (mtime, size, recs)
        return recs


def _iter_lines(path: str):
    # Plain line iteration handles arbitrarily long lines (agent transcripts
    # can embed tens-of-MiB messages); the file is read incrementally.
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line
    except OSError:
        return


def _parse_iso(ts: str) -> float:
    if not ts:
        return 0.0
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


# ---------------------------------------------------------------------------
# Claude — ~/.claude/projects/**/*.jsonl (per-message)
# ---------------------------------------------------------------------------


def claude_records(path: str) -> list[Record]:
    out: list[Record] = []
    for line in _iter_lines(path):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        msg = o.get("message")
        if not isinstance(msg, dict):
            continue
        model = msg.get("model")
        if not model or model == "<synthetic>":
            continue
        u = msg.get("usage")
        if not isinstance(u, dict):
            continue
        ts = _parse_iso(o.get("timestamp", ""))
        if not ts:
            continue
        out.append(
            Record(
                model=model,
                ts=ts,
                input=int(u.get("input_tokens") or 0),
                output=int(u.get("output_tokens") or 0),
                cache_read=int(u.get("cache_read_input_tokens") or 0),
                cache_creation=int(u.get("cache_creation_input_tokens") or 0),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Codex — ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl (accumulated/session)
# ---------------------------------------------------------------------------

_RE_CODEX_DATE = re.compile(r"(\d{4})/(\d{2})/(\d{2})")


def codex_records(path: str) -> list[Record]:
    model = ""
    session_ts = 0.0
    last_total: dict | None = None
    for line in _iter_lines(path):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        otype = o.get("type")
        if otype == "session_meta" or "session_meta" in o:
            meta = o.get("session_meta") or o.get("payload") or o
            if not model:
                model = meta.get("model") or meta.get("originator") or ""
            if not session_ts:
                session_ts = _parse_iso(meta.get("timestamp", "")) or _parse_iso(o.get("timestamp", ""))
        if otype == "turn_context":
            payload = o.get("payload") or {}
            if payload.get("model"):
                model = payload["model"]
        payload = o.get("payload") or o
        if isinstance(payload, dict) and payload.get("type") == "token_count":
            info = payload.get("info") or {}
            tot = info.get("total_token_usage")
            if isinstance(tot, dict):
                last_total = tot  # accumulated — keep the last
    if last_total is None:
        return []
    if not session_ts:
        m = _RE_CODEX_DATE.search(path.replace(os.sep, "/"))
        if m:
            session_ts = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).timestamp()
    cached = int(last_total.get("cached_input_tokens") or 0)
    inp = max(0, int(last_total.get("input_tokens") or 0) - cached)
    out_tok = int(last_total.get("output_tokens") or 0) + int(last_total.get("reasoning_output_tokens") or 0)
    return [
        Record(
            model=model or "gpt-5-codex",
            ts=session_ts,
            input=inp,
            output=out_tok,
            cache_read=cached,
            cache_creation=0,
        )
    ]


# ---------------------------------------------------------------------------
# Gemini — ~/.gemini/tmp/<project>/chats/session-*.jsonl (per-message)
# ---------------------------------------------------------------------------


def gemini_records(path: str) -> list[Record]:
    out: list[Record] = []
    for line in _iter_lines(path):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get("type") != "gemini":
            continue
        t = o.get("tokens")
        if not isinstance(t, dict):
            continue
        ts = _parse_iso(o.get("timestamp", ""))
        if not ts:
            continue
        out.append(
            Record(
                model=o.get("model") or "gemini-2.5-pro",
                ts=ts,
                input=int(t.get("input") or 0),
                output=int(t.get("output") or 0) + int(t.get("thoughts") or 0),
                cache_read=int(t.get("cached") or 0),
                cache_creation=0,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Subscription detection (on-disk)
# ---------------------------------------------------------------------------


def _read_json(path: str) -> dict | None:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def claude_has_subscription(creds_path: str) -> bool:
    doc = _read_json(creds_path)
    o = (doc or {}).get("claudeAiOauth")
    if not isinstance(o, dict):
        return False
    sub = str(o.get("subscriptionType") or "").lower()
    if sub and sub != "free":
        return True
    tier = str(o.get("rateLimitTier") or "").lower()
    return tier not in ("", "free")


def codex_has_subscription(auth_path: str) -> bool:
    # has_subscription = "quota-based view (%)" vs "pay-as-you-go ($)", NOT
    # "paid plan". A ChatGPT OAuth login consumes against the ChatGPT plan's
    # quota (free or paid alike) -> keep %. A bare API key is per-token -> $.
    # Free vs paid ChatGPT is intentionally not distinguished (needs a remote
    # plan_type call). See compat/SPEND_WIRE.md -> Subscription detection.
    doc = _read_json(auth_path)
    if not isinstance(doc, dict):
        return False
    return any(k in doc for k in ("tokens", "access_token", "OPENAI_ACCESS_TOKEN"))


# ---------------------------------------------------------------------------
# Provider fetcher
# ---------------------------------------------------------------------------


def _round2(x: float) -> float:
    # Round half away from zero, matching JS Math.round (half-up) and Go
    # math.Round for the non-negative spend values we deal with. Python's
    # built-in round() is banker's rounding (half-to-even), which would
    # diverge from the other two runtimes on exact half-cent boundaries and
    # break wire parity (see compat/vectors/spend_pricing.json).
    return math.floor(x * 100 + 0.5) / 100


def _fold_models(rows: list[ModelSpend]) -> list[ModelSpend]:
    if len(rows) <= MAX_MODELS:
        return rows
    head = rows[: MAX_MODELS - 1]
    other = ModelSpend("other", "Other", 0, 0, 0, 0, 0.0)
    for r in rows[MAX_MODELS - 1 :]:
        other.input_tokens += r.input_tokens
        other.output_tokens += r.output_tokens
        other.cache_read_tokens += r.cache_read_tokens
        other.cache_creation_tokens += r.cache_creation_tokens
        other.usd += r.usd
    other.usd = _round2(other.usd)
    return [*head, other]


class ProviderSpend:
    def __init__(self, root, match, parse, has_sub, pricing: Pricing) -> None:
        self.root = root
        self.match = match
        self.parse = parse
        self.has_sub = has_sub
        self.pricing = pricing
        self._file_cache = _FileRecordCache()

    def fetch(self, now: float) -> Snapshot:
        w = window_starts(now)
        cutoff = w.month - 86400  # 1-day slack
        acc = _Acc(w)
        for path, mtime, size in _list_files(self.root, self.match):
            if mtime < cutoff:
                continue
            for r in self._file_cache.get(path, mtime, size, self.parse):
                acc.add(r)

        table: PriceTable = self.pricing.table(now)
        snap = Snapshot()
        snap.has_subscription = bool(self.has_sub())
        snap.pricing_source = table.source
        snap.pricing_stale = table.stale

        # Sum in sorted-key order so the float accumulation order matches the
        # Go/JS impls. Float addition is not associative, so an unordered sum
        # could round to a different cent under Go's randomized map order or a
        # differently-discovered file order. See compat/SPEND_WIRE.md.
        def price_map(m: dict[str, Bundle]) -> tuple[float, int]:
            usd = 0.0
            tokens = 0
            for model in sorted(m):
                b = m[model]
                usd += table.cost_for(model, b)
                tokens += b.total()
            return usd, tokens

        tu, tt = price_map(acc.today)
        wu, wtk = price_map(acc.week)
        mu, mt = price_map(acc.month)
        snap.today_usd, snap.today_tokens = _round2(tu), tt
        snap.week_usd, snap.week_tokens = _round2(wu), wtk
        snap.month_usd, snap.month_tokens = _round2(mu), mt

        rows: list[tuple[ModelSpend, int]] = []
        for model, b in acc.month.items():
            rows.append(
                (
                    ModelSpend(
                        model=model,
                        label=label_for(model),
                        input_tokens=b.input,
                        output_tokens=b.output,
                        cache_read_tokens=b.cache_read,
                        cache_creation_tokens=b.cache_creation,
                        usd=_round2(table.cost_for(model, b)),
                    ),
                    b.total(),
                )
            )
        rows.sort(key=lambda x: (-x[0].usd, -x[1], x[0].model))
        snap.models = _fold_models([r for r, _ in rows])
        return snap


# ---------------------------------------------------------------------------
# Cache (TTL + stale-with-error, mirrors usage.Cache)
# ---------------------------------------------------------------------------


@dataclass
class _Entry:
    snap: Snapshot
    fetched: float


class Cache:
    def __init__(self, ttl_seconds: int, fetchers: dict[str, ProviderSpend]) -> None:
        self._ttl = max(0.001, float(ttl_seconds))
        self._fetchers = fetchers
        self._entries: dict[str, _Entry] = {}
        self._inflight: dict[str, asyncio.Task[Snapshot]] = {}
        self._lock = asyncio.Lock()
        self._now = time.time

    def providers(self) -> list[str]:
        return sorted(self._fetchers.keys())

    async def get(self, provider: str) -> Snapshot:
        fetcher = self._fetchers.get(provider)
        if fetcher is None:
            raise NotImplementedProvider(f"spend provider {provider!r} not enabled")
        async with self._lock:
            entry = self._entries.get(provider)
            now = self._now()
            if entry is not None and now - entry.fetched < self._ttl:
                snap = Snapshot(**asdict(entry.snap))
                snap.stale_seconds = int(now - entry.fetched)
                return snap
            task = self._inflight.get(provider)
            if task is None:
                task = asyncio.create_task(self._refresh(provider, fetcher))
                self._inflight[provider] = task
        try:
            return await task
        except SpendError as err:
            # Re-raise so the broker can answer stale-with-200 (200 +
            # X-Tmon-Stale-Reason); attach the last-good snapshot to the
            # exception. No last-good → propagate the error unadorned.
            async with self._lock:
                entry = self._entries.get(provider)
                if entry is not None:
                    snap = Snapshot(**asdict(entry.snap))
                    snap.stale_seconds = int(self._now() - entry.fetched)
                    err.stale_snapshot = snap
            raise

    async def _refresh(self, provider: str, fetcher: ProviderSpend) -> Snapshot:
        try:
            # Parsing + pricing are blocking; run off the event loop.
            now = self._now()
            snap = await asyncio.to_thread(fetcher.fetch, now)
            snap.fetched_at_unix = int(now)
            snap.stale_seconds = 0
            async with self._lock:
                self._entries[provider] = _Entry(snap=snap, fetched=now)
                self._inflight.pop(provider, None)
            return snap
        except SpendError:
            async with self._lock:
                self._inflight.pop(provider, None)
            raise
        except Exception as e:  # noqa: BLE001
            async with self._lock:
                self._inflight.pop(provider, None)
            raise SpendUnavailable(str(e)) from e


def _snapshot_to_dict(snap: Snapshot) -> dict:
    return asdict(snap)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_cache(cfg, logger=None) -> Cache | None:
    """Wire up the per-provider fetchers from cfg. Returns None when
    [spend].enabled is false (makes /spend/* answer 501)."""
    if not cfg.spend.enabled:
        return None
    pricing = Pricing(
        url=cfg.pricing.url,
        cache_path=cfg.pricing_cache_path_abs(),
        ttl_hours=cfg.pricing.ttl_hours,
        logger=logger,
    )
    fetchers: dict[str, ProviderSpend] = {
        PROVIDER_CLAUDE: ProviderSpend(
            root=cfg.claude_projects_path_abs(),
            match=lambda n: n.endswith(".jsonl"),
            parse=claude_records,
            has_sub=lambda: claude_has_subscription(cfg.oauth_path_abs()),
            pricing=pricing,
        ),
    }
    if cfg.codex.enabled:
        fetchers[PROVIDER_CODEX] = ProviderSpend(
            root=cfg.codex_sessions_path_abs(),
            match=lambda n: n.startswith("rollout-") and n.endswith(".jsonl"),
            parse=codex_records,
            has_sub=lambda: codex_has_subscription(cfg.codex_auth_path_abs()),
            pricing=pricing,
        )
    if cfg.gemini.enabled:
        fetchers[PROVIDER_GEMINI] = ProviderSpend(
            root=cfg.gemini_tmp_path_abs(),
            match=lambda n: n.startswith("session-") and n.endswith(".jsonl"),
            parse=gemini_records,
            # Always $ for Gemini: free Code-Assist and a paid tier both write
            # the same local oauth_creds.json, so they can't be told apart
            # without a remote call. Default to computed $ rather than guess.
            has_sub=lambda: False,
            pricing=pricing,
        )
    ttl = cfg.spend.cache_ttl_seconds or 300
    if logger:
        logger.info(f"spend: providers={sorted(fetchers)} cache_ttl={ttl}s")
    return Cache(ttl_seconds=ttl, fetchers=fetchers)
