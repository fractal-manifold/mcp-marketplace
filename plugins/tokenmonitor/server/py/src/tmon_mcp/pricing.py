"""Model price table: turns token counts into USD.

Source of truth is LiteLLM's machine-readable table (the same data ccusage
uses), fetched over HTTP and cached on disk, with an embedded fallback for
offline / first-run. Kept byte-compatible with js/src/pricing.js and
go/internal/spend/pricing.go. See compat/SPEND_WIRE.md ("Pricing").
"""

from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# Per-token USD rates. Keep in sync with the JS and Go fallback tables.
# (input, output, cache_read, cache_creation)
FALLBACK_PRICES: dict[str, tuple[float, float, float, float]] = {
    "claude-opus-4-8": (5e-6, 25e-6, 0.5e-6, 6.25e-6),
    "claude-opus-4-7": (5e-6, 25e-6, 0.5e-6, 6.25e-6),
    "claude-opus-4-6": (5e-6, 25e-6, 0.5e-6, 6.25e-6),
    "claude-opus-4-5": (5e-6, 25e-6, 0.5e-6, 6.25e-6),
    "claude-opus-4-1": (15e-6, 75e-6, 1.5e-6, 18.75e-6),
    "claude-sonnet-4-6": (3e-6, 15e-6, 0.3e-6, 3.75e-6),
    "claude-sonnet-4-5": (3e-6, 15e-6, 0.3e-6, 3.75e-6),
    "claude-haiku-4-5": (1e-6, 5e-6, 0.1e-6, 1.25e-6),
    "gpt-5": (1.25e-6, 10e-6, 0.125e-6, 0),
    "gpt-5-codex": (1.25e-6, 10e-6, 0.125e-6, 0),
    "o4-mini": (1.1e-6, 4.4e-6, 0.275e-6, 0),
    "gemini-2.5-pro": (1.25e-6, 10e-6, 0.31e-6, 0),
    "gemini-2.5-flash": (0.3e-6, 2.5e-6, 0.075e-6, 0),
    "gemini-3-flash-preview": (0.3e-6, 2.5e-6, 0.075e-6, 0),
}


@dataclass
class Rate:
    input: float
    output: float
    cache_read: float
    cache_creation: float


def _basename(s: str) -> str:
    i = s.rfind("/")
    return s[i + 1 :] if i >= 0 else s


class PriceTable:
    """Immutable snapshot of model rates plus provenance."""

    def __init__(self, rates: dict[str, Rate], source: str, stale: bool = False) -> None:
        self.rates = rates
        self.source = source  # "litellm" | "fallback" | "none"
        self.stale = stale

    def rate_for(self, model: str) -> Rate | None:
        if not model:
            return None
        r = self.rates.get(model)
        if r is not None:
            return r
        base = _basename(model)
        r = self.rates.get(base)
        if r is not None:
            return r
        # Deterministic across runtimes: longest basename match, ties broken
        # by the lexicographically smallest full key. Dict insertion order
        # (Py), object key order (JS) and randomized map order (Go) must not
        # influence which rate wins. See compat/SPEND_WIRE.md.
        best_key: str | None = None
        best_len = -1
        for key in self.rates:
            k = _basename(key)
            if not (base.startswith(k) or k.startswith(base)):
                continue
            if len(k) > best_len or (len(k) == best_len and (best_key is None or key < best_key)):
                best_key, best_len = key, len(k)
        return self.rates[best_key] if best_key is not None else None

    def cost_for(self, model: str, b: "Bundle") -> float:
        r = self.rate_for(model)
        if r is None:
            return 0.0
        return (
            b.input * r.input
            + b.output * r.output
            + b.cache_read * r.cache_read
            + b.cache_creation * r.cache_creation
        )


def _fallback_table() -> PriceTable:
    rates = {k: Rate(*v) for k, v in FALLBACK_PRICES.items()}
    return PriceTable(rates, "fallback")


def _parse_litellm(doc: dict) -> dict[str, Rate]:
    out: dict[str, Rate] = {}
    for key, e in doc.items():
        if key == "sample_spec" or not isinstance(e, dict):
            continue
        inn = e.get("input_cost_per_token")
        outp = e.get("output_cost_per_token")
        if not isinstance(inn, (int, float)) or not isinstance(outp, (int, float)):
            continue
        out[key] = Rate(
            float(inn),
            float(outp),
            float(e.get("cache_read_input_token_cost") or 0),
            float(e.get("cache_creation_input_token_cost") or 0),
        )
    return out


class Pricing:
    """Loads/caches the price table. Never fatal: pricing problems degrade
    to fallback/stale, they don't blank the spend response."""

    def __init__(self, url: str, cache_path: str, ttl_hours: int = 24, logger=None) -> None:
        self.url = url
        self.cache_path = cache_path
        self.ttl_s = max(1, ttl_hours) * 3600
        self.logger = logger
        self._table: PriceTable | None = None
        self._loaded_at = 0.0

    def _log(self, msg: str) -> None:
        if self.logger:
            self.logger.info(msg)

    def _read_disk(self) -> tuple[dict[str, Rate], float] | None:
        try:
            doc = json.loads(Path(self.cache_path).read_text())
        except (OSError, ValueError):
            return None
        prices = doc.get("prices")
        if not isinstance(prices, dict) or not prices:
            return None
        rates = {k: Rate(**v) if isinstance(v, dict) else Rate(*v) for k, v in prices.items()}
        return rates, float(doc.get("fetched_at_ms") or 0)

    def _write_disk(self, rates: dict[str, Rate], now_ms: int) -> None:
        try:
            p = Path(self.cache_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            prices = {
                k: {
                    "input": r.input,
                    "output": r.output,
                    "cache_read": r.cache_read,
                    "cache_creation": r.cache_creation,
                }
                for k, r in rates.items()
            }
            p.write_text(json.dumps({"fetched_at_ms": now_ms, "prices": prices}))
        except OSError as e:
            self._log(f"pricing: cache write failed: {e}")

    def _fetch_live(self) -> dict[str, Rate]:
        req = urllib.request.Request(self.url, method="GET")
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 (trusted URL)
            if resp.status < 200 or resp.status >= 300:
                raise RuntimeError(f"pricing fetch status={resp.status}")
            raw = resp.read()
        rates = _parse_litellm(json.loads(raw))
        if not rates:
            raise RuntimeError("pricing table empty")
        return rates

    def table(self, now: float | None = None) -> PriceTable:
        """Return a price table, refreshing if the cache is stale. Blocking;
        callers run it off the event loop."""
        now = time.time() if now is None else now
        if self._table is not None and now - self._loaded_at < self.ttl_s:
            return self._table

        disk = self._read_disk()
        if disk is not None and now - disk[1] / 1000.0 < self.ttl_s:
            self._table = PriceTable(disk[0], "litellm")
            self._loaded_at = now
            return self._table

        try:
            rates = self._fetch_live()
            self._write_disk(rates, int(now * 1000))
            self._table = PriceTable(rates, "litellm")
        except Exception as e:  # noqa: BLE001 — pricing must never be fatal
            self._log(f"pricing: live fetch failed ({e}); using {'stale cache' if disk else 'fallback'}")
            self._table = PriceTable(disk[0], "litellm", stale=True) if disk else _fallback_table()
        self._loaded_at = now
        return self._table
