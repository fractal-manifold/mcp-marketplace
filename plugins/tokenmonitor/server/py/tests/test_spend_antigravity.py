"""Antigravity spend must degrade to "--" with no stale Gemini dollars.

The Antigravity CLI (agy) has no machine-readable per-turn token source yet:
the Gemini-CLI chat-log JSONL is gone, and agy's proto+SQLite trajectory store
has no recoverable counts (spike 2026-06-30). So /spend/antigravity (and the
/spend/gemini alias) must raise NotImplementedProvider and — critically — must
NEVER surface a stale, Gemini-derived dollar figure under the renamed slot.
These tests lock that guarantee so a future re-wiring of gemini_records can't
silently break it.
"""

import asyncio
from types import SimpleNamespace

import pytest

from tmon_mcp.spend import (
    Cache,
    NotImplementedProvider,
    build_cache,
    canonical_provider,
)


def test_gemini_alias_canonicalizes():
    assert canonical_provider("gemini") == "antigravity"


def test_antigravity_spend_not_implemented():
    cache = Cache(ttl_seconds=300, fetchers={})  # no providers wired
    for p in ("antigravity", canonical_provider("gemini")):
        with pytest.raises(NotImplementedProvider):
            asyncio.run(cache.get(p))


def test_build_cache_omits_antigravity(tmp_path):
    cfg = SimpleNamespace(
        spend=SimpleNamespace(enabled=True, cache_ttl_seconds=300),
        pricing=SimpleNamespace(url="", ttl_hours=24),
        codex=SimpleNamespace(enabled=False),
        pricing_cache_path_abs=lambda: str(tmp_path / "price.json"),
        claude_projects_path_abs=lambda: str(tmp_path / "claude"),
        oauth_path_abs=lambda: str(tmp_path / "oauth.json"),
    )
    cache = build_cache(cfg)
    assert cache is not None
    provs = cache.providers()
    assert "antigravity" not in provs
    assert "gemini" not in provs
