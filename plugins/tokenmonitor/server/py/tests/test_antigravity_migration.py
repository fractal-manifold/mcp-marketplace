"""Gemini -> Antigravity provider migration (wire-compatible with the Go ref).

Google retired the Gemini CLI (2026-06-18) in favour of the Antigravity CLI
(`agy`). The broker renamed the provider to "antigravity" but must keep the
deprecated "gemini" wire string and legacy [gemini] config working:

  * a legacy tokenmonitor.toml ([gemini] + spend.gemini_tmp_path) still loads,
    merged into the canonical antigravity fields;
  * /usage/gemini and /spend/gemini still resolve via canonical_provider();
  * /spend/antigravity is NOT implemented (no recoverable token source yet);
  * the retrieveUserQuotaSummary parser maps the live grouped groups[] shape
    (agy 1.0.13, verified 2026-06-30) into one weekly slot per group, and an
    unrecognised body yields no slots.
"""

from __future__ import annotations

from tmon_mcp import config, spend, usage


# ---------------------------------------------------------------------------
# config: new [antigravity] section
# ---------------------------------------------------------------------------


def _write(tmp_path, body: str):
    p = tmp_path / "tokenmonitor.toml"
    p.write_text(body)
    return str(p)


def test_new_antigravity_section_loads(tmp_path):
    path = _write(
        tmp_path,
        """
[auth]
psk_passphrase = "passphrase-123"

[antigravity]
enabled = true
creds_path = "/tmp/agy/creds.json"
projects_path = "/tmp/agy/projects.json"
models = ["gemini-3.5-flash", "gemini-3.1-pro"]

[spend]
antigravity_conversations_path = "/tmp/agy/conversations"
""",
    )
    cfg = config.load(path)
    assert cfg.antigravity.enabled is True
    assert cfg.antigravity.creds_path == "/tmp/agy/creds.json"
    assert cfg.antigravity_models() == ["gemini-3.5-flash", "gemini-3.1-pro"]
    assert cfg.spend.antigravity_conversations_path == "/tmp/agy/conversations"


def test_antigravity_models_default_and_clamp(tmp_path):
    # Empty config -> defaults (Flash + Pro).
    path = _write(tmp_path, '[auth]\npsk_passphrase = "passphrase-123"\n')
    cfg = config.load(path)
    assert cfg.antigravity_models() == config.DEFAULT_ANTIGRAVITY_MODELS
    assert config.DEFAULT_ANTIGRAVITY_MODELS == ["gemini-3.5-flash", "gemini-3.1-pro"]

    # More than MAX_ANTIGRAVITY_MODELS -> clamped to 3.
    path = _write(
        tmp_path,
        """
[auth]
psk_passphrase = "passphrase-123"
[antigravity]
models = ["a", "b", "c", "d", "e"]
""",
    )
    cfg = config.load(path)
    assert cfg.antigravity_models() == ["a", "b", "c"]
    assert config.MAX_ANTIGRAVITY_MODELS == 3


# ---------------------------------------------------------------------------
# config: legacy [gemini] / gemini_tmp_path back-compat
# ---------------------------------------------------------------------------


def test_legacy_gemini_section_merges_into_antigravity(tmp_path):
    path = _write(
        tmp_path,
        """
[auth]
psk_passphrase = "passphrase-123"

[gemini]
enabled = true
creds_path = "/legacy/creds.json"
projects_path = "/legacy/projects.json"
models = ["gemini-2.5-pro"]

[spend]
gemini_tmp_path = "/legacy/tmp"
""",
    )
    cfg = config.load(path)
    # Legacy [gemini] folds forward into the canonical antigravity fields.
    assert cfg.antigravity.enabled is True
    assert cfg.antigravity.creds_path == "/legacy/creds.json"
    assert cfg.antigravity.projects_path == "/legacy/projects.json"
    assert cfg.antigravity_models() == ["gemini-2.5-pro"]
    # Legacy spend.gemini_tmp_path folds into antigravity_conversations_path.
    assert cfg.spend.antigravity_conversations_path == "/legacy/tmp"


def test_new_antigravity_section_wins_over_legacy_gemini(tmp_path):
    # When BOTH sections are present, the new [antigravity] section is
    # authoritative and the legacy [gemini] section is ignored (mirrors Go:
    # merge only fires when [antigravity] is absent).
    path = _write(
        tmp_path,
        """
[auth]
psk_passphrase = "passphrase-123"

[antigravity]
enabled = true
creds_path = "/new/creds.json"

[gemini]
enabled = false
creds_path = "/legacy/creds.json"

[spend]
antigravity_conversations_path = "/new/conversations"
gemini_tmp_path = "/legacy/tmp"
""",
    )
    cfg = config.load(path)
    assert cfg.antigravity.enabled is True
    assert cfg.antigravity.creds_path == "/new/creds.json"
    assert cfg.spend.antigravity_conversations_path == "/new/conversations"


# ---------------------------------------------------------------------------
# Provider alias canonicalization
# ---------------------------------------------------------------------------


def test_usage_canonical_provider_alias():
    assert usage.canonical_provider("gemini") == "antigravity"
    assert usage.canonical_provider("antigravity") == "antigravity"
    assert usage.canonical_provider("claude") == "claude"
    assert usage.PROVIDER_ANTIGRAVITY == "antigravity"
    assert usage.PROVIDER_GEMINI == "gemini"


def test_spend_canonical_provider_alias():
    assert spend.canonical_provider("gemini") == "antigravity"
    assert spend.canonical_provider("antigravity") == "antigravity"
    assert spend.canonical_provider("codex") == "codex"
    assert spend.PROVIDER_ANTIGRAVITY == "antigravity"
    assert spend.PROVIDER_GEMINI == "gemini"


# ---------------------------------------------------------------------------
# spend: no Antigravity fetcher registered -> /spend/antigravity unimplemented
# ---------------------------------------------------------------------------


def test_spend_build_cache_does_not_register_antigravity(tmp_path):
    path = _write(
        tmp_path,
        """
[auth]
psk_passphrase = "passphrase-123"
[antigravity]
enabled = true
""",
    )
    cfg = config.load(path)
    cache = spend.build_cache(cfg)
    assert cache is not None
    # Antigravity is enabled but no spend fetcher is wired: only claude.
    assert "antigravity" not in cache.providers()
    assert "gemini" not in cache.providers()
    assert cache.providers() == ["claude"]


async def test_spend_antigravity_returns_not_implemented(tmp_path):
    path = _write(
        tmp_path,
        '[auth]\npsk_passphrase = "passphrase-123"\n[antigravity]\nenabled = true\n',
    )
    cfg = config.load(path)
    cache = spend.build_cache(cfg)
    # The canonical key and the deprecated alias both resolve to "antigravity",
    # which has no fetcher -> NotImplementedProvider (broker maps to 501).
    import pytest

    with pytest.raises(spend.NotImplementedProvider):
        await cache.get(spend.canonical_provider("gemini"))


# ---------------------------------------------------------------------------
# Grouped retrieveUserQuotaSummary parser (agy 1.0.13 shape, live-verified
# 2026-06-30). Top-level groups[] -> one weekly slot per group; remainingFraction
# is REMAINING (pct_used = (1-remainingFraction)*100); the Gemini Models group
# drives the headline weekly bar. Mirrors the validated JS antigravityApplyQuota.
# ---------------------------------------------------------------------------


def test_quota_parser_grouped_shape():
    snap = usage.Snapshot()
    quota = {
        "groups": [
            {
                "displayName": "Gemini Models",
                "buckets": [
                    {"bucketId": "gemini-weekly", "window": "weekly", "remainingFraction": 0.0},
                ],
            },
            {
                "displayName": "Claude and GPT models",
                "buckets": [
                    {"bucketId": "3p-weekly", "window": "weekly", "remainingFraction": 0.906058},
                ],
            },
        ]
    }
    usage._antigravity_apply_quota(snap, quota, now_unix=1000.0)
    assert len(snap.slots) == 2
    # Labels: trailing " models"/" Models" stripped.
    assert snap.slots[0].label == "Gemini"
    assert snap.slots[1].label == "Claude and GPT"
    # pct = 100 * (1 - remainingFraction).
    assert snap.slots[0].pct == 100.0
    assert round(snap.slots[1].pct, 2) == 9.39
    # Each slot is a weekly window.
    assert snap.slots[0].window_seconds == usage.ANTIGRAVITY_WEEKLY
    # Headline weekly bar follows the Gemini Models group.
    assert snap.weekly_pct == 100.0


def test_quota_parser_picks_weekly_bucket():
    # When a group has multiple buckets, the weekly one is chosen.
    snap = usage.Snapshot()
    quota = {
        "groups": [
            {
                "displayName": "Gemini Models",
                "buckets": [
                    {"bucketId": "gemini-daily", "window": "daily", "remainingFraction": 0.5},
                    {"bucketId": "gemini-weekly", "window": "weekly", "remainingFraction": 0.2},
                ],
            }
        ]
    }
    usage._antigravity_apply_quota(snap, quota, now_unix=1000.0)
    assert len(snap.slots) == 1
    assert round(snap.slots[0].pct, 2) == 80.0
    assert snap.weekly_pct == round(snap.slots[0].pct, 2)


def test_quota_parser_headline_falls_back_to_first_group():
    # No Gemini group -> the first group drives the headline weekly bar.
    snap = usage.Snapshot()
    quota = {
        "groups": [
            {
                "displayName": "Claude and GPT models",
                "buckets": [{"window": "weekly", "remainingFraction": 0.25}],
            }
        ]
    }
    usage._antigravity_apply_quota(snap, quota, now_unix=1000.0)
    assert len(snap.slots) == 1
    assert snap.weekly_pct == 75.0
    assert snap.slots[0].label == "Claude and GPT"


def test_quota_parser_unrecognized_body_yields_no_slots():
    snap = usage.Snapshot()
    # No top-level groups[] -> no slots, no error.
    usage._antigravity_apply_quota(snap, {"somethingElse": []}, now_unix=1000.0)
    assert snap.slots == []
    assert snap.weekly_pct == 0.0


def test_group_label_strips_models_suffix_and_caps():
    assert usage._antigravity_group_label("Gemini Models") == "Gemini"
    assert usage._antigravity_group_label("Claude and GPT models") == "Claude and GPT"
    assert usage._antigravity_group_label("") == "Quota"
    # Capped to 15 chars.
    assert len(usage._antigravity_group_label("A really long group name without suffix")) == 15


# ---------------------------------------------------------------------------
# /usage/gemini alias resolves to the canonical "antigravity" fetcher.
#
# The broker verifies the HMAC against the literal request path (/usage/gemini)
# and only THEN folds the alias onto "antigravity" via canonical_provider().
# Here we prove the second half: the canonical key resolves to the wired
# fetcher in the usage cache (the HMAC-on-literal-path half is covered by the
# existing auth-vector tests). antigravity_fetcher() also surfaces the wired
# fetcher for the per-device override path.
# ---------------------------------------------------------------------------


class _FakeAntigravityUsageFetcher(usage.AntigravityFetcher):
    def __init__(self) -> None:  # bypass the dataclass paths/token machinery
        pass

    async def fetch(self, session):  # noqa: ANN001
        return usage.Snapshot(session_pct=33.0, tier="agy-tier")


async def test_usage_gemini_alias_resolves_to_antigravity_fetcher():
    cache = usage.Cache(
        ttl_seconds=30,
        fetchers={usage.PROVIDER_ANTIGRAVITY: _FakeAntigravityUsageFetcher()},
    )
    # Deployed firmware polls /usage/gemini; the broker canonicalizes the
    # provider AFTER HMAC verification, so the cache is queried as "antigravity".
    snap = await cache.get(None, usage.canonical_provider("gemini"))
    assert snap.session_pct == 33.0
    assert snap.tier == "agy-tier"
    # New firmware uses /usage/antigravity directly.
    snap2 = await cache.get(None, usage.canonical_provider("antigravity"))
    assert snap2.session_pct == 33.0
    # The per-device override path finds the wired fetcher under the new key.
    assert cache.antigravity_fetcher() is not None
