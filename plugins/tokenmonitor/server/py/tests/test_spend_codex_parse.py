"""Codex rollout-log parser edge cases (bug 19), matching the Go reference.

  - a malformed session_meta (a string, not an object) must not crash;
  - a nested payload token_count is counted;
  - a TOP-LEVEL token_count (no payload wrapper) is ignored — the old
    `o.get("payload") or o` fallback double-counted it.

The top-level record is LAST so a fallback would let it win (999); the correct
parser keeps the nested totals (90 / 50).
"""

from __future__ import annotations

from pathlib import Path

from tmon_mcp.spend import codex_records

FIXTURE = (
    '{"type":"session_meta","session_meta":"bogus-string","timestamp":"2026-03-20T10:00:00Z"}\n'
    '{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":'
    '{"input_tokens":100,"cached_input_tokens":10,"output_tokens":50}}}}\n'
    '{"type":"token_count","info":{"total_token_usage":{"input_tokens":999,"output_tokens":999}}}\n'
)


def test_top_level_token_count_ignored_and_bogus_meta_safe(tmp_path: Path):
    path = tmp_path / "rollout-test.jsonl"
    path.write_text(FIXTURE)
    recs = codex_records(str(path))  # must not raise on the bogus session_meta
    assert len(recs) == 1
    r = recs[0]
    # input = 100 - 10 cached = 90; output = 50; cache_read = 10.
    assert (r.input, r.output, r.cache_read) == (90, 50, 10)
