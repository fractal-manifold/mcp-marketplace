// Codex rollout-log parser edge cases (bug 19), matching the Go reference.
//
//   - a malformed session_meta (a string, not an object) must not crash;
//   - a nested payload token_count is counted;
//   - a TOP-LEVEL token_count (no payload wrapper) is ignored — the old
//     `o.payload || o` fallback double-counted it.
//
// The top-level record is LAST so a fallback would let it win (999); the
// correct parser keeps the nested totals (90 / 50).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { _internals } from "../src/spend.js";

const FIXTURE =
  '{"type":"session_meta","session_meta":"bogus-string","timestamp":"2026-03-20T10:00:00Z"}\n' +
  '{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":' +
  '{"input_tokens":100,"cached_input_tokens":10,"output_tokens":50}}}}\n' +
  '{"type":"token_count","info":{"total_token_usage":{"input_tokens":999,"output_tokens":999}}}\n';

test("top-level token_count ignored and bogus session_meta is crash-safe", () => {
  const dir = mkdtempSync(join(tmpdir(), "tmon-spend-"));
  try {
    const path = join(dir, "rollout-test.jsonl");
    writeFileSync(path, FIXTURE, "utf8");
    const recs = _internals.codexRecords(path); // must not throw
    assert.equal(recs.length, 1);
    const r = recs[0];
    // input = 100 - 10 cached = 90; output = 50; cache_read = 10.
    assert.equal(r.input_tokens, 90);
    assert.equal(r.output_tokens, 50);
    assert.equal(r.cache_read_tokens, 10);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
