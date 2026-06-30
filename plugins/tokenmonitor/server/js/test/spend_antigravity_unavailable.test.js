import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SpendCache,
  NotImplementedProvider,
  canonicalProvider,
  buildSpendCache,
} from "../src/spend.js";

// The Antigravity CLI (agy) has no machine-readable per-turn token source yet:
// the Gemini-CLI chat-log JSONL is gone, and agy's proto+SQLite trajectory
// store has no recoverable counts (spike 2026-06-30). So /spend/antigravity
// must degrade to "--" and — critically — must NEVER surface a stale,
// Gemini-derived dollar figure under the renamed slot. These tests lock that
// guarantee so a future re-wiring of geminiRecords can't silently break it.

test("gemini spend wire alias canonicalizes to antigravity", () => {
  assert.equal(canonicalProvider("gemini"), "antigravity");
});

test("spend cache with no antigravity fetcher throws NotImplementedProvider and attaches no stale snapshot", async () => {
  const cache = new SpendCache(300, {}); // no providers wired
  for (const p of ["antigravity", canonicalProvider("gemini")]) {
    let captured;
    await assert.rejects(
      () => cache.get(p),
      (e) => {
        captured = e;
        return e instanceof NotImplementedProvider;
      },
    );
    assert.equal(captured.staleSnapshot, undefined, `must not attach a stale snapshot for ${p}`);
  }
});

test("buildSpendCache never registers antigravity (no stale Gemini dollars possible)", () => {
  const cfg = {
    spend: { enabled: true, cache_ttl_seconds: 300 },
    pricing: { url: "", ttl_hours: 24 },
    pricingCachePathAbs: () => "/nonexistent/price.json",
    claudeProjectsPathAbs: () => "/nonexistent/claude",
    oauthPathAbs: () => "/nonexistent/oauth.json",
    codex: { enabled: false },
  };
  const cache = buildSpendCache(cfg, {});
  const provs = cache.providers();
  assert.ok(!provs.includes("antigravity"), `antigravity must not be a spend provider: ${provs}`);
  assert.ok(!provs.includes("gemini"), `gemini must not be a spend provider: ${provs}`);
});
