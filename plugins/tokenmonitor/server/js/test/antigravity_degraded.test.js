// Antigravity degraded marker (bug 12): loadCodeAssist OK but the quota
// sub-RPC failed → snapshot.degraded=true and the key serialises; on quota
// success the key is absent from the serialised JSON.

import { test } from "node:test";
import assert from "node:assert/strict";

import { AntigravityFetcher } from "../src/usage.js";

// Pre-seed the keyring token so the fetcher never shells out to secret-tool.
function seededFetcher() {
  const f = new AntigravityFetcher({});
  f._cachedToken = { token: "seeded", expiresAtMs: Date.now() + 3_600_000 };
  f.logger = { info() {}, warn() {}, error() {} };
  return f;
}

// Route the global fetch by URL: loadCodeAssist always 200, quota configurable.
function withMockFetch(quotaStatus, quotaBody, fn) {
  const orig = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("loadCodeAssist")) {
      return new Response(
        JSON.stringify({ cloudaicompanionProject: "proj-123", currentTier: { id: "free-tier" } }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(quotaBody, { status: quotaStatus, headers: { "content-type": "application/json" } });
  };
  return Promise.resolve(fn()).finally(() => { globalThis.fetch = orig; });
}

test("quota RPC failure marks the snapshot degraded and serialises the key", async () => {
  await withMockFetch(500, JSON.stringify({ error: "boom" }), async () => {
    const snap = await seededFetcher().fetch();
    assert.equal(snap.degraded, true);
    assert.match(JSON.stringify(snap), /"degraded":true/);
  });
});

test("quota RPC success leaves degraded absent from the serialised JSON", async () => {
  const body = JSON.stringify({
    groups: [{
      displayName: "Gemini Models",
      buckets: [{ bucketId: "gemini-weekly", window: "weekly", resetTime: "2026-07-07T10:55:39Z", remainingFraction: 0.5 }],
    }],
  });
  await withMockFetch(200, body, async () => {
    const snap = await seededFetcher().fetch();
    assert.notEqual(snap.degraded, true);
    assert.equal(/degraded/.test(JSON.stringify(snap)), false);
  });
});
