// 429 back-off: once a provider fetch throws RateLimited, the cache must NOT
// re-hit upstream until the Retry-After window elapses. It serves the last
// snapshot stale-200 when one exists, or surfaces RateLimited (with the
// remaining wait) when the cache is cold. This is the regression guard for
// the multi-instance incident where a transient 429 got re-triggered on
// every device poll because Retry-After was parsed but never honored.

import { test } from "node:test";
import assert from "node:assert/strict";

import { Cache, RateLimited, Upstream } from "../src/usage.js";

function stub(seq) {
  // seq: array of () => Promise<Snapshot> | throws; advances per call.
  let i = 0;
  const f = {
    calls: 0,
    async fetch() {
      f.calls++;
      const step = seq[Math.min(i, seq.length - 1)];
      i++;
      return step();
    },
  };
  return f;
}

function snap(pct) {
  return {
    session_pct: pct, weekly_pct: 0, design_pct: 0, design_present: false,
    session_reset_eta_seconds: 0, weekly_reset_eta_seconds: 0, design_reset_eta_seconds: 0,
    session_window_seconds: 0, weekly_window_seconds: 0, tier: "unknown",
    fetched_at_unix: 0, stale_seconds: 0, slots: [],
  };
}

test("cold 429 suppresses upstream re-hits for the Retry-After window", async () => {
  const f = stub([() => { throw new RateLimited(600); }]);
  const c = new Cache(30, { x: f });
  let t = 1_000_000;
  c.now = () => t;

  // First poll: real fetch, throws RateLimited.
  await assert.rejects(c.get("x"), (e) => e instanceof RateLimited);
  assert.equal(f.calls, 1);

  // Subsequent polls within the window: NO new upstream call.
  t += 30_000;
  await assert.rejects(c.get("x"), (e) => e instanceof RateLimited && e.retryAfter > 0);
  t += 300_000;
  await assert.rejects(c.get("x"), (e) => e instanceof RateLimited);
  assert.equal(f.calls, 1, "must not re-hit upstream during cooldown");

  // After the window: one fresh attempt is allowed again.
  t += 600_000;
  await assert.rejects(c.get("x"), (e) => e instanceof RateLimited);
  assert.equal(f.calls, 2);
});

test("429 after a good snapshot serves stale-200 without re-hitting upstream", async () => {
  const f = stub([() => snap(42), () => { throw new RateLimited(600); }]);
  const c = new Cache(30, { x: f });
  let t = 1_000_000;
  c.now = () => t;

  const first = await c.get("x");
  assert.equal(first.session_pct, 42);
  assert.equal(f.calls, 1);

  // Past TTL → refresh attempt hits 429 → arms cooldown, propagates error
  // (broker turns that into stale-200 via e.staleSnapshot).
  t += 31_000;
  await assert.rejects(c.get("x"), (e) => e instanceof RateLimited && e.staleSnapshot?.session_pct === 42);
  assert.equal(f.calls, 2);

  // Within cooldown: served stale-200 directly, no upstream call.
  t += 5_000;
  const stale = await c.get("x");
  assert.equal(stale.session_pct, 42);
  assert.equal(f.calls, 2, "must not re-hit upstream during cooldown");
});

test("a successful fetch clears the cooldown", async () => {
  const f = stub([() => { throw new RateLimited(600); }, () => snap(7)]);
  const c = new Cache(30, { x: f });
  let t = 1_000_000;
  c.now = () => t;

  await assert.rejects(c.get("x"), (e) => e instanceof RateLimited);
  t += 600_001; // window elapsed
  const ok = await c.get("x");
  assert.equal(ok.session_pct, 7);
  assert.equal(f.calls, 2);

  // Cooldown cleared: a normal refresh proceeds after TTL (no suppression).
  t += 31_000;
  const again = await c.get("x");
  assert.equal(again.session_pct, 7);
  assert.equal(f.calls, 3);
});

test("non-429 upstream errors do NOT arm the cooldown", async () => {
  const f = stub([() => snap(11), () => { throw new Upstream("status=500"); }, () => { throw new Upstream("status=500"); }]);
  const c = new Cache(1, { x: f });
  let t = 1_000_000;
  c.now = () => t;

  await c.get("x");
  t += 2_000;
  await assert.rejects(c.get("x"), (e) => e instanceof Upstream);
  t += 2_000;
  // No cooldown for plain Upstream → upstream IS retried each poll past TTL.
  await assert.rejects(c.get("x"), (e) => e instanceof Upstream);
  assert.equal(f.calls, 3);
});
