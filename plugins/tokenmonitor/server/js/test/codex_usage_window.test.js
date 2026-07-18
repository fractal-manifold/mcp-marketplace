// Codex usage-window mapping. OpenAI collapsed Codex to a SINGLE weekly limit
// (2026-07): primary_window is the 7d weekly window, secondary_window is null.
// The broker must render Codex weekly-only (session hidden), like Antigravity,
// while still handling the legacy two-window shape.

import { test } from "node:test";
import assert from "node:assert/strict";

import { CodexFetcher } from "../src/usage.js";

const fakeCreds = { accessToken: "tok", accountId: "acct", isExpired: () => false };
function fetcher() {
  return new CodexFetcher({ authPath: "/dev/null", loadCodex: () => fakeCreds });
}

function withMockFetch(body, fn) {
  const orig = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  return Promise.resolve(fn()).finally(() => { globalThis.fetch = orig; });
}

test("codex single weekly window: primary→weekly, session hidden, one slot", async () => {
  const body = {
    plan_type: "plus",
    rate_limit: {
      allowed: true,
      limit_reached: false,
      primary_window: { used_percent: 1, limit_window_seconds: 604800, reset_after_seconds: 602722, reset_at: 1784812589 },
      secondary_window: null,
    },
    rate_limit_reset_credits: { available_count: 4 },
  };
  await withMockFetch(body, async () => {
    const snap = await fetcher().fetch();
    assert.equal(snap.weekly_pct, 1);
    assert.equal(snap.weekly_window_seconds, 604800);
    assert.equal(snap.weekly_reset_eta_seconds, 602722);
    assert.equal(snap.session_window_seconds, 0, "session card hidden");
    assert.equal(snap.session_pct, 0);
    assert.equal(snap.tier, "plus");
    assert.deepEqual(snap.slots, [
      { label: "Weekly", pct: 1, window_seconds: 604800, reset_eta_seconds: 602722 },
    ]);
  });
});

test("codex inverted windows: classify by duration, not position", async () => {
  // Forward-looking: OpenAI may re-add the 5h limit as secondary_window while
  // keeping the weekly window in primary_window. Classifying by duration keeps
  // the labels right — 604800 is Weekly, 18000 is Session.
  const body = {
    plan_type: "pro",
    rate_limit: {
      primary_window: { used_percent: 6, limit_window_seconds: 604800, reset_after_seconds: 582744 },
      secondary_window: { used_percent: 33, limit_window_seconds: 18000, reset_after_seconds: 14007 },
    },
  };
  await withMockFetch(body, async () => {
    const snap = await fetcher().fetch();
    assert.equal(snap.session_pct, 33);
    assert.equal(snap.session_window_seconds, 18000);
    assert.equal(snap.weekly_pct, 6);
    assert.equal(snap.weekly_window_seconds, 604800);
    assert.deepEqual(snap.slots, [
      { label: "Session", pct: 33, window_seconds: 18000, reset_eta_seconds: 14007 },
      { label: "Weekly", pct: 6, window_seconds: 604800, reset_eta_seconds: 582744 },
    ]);
  });
});

test("codex monthly window (>2wk) surfaces via slots only", async () => {
  const body = {
    plan_type: "pro",
    rate_limit: {
      primary_window: { used_percent: 20, limit_window_seconds: 18000, reset_after_seconds: 3600 },
      secondary_window: { used_percent: 42, limit_window_seconds: 2592000, reset_after_seconds: 1000000 },
    },
  };
  await withMockFetch(body, async () => {
    const snap = await fetcher().fetch();
    assert.equal(snap.session_pct, 20);
    assert.equal(snap.session_window_seconds, 18000);
    assert.equal(snap.weekly_window_seconds, 0, "weekly card hidden");
    assert.equal(snap.weekly_pct, 0);
    assert.deepEqual(snap.slots, [
      { label: "Session", pct: 20, window_seconds: 18000, reset_eta_seconds: 3600 },
      { label: "Monthly", pct: 42, window_seconds: 2592000, reset_eta_seconds: 1000000 },
    ]);
  });
});

test("codex fractional limit_window_seconds floors (parity with go/py)", async () => {
  const body = {
    plan_type: "plus",
    rate_limit: {
      primary_window: { used_percent: 10, limit_window_seconds: 18000.5, reset_after_seconds: 100 },
      secondary_window: { used_percent: 20, limit_window_seconds: 604800, reset_after_seconds: 200 },
    },
  };
  await withMockFetch(body, async () => {
    const snap = await fetcher().fetch();
    assert.equal(snap.session_window_seconds, 18000, "fractional window floors to 18000");
    assert.equal(snap.weekly_window_seconds, 604800);
  });
});

test("codex legacy two-window shape still maps to Session + Weekly", async () => {
  const body = {
    plan_type: "plus",
    rate_limit: {
      primary_window: { used_percent: 33, limit_window_seconds: 18000, reset_after_seconds: 14007, reset_at: 1779678515 },
      secondary_window: { used_percent: 6, limit_window_seconds: 604800, reset_after_seconds: 582744, reset_at: 1780247253 },
    },
  };
  await withMockFetch(body, async () => {
    const snap = await fetcher().fetch();
    assert.equal(snap.session_pct, 33);
    assert.equal(snap.session_window_seconds, 18000);
    assert.equal(snap.weekly_pct, 6);
    assert.equal(snap.weekly_window_seconds, 604800);
    assert.deepEqual(snap.slots, [
      { label: "Session", pct: 33, window_seconds: 18000, reset_eta_seconds: 14007 },
      { label: "Weekly", pct: 6, window_seconds: 604800, reset_eta_seconds: 582744 },
    ]);
  });
});
