// DST-correctness of the weekly spend window boundary (bug 10).
//
// The week start must be local Monday 00:00 even when a DST transition falls
// inside the week. The old `dow * 86400_000` arithmetic lands an hour off
// because a spring-forward day is only 23 h long. Matches the Go reference.
//
// TZ must be set before any Date is constructed; node --test runs each file in
// its own process so this is safe.
process.env.TZ = "Europe/Madrid";

import { test } from "node:test";
import assert from "node:assert/strict";

import { windowStarts } from "../src/spend.js";

test("week start is local Monday 00:00 across the spring-forward", () => {
  // Sunday 2026-03-29 12:00 CEST (UTC+2, just after the 02:00 spring-forward)
  // == 10:00 UTC.
  const now = Date.UTC(2026, 2, 29, 10, 0, 0);
  const { week } = windowStarts(now);

  // Correct: Monday 2026-03-23 00:00 CET (UTC+1, still winter) ==
  // 2026-03-22 23:00 UTC. The buggy dow*86400_000 math would give 22:00 UTC.
  assert.equal(week, Date.UTC(2026, 2, 22, 23, 0, 0));
});
