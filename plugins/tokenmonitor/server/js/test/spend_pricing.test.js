import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { PriceTable } from "../src/pricing.js";

const here = dirname(fileURLToPath(import.meta.url));

// Locate the authoritative monorepo compat/ (see auth.test.js for why the
// upward walk skips the partial server/compat/ slice).
function findCompat(rel) {
  let dir = here;
  for (let i = 0; i < 12; i++) {
    const c = join(dir, "compat", rel);
    if (existsSync(c)) return c;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
const compat = findCompat("vectors/spend_pricing.json");
const skip = compat ? false : "compat/vectors/spend_pricing.json unavailable (standalone checkout)";
const data = compat ? JSON.parse(readFileSync(compat, "utf8")) : { cases: [] };

// Mirror the broker's wire rounding: half-up at the cent. Kept in lockstep
// with go round2() and py _round2() — the vector's half-cent case fails if
// any runtime drifts to banker's rounding.
const round2 = (x) => Math.round(x * 100) / 100;

test("spend pricing vectors: per-model USD + cents match across runtimes", { skip }, () => {
  assert.ok(data.cases.length > 0, "compat spend cases empty");
  const table = new PriceTable(data.prices, "fallback", false);
  for (const c of data.cases) {
    const raw = table.costFor(c.model, c.tokens);
    const wireUsd = round2(raw);
    const cents = Math.round(wireUsd * 100);
    assert.equal(wireUsd, c.expected_usd, `usd for ${c.note} (${c.model})`);
    assert.equal(cents, c.expected_cents, `cents for ${c.note} (${c.model})`);
  }
});
