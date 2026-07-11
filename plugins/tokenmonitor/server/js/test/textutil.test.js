import { test } from "node:test";
import assert from "node:assert/strict";

import { clipCodePoints } from "../src/textutil.js";

test("clipCodePoints counts code points, not UTF-16 units", () => {
  assert.equal(clipCodePoints("", 15), "");
  assert.equal(clipCodePoints("short", 15), "short");
  assert.equal(clipCodePoints("exactly15chars!", 15), "exactly15chars!");
  assert.equal(clipCodePoints("sixteen chars!!!", 15), "sixteen chars!!");
  // 15 code points with a multibyte char — must survive intact.
  assert.equal(clipCodePoints("Dragón de fuego", 15), "Dragón de fuego");
  assert.equal(clipCodePoints("Dragón de fuegoX", 15), "Dragón de fuego");
  // Astral (surrogate-pair) code points count as one each; a UTF-16
  // .slice(0, 2) here would split the second dragon into a lone surrogate.
  assert.equal(clipCodePoints("🐉🐉🐉", 2), "🐉🐉");
  assert.equal(clipCodePoints("🐉🐉🐉", 15), "🐉🐉🐉");
  assert.equal(clipCodePoints("abc", 0), "");
  // Never emits a lone surrogate.
  for (const cut of ["🐉🐉🐉", "a🐉b🐉", "🐉aaaaaaaaaaaaaa🐉"]) {
    const out = clipCodePoints(cut, 15);
    assert.ok(!/[\uD800-\uDBFF]$/.test(out), `lone surrogate at end of ${JSON.stringify(out)}`);
  }
});
