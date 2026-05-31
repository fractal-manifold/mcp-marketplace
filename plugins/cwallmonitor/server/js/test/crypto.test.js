import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createCipheriv } from "node:crypto";

import { encryptPending, decryptPending } from "../src/registry/crypto.js";

const here = dirname(fileURLToPath(import.meta.url));

// See auth.test.js findCompat for why this walks up past the partial
// server/compat/ runtime slice to the authoritative monorepo compat/.
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
const compat = findCompat("vectors/aes_ctr.json");
const skip = compat ? false : "compat/vectors/aes_ctr.json unavailable (standalone checkout)";
const data = compat ? JSON.parse(readFileSync(compat, "utf8")) : { vectors: [] };

test("AES-CTR vectors match byte-for-byte", { skip }, () => {
  for (const v of data.vectors) {
    const key = Buffer.from(v.key_hex, "hex");
    const iv = Buffer.from(v.iv_hex, "hex");
    const pt = Buffer.from(v.plaintext_hex, "hex");
    const c = createCipheriv("aes-256-ctr", key, iv);
    const ct = Buffer.concat([c.update(pt), c.final()]);
    assert.equal(ct.toString("hex"), v.ciphertext_hex, `vector ${v.name}`);
  }
});

test("encryptPending uses fresh IV per call and round-trips", () => {
  const key = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) key[i] = i;
  const pt = Buffer.from("hello pending payload", "utf8");
  const { nonce: n1, ciphertext: c1 } = encryptPending(key, pt);
  const { nonce: n2, ciphertext: c2 } = encryptPending(key, pt);
  assert.notDeepEqual(n1, n2);
  assert.notDeepEqual(c1, c2);
  assert.deepEqual(decryptPending(key, n1, c1), pt);
  assert.deepEqual(decryptPending(key, n2, c2), pt);
});

test("encryptPending enforces key length", () => {
  assert.throws(() => encryptPending(Buffer.alloc(16), Buffer.from("x")));
  assert.throws(() => decryptPending(Buffer.alloc(16), Buffer.alloc(16), Buffer.from("x")));
  assert.throws(() => decryptPending(Buffer.alloc(32), Buffer.alloc(8), Buffer.from("x")));
  assert.throws(() => decryptPending(Buffer.alloc(32), Buffer.alloc(16), Buffer.alloc(0)));
});
