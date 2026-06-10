import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createCipheriv, createDecipheriv } from "node:crypto";

import {
  encryptPending, decryptPending,
  encryptPendingGCM, decryptPendingGCM,
  gcmFwGate, PENDING_GCM_MIN_FW,
} from "../src/registry/crypto.js";

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

const gcmPath = findCompat("vectors/aes_gcm.json");
const gcmSkip = gcmPath ? false : "compat/vectors/aes_gcm.json unavailable (standalone checkout)";
const gcm = gcmPath ? JSON.parse(readFileSync(gcmPath, "utf8")) : { vectors: [], negative_vectors: [], min_fw_version: "" };

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

// ---- AES-256-GCM pending blob (compat/vectors/aes_gcm.json) ----

test("PENDING_GCM_MIN_FW matches the contract file", { skip: gcmSkip }, () => {
  assert.equal(PENDING_GCM_MIN_FW, gcm.min_fw_version);
});

test("AES-GCM positive vectors: ciphertext matches byte-for-byte (fixed nonce)", { skip: gcmSkip }, () => {
  assert.ok(gcm.vectors.length > 0, "compat gcm vectors empty");
  for (const v of gcm.vectors) {
    const key = Buffer.from(v.key_hex, "hex");
    const nonce = Buffer.from(v.nonce_hex, "hex");
    const pt = Buffer.from(v.plaintext_hex, "hex");
    // Inject the fixed nonce so the output is reproducible; compare ct||tag.
    const { nonce: usedNonce, ciphertext } = encryptPendingGCM(key, pt, v.version, nonce);
    assert.deepEqual(usedNonce, nonce, `vector ${v.name}: nonce passthrough`);
    assert.equal(ciphertext.toString("hex"), v.ciphertext_hex, `vector ${v.name}: ciphertext`);
    // And the plaintext_utf8 must encode to the same bytes (raw UTF-8, e.g. á = c3 a1).
    assert.equal(Buffer.from(v.plaintext_utf8, "utf8").toString("hex"), v.plaintext_hex, `vector ${v.name}: utf8`);
  }
});

test("AES-GCM positive vectors: decrypt(ct||tag, aad) round-trips", { skip: gcmSkip }, () => {
  for (const v of gcm.vectors) {
    const key = Buffer.from(v.key_hex, "hex");
    const nonce = Buffer.from(v.nonce_hex, "hex");
    const ct = Buffer.from(v.ciphertext_hex, "hex");
    // Decrypt via the library primitives directly, mirroring how a device /
    // peer would: setAuthTag from the appended 16 bytes + setAAD = ascii(version).
    const tag = ct.subarray(ct.length - 16);
    const body = ct.subarray(0, ct.length - 16);
    const dec = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    dec.setAAD(Buffer.from(v.aad_ascii, "ascii"));
    dec.setAuthTag(tag);
    const pt = Buffer.concat([dec.update(body), dec.final()]);
    assert.equal(pt.toString("hex"), v.plaintext_hex, `vector ${v.name}`);
    // decryptPendingGCM (which splits ct||tag itself) must agree.
    const pt2 = decryptPendingGCM(key, nonce, ct, v.version);
    assert.equal(pt2.toString("hex"), v.plaintext_hex, `vector ${v.name}: helper`);
  }
});

test("AES-GCM negative vectors must error, never return plaintext", { skip: gcmSkip }, () => {
  assert.ok(gcm.negative_vectors.length > 0, "compat gcm negative vectors empty");
  for (const v of gcm.negative_vectors) {
    const key = Buffer.from(v.key_hex, "hex");
    const nonce = Buffer.from(v.nonce_hex, "hex");
    const ct = Buffer.from(v.ciphertext_hex, "hex");
    assert.throws(
      () => decryptPendingGCM(key, nonce, ct, v.version),
      undefined,
      `negative vector ${v.name} must throw`,
    );
  }
});

test("encryptPendingGCM uses a fresh 12-byte nonce per call and round-trips", () => {
  const key = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) key[i] = i;
  const pt = Buffer.from("hello gcm payload", "utf8");
  const a = encryptPendingGCM(key, pt, 5);
  const b = encryptPendingGCM(key, pt, 5);
  assert.equal(a.nonce.length, 12);
  assert.notDeepEqual(a.nonce, b.nonce);
  assert.notDeepEqual(a.ciphertext, b.ciphertext);
  assert.deepEqual(decryptPendingGCM(key, a.nonce, a.ciphertext, 5), pt);
  // Wrong AAD/version fails authentication.
  assert.throws(() => decryptPendingGCM(key, a.nonce, a.ciphertext, 6));
});

test("encryptPendingGCM/decryptPendingGCM enforce key + nonce lengths", () => {
  assert.throws(() => encryptPendingGCM(Buffer.alloc(16), Buffer.from("x"), 1));
  assert.throws(() => encryptPendingGCM(Buffer.alloc(32), Buffer.from("x"), 1, Buffer.alloc(16)));
  assert.throws(() => decryptPendingGCM(Buffer.alloc(16), Buffer.alloc(12), Buffer.alloc(32), 1));
  assert.throws(() => decryptPendingGCM(Buffer.alloc(32), Buffer.alloc(16), Buffer.alloc(32), 1));
  assert.throws(() => decryptPendingGCM(Buffer.alloc(32), Buffer.alloc(12), Buffer.alloc(8), 1));
});

// GCM_GATE_CASES is the cross-impl edge-case table. It MUST stay byte-identical
// to TestFwSupportsGCM_GateComparator (go) and test_gcm_fw_gate_comparator (py)
// so the three brokers never diverge on which firmware gets GCM vs CTR. The
// rule is strict packSemver(): exactly MAJOR.MINOR.PATCH numeric (no leading
// zeros, in range), optional "-suffix" ignored; ANYTHING else → CTR.
const GCM_GATE_CASES = [
  // At/above the floor → GCM.
  ["0.8.1", true],
  ["0.8.99", true],
  ["0.8.9", true],
  ["0.9.0", true],
  ["0.9.1", true],
  ["1.0.0", true],
  ["0.10.0", true],
  ["255.255.65535", true],
  // Suffix of the floor still counts (same source tree, carries the decryptor).
  ["0.8.1-dev.202606091938", true],
  ["0.8.1-rc1", true],
  // Below the floor → CTR.
  ["0.8.0", false],
  ["0.7.99", false],
  ["0.8.0-dev.1", false],
  ["0.0.0", false],
  // Loose forms the OLD js accepted but go/py REJECT — must now be CTR.
  ["0.9", false], // too few components
  ["v0.9.0", false], // leading "v" not stripped by packSemver
  ["0.9.0+build", false], // "+build" not stripped (split on "-" only)
  ["00.9.0", false], // leading zero
  ["0.09.0", false], // leading zero
  ["0.9junk.0", false], // non-digit component
  ["256.0.0", false], // major out of 8-bit range
  ["0.0.65536", false], // patch out of 16-bit range
  ["999999999999.0.0", false], // huge component
  ["0.9.0.0", false], // too many components
  // Absent / unparseable → CTR.
  ["", false],
  ["garbage", false],
  ["not.a.version", false],
];

test("gcmFwGate: strict packSemver gate, cross-impl edge-case table", () => {
  for (const [fw, want] of GCM_GATE_CASES) {
    assert.equal(gcmFwGate(fw), want, `gcmFwGate(${JSON.stringify(fw)})`);
  }
  // Non-string inputs also fall back to CTR.
  assert.equal(gcmFwGate(undefined), false);
  assert.equal(gcmFwGate(null), false);
});
