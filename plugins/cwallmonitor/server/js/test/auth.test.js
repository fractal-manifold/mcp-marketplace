import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as auth from "../src/auth.js";

const here = dirname(fileURLToPath(import.meta.url));

// The server source now lives inside the cwallmonitor plugin, whose
// server/compat/ holds only tool-schemas.json (the runtime slice). Probe for
// the specific file so that partial dir is skipped and the walk reaches the
// authoritative monorepo compat/. Absent in a standalone plugin checkout, so
// the byte-exact vector tests skip cleanly there.
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
const compat = findCompat("vectors/hmac.json");
const skip = compat ? false : "compat/vectors/hmac.json unavailable (standalone checkout)";
const data = compat ? JSON.parse(readFileSync(compat, "utf8")) : { vectors: [], negative_vectors: [] };

test("HMAC v2 vectors match byte-for-byte", { skip }, () => {
  assert.ok(data.vectors.length > 0, "compat vectors empty");
  for (const v of data.vectors) {
    const got = auth.computeSignature(
      Buffer.from(v.psk_utf8, "utf8"),
      v.method, v.path, v.timestamp, v.nonce,
      v.device ?? "", v.config_version ?? "",
    );
    assert.equal(got, v.expected_hex, `vector ${v.name}`);
  }
});

test("Negative vector: lowercased nonce", { skip }, () => {
  for (const v of data.negative_vectors) {
    if (!v.expected_hex_from_lowercased) continue;
    const got = auth.computeSignature(
      Buffer.from(v.psk_utf8, "utf8"),
      v.method, v.path, v.timestamp, v.nonce_after_lowercase,
      v.device ?? "", v.config_version ?? "",
    );
    assert.equal(got, v.expected_hex_from_lowercased);
  }
});

test("v1 form is no longer reproduced (bump regression test)", { skip }, () => {
  for (const v of data.negative_vectors) {
    if (!v.v1_expected_hex_rejected_now || !v.v2_expected_hex) continue;
    const got = auth.computeSignature(
      Buffer.from(v.psk_utf8, "utf8"),
      v.method, v.path, v.timestamp, v.nonce, "", "",
    );
    assert.equal(got, v.v2_expected_hex);
    assert.notEqual(got, v.v1_expected_hex_rejected_now);
  }
});

test("Verify happy path", () => {
  const psk = Buffer.from("psk-32-bytes-of-secret-material!", "utf8");
  const cache = new auth.NonceCache(300);
  const ts = "1700000000";
  const nonce = "0123456789abcdef0123456789abcdef";
  const sig = auth.computeSignature(psk, "GET", "/credentials", ts, nonce, "", "");
  auth.verify(psk, "GET", "/credentials", ts, nonce, sig, "", "", cache, 60, 1700000000);
});

test("Verify replay rejected", () => {
  const psk = Buffer.from("psk-32-bytes-of-secret-material!", "utf8");
  const cache = new auth.NonceCache(300);
  const ts = "1700000000";
  const nonce = "0123456789abcdef0123456789abcdef";
  const sig = auth.computeSignature(psk, "GET", "/credentials", ts, nonce, "", "");
  auth.verify(psk, "GET", "/credentials", ts, nonce, sig, "", "", cache, 60, 1700000000);
  assert.throws(
    () => auth.verify(psk, "GET", "/credentials", ts, nonce, sig, "", "", cache, 60, 1700000000),
    /replay/,
  );
});

test("Verify skew rejected", () => {
  const psk = Buffer.from("psk-32-bytes-of-secret-material!", "utf8");
  const cache = new auth.NonceCache(300);
  const oldTs = String(1700000000 - 120);
  const nonce = "0123456789abcdef0123456789abcdef";
  const sig = auth.computeSignature(psk, "GET", "/credentials", oldTs, nonce, "", "");
  assert.throws(
    () => auth.verify(psk, "GET", "/credentials", oldTs, nonce, sig, "", "", cache, 60, 1700000000),
    /skew/,
  );
});

test("VerifyMulti picks pending PSK", () => {
  const active = Buffer.from("active-32-bytes-of-secret-mat!!!", "utf8");
  const pending = Buffer.from("pending-32-bytes-of-secret-mat!!", "utf8");
  const cache = new auth.NonceCache(300);
  const ts = "1700000000";
  const nonce = "1111111111111111aaaaaaaaaaaaaaaa";
  const sig = auth.computeSignature(
    pending, "GET", "/device/ab12cd34/sync", ts, nonce, "ab12cd34", "",
  );
  const res = auth.verifyMulti(
    [active, pending], "GET", "/device/ab12cd34/sync", ts, nonce, sig,
    "ab12cd34", "", cache, 60, 1700000000,
  );
  assert.equal(res.pskIndex, 1);
});

test("VerifyMulti wrong PSK does not burn nonce", () => {
  const wrong = Buffer.from("wrong-32-bytes-of-secret-materi!", "utf8");
  const right = Buffer.from("right-32-bytes-of-secret-materi!", "utf8");
  const cache = new auth.NonceCache(300);
  const ts = "1700000000";
  const nonce = "5555555555555555eeeeeeeeeeeeeeee";
  const sig = auth.computeSignature(right, "GET", "/credentials", ts, nonce, "", "");
  assert.throws(
    () => auth.verifyMulti([wrong], "GET", "/credentials", ts, nonce, sig, "", "", cache, 60, 1700000000),
    /signature/,
  );
  const res = auth.verifyMulti([right], "GET", "/credentials", ts, nonce, sig, "", "", cache, 60, 1700000000);
  assert.equal(res.pskIndex, 0);
});

test("Tampered X-Cwm-Config-Version is rejected", () => {
  const psk = Buffer.from("psk-32-bytes-of-secret-material!", "utf8");
  const cache = new auth.NonceCache(300);
  const ts = "1700000000";
  const nonce = "0123456789abcdef0123456789abcdef";
  // Client signs for version=5.
  const sig = auth.computeSignature(
    psk, "GET", "/device/ab12cd34/sync", ts, nonce, "ab12cd34", "5",
  );
  // Attacker replays with version=999.
  assert.throws(
    () => auth.verify(
      psk, "GET", "/device/ab12cd34/sync", ts, nonce, sig,
      "ab12cd34", "999", cache, 60, 1700000000,
    ),
    /signature/,
  );
});

test("Tampered X-Cwm-Device is rejected", () => {
  const psk = Buffer.from("psk-32-bytes-of-secret-material!", "utf8");
  const cache = new auth.NonceCache(300);
  const ts = "1700000000";
  const nonce = "0123456789abcdef0123456789abcdef";
  const sig = auth.computeSignature(psk, "GET", "/credentials", ts, nonce, "ab12cd34", "");
  assert.throws(
    () => auth.verify(
      psk, "GET", "/credentials", ts, nonce, sig,
      "99887766", "", cache, 60, 1700000000,
    ),
    /signature/,
  );
});
