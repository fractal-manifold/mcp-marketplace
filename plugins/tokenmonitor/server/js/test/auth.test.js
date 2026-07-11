import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as auth from "../src/auth.js";

const here = dirname(fileURLToPath(import.meta.url));

// The server source now lives inside the tokenmonitor plugin, whose
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

test("percent-encoded path signs the DECODED form", { skip }, () => {
  const v = data.vectors.find((x) => x.name === "percent-encoded-path-signs-decoded");
  assert.ok(v, "percent-encoded-path-signs-decoded vector present");
  // Signing the decoded path reproduces expected_hex...
  const decoded = auth.computeSignature(
    Buffer.from(v.psk_utf8, "utf8"),
    v.method, v.path, v.timestamp, v.nonce, v.device ?? "", v.config_version ?? "",
  );
  assert.equal(decoded, v.expected_hex);
  // ...and decoding the raw wire path yields the same value (this is the
  // canonicalization the server performs).
  assert.equal(decodeURIComponent(v.raw_path_on_wire), v.path);
  // Signing the still-encoded form gives the WRONG hash the contract pins.
  const raw = auth.computeSignature(
    Buffer.from(v.psk_utf8, "utf8"),
    v.method, v.raw_path_on_wire, v.timestamp, v.nonce, v.device ?? "", v.config_version ?? "",
  );
  assert.equal(raw, v.raw_path_must_not_be_signed);
  assert.notEqual(decoded, raw);
});

test("reject_vectors: non-ASCII auth header value is detectable pre-HMAC", { skip }, () => {
  const rv = data.reject_vectors || [];
  const v = rv.find((x) => x.name === "non-ascii-auth-header-value");
  assert.ok(v, "non-ascii-auth-header-value reject vector present");
  // The wire value carries non-ASCII bytes (latin-1-decoded by Node's http
  // parser). Mirror that decode and assert at least one char is > 0x7f, which
  // is exactly what the server's authHeadersAreASCII guard tests.
  const asSeen = Buffer.from(v.header_value_hex, "hex").toString("latin1");
  let hasNonAscii = false;
  for (let i = 0; i < asSeen.length; i++) if (asSeen.charCodeAt(i) > 0x7f) hasNonAscii = true;
  assert.equal(hasNonAscii, true);
  // A pure-ASCII value must NOT be flagged.
  let asciiClean = true;
  for (let i = 0; i < "ab12cd34".length; i++) if ("ab12cd34".charCodeAt(i) > 0x7f) asciiClean = false;
  assert.equal(asciiClean, true);
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

test("HMAC v3 body_vectors match byte-for-byte and verify end-to-end", { skip }, () => {
  const vs = data.body_vectors || [];
  assert.ok(vs.length > 0, "body_vectors missing from hmac.json");
  for (const v of vs) {
    const psk = Buffer.from(v.psk_utf8, "utf8");
    const body = Buffer.from(v.body_utf8, "utf8");
    const digest = createHash("sha256").update(body).digest("hex");
    assert.equal(digest, v.body_sha256, `body digest ${v.name}`);
    const got = auth.computeSignatureBody(
      psk, v.method, v.path, v.timestamp, v.nonce,
      v.device, v.config_version, v.body_sha256,
    );
    assert.equal(got, v.expected_hex, `vector ${v.name}`);
    // Stripping X-Tmon-Body-Sha256 cannot downgrade: the v2 form differs.
    const v2 = auth.computeSignature(
      psk, v.method, v.path, v.timestamp, v.nonce, v.device, v.config_version,
    );
    assert.notEqual(v2, got);
    if (v.v2_form_must_differ) assert.equal(v2, v.v2_form_must_differ);
    // End-to-end verify.
    const cache = new auth.NonceCache(300);
    const res = auth.verifyMultiBody(
      [psk], v.method, v.path, v.timestamp, v.nonce, got,
      v.device, v.config_version, v.body_sha256, body,
      cache, 60, Number(v.timestamp),
    );
    assert.equal(res.pskIndex, 0);
  }
});

test("HMAC v3 body_reject_vectors: malformed/mismatching digest rejected pre-HMAC", { skip }, () => {
  const rvs = data.body_reject_vectors || [];
  assert.ok(rvs.length > 0, "body_reject_vectors missing from hmac.json");
  const psk = Buffer.from("active-32-bytes-of-secret-mat!!!", "utf8");
  for (const rv of rvs) {
    assert.equal(rv.must_reject, true, rv.name);
    const cache = new auth.NonceCache(300);
    assert.throws(
      () => auth.verifyMultiBody(
        [psk], "POST", "/device/ab12cd34/settings",
        "1700000180", "3333333333333333cccccccccccccccc", "0".repeat(64),
        "ab12cd34", "42",
        rv.body_sha256_header, Buffer.from(rv.body_utf8, "utf8"),
        cache, 60, 1700000180,
      ),
      (e) => e instanceof auth.AuthError && e.kind === auth.ERR_BAD_BODY_DIGEST,
      rv.name,
    );
  }
});

test("verifyMultiBody without header falls back to legacy v2", () => {
  const psk = Buffer.from("active-32-bytes-of-secret-mat!!!", "utf8");
  const cache = new auth.NonceCache(300);
  const ts = "1700000180";
  const nonce = "3333333333333333cccccccccccccccc";
  const sig = auth.computeSignature(psk, "POST", "/device/ab12cd34/settings", ts, nonce, "ab12cd34", "42");
  const res = auth.verifyMultiBody(
    [psk], "POST", "/device/ab12cd34/settings", ts, nonce, sig,
    "ab12cd34", "42", "", Buffer.from('{"vol":25}', "utf8"),
    cache, 60, 1700000180,
  );
  assert.equal(res.pskIndex, 0);
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

test("Tampered X-Tmon-Config-Version is rejected", () => {
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

test("Tampered X-Tmon-Device is rejected", () => {
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
