// normalizeKeyringToken must extract agy's token across the platform layouts:
// Linux libsecret stores the JSON {token:{access_token,expiry}} directly; the
// macOS Keychain stores `<id>:<base64url(JSON)>`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeKeyringToken } from "../src/usage.js";

const INNER = { token: { access_token: "AT123", expiry: "2026-07-24T00:00:00Z" } };
const b64url = (s) => Buffer.from(s).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

test("linux libsecret shape {token:{...}}", () => {
  const t = normalizeKeyringToken(JSON.stringify(INNER));
  assert.equal(t.access_token, "AT123");
  assert.equal(t.expiry, "2026-07-24T00:00:00Z");
});

test("macOS <id>:<base64url(JSON)> shape", () => {
  const mac = "someid1234567890:" + b64url(JSON.stringify(INNER));
  const t = normalizeKeyringToken(mac);
  assert.equal(t.access_token, "AT123");
  assert.equal(t.expiry, "2026-07-24T00:00:00Z");
});

test("top-level {access_token,...} shape", () => {
  const t = normalizeKeyringToken(JSON.stringify({ access_token: "AT9", expiry: "2026-01-01T00:00:00Z" }));
  assert.equal(t.access_token, "AT9");
});

test("garbage / empty / bare token → null (parity with Go/Python: only JSON or id:base64url(JSON))", () => {
  assert.equal(normalizeKeyringToken("not a token with spaces"), null);
  assert.equal(normalizeKeyringToken("eyJhbGciOiJub25lIn0.eyJleHAiOjF9.sig"), null); // bare JWT unsupported
  assert.equal(normalizeKeyringToken(""), null);
  assert.equal(normalizeKeyringToken(null), null);
});
