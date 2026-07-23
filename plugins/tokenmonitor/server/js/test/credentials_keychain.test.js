// macOS Keychain fallback for Claude creds: on darwin a missing
// ~/.claude/.credentials.json falls back to the login Keychain, which serves
// the same {"claudeAiOauth":{...}} JSON blob. On Linux it stays file-only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  load, readRaw, CredsFileMissing, KEYCHAIN_SERVICE,
  _setKeychainReader, _setDefaultOAuthPath,
} from "../src/creds.js";

const BLOB = `{"claudeAiOauth":{"accessToken":"kc","expiresAt":1700000000000}}`;
const MISSING = "/nonexistent/path/.credentials.json";

test("file wins over keychain — keychain not consulted when file exists", () => {
  const restore = _setKeychainReader(() => { throw new Error("keychain must not be consulted"); });
  try {
    const dir = mkdtempSync(join(tmpdir(), "tmon-creds-"));
    const p = join(dir, "creds.json");
    writeFileSync(p, `{"claudeAiOauth":{"accessToken":"f","expiresAt":1700000000000}}`);
    const c = load(p);
    assert.equal(c.accessToken, "f");
  } finally {
    _setKeychainReader(restore);
  }
});

test("darwin: missing DEFAULT file falls back to keychain", { skip: process.platform !== "darwin" }, () => {
  const rk = _setKeychainReader((service) => {
    assert.equal(service, KEYCHAIN_SERVICE);
    return BLOB;
  });
  const rd = _setDefaultOAuthPath(() => MISSING); // treat MISSING as the default path
  try {
    const c = load(MISSING);
    assert.equal(c.accessToken, "kc");
    assert.equal(readRaw(MISSING), BLOB);
  } finally {
    _setKeychainReader(rk);
    _setDefaultOAuthPath(rd);
  }
});

test("darwin: missing EXPLICIT override does NOT hit keychain", { skip: process.platform !== "darwin" }, () => {
  const rk = _setKeychainReader(() => { throw new Error("keychain must not be consulted for an override"); });
  const rd = _setDefaultOAuthPath(() => "/the/default/.credentials.json");
  try {
    assert.throws(() => load("/some/custom/override.json"), CredsFileMissing);
  } finally {
    _setKeychainReader(rk);
    _setDefaultOAuthPath(rd);
  }
});

test("darwin: keychain miss still throws CredsFileMissing", { skip: process.platform !== "darwin" }, () => {
  const rk = _setKeychainReader(() => { throw new Error("not found"); });
  const rd = _setDefaultOAuthPath(() => MISSING);
  try {
    assert.throws(() => load(MISSING), CredsFileMissing);
  } finally {
    _setKeychainReader(rk);
    _setDefaultOAuthPath(rd);
  }
});

test("non-darwin: missing file throws CredsFileMissing (no keychain)", { skip: process.platform === "darwin" }, () => {
  assert.throws(() => load(MISSING), CredsFileMissing);
});
