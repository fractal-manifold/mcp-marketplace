// Read the Claude CLI OAuth credentials. On Linux the CLI writes a plaintext
// file (~/.claude/.credentials.json by default); on macOS it stores the same
// {"claudeAiOauth":{...}} JSON blob in the login Keychain instead. readRaw
// hides that difference — file first, then the Keychain on darwin.

import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

export class CredsFileMissing extends Error {}
export class CredsParse extends Error {}

// macOS login-Keychain generic-password service name the Claude CLI uses.
export const KEYCHAIN_SERVICE = "Claude Code-credentials";

// Overridable for tests. Shells out to /usr/bin/security to print the secret
// to stdout. The first read may pop a GUI authorization prompt; once the user
// picks "Always Allow" it succeeds silently. The short timeout keeps a
// never-answered prompt from wedging the poll loop.
let keychainReader = (service) =>
  execFileSync("/usr/bin/security", ["find-generic-password", "-s", service, "-w"], {
    encoding: "utf8",
    timeout: 5_000,
    stdio: ["ignore", "pipe", "ignore"],
  });

// The platform-default Claude credentials file. The Keychain fallback only
// applies to this path. Overridable for tests.
let defaultOAuthPath = () => join(homedir(), ".claude", ".credentials.json");

// Test hook — swap the Keychain reader; returns the previous one.
export function _setKeychainReader(fn) {
  const prev = keychainReader;
  keychainReader = fn;
  return prev;
}

// Test hook — swap the default-path resolver; returns the previous one.
export function _setDefaultOAuthPath(fn) {
  const prev = defaultOAuthPath;
  defaultOAuthPath = fn;
  return prev;
}

// Return the raw Claude credentials JSON blob, Keychain-aware on macOS. The
// file wins when present. Only a missing DEFAULT file falls back to the
// Keychain (and only on darwin) — a missing explicit oauth_path override
// errors instead of silently serving the login account's token.
export function readRaw(path, service = KEYCHAIN_SERVICE) {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    if (e.code !== "ENOENT") throw new CredsParse(`credentials read error: ${e.message}`);
  }
  if (process.platform === "darwin" && path === defaultOAuthPath()) {
    try {
      const raw = keychainReader(service);
      if (raw && raw.trim()) return raw;
    } catch {
      // fall through to the file-missing error below
    }
    throw new CredsFileMissing(
      `credentials file missing: ${path} (macOS Keychain "${service}" also unavailable)`);
  }
  throw new CredsFileMissing(`credentials file missing: ${path}`);
}

export function load(path) {
  const rawText = readRaw(path);
  let doc;
  try {
    doc = JSON.parse(rawText);
  } catch (e) {
    throw new CredsParse(`credentials parse error: ${e.message}`);
  }
  const oauth = doc?.claudeAiOauth || {};
  const token = oauth.accessToken || "";
  const expiresAt = oauth.expiresAt || 0;
  if (!token) throw new CredsParse("missing or invalid 'accessToken'");
  if (!expiresAt) throw new CredsParse("missing or invalid 'expiresAt'");
  return {
    accessToken: token,
    expiresAtUnixMS: expiresAt,
    expiresAtISO() {
      const d = new Date(expiresAt);
      return d.toISOString().replace(/\.(\d{3})Z$/, ".$1Z");
    },
    isExpired(nowMs) { return nowMs >= expiresAt; },
  };
}

// Decode a JWT and return its `exp` claim as unix ms (0 on parse error).
function jwtExpMS(token) {
  const parts = (token || "").split(".");
  if (parts.length !== 3) return 0;
  try {
    const padded = parts[1] + "=".repeat((4 - parts[1].length % 4) % 4);
    const json = Buffer.from(padded, "base64url").toString("utf8");
    const claims = JSON.parse(json);
    const exp = claims.exp;
    if (typeof exp !== "number") return 0;
    return exp < 1e12 ? exp * 1000 : exp;
  } catch {
    return 0;
  }
}

export function loadCodex(path) {
  if (!existsSync(path)) throw new CredsFileMissing(`codex auth file missing: ${path}`);
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new CredsParse(`codex auth parse error: ${e.message}`);
  }
  const tokens = doc?.tokens || {};
  const access = tokens.access_token || doc?.access_token || "";
  const account = tokens.account_id || doc?.account_id || "";
  if (!access) throw new CredsParse("missing access_token");
  if (!account) throw new CredsParse("missing account_id");

  let expMs = 0;
  const rawExp = doc?.expires_at;
  if (typeof rawExp === "string" && rawExp) {
    const t = Date.parse(rawExp);
    if (Number.isFinite(t)) expMs = t;
  } else if (typeof rawExp === "number") {
    expMs = rawExp < 1e12 ? rawExp * 1000 : rawExp;
  }
  if (!expMs) expMs = jwtExpMS(access);
  if (!expMs) expMs = jwtExpMS(tokens.id_token || doc?.id_token || "");
  if (!expMs) throw new CredsParse("missing expires_at or JWT exp");
  return {
    accessToken: access,
    accountId: account,
    expiresAtUnixMS: expMs,
    expiresAtISO() {
      const d = new Date(expMs);
      return d.toISOString().replace(/\.(\d{3})Z$/, ".$1Z");
    },
    isExpired(nowMs) { return nowMs >= expMs; },
  };
}
