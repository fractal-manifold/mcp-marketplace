// Read ~/.claude/.credentials.json.

import { readFileSync, existsSync } from "node:fs";

export class CredsFileMissing extends Error {}
export class CredsParse extends Error {}

export function load(path) {
  if (!existsSync(path)) throw new CredsFileMissing(`credentials file missing: ${path}`);
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
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
