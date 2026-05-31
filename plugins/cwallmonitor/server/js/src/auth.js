// HMAC-SHA256 request signing + nonce replay cache (v2).
//
// Canonical input:
//   METHOD\nPATH\nTIMESTAMP\nNONCE\nDEVICE\nVERSION
//
// Mirrors cwm-mcp/internal/auth/auth.go. See ../compat/HMAC_CANONICAL.md
// for the byte-exact contract and ../compat/vectors/hmac.json for the
// pinned test vectors every implementation must reproduce.

import { createHmac, timingSafeEqual } from "node:crypto";

export function computeSignature(psk, method, path, ts, nonce, device = "", configVersion = "") {
  // psk: Buffer (or string interpreted as utf-8). method/path/ts/nonce/device/configVersion: strings.
  const key = Buffer.isBuffer(psk) ? psk : Buffer.from(psk, "utf8");
  const mac = createHmac("sha256", key);
  mac.update(method);
  mac.update("\n");
  mac.update(path);
  mac.update("\n");
  mac.update(ts);
  mac.update("\n");
  mac.update(nonce);
  mac.update("\n");
  mac.update(device);
  mac.update("\n");
  mac.update(configVersion);
  return mac.digest("hex");
}

const HEX32_RE = /^[0-9A-Fa-f]{32}$/;
const DECIMAL_RE = /^-?[0-9]+$/;

function isHex32(s) {
  return HEX32_RE.test(s);
}

function parseStrictInt(s) {
  // Reject "123abc" and similar; mirrors Go's strconv.ParseInt(10).
  if (typeof s !== "string" || !DECIMAL_RE.test(s)) return null;
  const n = Number(s);
  if (!Number.isFinite(n) || !Number.isSafeInteger(n)) return null;
  return n;
}

export class AuthError extends Error {
  constructor(kind) {
    super(kind);
    this.kind = kind;
  }
}

export const ERR_MISSING_HEADERS = "missing headers";
export const ERR_BAD_TIMESTAMP = "bad timestamp";
export const ERR_TIMESTAMP_SKEW = "timestamp skew";
export const ERR_BAD_NONCE_FORMAT = "bad nonce format";
export const ERR_BAD_SIGNATURE = "bad signature";
export const ERR_NONCE_REPLAY = "nonce replay";

export class NonceCache {
  constructor(ttlSeconds) {
    this.ttl = ttlSeconds;
    this._seen = new Map();
  }
  checkAndAdd(nonce, nowTs) {
    this._reap(nowTs);
    if (this._seen.has(nonce)) return false;
    this._seen.set(nonce, nowTs);
    return true;
  }
  _reap(nowTs) {
    const cutoff = nowTs - this.ttl;
    for (const [n, t] of this._seen) {
      if (t < cutoff) this._seen.delete(n);
    }
  }
}

function constantTimeEqualHex(aHex, bHex) {
  if (aHex.length !== bHex.length) return false;
  return timingSafeEqual(Buffer.from(aHex, "ascii"), Buffer.from(bHex, "ascii"));
}

// verify() and verifyMulti() now take deviceHeader and configVersionHeader
// — pass them straight from req.headers["x-cwm-device"] || "" etc. Their
// position mirrors the Go signature (between sigHeader and cache).
export function verify(psk, method, path, tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader, cache, maxSkewSeconds, now) {
  if (!tsHeader || !nonceHeader || !sigHeader) throw new AuthError(ERR_MISSING_HEADERS);
  const ts = parseStrictInt(tsHeader);
  if (ts === null) throw new AuthError(ERR_BAD_TIMESTAMP);
  const nowTs = now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(Math.floor(nowTs) - ts) > maxSkewSeconds) throw new AuthError(ERR_TIMESTAMP_SKEW);
  if (!isHex32(nonceHeader)) throw new AuthError(ERR_BAD_NONCE_FORMAT);
  const nonceLC = nonceHeader.toLowerCase();
  // Sign with the exact header bytes, not a reformatted integer, so any
  // future spec tightening (no leading zeros, etc.) catches mismatches.
  const expected = computeSignature(
    psk, method, path, tsHeader, nonceLC,
    deviceHeader ?? "", configVersionHeader ?? "",
  );
  if (!constantTimeEqualHex(sigHeader.toLowerCase(), expected)) throw new AuthError(ERR_BAD_SIGNATURE);
  if (!cache.checkAndAdd(nonceLC, nowTs)) throw new AuthError(ERR_NONCE_REPLAY);
}

export function verifyMulti(psks, method, path, tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader, cache, maxSkewSeconds, now) {
  if (!tsHeader || !nonceHeader || !sigHeader) throw new AuthError(ERR_MISSING_HEADERS);
  const ts = parseStrictInt(tsHeader);
  if (ts === null) throw new AuthError(ERR_BAD_TIMESTAMP);
  const nowTs = now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(Math.floor(nowTs) - ts) > maxSkewSeconds) throw new AuthError(ERR_TIMESTAMP_SKEW);
  if (!isHex32(nonceHeader)) throw new AuthError(ERR_BAD_NONCE_FORMAT);
  const nonceLC = nonceHeader.toLowerCase();
  const sigLC = sigHeader.toLowerCase();
  const tsStr = tsHeader;
  const dev = deviceHeader ?? "";
  const ver = configVersionHeader ?? "";
  let matched = -1;
  for (let i = 0; i < psks.length; i++) {
    const psk = psks[i];
    if (!psk || psk.length === 0) continue;
    if (constantTimeEqualHex(sigLC, computeSignature(psk, method, path, tsStr, nonceLC, dev, ver))) {
      matched = i;
      break;
    }
  }
  if (matched < 0) throw new AuthError(ERR_BAD_SIGNATURE);
  if (!cache.checkAndAdd(nonceLC, nowTs)) throw new AuthError(ERR_NONCE_REPLAY);
  return { pskIndex: matched };
}
