// Pending-blob encryption. Two wire schemes:
//   - legacy AES-256-CTR, 16-byte IV (no "enc" field) — pre-0.9.0 firmware.
//   - AES-256-GCM, 12-byte nonce, 16-byte tag appended to ciphertext, AAD =
//     ASCII decimal of pending.version ("enc":"gcm") — firmware >= 0.9.0.
// Mirrors registry/crypto.go. See ../compat/SECURITY.md and
// ../compat/vectors/aes_gcm.json (the byte-exact GCM contract).

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { packSemver } from "../ota.js";

export const PENDING_NONCE_LEN = 16;
export const PENDING_GCM_NONCE_LEN = 12;
export const PENDING_GCM_TAG_LEN = 16;

// Firmware at or above this version understands the GCM wire format. The
// broker only emits "enc":"gcm" when the live X-Cwm-Fw-Version request header
// is >= this; older firmware keeps getting the legacy CTR blob. Must equal
// compat/vectors/aes_gcm.json min_fw_version (asserted in the tests).
export const PENDING_GCM_MIN_FW = "0.9.0";

export function encryptPending(key, plaintext) {
  if (key.length !== 32) throw new Error(`registry/crypto: key must be 32 bytes, got ${key.length}`);
  const nonce = randomBytes(PENDING_NONCE_LEN);
  const cipher = createCipheriv("aes-256-ctr", key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce, ciphertext: ct };
}

export function decryptPending(key, nonce, ciphertext) {
  if (key.length !== 32) throw new Error(`registry/crypto: key must be 32 bytes, got ${key.length}`);
  if (nonce.length !== PENDING_NONCE_LEN) throw new Error(`registry/crypto: nonce must be ${PENDING_NONCE_LEN} bytes, got ${nonce.length}`);
  if (!ciphertext || ciphertext.length === 0) throw new Error("registry/crypto: empty ciphertext");
  const dec = createDecipheriv("aes-256-ctr", key, nonce);
  return Buffer.concat([dec.update(ciphertext), dec.final()]);
}

// encryptPendingGCM encrypts the pending payload with AES-256-GCM. The 12-byte
// nonce is generated fresh unless `fixedNonce` is supplied (tests inject a
// pinned nonce to reproduce vector ciphertext byte-for-byte). The returned
// ciphertext is ct||tag — the 16-byte GCM tag appended, matching the native
// PSA / Go crypto/cipher GCM / Python AESGCM byte order. AAD binds the blob to
// pending.version: the ASCII decimal of `version` (e.g. 7 => the byte "7"),
// NOT the raw 4-byte integer.
export function encryptPendingGCM(key, plaintext, version, fixedNonce) {
  if (key.length !== 32) throw new Error(`registry/crypto: key must be 32 bytes, got ${key.length}`);
  let nonce;
  if (fixedNonce !== undefined) {
    if (fixedNonce.length !== PENDING_GCM_NONCE_LEN) {
      throw new Error(`registry/crypto: gcm nonce must be ${PENDING_GCM_NONCE_LEN} bytes, got ${fixedNonce.length}`);
    }
    nonce = fixedNonce;
  } else {
    nonce = randomBytes(PENDING_GCM_NONCE_LEN);
  }
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: PENDING_GCM_TAG_LEN });
  const aad = Buffer.from(String(version >>> 0), "ascii");
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { nonce, ciphertext: Buffer.concat([ct, tag]) };
}

// decryptPendingGCM is the inverse of encryptPendingGCM: `ciphertext` is the
// ct||tag concatenation as it travels on the wire. Throws on a bad tag, wrong
// AAD (version mismatch), wrong key length, or a non-12-byte nonce — never
// returns plaintext on authentication failure.
export function decryptPendingGCM(key, nonce, ciphertext, version) {
  if (key.length !== 32) throw new Error(`registry/crypto: key must be 32 bytes, got ${key.length}`);
  if (nonce.length !== PENDING_GCM_NONCE_LEN) throw new Error(`registry/crypto: gcm nonce must be ${PENDING_GCM_NONCE_LEN} bytes, got ${nonce.length}`);
  if (!ciphertext || ciphertext.length < PENDING_GCM_TAG_LEN) throw new Error("registry/crypto: ciphertext shorter than gcm tag");
  const ct = ciphertext.subarray(0, ciphertext.length - PENDING_GCM_TAG_LEN);
  const tag = ciphertext.subarray(ciphertext.length - PENDING_GCM_TAG_LEN);
  const dec = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: PENDING_GCM_TAG_LEN });
  const aad = Buffer.from(String(version >>> 0), "ascii");
  dec.setAAD(aad);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(ct), dec.final()]);
}

// gcmFwGate reports whether a live X-Cwm-Fw-Version header value is at or above
// PENDING_GCM_MIN_FW, i.e. the device understands the GCM wire format. Uses the
// SAME strict packSemver() the Go (ota.PackSemver / fwSupportsGCM) and Python
// (ota.pack_semver / gcm_fw_gate_open) brokers use, so identical headers gate
// identically across all three impls: the version must be a strict numeric
// MAJOR.MINOR.PATCH (exactly three components, ASCII digits, no leading zeros,
// in 8.8.16 range). An optional "-dev.<ts>" prerelease suffix is IGNORED (a
// 0.9.0-dev build carries the GCM decryptor). ANYTHING else — "0.9", "v0.9.0",
// "0.9.0+build", "00.9.0", out-of-range, empty/absent — fails packSemver and
// falls back to legacy CTR.
export function gcmFwGate(fwHeader) {
  const got = packSemver(fwHeader);
  if (got === null) return false;
  const floor = packSemver(PENDING_GCM_MIN_FW);
  return got >= floor;
}
