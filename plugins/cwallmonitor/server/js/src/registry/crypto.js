// AES-256-CTR pending blob. Mirrors registry/crypto.go. See ../compat/SECURITY.md.

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export const PENDING_NONCE_LEN = 16;

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
