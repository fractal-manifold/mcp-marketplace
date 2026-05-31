"""AES-256-CTR for pending config blobs. See ../compat/SECURITY.md."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PENDING_NONCE_LEN = 16  # AES block size


def encrypt_pending(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError(f"registry/crypto: key must be 32 bytes, got {len(key)}")
    nonce = os.urandom(PENDING_NONCE_LEN)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    ciphertext = enc.update(plaintext) + enc.finalize()
    return nonce, ciphertext


def decrypt_pending(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError(f"registry/crypto: key must be 32 bytes, got {len(key)}")
    if len(nonce) != PENDING_NONCE_LEN:
        raise ValueError(f"registry/crypto: nonce must be {PENDING_NONCE_LEN} bytes, got {len(nonce)}")
    if not ciphertext:
        raise ValueError("registry/crypto: empty ciphertext")
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()
