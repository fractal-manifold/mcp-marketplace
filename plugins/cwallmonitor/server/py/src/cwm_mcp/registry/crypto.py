"""AES for pending config blobs. See ../compat/SECURITY.md.

Legacy wire = AES-256-CTR (16-byte IV, no auth tag). New wire (firmware
>= PENDING_GCM_MIN_FW) = AES-256-GCM: 12-byte nonce, payload = ct||tag,
AAD = ASCII decimal of pending.version. See ../compat/vectors/aes_gcm.json.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PENDING_NONCE_LEN = 16  # AES block size (CTR IV)
PENDING_GCM_NONCE_LEN = 12  # AES-GCM nonce
# Firmware at or above this version carries the GCM decrypt path. The broker
# only emits "enc":"gcm" when the live X-Cwm-Fw-Version says so.
PENDING_GCM_MIN_FW = "0.9.0"


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


def encrypt_pending_gcm(
    key: bytes, plaintext: bytes, version: int, nonce: bytes | None = None
) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt. Returns (nonce, ct||tag).

    AAD = ASCII decimal of `version` (e.g. 7 -> b"7"), binding the blob to
    pending.version. AESGCM.encrypt natively appends the 16-byte tag. nonce
    is for tests only; production passes None for a fresh 12-byte nonce.
    """
    if len(key) != 32:
        raise ValueError(f"registry/crypto: key must be 32 bytes, got {len(key)}")
    if nonce is None:
        nonce = os.urandom(PENDING_GCM_NONCE_LEN)
    elif len(nonce) != PENDING_GCM_NONCE_LEN:
        raise ValueError(
            f"registry/crypto: gcm nonce must be {PENDING_GCM_NONCE_LEN} bytes, got {len(nonce)}"
        )
    aad = str(version).encode("ascii")
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct_tag


def decrypt_pending_gcm(
    key: bytes, nonce: bytes, ciphertext: bytes, version: int
) -> bytes:
    """AES-256-GCM decrypt of ct||tag. Raises on auth failure / bad lengths.

    Rejects non-32-byte keys and non-12-byte nonces (blocks the CTR-IV
    downgrade-strip described in aes_gcm.json's negative vectors)."""
    if len(key) != 32:
        raise ValueError(f"registry/crypto: key must be 32 bytes, got {len(key)}")
    if len(nonce) != PENDING_GCM_NONCE_LEN:
        raise ValueError(
            f"registry/crypto: gcm nonce must be {PENDING_GCM_NONCE_LEN} bytes, got {len(nonce)}"
        )
    if not ciphertext:
        raise ValueError("registry/crypto: empty ciphertext")
    aad = str(version).encode("ascii")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def gcm_fw_gate_open(fw_version: str) -> bool:
    """True when the live X-Cwm-Fw-Version warrants GCM emission, i.e. its
    numeric MAJOR.MINOR.PATCH prefix is >= PENDING_GCM_MIN_FW.

    The -suffix is ignored on purpose: a dev build "0.9.0-dev.<ts>" carries
    the same decrypt code as the "0.9.0" release, so it must also get GCM.
    Garbage / empty / absent versions (pack returns None) fall back to CTR —
    we never gate on registry state, only on what the device reports."""
    from ..ota import pack_semver  # lazy: avoid import cycle (ota → registry)

    packed = pack_semver(fw_version)
    if packed is None:
        return False
    floor = pack_semver(PENDING_GCM_MIN_FW)
    assert floor is not None  # constant is well-formed
    return packed >= floor
