"""Validate AES-CTR against ../compat/vectors/aes_ctr.json."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cwm_mcp.registry import crypto


def _find_compat(rel: str) -> Path:
    """Walk up to the authoritative monorepo `compat/<rel>` (see
    test_auth_vectors._find_compat for why the walk skips the partial
    server/compat/ runtime slice)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "compat" / rel
        if cand.exists():
            return cand
    pytest.skip(f"compat/{rel} not available (standalone checkout)", allow_module_level=True)


COMPAT = _find_compat("vectors/aes_ctr.json")


def _vectors():
    return json.loads(COMPAT.read_text())


def test_aes_ctr_vectors_byte_for_byte():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    data = _vectors()
    for v in data["vectors"]:
        key = bytes.fromhex(v["key_hex"])
        iv = bytes.fromhex(v["iv_hex"])
        pt = bytes.fromhex(v["plaintext_hex"])
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        enc = cipher.encryptor()
        ct = enc.update(pt) + enc.finalize()
        assert ct.hex() == v["ciphertext_hex"], f"vector {v['name']!r}"


def test_encrypt_round_trip_fresh_nonce():
    key = bytes(range(32))
    pt = b"hello pending payload"
    n1, c1 = crypto.encrypt_pending(key, pt)
    n2, c2 = crypto.encrypt_pending(key, pt)
    assert n1 != n2, "fresh nonce per call"
    assert c1 != c2, "ciphertexts must differ for identical plaintext"
    assert crypto.decrypt_pending(key, n1, c1) == pt
    assert crypto.decrypt_pending(key, n2, c2) == pt


def test_encrypt_key_length_enforced():
    with pytest.raises(ValueError):
        crypto.encrypt_pending(b"short", b"x")
    with pytest.raises(ValueError):
        crypto.decrypt_pending(b"short", bytes(16), b"x")
    with pytest.raises(ValueError):
        crypto.decrypt_pending(bytes(32), b"short", b"x")
    with pytest.raises(ValueError):
        crypto.decrypt_pending(bytes(32), bytes(16), b"")
