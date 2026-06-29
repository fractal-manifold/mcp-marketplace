"""Validate AES-256-GCM pending encryption against ../compat/vectors/aes_gcm.json.

Round-trips every positive vector with the fixed nonce, comparing the
ciphertext (ct||tag) byte-for-byte; asserts every negative vector errors;
pins PENDING_GCM_MIN_FW to the file's min_fw_version; exercises the live-fw
gate comparator. Follows the upward-walk + skip pattern of the other vector
tests but is expected to RUN inside the monorepo.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tmon_mcp.registry import crypto


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


COMPAT = _find_compat("vectors/aes_gcm.json")


def _data():
    return json.loads(COMPAT.read_text())


def test_gcm_positive_vectors_byte_for_byte():
    data = _data()
    assert data["vectors"], "compat gcm vectors empty"
    for v in data["vectors"]:
        key = bytes.fromhex(v["key_hex"])
        nonce = bytes.fromhex(v["nonce_hex"])
        pt = bytes.fromhex(v["plaintext_hex"])
        out_nonce, ct = crypto.encrypt_pending_gcm(key, pt, v["version"], nonce)
        assert out_nonce == nonce
        assert ct.hex() == v["ciphertext_hex"], (
            f"vector {v['name']!r}: got {ct.hex()}, want {v['ciphertext_hex']}"
        )
        # And it round-trips back to the plaintext with the matching AAD.
        assert crypto.decrypt_pending_gcm(key, nonce, ct, v["version"]) == pt


def test_gcm_negative_vectors_must_error():
    data = _data()
    assert data["negative_vectors"], "compat gcm negative vectors empty"
    for v in data["negative_vectors"]:
        assert v.get("must_error") is True, v["name"]
        key = bytes.fromhex(v["key_hex"])
        nonce = bytes.fromhex(v["nonce_hex"])
        ct = bytes.fromhex(v["ciphertext_hex"])
        with pytest.raises(Exception, match=r".*"):
            crypto.decrypt_pending_gcm(key, nonce, ct, v["version"])


def test_gcm_min_fw_matches_vector_file():
    assert crypto.PENDING_GCM_MIN_FW == _data()["min_fw_version"]


def test_gcm_fresh_nonce_per_call():
    key = bytes(range(32))
    pt = b"hello pending payload"
    n1, c1 = crypto.encrypt_pending_gcm(key, pt, 3)
    n2, c2 = crypto.encrypt_pending_gcm(key, pt, 3)
    assert len(n1) == crypto.PENDING_GCM_NONCE_LEN
    assert n1 != n2, "fresh nonce per call"
    assert c1 != c2, "ciphertexts must differ for identical plaintext"
    assert crypto.decrypt_pending_gcm(key, n1, c1, 3) == pt


def test_gcm_key_and_nonce_length_enforced():
    with pytest.raises(ValueError):
        crypto.encrypt_pending_gcm(b"short", b"x", 1)
    with pytest.raises(ValueError):
        crypto.encrypt_pending_gcm(bytes(32), b"x", 1, nonce=bytes(16))
    with pytest.raises(ValueError):
        crypto.decrypt_pending_gcm(b"short", bytes(12), b"x", 1)
    with pytest.raises(ValueError):
        crypto.decrypt_pending_gcm(bytes(32), bytes(16), b"x", 1)
    with pytest.raises(ValueError):
        crypto.decrypt_pending_gcm(bytes(32), bytes(12), b"", 1)


# Cross-impl edge-case table. MUST stay byte-identical to GCM_GATE_CASES
# (js test/crypto.test.js) and TestFwSupportsGCM_GateComparator (go) so the
# three brokers never diverge on which firmware gets GCM vs CTR. The rule is
# strict ota.pack_semver: exactly MAJOR.MINOR.PATCH numeric (no leading zeros,
# in range), optional "-suffix" ignored; anything else falls back to CTR.
@pytest.mark.parametrize(
    "fw,expect_gcm",
    [
        # At/above the floor → GCM.
        ("0.8.1", True),
        ("0.8.99", True),
        ("0.9.0", True),
        ("0.9.1", True),
        ("1.0.0", True),
        ("0.10.0", True),
        ("255.255.65535", True),
        # Suffix of the floor still counts (same source tree).
        ("0.8.1-dev.202606091938", True),
        ("0.8.1-rc1", True),
        # Below the floor → CTR.
        ("0.8.0", False),
        ("0.7.99", False),
        ("0.8.0-dev.1", False),
        ("0.0.0", False),
        # Loose forms go/py REJECT (old js accepted) → CTR.
        ("0.9", False),  # too few components
        ("v0.9.0", False),  # leading "v" not stripped
        ("0.9.0+build", False),  # "+build" not stripped (split on "-" only)
        ("00.9.0", False),  # leading zero
        ("0.09.0", False),  # leading zero
        ("0.9junk.0", False),  # non-digit component
        ("256.0.0", False),  # major out of 8-bit range
        ("0.0.65536", False),  # patch out of 16-bit range
        ("999999999999.0.0", False),  # huge component
        ("0.9.0.0", False),  # too many components
        # Absent / unparseable → CTR.
        ("", False),
        ("garbage", False),
        ("not.a.version", False),
    ],
)
def test_gcm_fw_gate_comparator(fw, expect_gcm):
    assert crypto.gcm_fw_gate_open(fw) is expect_gcm
