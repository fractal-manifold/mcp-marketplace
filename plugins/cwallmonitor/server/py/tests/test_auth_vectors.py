"""Validate the HMAC implementation byte-for-byte against ../compat/vectors/hmac.json (v2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cwm_mcp import auth


def _find_compat(rel: str) -> Path:
    """Walk up to the authoritative monorepo `compat/<rel>`.

    The server source now lives inside the cwallmonitor plugin, whose
    `server/compat/` holds only `tool-schemas.json` (the runtime slice). We
    probe for the *specific* file so that partial dir is skipped and the walk
    continues up to the monorepo root, where the full `compat/` lives. In a
    standalone plugin checkout (no monorepo around it) the file is absent and
    the byte-exact vector tests skip cleanly."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "compat" / rel
        if cand.exists():
            return cand
    pytest.skip(f"compat/{rel} not available (standalone checkout)", allow_module_level=True)


COMPAT = _find_compat("vectors/hmac.json")


def _load_vectors():
    return json.loads(COMPAT.read_text())


def test_known_vectors_match_byte_for_byte():
    data = _load_vectors()
    assert data["vectors"], "compat vectors empty"
    for v in data["vectors"]:
        psk = v["psk_utf8"].encode("utf-8")
        got = auth.compute_signature(
            psk, v["method"], v["path"], v["timestamp"], v["nonce"],
            v.get("device", ""), v.get("config_version", ""),
        )
        assert got == v["expected_hex"], (
            f"vector {v['name']!r}: got {got}, want {v['expected_hex']}"
        )


def test_negative_vector_lowercase_nonce():
    data = _load_vectors()
    for v in data["negative_vectors"]:
        if "expected_hex_from_lowercased" not in v:
            continue
        psk = v["psk_utf8"].encode("utf-8")
        got = auth.compute_signature(
            psk, v["method"], v["path"], v["timestamp"], v["nonce_after_lowercase"],
            v.get("device", ""), v.get("config_version", ""),
        )
        assert got == v["expected_hex_from_lowercased"]


def test_v1_form_is_dead():
    """The v1 canonical (no trailing DEVICE/VERSION) must not reproduce the
    v2 signature for the same inputs — pins the bump so a future regression
    that silently re-introduces v1 fails this test."""
    data = _load_vectors()
    for v in data["negative_vectors"]:
        if "v1_expected_hex_rejected_now" not in v:
            continue
        psk = v["psk_utf8"].encode("utf-8")
        got = auth.compute_signature(
            psk, v["method"], v["path"], v["timestamp"], v["nonce"], "", "",
        )
        assert got == v["v2_expected_hex"]
        assert got != v["v1_expected_hex_rejected_now"]


def test_verify_happy_path():
    psk = b"psk-32-bytes-of-secret-material!"
    cache = auth.NonceCache(ttl_seconds=300)
    now = 1700000000.0
    ts = "1700000000"
    nonce = "0123456789abcdef0123456789abcdef"
    sig = auth.compute_signature(psk, "GET", "/credentials", ts, nonce, "", "")
    auth.verify(psk, "GET", "/credentials", ts, nonce, sig, "", "", cache, 60, now)


def test_verify_replay():
    psk = b"psk-32-bytes-of-secret-material!"
    cache = auth.NonceCache(ttl_seconds=300)
    now = 1700000000.0
    ts = "1700000000"
    nonce = "0123456789abcdef0123456789abcdef"
    sig = auth.compute_signature(psk, "GET", "/credentials", ts, nonce, "", "")
    auth.verify(psk, "GET", "/credentials", ts, nonce, sig, "", "", cache, 60, now)
    with pytest.raises(auth.AuthError) as exc:
        auth.verify(psk, "GET", "/credentials", ts, nonce, sig, "", "", cache, 60, now)
    assert "replay" in str(exc.value)


def test_verify_skew():
    psk = b"psk-32-bytes-of-secret-material!"
    cache = auth.NonceCache(ttl_seconds=300)
    now = 1700000000.0
    old_ts = str(1700000000 - 120)
    nonce = "0123456789abcdef0123456789abcdef"
    sig = auth.compute_signature(psk, "GET", "/credentials", old_ts, nonce, "", "")
    with pytest.raises(auth.AuthError) as exc:
        auth.verify(psk, "GET", "/credentials", old_ts, nonce, sig, "", "", cache, 60, now)
    assert "skew" in str(exc.value)


def test_verify_bad_nonce_format():
    psk = b"x" * 32
    cache = auth.NonceCache(ttl_seconds=300)
    now = 1700000000.0
    ts = "1700000000"
    sig = "deadbeef"
    with pytest.raises(auth.AuthError) as exc:
        auth.verify(psk, "GET", "/credentials", ts, "not-hex", sig, "", "", cache, 60, now)
    assert "nonce" in str(exc.value)


def test_verify_multi_picks_pending():
    active = b"active-32-bytes-of-secret-mat!!!"
    pending = b"pending-32-bytes-of-secret-mat!!"
    cache = auth.NonceCache(ttl_seconds=300)
    now = 1700000000.0
    ts = "1700000000"
    nonce = "1111111111111111aaaaaaaaaaaaaaaa"
    sig = auth.compute_signature(
        pending, "GET", "/device/ab12cd34/sync", ts, nonce, "ab12cd34", "",
    )
    res = auth.verify_multi(
        [active, pending], "GET", "/device/ab12cd34/sync", ts, nonce, sig,
        "ab12cd34", "", cache, 60, now,
    )
    assert res.psk_index == 1


def test_verify_multi_wrong_psk_does_not_burn_nonce():
    wrong = b"wrong-32-bytes-of-secret-materi!"
    right = b"right-32-bytes-of-secret-materi!"
    cache = auth.NonceCache(ttl_seconds=300)
    now = 1700000000.0
    ts = "1700000000"
    nonce = "5555555555555555eeeeeeeeeeeeeeee"
    sig = auth.compute_signature(right, "GET", "/credentials", ts, nonce, "", "")
    with pytest.raises(auth.AuthError):
        auth.verify_multi(
            [wrong], "GET", "/credentials", ts, nonce, sig, "", "", cache, 60, now,
        )
    # Real verify with correct PSK and same nonce must succeed.
    res = auth.verify_multi(
        [right], "GET", "/credentials", ts, nonce, sig, "", "", cache, 60, now,
    )
    assert res.psk_index == 0


def test_tampered_version_header_rejected():
    """Regression test for the v1→v2 bump: changing X-Cwm-Config-Version
    after the client signs must invalidate the signature."""
    psk = b"psk-32-bytes-of-secret-material!"
    cache = auth.NonceCache(ttl_seconds=300)
    now = 1700000000.0
    ts = "1700000000"
    nonce = "0123456789abcdef0123456789abcdef"
    # Client signs for version=5.
    sig = auth.compute_signature(
        psk, "GET", "/device/ab12cd34/sync", ts, nonce, "ab12cd34", "5",
    )
    # Attacker replays with version=999 — must reject.
    with pytest.raises(auth.AuthError) as exc:
        auth.verify(
            psk, "GET", "/device/ab12cd34/sync", ts, nonce, sig,
            "ab12cd34", "999", cache, 60, now,
        )
    assert "signature" in str(exc.value)


def test_tampered_device_header_rejected():
    psk = b"psk-32-bytes-of-secret-material!"
    cache = auth.NonceCache(ttl_seconds=300)
    now = 1700000000.0
    ts = "1700000000"
    nonce = "0123456789abcdef0123456789abcdef"
    sig = auth.compute_signature(
        psk, "GET", "/credentials", ts, nonce, "ab12cd34", "",
    )
    with pytest.raises(auth.AuthError) as exc:
        auth.verify(
            psk, "GET", "/credentials", ts, nonce, sig,
            "99887766", "", cache, 60, now,
        )
    assert "signature" in str(exc.value)
