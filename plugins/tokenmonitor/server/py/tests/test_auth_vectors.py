"""Validate the HMAC implementation byte-for-byte against ../compat/vectors/hmac.json (v2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tmon_mcp import auth


def _find_compat(rel: str) -> Path:
    """Walk up to the authoritative monorepo `compat/<rel>`.

    The server source now lives inside the tokenmonitor plugin, whose
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


def test_percent_encoded_path_signs_decoded():
    """The DECODED path is signed (aiohttp req.path / Go r.URL.Path are
    already %-decoded). Signing the still-encoded form yields a different,
    WRONG hash. Wires the percent-encoded-path vector from hmac.json."""
    data = _load_vectors()
    matched = 0
    for v in data["vectors"]:
        if "raw_path_on_wire" not in v:
            continue
        matched += 1
        psk = v["psk_utf8"].encode("utf-8")
        # Signing the decoded path reproduces the expected signature.
        got = auth.compute_signature(
            psk, v["method"], v["path"], v["timestamp"], v["nonce"],
            v.get("device", ""), v.get("config_version", ""),
        )
        assert got == v["expected_hex"], f"vector {v['name']!r}"
        # Signing the raw (encoded) path must NOT match, and must equal the
        # documented wrong answer.
        wrong = auth.compute_signature(
            psk, v["method"], v["raw_path_on_wire"], v["timestamp"], v["nonce"],
            v.get("device", ""), v.get("config_version", ""),
        )
        assert wrong != v["expected_hex"]
        assert wrong == v["raw_path_must_not_be_signed"]
    assert matched, "percent-encoded-path vector not found in hmac.json"


def test_non_ascii_auth_header_rejected():
    """X-Tmon-* auth headers are ASCII-only: a non-ASCII value must be
    rejected as an AuthError (mapped to 401), never escape as a 500 from
    .encode('ascii'). Wires the reject_vectors entry from hmac.json."""
    data = _load_vectors()
    rejects = data.get("reject_vectors", [])
    assert rejects, "reject_vectors missing from hmac.json"
    matched = 0
    for rv in rejects:
        assert rv.get("must_reject") is True, rv["name"]
        # The hex round-trips to the same UTF-8 value the vector pins.
        val = rv["header_value_utf8"]
        assert val.encode("utf-8").hex() == rv["header_value_hex"]
        assert not val.isascii()
        matched += 1

        psk = b"active-32-bytes-of-secret-mat!!!"
        cache = auth.NonceCache(ttl_seconds=300)
        now = 1700000000.0
        ts = "1700000000"
        nonce = "0123456789abcdef0123456789abcdef"
        # A plausible (correctly-shaped) signature is irrelevant — the
        # non-ASCII header must be rejected BEFORE the HMAC is computed.
        sig = "0" * 64
        header = rv["header"]
        device = val if header == "X-Tmon-Device" else ""
        config_version = val if header == "X-Tmon-Config-Version" else ""
        with pytest.raises(auth.AuthError):
            auth.verify(
                psk, "GET", "/device/ab12cd34/sync", ts, nonce, sig,
                device, config_version, cache, 60, now,
            )
        with pytest.raises(auth.AuthError):
            auth.verify_multi(
                [psk], "GET", "/device/ab12cd34/sync", ts, nonce, sig,
                device, config_version, cache, 60, now,
            )
    assert matched, "no reject vectors exercised"


def test_body_vectors_v3():
    """v3 (body-covering) canonical: the digest of body_utf8 must match
    body_sha256, compute_signature_body must reproduce expected_hex, the v2
    form of the same fields must differ (stripping X-Tmon-Body-Sha256 cannot
    downgrade), and verify_multi_body must accept the whole request."""
    import hashlib

    data = _load_vectors()
    vectors = data.get("body_vectors", [])
    assert vectors, "body_vectors missing from hmac.json"
    for v in vectors:
        psk = v["psk_utf8"].encode("utf-8")
        body = v["body_utf8"].encode("utf-8")
        assert hashlib.sha256(body).hexdigest() == v["body_sha256"], v["name"]
        got = auth.compute_signature_body(
            psk, v["method"], v["path"], v["timestamp"], v["nonce"],
            v["device"], v["config_version"], v["body_sha256"],
        )
        assert got == v["expected_hex"], f"vector {v['name']!r}: got {got}"
        v2 = auth.compute_signature(
            psk, v["method"], v["path"], v["timestamp"], v["nonce"],
            v["device"], v["config_version"],
        )
        assert v2 != got, "v3 hash equals v2 hash — header stripping would downgrade"
        if "v2_form_must_differ" in v:
            assert v2 == v["v2_form_must_differ"]
        # End-to-end verify.
        cache = auth.NonceCache(ttl_seconds=300)
        res = auth.verify_multi_body(
            [psk], v["method"], v["path"], v["timestamp"], v["nonce"], got,
            v["device"], v["config_version"], v["body_sha256"], body,
            cache, 60, float(v["timestamp"]),
        )
        assert res.psk_index == 0


def test_body_reject_vectors():
    """Malformed or mismatching X-Tmon-Body-Sha256 must be rejected as a bad
    body digest before any HMAC is computed."""
    data = _load_vectors()
    rejects = data.get("body_reject_vectors", [])
    assert rejects, "body_reject_vectors missing from hmac.json"
    psk = b"active-32-bytes-of-secret-mat!!!"
    for rv in rejects:
        assert rv.get("must_reject") is True, rv["name"]
        cache = auth.NonceCache(ttl_seconds=300)
        with pytest.raises(auth.AuthError) as exc:
            auth.verify_multi_body(
                [psk], "POST", "/device/ab12cd34/settings",
                "1700000180", "3333333333333333cccccccccccccccc", "0" * 64,
                "ab12cd34", "42",
                rv["body_sha256_header"], rv["body_utf8"].encode("utf-8"),
                cache, 60, 1700000180.0,
            )
        assert "body digest" in str(exc.value), rv["name"]


def test_verify_multi_body_absent_header_is_legacy_v2():
    """No X-Tmon-Body-Sha256 → verify_multi_body must behave exactly like
    verify_multi (old firmware until it gets the OTA)."""
    psk = b"active-32-bytes-of-secret-mat!!!"
    cache = auth.NonceCache(ttl_seconds=300)
    ts = "1700000180"
    nonce = "3333333333333333cccccccccccccccc"
    sig = auth.compute_signature(
        psk, "POST", "/device/ab12cd34/settings", ts, nonce, "ab12cd34", "42",
    )
    res = auth.verify_multi_body(
        [psk], "POST", "/device/ab12cd34/settings", ts, nonce, sig,
        "ab12cd34", "42", "", b'{"vol":25}',
        cache, 60, 1700000180.0,
    )
    assert res.psk_index == 0


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
    """Regression test for the v1→v2 bump: changing X-Tmon-Config-Version
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
