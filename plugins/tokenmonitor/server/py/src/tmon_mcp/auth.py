"""HMAC-SHA256 request signing and nonce replay cache.

Mirrors tokenmonitor-mcp/internal/auth/auth.go byte-for-byte. See
../compat/HMAC_CANONICAL.md for the canonical form.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import re
import threading
import time
from dataclasses import dataclass, field


def compute_signature(
    psk: bytes,
    method: str,
    path: str,
    ts: str,
    nonce: str,
    device: str = "",
    config_version: str = "",
) -> str:
    """Canonical HMAC v2: HMAC-SHA256(psk, METHOD\\nPATH\\nTS\\nNONCE\\nDEVICE\\nVERSION) → hex lowercase.

    Pass empty strings for device and/or config_version when the
    corresponding X-Tmon-* header is not present. Empty strings still
    contribute their trailing "\\n" separators, so the result is
    distinct from the deprecated v1 form.
    """
    msg = f"{method}\n{path}\n{ts}\n{nonce}\n{device}\n{config_version}".encode("ascii")
    return _hmac.new(psk, msg, hashlib.sha256).hexdigest()


def compute_signature_body(
    psk: bytes,
    method: str,
    path: str,
    ts: str,
    nonce: str,
    device: str,
    config_version: str,
    body_sha256: str,
) -> str:
    """Canonical HMAC v3 (body-covering): the v2 string with
    "\\n" + BODY_SHA256 appended, where body_sha256 is the lowercase-hex
    SHA-256 of the raw request body (the X-Tmon-Body-Sha256 header value).
    Only used when that header is present; requests without it keep the
    v2 form."""
    msg = (
        f"{method}\n{path}\n{ts}\n{nonce}\n{device}\n{config_version}\n{body_sha256}"
    ).encode("ascii")
    return _hmac.new(psk, msg, hashlib.sha256).hexdigest()


_HEX32_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
_LOWER_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL_RE = re.compile(r"^-?[0-9]+$")


def _is_hex32(s: str) -> bool:
    return bool(_HEX32_RE.fullmatch(s))


def _is_lower_hex64(s: str) -> bool:
    # X-Tmon-Body-Sha256 is STRICT lowercase (no case folding, unlike the
    # nonce) — its verbatim bytes are part of the canonical input.
    return bool(_LOWER_HEX64_RE.fullmatch(s))


def _parse_strict_int(s: str) -> int | None:
    # Mirror Go's strconv.ParseInt(s, 10, 64): reject whitespace,
    # underscores, hex prefixes. int() in Python would accept "1_000".
    if not _DECIMAL_RE.fullmatch(s):
        return None
    try:
        return int(s)
    except ValueError:
        return None


class AuthError(Exception):
    pass


ERR_MISSING_HEADERS = AuthError("missing headers")
ERR_BAD_TIMESTAMP = AuthError("bad timestamp")
ERR_TIMESTAMP_SKEW = AuthError("timestamp skew")
ERR_BAD_NONCE_FORMAT = AuthError("bad nonce format")
ERR_BAD_SIGNATURE = AuthError("bad signature")
ERR_NONCE_REPLAY = AuthError("nonce replay")
ERR_NON_ASCII_HEADER = AuthError("non-ascii auth header")
ERR_BAD_BODY_DIGEST = AuthError("bad body digest")


def _auth_headers_ascii(*values: str) -> bool:
    """Auth headers (X-Tmon-*) are ASCII-only per compat/HMAC_CANONICAL.md.
    A non-ASCII value (attacker-controlled, pre-auth) must be rejected as a
    normal 401 — never let .encode('ascii') escape as a 500. str.isascii()
    is True for the empty string, so absent headers pass."""
    return all(v.isascii() for v in values)


@dataclass
class NonceCache:
    """TTL-bounded cache; reaping is lazy on insert."""

    ttl_seconds: float
    _seen: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def check_and_add(self, nonce: str, now_ts: float) -> bool:
        with self._lock:
            self._reap(now_ts)
            if nonce in self._seen:
                return False
            self._seen[nonce] = now_ts
            return True

    def _reap(self, now_ts: float) -> None:
        cutoff = now_ts - self.ttl_seconds
        stale = [n for n, t in self._seen.items() if t < cutoff]
        for n in stale:
            del self._seen[n]


def verify(
    psk: bytes,
    method: str,
    path: str,
    ts_header: str,
    nonce_header: str,
    sig_header: str,
    device_header: str = "",
    config_version_header: str = "",
    cache: NonceCache | None = None,
    max_skew_seconds: int = 60,
    now: float | None = None,
) -> None:
    """Single-PSK verification. Raises AuthError on rejection.

    device_header / config_version_header come straight from
    request.headers.get(..., "") on the server side — no normalisation,
    no lowercasing. See compat/HMAC_CANONICAL.md for the byte-exact
    contract.
    """
    if cache is None:
        raise TypeError("verify() requires a NonceCache")
    if not ts_header or not nonce_header or not sig_header:
        raise ERR_MISSING_HEADERS
    if not _auth_headers_ascii(
        ts_header, nonce_header, sig_header, device_header, config_version_header
    ):
        raise ERR_NON_ASCII_HEADER
    ts = _parse_strict_int(ts_header)
    if ts is None:
        raise ERR_BAD_TIMESTAMP
    now_ts = time.time() if now is None else now
    if abs(int(now_ts) - ts) > max_skew_seconds:
        raise ERR_TIMESTAMP_SKEW
    if not _is_hex32(nonce_header):
        raise ERR_BAD_NONCE_FORMAT
    nonce_lc = nonce_header.lower()
    expected = compute_signature(
        psk, method, path, ts_header, nonce_lc,
        device_header, config_version_header,
    )
    if not _hmac.compare_digest(sig_header.lower(), expected):
        raise ERR_BAD_SIGNATURE
    if not cache.check_and_add(nonce_lc, now_ts):
        raise ERR_NONCE_REPLAY


@dataclass
class VerifyResult:
    psk_index: int


def verify_multi(
    psks: list[bytes | None],
    method: str,
    path: str,
    ts_header: str,
    nonce_header: str,
    sig_header: str,
    device_header: str = "",
    config_version_header: str = "",
    cache: NonceCache | None = None,
    max_skew_seconds: int = 60,
    now: float | None = None,
) -> VerifyResult:
    """Try each PSK; nonce only burned after a match. Mirrors auth.VerifyMulti."""
    if cache is None:
        raise TypeError("verify_multi() requires a NonceCache")
    if not ts_header or not nonce_header or not sig_header:
        raise ERR_MISSING_HEADERS
    if not _auth_headers_ascii(
        ts_header, nonce_header, sig_header, device_header, config_version_header
    ):
        raise ERR_NON_ASCII_HEADER
    ts = _parse_strict_int(ts_header)
    if ts is None:
        raise ERR_BAD_TIMESTAMP
    now_ts = time.time() if now is None else now
    if abs(int(now_ts) - ts) > max_skew_seconds:
        raise ERR_TIMESTAMP_SKEW
    if not _is_hex32(nonce_header):
        raise ERR_BAD_NONCE_FORMAT
    nonce_lc = nonce_header.lower()
    sig_lc = sig_header.lower()
    ts_str = ts_header

    matched = -1
    for i, psk in enumerate(psks):
        if not psk:
            continue
        expected = compute_signature(
            psk, method, path, ts_str, nonce_lc,
            device_header, config_version_header,
        )
        if _hmac.compare_digest(sig_lc, expected):
            matched = i
            break
    if matched < 0:
        raise ERR_BAD_SIGNATURE
    if not cache.check_and_add(nonce_lc, now_ts):
        raise ERR_NONCE_REPLAY
    return VerifyResult(psk_index=matched)


def verify_multi_body(
    psks: list[bytes | None],
    method: str,
    path: str,
    ts_header: str,
    nonce_header: str,
    sig_header: str,
    device_header: str = "",
    config_version_header: str = "",
    body_sha_header: str = "",
    body: bytes = b"",
    cache: NonceCache | None = None,
    max_skew_seconds: int = 60,
    now: float | None = None,
) -> VerifyResult:
    """Body-aware verify_multi (HMAC v3). Mirrors auth.VerifyMultiBody.

    body_sha_header comes from X-Tmon-Body-Sha256 verbatim. Absent header →
    legacy v2 path (old firmware until it gets the OTA). Present → strict
    lowercase 64-hex gate, sha256(body) must match, and the digest joins the
    canonical string. Stripping the header cannot downgrade a v3-signed
    request: its signature only verifies under the v3 canonical.
    """
    if cache is None:
        raise TypeError("verify_multi_body() requires a NonceCache")
    if not body_sha_header:
        return verify_multi(
            psks, method, path, ts_header, nonce_header, sig_header,
            device_header, config_version_header,
            cache=cache, max_skew_seconds=max_skew_seconds, now=now,
        )
    if not ts_header or not nonce_header or not sig_header:
        raise ERR_MISSING_HEADERS
    if not _auth_headers_ascii(
        ts_header, nonce_header, sig_header,
        device_header, config_version_header, body_sha_header,
    ):
        raise ERR_NON_ASCII_HEADER
    if not _is_lower_hex64(body_sha_header):
        raise ERR_BAD_BODY_DIGEST
    # Digest is public (a hash of the body the sender already sent) — plain
    # compare is fine; only the HMAC below needs constant time.
    if hashlib.sha256(body).hexdigest() != body_sha_header:
        raise ERR_BAD_BODY_DIGEST
    ts = _parse_strict_int(ts_header)
    if ts is None:
        raise ERR_BAD_TIMESTAMP
    now_ts = time.time() if now is None else now
    if abs(int(now_ts) - ts) > max_skew_seconds:
        raise ERR_TIMESTAMP_SKEW
    if not _is_hex32(nonce_header):
        raise ERR_BAD_NONCE_FORMAT
    nonce_lc = nonce_header.lower()
    sig_lc = sig_header.lower()

    matched = -1
    for i, psk in enumerate(psks):
        if not psk:
            continue
        expected = compute_signature_body(
            psk, method, path, ts_header, nonce_lc,
            device_header, config_version_header, body_sha_header,
        )
        if _hmac.compare_digest(sig_lc, expected):
            matched = i
            break
    if matched < 0:
        raise ERR_BAD_SIGNATURE
    if not cache.check_and_add(nonce_lc, now_ts):
        raise ERR_NONCE_REPLAY
    return VerifyResult(psk_index=matched)


# --------------------------------------------------------------------------
# Response direction (v1)
# --------------------------------------------------------------------------
# The request signatures above only ever proved the DEVICE to the BROKER. That
# was enough while the broker's address was configuration someone typed; it is
# not enough now that the device locates its broker by mDNS, where any host on
# the LAN can advertise a `devs=` list containing our (public) device_id. This
# tag is the other half: proof that the responder holds the device's PSK.
#
# Mirrors auth.ComputeResponseSignature in the Go broker and
# tmon_resp_sig_canonical() in firmware/components/crypto. Vectors:
# compat/vectors/hmac.json → response_vectors.

RESPONSE_SIG_PREFIX = "tmon-resp-v1"
RESPONSE_SIG_HEADER = "X-Tmon-Resp-Signature"


def body_sha256_hex(body: bytes) -> str:
    """Lowercase-hex SHA-256 of the exact response bytes."""
    return hashlib.sha256(body or b"").hexdigest()


def compute_response_signature(
    psk: bytes,
    device: str,
    nonce: str,
    host: str,
    path: str,
    status: int,
    body_sha256: str,
) -> str:
    """HMAC-SHA256(psk, PREFIX\\nDEVICE\\nNONCE\\nHOST\\nPATH\\nSTATUS\\nBODY_SHA256).

    `nonce` is the request's X-Tmon-Nonce, lower-cased exactly as the request
    verifiers do — that binding is what makes the tag a challenge-response
    rather than something an impostor could precompute or replay. `status` is
    the decimal HTTP status, so a 200 tag cannot be spliced onto a 503.

    `host` is the LOCAL socket address this broker answered on
    ("<ipv4>:<port>"), never the client-supplied Host header. It is what makes
    the tag prove *this address*: without it an impostor can advertise itself
    on the LAN, forward each request to the real broker, and return the real
    broker's tag — which verifies, and the device then adopts and caches the
    relay. See response_sig_host().
    """
    msg = (
        f"{RESPONSE_SIG_PREFIX}\n{device}\n{nonce.lower()}\n{host}\n{path}"
        f"\n{status}\n{body_sha256}"
    ).encode("ascii")
    return _hmac.new(psk, msg, hashlib.sha256).hexdigest()


def response_sig_host(request) -> str:
    """The HOST field for `request`: the local end of its socket, "<ip>:<port>".

    Taken from the transport, never from the Host header — a relay forwards
    that header untouched, so signing it would prove nothing about who
    answered. An IPv4-mapped local address ("::ffff:192.168.1.28", what a
    dual-stack listener reports) is unwrapped so a broker bound to "::" signs
    the same bytes as one bound to "0.0.0.0".

    Returns "" when there is no usable local address; the caller must then emit
    no tag rather than sign an empty host, which would canonicalise every
    address alike and switch the relay binding back off.
    """
    transport = getattr(request, "transport", None)
    sockname = transport.get_extra_info("sockname") if transport is not None else None
    if not isinstance(sockname, tuple) or len(sockname) < 2:
        return ""
    host, port = str(sockname[0]), sockname[1]
    if host.lower().startswith("::ffff:"):
        host = host[7:]
    if not host or not isinstance(port, int):
        return ""
    return f"{host}:{port}"
