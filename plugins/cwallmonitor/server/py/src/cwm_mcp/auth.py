"""HMAC-SHA256 request signing and nonce replay cache.

Mirrors cwm-mcp/internal/auth/auth.go byte-for-byte. See
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
    corresponding X-Cwm-* header is not present. Empty strings still
    contribute their trailing "\\n" separators, so the result is
    distinct from the deprecated v1 form.
    """
    msg = f"{method}\n{path}\n{ts}\n{nonce}\n{device}\n{config_version}".encode("ascii")
    return _hmac.new(psk, msg, hashlib.sha256).hexdigest()


_HEX32_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
_DECIMAL_RE = re.compile(r"^-?[0-9]+$")


def _is_hex32(s: str) -> bool:
    return bool(_HEX32_RE.fullmatch(s))


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
