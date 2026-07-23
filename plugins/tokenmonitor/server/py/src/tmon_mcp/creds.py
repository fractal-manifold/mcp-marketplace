"""Reader for the Claude CLI OAuth credentials.

On Linux the CLI writes a plaintext file (``~/.claude/.credentials.json`` by
default); on macOS it stores the same ``{"claudeAiOauth": {...}}`` JSON blob in
the login Keychain instead. ``read_raw`` hides that difference — file first,
then the Keychain on darwin.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


class CredsFileMissing(Exception):
    pass


class CredsParse(Exception):
    pass


# macOS login-Keychain generic-password service name the Claude CLI uses.
KEYCHAIN_SERVICE = "Claude Code-credentials"


def _default_keychain_reader(service: str) -> str:
    """Shell out to /usr/bin/security and print the secret to stdout.

    The first read may raise a GUI authorization prompt; once the user picks
    "Always Allow" it succeeds silently. The short timeout keeps a
    never-answered prompt from wedging the poll loop.
    """
    return subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-s", service, "-w"],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    ).stdout


# Overridable for tests.
_keychain_reader = _default_keychain_reader


def _default_oauth_path() -> str:
    """Platform-default Claude credentials file — the only path the Keychain
    fallback applies to. Overridable in tests."""
    return str(Path.home() / ".claude" / ".credentials.json")


def set_keychain_reader(fn):
    """Test hook — swap the Keychain reader; returns the previous one."""
    global _keychain_reader
    prev = _keychain_reader
    _keychain_reader = fn
    return prev


def read_raw(path: str, service: str = KEYCHAIN_SERVICE) -> str:
    """Return the raw Claude credentials JSON blob, Keychain-aware on macOS.

    The file wins when present. Only a missing DEFAULT file falls back to the
    Keychain (and only on darwin) — a missing explicit oauth_path override
    errors instead of silently serving the login account's token. A non-ENOENT
    read error surfaces as CredsParse (parity with the Go/JS impls).
    """
    p = Path(path)
    try:
        return p.read_text()
    except FileNotFoundError:
        pass
    except OSError as e:
        raise CredsParse(f"credentials read error: {e}") from e
    if sys.platform == "darwin" and str(p) == _default_oauth_path():
        try:
            raw = _keychain_reader(service)
        except Exception:
            raw = ""
        if raw and raw.strip():
            return raw
        raise CredsFileMissing(
            f'credentials file missing: {path} (macOS Keychain "{service}" also unavailable)'
        )
    raise CredsFileMissing(f"credentials file missing: {path}")


@dataclass
class Stored:
    access_token: str
    expires_at_unix_ms: int

    def expires_at_iso(self) -> str:
        t = time.gmtime(self.expires_at_unix_ms / 1000.0)
        ms = self.expires_at_unix_ms % 1000
        return time.strftime("%Y-%m-%dT%H:%M:%S", t) + f".{ms:03d}Z"

    def is_expired(self, now_ms: int) -> bool:
        return now_ms >= self.expires_at_unix_ms


def load(path: str) -> Stored:
    raw = read_raw(path)
    try:
        doc = json.loads(raw)
    except Exception as e:
        raise CredsParse(f"credentials parse error: {e}") from e
    oauth = doc.get("claudeAiOauth") or {}
    token = oauth.get("accessToken") or ""
    expires_at = oauth.get("expiresAt") or 0
    if not token:
        raise CredsParse("missing or invalid 'accessToken'")
    if not expires_at:
        raise CredsParse("missing or invalid 'expiresAt'")
    return Stored(access_token=token, expires_at_unix_ms=int(expires_at))


@dataclass
class CodexStored:
    access_token: str
    account_id: str
    expires_at_unix_ms: int

    def expires_at_iso(self) -> str:
        t = time.gmtime(self.expires_at_unix_ms / 1000.0)
        ms = self.expires_at_unix_ms % 1000
        return time.strftime("%Y-%m-%dT%H:%M:%S", t) + f".{ms:03d}Z"

    def is_expired(self, now_ms: int) -> bool:
        return now_ms >= self.expires_at_unix_ms


def _jwt_exp_ms(token: str) -> int:
    """Return the JWT's `exp` claim as unix ms (0 on parse error)."""
    import base64

    parts = token.split(".")
    if len(parts) != 3:
        return 0
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return 0
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        return 0
    v = int(exp)
    if v < 1_000_000_000_000:  # epoch seconds → ms
        v *= 1000
    return v


def load_codex(path: str) -> CodexStored:
    """Read ~/.codex/auth.json (both new "tokens" and old flat shape)."""
    p = Path(path)
    if not p.is_file():
        raise CredsFileMissing(f"codex auth file missing: {path}")
    try:
        doc = json.loads(p.read_text())
    except Exception as e:
        raise CredsParse(f"codex auth parse error: {e}") from e

    tokens = doc.get("tokens") or {}
    access = tokens.get("access_token") or doc.get("access_token") or ""
    account = tokens.get("account_id") or doc.get("account_id") or ""
    if not access:
        raise CredsParse("missing access_token")
    if not account:
        raise CredsParse("missing account_id")

    # Prefer an explicit expires_at if the file carries one (older CLI
    # builds did); otherwise read the JWT's exp claim.
    exp_ms = 0
    raw_exp = doc.get("expires_at")
    if isinstance(raw_exp, str) and raw_exp:
        try:
            # Accept RFC3339 with or without microseconds.
            from datetime import datetime, timezone

            t = datetime.fromisoformat(raw_exp.replace("Z", "+00:00"))
            exp_ms = int(t.astimezone(timezone.utc).timestamp() * 1000)
        except Exception:
            exp_ms = 0
    elif isinstance(raw_exp, (int, float)):
        v = int(raw_exp)
        if v < 1_000_000_000_000:
            v *= 1000
        exp_ms = v
    if exp_ms == 0:
        exp_ms = _jwt_exp_ms(access)
    if exp_ms == 0:
        id_token = tokens.get("id_token") or doc.get("id_token") or ""
        exp_ms = _jwt_exp_ms(id_token)
    if exp_ms == 0:
        raise CredsParse("missing expires_at or JWT exp")
    return CodexStored(access_token=access, account_id=account, expires_at_unix_ms=exp_ms)
