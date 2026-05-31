"""Reader for ~/.claude/.credentials.json."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path


class CredsFileMissing(Exception):
    pass


class CredsParse(Exception):
    pass


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
    p = Path(path)
    if not p.is_file():
        raise CredsFileMissing(f"credentials file missing: {path}")
    try:
        doc = json.loads(p.read_text())
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
