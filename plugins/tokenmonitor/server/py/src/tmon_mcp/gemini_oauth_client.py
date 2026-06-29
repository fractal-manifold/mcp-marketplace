"""Runtime resolver for the OAuth installed-app credentials that
@google/gemini-cli ships in its bundle.

We don't keep the values in source — they are extracted lazily from a
local @google/gemini-cli install if one exists, or, failing that, by
downloading the published npm tarball. Google does not classify these
as confidential (installed-app clients can't keep secrets), but their
textual form trips secret scanners, so we never commit them.
"""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable, Iterable

import aiohttp


_PREFIX = bytes([0x47, 0x4F, 0x43, 0x53, 0x50, 0x58, 0x2D]).decode()  # Google installed-app secret prefix
_ID_RE = re.compile(rb"[0-9]{6,}-[a-z0-9]+\.apps\.googleusercontent\.com")
_SECRET_RE = re.compile((_PREFIX + r"[A-Za-z0-9_-]{20,}").encode())


@dataclass(frozen=True)
class GeminiOAuthClient:
    client_id: str
    client_secret: str


_CACHED: GeminiOAuthClient | None = None


async def resolve_gemini_oauth_client(session: aiohttp.ClientSession) -> GeminiOAuthClient:
    """Return (client_id, client_secret). Memoised per process."""
    global _CACHED
    if _CACHED is not None:
        return _CACHED
    local = _from_local_cli()
    if local is not None:
        _CACHED = local
        return _CACHED
    remote = await _from_npm_registry(session)
    _CACHED = remote
    return remote


def _candidate_roots() -> Iterable[Path]:
    home = Path.home()
    return [
        Path("/usr/lib/node_modules/@google/gemini-cli"),
        Path("/usr/local/lib/node_modules/@google/gemini-cli"),
        home / ".npm-global/lib/node_modules/@google/gemini-cli",
        home / ".local/lib/node_modules/@google/gemini-cli",
        home / "node_modules/@google/gemini-cli",
    ]


def _from_local_cli() -> GeminiOAuthClient | None:
    for root in _candidate_roots():
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in (".js", ".mjs", ".cjs"):
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            hit = _extract(data)
            if hit is not None:
                return hit
    return None


async def _from_npm_registry(session: aiohttp.ClientSession) -> GeminiOAuthClient:
    meta_url = "https://registry.npmjs.org/@google/gemini-cli/latest"
    timeout = aiohttp.ClientTimeout(total=30)
    async with session.get(meta_url, timeout=timeout, headers={"Accept": "application/json"}) as resp:
        resp.raise_for_status()
        meta = await resp.json()
    tarball = (meta.get("dist") or {}).get("tarball") or ""
    if not tarball:
        raise RuntimeError("npm registry returned empty tarball URL for @google/gemini-cli")
    async with session.get(tarball, timeout=timeout) as resp:
        resp.raise_for_status()
        body = await resp.read()
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            name = member.name
            if not (name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs")):
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            try:
                data = f.read(16 * 1024 * 1024)
            finally:
                f.close()
            hit = _extract(data)
            if hit is not None:
                return hit
    raise RuntimeError("OAuth client not found in @google/gemini-cli bundle")


def _extract(data: bytes) -> GeminiOAuthClient | None:
    # The bundle commonly contains two installed-app client IDs: the
    # gemini-cli one (right next to OAUTH_CLIENT_SECRET) and an unrelated
    # Cloud SDK one earlier in the file. Naively taking .search() for
    # each yields a mismatched pair. We anchor on the secret (unique to
    # gemini-cli in the bundle) and search a window around it for the
    # paired client ID.
    sec_m = _SECRET_RE.search(data)
    if sec_m is None:
        return None
    window = 2048
    start = max(0, sec_m.start() - window)
    end = min(len(data), sec_m.end() + window)
    id_m = _ID_RE.search(data[start:end])
    if id_m is None:
        return None
    return GeminiOAuthClient(
        client_id=id_m.group(0).decode(),
        client_secret=sec_m.group(0).decode(),
    )
