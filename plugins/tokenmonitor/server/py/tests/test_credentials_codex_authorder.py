"""Codex credentials endpoint authenticates BEFORE checking enablement (bug 11).

An unsigned probe of /credentials/codex must return 401 whether or not codex
is enabled, so an unauthenticated caller cannot distinguish enabled (401) from
disabled (was 404) and thereby learn the provider's enablement. Matches the Go
reference (handleCodexCredentials: verify, then enabled).

Drives the handler directly with a mocked request (the full make_app router
isn't needed and doesn't build on this aiohttp version — same pattern as
test_updatecheck._sync_body).
"""

from __future__ import annotations

from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from tmon_mcp import auth
from tmon_mcp.config import Config
from tmon_mcp.state import State
from tmon_mcp.broker import server as broker_server


def _app(codex_enabled: bool) -> web.Application:
    cfg = Config()
    cfg.codex.enabled = codex_enabled
    cfg.psk_bytes = b"psk-32-bytes-of-secret-material!"
    app = web.Application()
    app["cfg"] = cfg
    app["cache"] = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    app["state"] = State()
    app["registry"] = None
    return app


async def _status_for(codex_enabled: bool) -> int:
    # No HMAC headers → the request is unsigned.
    req = make_mocked_request("GET", "/credentials/codex", app=_app(codex_enabled))
    resp = await broker_server._handle_credentials_codex(req)
    return resp.status


async def test_unsigned_codex_disabled_is_401_not_404():
    assert await _status_for(codex_enabled=False) == 401


async def test_unsigned_codex_enabled_is_also_401():
    # Same 401 whether enabled or disabled → no enablement leak.
    assert await _status_for(codex_enabled=True) == 401
