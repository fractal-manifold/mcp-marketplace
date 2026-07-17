"""make_app builds and HEAD /firmware/{name} resolves (aiohttp regression).

The firmware route registered both add_get and an explicit add_head for the
same path. On modern aiohttp add_get already registers HEAD (allow_head=True),
so the explicit add_head double-registered HEAD and make_app raised
"Added route will never be executed, method HEAD is already registered" at
startup — leaving the whole py runtime unable to boot. This guards that
make_app builds and HEAD still routes to the firmware handler.
"""

from __future__ import annotations

from aiohttp.test_utils import make_mocked_request

from tmon_mcp import auth, usage, spend
from tmon_mcp.config import Config
from tmon_mcp.state import State
from tmon_mcp.broker import server as broker_server


def _app():
    cfg = Config()
    cache = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    return broker_server.make_app(cfg, cache, State(), None, None,
                                  usage.Cache(30, {}), spend.Cache(300, {}))


def test_make_app_builds():
    # The bug made this raise at construction time.
    app = _app()
    assert app is not None


async def test_head_firmware_routes_to_handler():
    app = _app()
    for method in ("GET", "HEAD"):
        req = make_mocked_request(method, "/firmware/tokenmonitor-0.10.0.bin", app=app)
        match = await app.router.resolve(req)
        assert match.http_exception is None
        assert match.handler is broker_server._handle_firmware, (
            f"{method} /firmware/ should route to _handle_firmware, "
            f"got {match.handler}"
        )
