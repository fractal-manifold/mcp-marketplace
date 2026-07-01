"""Broker HTTP status parity with the Go reference (bug 21).

  - a matched path with the wrong method → 405 "method not allowed";
  - unknown path → 404;
  - a generic (non-unavailable, non-notimpl) spend error → 500 "internal";
  - 502 usage-error bodies are fixed strings (transport error / upstream error),
    never the upstream detail.
"""

from __future__ import annotations

import json

from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from tmon_mcp import auth, spend, usage
from tmon_mcp.broker import server as broker_server
from tmon_mcp.config import Config
from tmon_mcp.registry.store import ConfigPayload, Registry
from tmon_mcp.state import State


def _sign_headers(psk: bytes, device_id: str, path: str, config_version: str = "1"):
    ts = "1700000000"
    nonce = "0123456789abcdef0123456789abcdef"
    sig = auth.compute_signature(psk, "GET", path, ts, nonce, device_id, config_version)
    return {
        "X-Tmon-Timestamp": ts,
        "X-Tmon-Nonce": nonce,
        "X-Tmon-Signature": sig,
        "X-Tmon-Device": device_id,
        "X-Tmon-Config-Version": config_version,
    }


# --- 405 / 404 catch-all ---------------------------------------------------


async def test_wrong_method_on_known_path_is_405():
    req = make_mocked_request("POST", "/usage/claude")  # GET-only route
    resp = await broker_server._not_found_or_405(req)
    assert resp.status == 405
    assert json.loads(resp.body)["error"] == "method not allowed"


async def test_unknown_path_is_404():
    req = make_mocked_request("GET", "/nope")
    resp = await broker_server._not_found_or_405(req)
    assert resp.status == 404


# --- 502 fixed bodies ------------------------------------------------------


def test_502_bodies_are_fixed_strings():
    status, resp = broker_server._map_usage_error(usage.Transport("secret detail 123"))
    assert status == 502
    assert json.loads(resp.body)["error"] == "transport error"

    status, resp = broker_server._map_usage_error(usage.Upstream("secret detail 456"))
    assert status == 502
    assert json.loads(resp.body)["error"] == "upstream error"

    # An unknown UsageError subclass maps to 500 internal (Go default).
    class _Weird(usage.UsageError):
        pass

    status, resp = broker_server._map_usage_error(_Weird("x"))
    assert status == 500
    assert json.loads(resp.body)["error"] == "internal error"


# --- generic spend error → 500 --------------------------------------------


class _GenericSpendCache:
    async def get(self, provider):  # noqa: ANN001
        raise spend.SpendError("boom")  # base class: not Unavailable/NotImpl


async def test_generic_spend_error_is_500(tmp_path):
    cfg = Config()
    cfg.security.max_timestamp_skew_seconds = 10_000_000_000
    cache = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    reg = Registry(str(tmp_path / "devices"))
    device_id = "aabbccdd"
    psk_hex = "11" * 32
    reg.register(device_id, ConfigPayload(broker_url="http://localhost:8765", psk_hex=psk_hex))

    app = web.Application()
    app["cfg"] = cfg
    app["cache"] = cache
    app["state"] = State()
    app["registry"] = reg
    app["spend_cache"] = _GenericSpendCache()

    path = "/spend/claude"
    headers = _sign_headers(bytes.fromhex(psk_hex), device_id, path)
    req = make_mocked_request("GET", path, headers=headers, match_info={"provider": "claude"}, app=app)
    resp = await broker_server._handle_spend(req)
    assert resp.status == 500
    assert json.loads(resp.body)["error"] == "internal"
