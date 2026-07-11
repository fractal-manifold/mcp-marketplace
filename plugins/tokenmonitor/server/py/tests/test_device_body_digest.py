"""Endpoint coverage for the HMAC v3 body digest (compat/HMAC_CANONICAL.md):
/device/{id}/settings and /logs must accept a correctly-digested body, reject
a tampered or malformed digest with 401, keep accepting legacy v2 (no header)
requests, and keep the oversize behavior intact. Mirrors the Go
device_body_digest_test.go contract."""

from __future__ import annotations

import asyncio
import hashlib
import time
from pathlib import Path
from unittest import mock

from aiohttp import streams
from aiohttp.test_utils import make_mocked_request

from tmon_mcp import auth
from tmon_mcp.config import Config
from tmon_mcp.state import State
from tmon_mcp.broker import server as broker_server
from tmon_mcp.registry.store import ConfigPayload, Registry

DEVICE_ID = "ab12cd34"
PSK_HEX = "aa" * 32
PSK = bytes.fromhex(PSK_HEX)


def _app(tmp_path: Path):
    cfg = Config()
    cfg.psk_bytes = b"psk-32-bytes-of-secret-material!"
    reg = Registry(str(tmp_path / "devices"))
    reg.register(DEVICE_ID, ConfigPayload(broker_url="http://x", psk_hex=PSK_HEX))
    from aiohttp import web

    app = web.Application()
    app["cfg"] = cfg
    app["cache"] = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    app["state"] = State()
    app["registry"] = reg
    return app, reg


_nonce_counter = 0


def _next_nonce() -> str:
    global _nonce_counter
    _nonce_counter += 1
    return f"{_nonce_counter:032x}"


def _signed_post(app, endpoint: str, body: bytes, *, digest: str | None = "auto"):
    """digest='auto' → correct v3 signing; None → legacy v2 (no header);
    any other string → sent verbatim as X-Tmon-Body-Sha256 and signed v3."""
    path = f"/device/{DEVICE_ID}/{endpoint}"
    ts = str(int(time.time()))
    nonce = _next_nonce()
    headers = {
        "X-Tmon-Timestamp": ts,
        "X-Tmon-Nonce": nonce,
        "X-Tmon-Device": DEVICE_ID,
        "X-Tmon-Config-Version": "1",
        "Content-Length": str(len(body)),
    }
    if digest is None:
        headers["X-Tmon-Signature"] = auth.compute_signature(
            PSK, "POST", path, ts, nonce, DEVICE_ID, "1",
        )
    else:
        d = hashlib.sha256(body).hexdigest() if digest == "auto" else digest
        headers["X-Tmon-Body-Sha256"] = d
        headers["X-Tmon-Signature"] = auth.compute_signature_body(
            PSK, "POST", path, ts, nonce, DEVICE_ID, "1", d,
        )

    payload = streams.StreamReader(
        mock.Mock(_reading_paused=False), limit=2**20,
        loop=asyncio.get_event_loop(),
    )
    payload.feed_data(body)
    payload.feed_eof()
    return make_mocked_request(
        "POST", path, headers=headers, payload=payload, app=app,
        match_info={"device_id": DEVICE_ID},
    )


async def test_settings_v3_digest_accepts_and_persists(tmp_path):
    app, reg = _app(tmp_path)
    req = _signed_post(app, "settings", b'{"vol":25}')
    resp = await broker_server._handle_device_settings(req)
    assert resp.status == 204
    dev = reg.load(DEVICE_ID)
    assert dev.active.payload.vol == 25


async def test_settings_tampered_body_rejected_401(tmp_path):
    app, reg = _app(tmp_path)
    # Digest of {"vol":25}, but the wire body says vol:99 — on-path tamper.
    good = hashlib.sha256(b'{"vol":25}').hexdigest()
    req = _signed_post(app, "settings", b'{"vol":99}', digest=good)
    resp = await broker_server._handle_device_settings(req)
    assert resp.status == 401
    assert reg.load(DEVICE_ID).active.payload.vol is None


async def test_settings_malformed_digest_rejected_401(tmp_path):
    app, _ = _app(tmp_path)
    for bad in ("A" * 64, "a" * 63, "g" * 64):
        req = _signed_post(app, "settings", b'{"vol":25}', digest=bad)
        resp = await broker_server._handle_device_settings(req)
        assert resp.status == 401, f"digest {bad!r}"


async def test_settings_no_header_legacy_v2_accepted(tmp_path):
    app, reg = _app(tmp_path)
    req = _signed_post(app, "settings", b'{"vol":30}', digest=None)
    resp = await broker_server._handle_device_settings(req)
    assert resp.status == 204
    assert reg.load(DEVICE_ID).active.payload.vol == 30


async def test_logs_v3_digest_accepted(tmp_path):
    app, _ = _app(tmp_path)
    req = _signed_post(app, "logs", b"I (123) tmon: boot\n")
    resp = await broker_server._handle_device_logs(req)
    assert resp.status == 202


async def test_logs_oversize_body_still_413(tmp_path):
    from tmon_mcp import devlog

    app, _ = _app(tmp_path)
    big = b"x" * (devlog.MAX_BODY_BYTES + 1)
    req = _signed_post(app, "logs", big)
    resp = await broker_server._handle_device_logs(req)
    assert resp.status == 413
