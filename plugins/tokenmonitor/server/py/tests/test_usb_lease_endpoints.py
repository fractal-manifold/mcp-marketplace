"""Broker serial-lease endpoint contract (mirrors Go serial_lease_test.go):
grant → 409 on second → renew → release → 410-on-renew-after-release;
missing body digest → 401; non-loopback peer → 403; no lease manager → 503;
tampered digest → 401."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time

from aiohttp import streams
from aiohttp.test_utils import make_mocked_request
from unittest import mock

from tmon_mcp import auth, usbprov
from tmon_mcp.broker import server as broker_server
from tmon_mcp.config import Config
from tmon_mcp.state import State
from tmon_mcp.usbprov.leasewire import LEASE_PATH, LEASE_RELEASE_PATH, LEASE_RENEW_PATH

PSK = b"psk-32-bytes-of-secret-material!"


class _FakeTransport:
    def __init__(self, peer):
        self._peer = peer

    def get_extra_info(self, name, default=None):
        if name == "peername":
            return self._peer
        return default


def _app(*, with_lease: bool = True) -> object:
    from aiohttp import web

    cfg = Config()
    cfg.psk_bytes = PSK
    app = web.Application()
    app["cfg"] = cfg
    app["cache"] = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    app["state"] = State()
    lease = usbprov.LeaseManager(usbprov.NopController(), 10.0) if with_lease else None
    app["lease"] = lease
    return app, lease


_nonce_counter = 0


def _next_nonce() -> str:
    global _nonce_counter
    _nonce_counter += 1
    return f"{_nonce_counter:032x}"


def _req(app, path: str, body: bytes, *, peer=("127.0.0.1", 5000), digest="auto", method="POST"):
    ts = str(int(time.time()))
    nonce = _next_nonce()
    headers = {
        "X-Tmon-Timestamp": ts,
        "X-Tmon-Nonce": nonce,
        "Content-Length": str(len(body)),
        "Content-Type": "application/json",
    }
    if digest is not None:
        d = hashlib.sha256(body).hexdigest() if digest == "auto" else digest
        headers["X-Tmon-Body-Sha256"] = d
        headers["X-Tmon-Signature"] = auth.compute_signature_body(
            PSK, "POST", path, ts, nonce, "", "", d
        )
    else:
        # legacy v2 (no body digest) — must be rejected by the lease endpoints
        headers["X-Tmon-Signature"] = auth.compute_signature(PSK, "POST", path, ts, nonce, "", "")

    payload = streams.StreamReader(
        mock.Mock(_reading_paused=False), limit=2**20, loop=asyncio.get_event_loop()
    )
    payload.feed_data(body)
    payload.feed_eof()
    return make_mocked_request(
        method, path, headers=headers, payload=payload, app=app, transport=_FakeTransport(peer)
    )


async def _grant(app, port="/dev/null"):
    body = json.dumps({"port": port, "ttl_ms": 5000}).encode()
    return await broker_server._handle_serial_lease(_req(app, LEASE_PATH, body))


async def test_grant_conflict_renew_release_gone_cycle():
    app, _ = _app()
    # /dev/null canonicalises fine and NopController never suspends anything.
    resp = await _grant(app)
    assert resp.status == 200
    data = json.loads(resp.text)
    lease_id = data["lease_id"]
    # Field names are the cross-runtime contract (PROVISION_WIRE §6): ttl_ms
    # (not granted_ms), plus the canonical port echoed back.
    assert data["ttl_ms"] == 5000 and len(lease_id) == 32
    assert data["port"] == os.path.realpath("/dev/null")
    assert isinstance(data["expires_unix_ms"], int)

    # Second grant on the same canonical port → 409 with the §6 body shape.
    resp2 = await _grant(app)
    assert resp2.status == 409
    assert json.loads(resp2.text) == {"error": "busy", "holder": "lease"}

    # Renew the live lease → 200. The body carries ONLY the id; the leader
    # re-applies the TTL it granted, so the response echoes that 5000.
    rbody = json.dumps({"lease_id": lease_id}).encode()
    r = await broker_server._handle_serial_lease(_req(app, LEASE_RENEW_PATH, rbody))
    assert r.status == 200
    rdata = json.loads(r.text)
    assert rdata["ttl_ms"] == 5000 and isinstance(rdata["expires_unix_ms"], int)

    # Release → 200 (idempotent).
    relbody = json.dumps({"lease_id": lease_id}).encode()
    rel = await broker_server._handle_serial_lease(_req(app, LEASE_RELEASE_PATH, relbody))
    assert rel.status == 200
    rel2 = await broker_server._handle_serial_lease(_req(app, LEASE_RELEASE_PATH, relbody))
    assert rel2.status == 200

    # Renew after release → 410 Gone.
    r2 = await broker_server._handle_serial_lease(_req(app, LEASE_RENEW_PATH, rbody))
    assert r2.status == 410

    # And the port is grantable again after release.
    resp3 = await _grant(app)
    assert resp3.status == 200


async def test_missing_body_digest_401():
    app, _ = _app()
    body = json.dumps({"port": "/dev/null", "ttl_ms": 5000}).encode()
    resp = await broker_server._handle_serial_lease(_req(app, LEASE_PATH, body, digest=None))
    assert resp.status == 401


async def test_tampered_body_digest_401():
    app, _ = _app()
    good = hashlib.sha256(json.dumps({"port": "/dev/null", "ttl_ms": 5000}).encode()).hexdigest()
    # Wire body differs from the digested body → 401.
    other = json.dumps({"port": "/dev/zero", "ttl_ms": 5000}).encode()
    resp = await broker_server._handle_serial_lease(_req(app, LEASE_PATH, other, digest=good))
    assert resp.status == 401


async def test_non_loopback_peer_403():
    app, _ = _app()
    body = json.dumps({"port": "/dev/null", "ttl_ms": 5000}).encode()
    resp = await broker_server._handle_serial_lease(
        _req(app, LEASE_PATH, body, peer=("10.0.0.5", 5000))
    )
    assert resp.status == 403


async def test_no_lease_manager_503():
    app, _ = _app(with_lease=False)
    body = json.dumps({"port": "/dev/null", "ttl_ms": 5000}).encode()
    resp = await broker_server._handle_serial_lease(_req(app, LEASE_PATH, body))
    assert resp.status == 503


async def test_503_before_403_when_no_manager():
    # nil-manager takes priority over the loopback check (Go orders it first).
    app, _ = _app(with_lease=False)
    body = json.dumps({"port": "/dev/null", "ttl_ms": 5000}).encode()
    resp = await broker_server._handle_serial_lease(
        _req(app, LEASE_PATH, body, peer=("10.0.0.5", 5000))
    )
    assert resp.status == 503


async def test_ttl_ms_outside_int64_is_400():
    """Go unmarshals ttl_ms into an int64, so a value it answers 400 for must not
    quietly clamp to the max here — the same request has to get the same answer
    whichever runtime happens to be leader."""
    app, _ = _app()
    body = json.dumps({"port": "/dev/null", "ttl_ms": 2**63}).encode()
    resp = await broker_server._handle_serial_lease(_req(app, LEASE_PATH, body))
    assert resp.status == 400
