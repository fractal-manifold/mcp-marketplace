"""End-to-end coverage for X-Tmon-Resp-Signature (compat/HMAC_CANONICAL.md).

The tag is what a device uses to decide that an address it found by mDNS is
really its broker. Two things have to hold, and neither is visible from the
auth-module vector tests:

  * the header actually reaches the wire, computed over the bytes and status
    the client received — the middleware has to see the finished response, not
    the handler's intent;
  * it is absent on anything that did not authenticate as this device, because
    a tag emitted before auth would let an unauthenticated caller use the
    broker as a signing oracle.

Mirrors the Go resp_sig_test.go contract.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

from tmon_mcp import auth, spend, usage
from tmon_mcp.broker import server as broker_server
from tmon_mcp.config import Config
from tmon_mcp.registry.store import ConfigPayload, Registry
from tmon_mcp.state import State

DEVICE_ID = "ab12cd34"
PSK_HEX = "aa" * 32
PSK = bytes.fromhex(PSK_HEX)

_nonce_counter = 0


def _next_nonce() -> str:
    global _nonce_counter
    _nonce_counter += 1
    return f"{_nonce_counter:032x}"


def _make_app(tmp_path: Path):
    cfg = Config()
    cfg.psk_bytes = b"psk-32-bytes-of-secret-material!"
    reg = Registry(str(tmp_path / "devices"))
    reg.register(DEVICE_ID, ConfigPayload(broker_url="http://x", psk_hex=PSK_HEX))
    cache = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    app = broker_server.make_app(cfg, cache, State(), None, reg,
                                 usage.Cache(30, {}), spend.Cache(300, {}))
    return app, reg


def _authority(client: TestClient) -> str:
    """What the device would compute for HOST: the address it dialled.

    The broker derives the same string from its own end of the socket, so the
    two agree only when nothing is relaying in between.
    """
    return f"127.0.0.1:{client.server.port}"


def _sync_headers(nonce: str, *, psk: bytes = PSK) -> dict[str, str]:
    path = f"/device/{DEVICE_ID}/sync"
    ts = str(int(time.time()))
    return {
        "X-Tmon-Timestamp": ts,
        "X-Tmon-Nonce": nonce,
        "X-Tmon-Device": DEVICE_ID,
        "X-Tmon-Config-Version": "1",
        "X-Tmon-Signature": auth.compute_signature(
            psk, "GET", path, ts, nonce, DEVICE_ID, "1",
        ),
    }


async def test_sync_response_carries_a_tag_the_device_psk_verifies(tmp_path: Path):
    app, _ = _make_app(tmp_path)
    async with TestClient(TestServer(app)) as client:
        nonce = _next_nonce()
        resp = await client.get(f"/device/{DEVICE_ID}/sync", headers=_sync_headers(nonce))
        body = await resp.read()
        sig = resp.headers.get(auth.RESPONSE_SIG_HEADER)
        assert sig, "authenticated response carried no pairing proof"
        want = auth.compute_response_signature(
            PSK, DEVICE_ID, nonce, _authority(client), f"/device/{DEVICE_ID}/sync",
            resp.status, hashlib.sha256(body).hexdigest(),
        )
        assert sig == want

        # Bound to the address that answered. This is the anti-relay property:
        # an impostor on the LAN can forward our request to the real broker and
        # hand back this very tag, and the only thing that stops the device
        # adopting the relay is that the tag names the broker's address.
        relayed = auth.compute_response_signature(
            PSK, DEVICE_ID, nonce, "192.168.1.99:8765", f"/device/{DEVICE_ID}/sync",
            resp.status, hashlib.sha256(body).hexdigest(),
        )
        assert sig != relayed


async def test_tag_is_bound_to_this_requests_nonce(tmp_path: Path):
    """The binding that makes it a challenge-response: the same broker, same
    path, same body, but a different nonce must produce a different tag —
    otherwise an impostor could record one answer and replay it forever."""
    app, _ = _make_app(tmp_path)
    async with TestClient(TestServer(app)) as client:
        sigs = []
        for _ in range(2):
            nonce = _next_nonce()
            resp = await client.get(f"/device/{DEVICE_ID}/sync",
                                    headers=_sync_headers(nonce))
            await resp.read()
            sigs.append(resp.headers.get(auth.RESPONSE_SIG_HEADER))
        assert all(sigs)
        assert sigs[0] != sigs[1]


async def test_no_tag_on_an_unauthorized_response(tmp_path: Path):
    """A 401 must not be signed. We hold no proof that the caller is the paired
    device, and signing anything it chose the nonce for would turn the broker
    into an oracle for the PSK it just failed to demonstrate."""
    app, _ = _make_app(tmp_path)
    async with TestClient(TestServer(app)) as client:
        nonce = _next_nonce()
        headers = _sync_headers(nonce, psk=b"\x00" * 32)   # wrong key
        resp = await client.get(f"/device/{DEVICE_ID}/sync", headers=headers)
        await resp.read()
        assert resp.status == 401
        assert auth.RESPONSE_SIG_HEADER not in resp.headers


async def test_a_wrong_psk_does_not_verify(tmp_path: Path):
    """The impostor case, from the device's side: something on the LAN that
    answers but does not hold our PSK produces a tag we must reject."""
    app, _ = _make_app(tmp_path)
    async with TestClient(TestServer(app)) as client:
        nonce = _next_nonce()
        resp = await client.get(f"/device/{DEVICE_ID}/sync", headers=_sync_headers(nonce))
        body = await resp.read()
        sig = resp.headers[auth.RESPONSE_SIG_HEADER]
        impostor = auth.compute_response_signature(
            b"\x11" * 32, DEVICE_ID, nonce, _authority(client), f"/device/{DEVICE_ID}/sync",
            resp.status, hashlib.sha256(body).hexdigest(),
        )
        assert sig != impostor


def test_pending_payload_broker_url_is_a_legacy_repoint(tmp_path: Path):
    """broker_url travels in a pending under two conditions at once: an
    operator staged it (it differs from the active record's address — the
    registry's own value is never echoed), and the device asking reports
    firmware older than 1.0.1, the release where the address stopped being
    configuration. Mirror of Go TestPendingPayloadJSON_BrokerURLIsALegacyRepoint."""
    import json

    staged, recorded = "http://192.168.1.50:8765", "http://192.168.1.28:8765"
    cases = [
        ("legacy 0.12.0", staged, recorded, "0.12.0", True),
        ("legacy 1.0.0", staged, recorded, "1.0.0", True),
        ("legacy dev build", staged, recorded, "1.0.0-dev.202609011200", True),
        ("legacy, registry had no address", staged, "", "0.10.3", True),
        ("1.0.1", staged, recorded, "1.0.1", False),
        ("1.0.1 dev build", staged, recorded, "1.0.1-dev.202609181200", False),
        ("2.0.0", staged, recorded, "2.0.0", False),
        ("no version reported", staged, recorded, "", False),
        ("unparseable version", staged, recorded, "dev", False),
        ("legacy, but only the registry's own address", recorded, recorded, "0.12.0", False),
        ("legacy, nothing staged", "", recorded, "0.12.0", False),
    ]
    for name, pending_url, active_url, fw, want in cases:
        wire = json.loads(
            broker_server._pending_payload_json(
                ConfigPayload(version=9, broker_url=pending_url, city="Barcelona"), active_url, fw
            )
        )
        assert ("broker_url" in wire) is want, name
        if want:
            assert wire["broker_url"] == staged, name
        assert wire["city"] == "Barcelona", name
