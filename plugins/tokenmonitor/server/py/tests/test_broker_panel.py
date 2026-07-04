"""GET /device/{id}/panel — serve a user-authored panel document verbatim.

Mirrors the Go internal/broker/panel_test.go contract: 200 + exact bytes for a
configured file, 404 when unconfigured / unknown device, 422 oversize / non-JSON,
401 bad signature, and per-device <dir>/<id>.json precedence. Drives the handler
directly with make_mocked_request (same pattern as
test_credentials_codex_authorder).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from aiohttp.test_utils import make_mocked_request

from tmon_mcp import auth
from tmon_mcp.config import Config
from tmon_mcp.state import State
from tmon_mcp.broker import server as broker_server
from tmon_mcp.registry.store import ConfigPayload, Registry

DEVICE_ID = "ab12cd34"
PSK_HEX = "aa" * 32
PSK = bytes.fromhex(PSK_HEX)


def _app(tmp_path: Path, *, file: str = "", dir: str = "", with_device: bool = True):
    cfg = Config()
    cfg.panel.file = file
    cfg.panel.dir = dir
    cfg.psk_bytes = b"psk-32-bytes-of-secret-material!"
    reg = Registry(str(tmp_path / "devices"))
    if with_device:
        reg.register(DEVICE_ID, ConfigPayload(broker_url="http://x", psk_hex=PSK_HEX))
    from aiohttp import web

    app = web.Application()
    app["cfg"] = cfg
    app["cache"] = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    app["state"] = State()
    app["registry"] = reg
    return app


def _signed_request(app, *, tamper: bool = False):
    path = f"/device/{DEVICE_ID}/panel"
    ts = str(int(time.time()))
    nonce = "0" * 32
    sig = auth.compute_signature(PSK, "GET", path, ts, nonce, DEVICE_ID, "1")
    if tamper:
        sig = "0" * len(sig)
    headers = {
        "X-Tmon-Timestamp": ts,
        "X-Tmon-Nonce": nonce,
        "X-Tmon-Signature": sig,
        "X-Tmon-Device": DEVICE_ID,
        "X-Tmon-Config-Version": "1",
    }
    return make_mocked_request(
        "GET", path, headers=headers, app=app, match_info={"device_id": DEVICE_ID}
    )


async def _run(app, *, tamper: bool = False):
    req = _signed_request(app, tamper=tamper)
    return await broker_server._handle_device_panel(req)


async def test_configured_file_serves_verbatim(tmp_path):
    body = '{"version":1,"tiles":[{"type":"text","text":"hi"}]}'
    f = tmp_path / "panel.json"
    f.write_text(body)
    resp = await _run(_app(tmp_path, file=str(f)))
    assert resp.status == 200
    assert resp.body == body.encode()
    assert resp.headers["Cache-Control"] == "no-store"


async def test_not_configured_404(tmp_path):
    resp = await _run(_app(tmp_path))
    assert resp.status == 404


async def test_unknown_device_404(tmp_path):
    f = tmp_path / "panel.json"
    f.write_text('{"version":1}')
    resp = await _run(_app(tmp_path, file=str(f), with_device=False))
    assert resp.status == 404


async def test_oversize_422(tmp_path):
    f = tmp_path / "panel.json"
    f.write_text('{"x":"' + "a" * (8 * 1024) + '"}')
    resp = await _run(_app(tmp_path, file=str(f)))
    assert resp.status == 422


async def test_bad_json_422(tmp_path):
    f = tmp_path / "panel.json"
    f.write_text("not json at all")
    resp = await _run(_app(tmp_path, file=str(f)))
    assert resp.status == 422


async def test_bad_signature_401(tmp_path):
    f = tmp_path / "panel.json"
    f.write_text('{"version":1}')
    resp = await _run(_app(tmp_path, file=str(f)), tamper=True)
    assert resp.status == 401


async def test_per_device_dir_wins(tmp_path):
    d = tmp_path / "panels"
    d.mkdir()
    (d / "global.json").write_text('{"src":"global"}')
    (d / "default.json").write_text('{"src":"default"}')
    per = '{"src":"perdevice"}'
    (d / f"{DEVICE_ID}.json").write_text(per)
    resp = await _run(_app(tmp_path, file=str(d / "global.json"), dir=str(d)))
    assert resp.status == 200
    assert resp.body == per.encode()


async def test_explicit_per_device_file_wins(tmp_path):
    # An explicit [panel.file].<id> entry beats both the dir convention and the
    # default file.
    d = tmp_path / "panels"
    d.mkdir()
    (d / "def.json").write_text('{"src":"default"}')
    (d / f"{DEVICE_ID}.json").write_text('{"src":"dir"}')
    explicit = tmp_path / "explicit.json"
    want = '{"src":"explicit"}'
    explicit.write_text(want)
    app = _app(tmp_path, dir=str(d))
    app["cfg"].panel.file = {"default": str(d / "def.json"), DEVICE_ID: str(explicit)}
    resp = await _run(app)
    assert resp.status == 200
    assert resp.body == want.encode()


def _compat_golden(name: str) -> str | None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "compat" / "panel" / "golden" / name
        if cand.is_file():
            return str(cand)
    return None


async def test_serves_compat_golden(tmp_path):
    golden = _compat_golden("session_line.json")
    if golden is None:
        pytest.skip("compat/panel/golden not found (standalone checkout)")
    want = Path(golden).read_bytes()
    resp = await _run(_app(tmp_path, file=golden))
    assert resp.status == 200
    assert resp.body == want
