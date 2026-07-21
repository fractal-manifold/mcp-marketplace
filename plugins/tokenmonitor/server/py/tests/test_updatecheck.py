"""Broker self-version check (go/py/js parity).

Covers the updatecheck module verdict logic (outdated / up-to-date / unknown)
and the wire surfaces that advertise it: the /device/<id>/sync body carries
broker_update_available / broker_version / broker_latest ONLY when the check is
known, and the tokenmonitor_status snapshot carries update_available /
latest_version. Omit-when-unknown must match the Go broker's omitempty fields.

The remote fetch is mocked two ways: (1) monkeypatching updatecheck.fetch_latest
for the pure verdict tests, and (2) pointing TMON_MARKETPLACE_URL at a
throwaway local HTTP server to exercise the real fetch + URL override path.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from tmon_mcp import auth, updatecheck
from tmon_mcp.broker import server as broker_server
from tmon_mcp.config import Config
from tmon_mcp.registry.store import ConfigPayload, Registry
from tmon_mcp.state import State, UpdateInfo


# ---------------------------------------------------------------------------
# module verdict logic
# ---------------------------------------------------------------------------


def test_check_marks_outdated_when_remote_newer(monkeypatch):
    monkeypatch.setattr(updatecheck, "fetch_latest", lambda: "0.9.5")
    info = updatecheck.check("0.9.4")
    assert info.known is True
    assert info.outdated is True
    assert info.current == "0.9.4"
    assert info.latest == "0.9.5"
    assert info.checked_at  # RFC3339 stamp present


def test_check_up_to_date_when_equal(monkeypatch):
    monkeypatch.setattr(updatecheck, "fetch_latest", lambda: "0.9.4")
    info = updatecheck.check("0.9.4")
    assert info.known is True
    assert info.outdated is False
    assert info.latest == "0.9.4"


def test_check_not_outdated_when_remote_older(monkeypatch):
    monkeypatch.setattr(updatecheck, "fetch_latest", lambda: "0.9.3")
    info = updatecheck.check("0.9.4")
    assert info.known is True
    assert info.outdated is False


def test_check_unknown_on_fetch_failure(monkeypatch):
    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(updatecheck, "fetch_latest", boom)
    info = updatecheck.check("0.9.4")
    assert info.known is False
    assert info.outdated is False
    assert info.current == "0.9.4"


def test_check_unknown_when_entry_absent(monkeypatch):
    monkeypatch.setattr(updatecheck, "fetch_latest", lambda: "")
    info = updatecheck.check("0.9.4")
    assert info.known is False


def test_check_unknown_when_unparseable(monkeypatch):
    monkeypatch.setattr(updatecheck, "fetch_latest", lambda: "not-a-version")
    info = updatecheck.check("0.9.4")
    assert info.known is False


# ---------------------------------------------------------------------------
# real fetch_latest against a local server (URL override)
# ---------------------------------------------------------------------------


class _CatalogHandler(BaseHTTPRequestHandler):
    payload = b"{}"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.__class__.payload)

    def log_message(self, *_a):  # silence
        pass


def _serve_catalog(doc: dict, monkeypatch):
    _CatalogHandler.payload = json.dumps(doc).encode()
    srv = HTTPServer(("127.0.0.1", 0), _CatalogHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address
    monkeypatch.setenv("TMON_MARKETPLACE_URL", f"http://{host}:{port}/marketplace.json")
    return srv


def test_marketplace_url_precedence(monkeypatch):
    # TMON_ is canonical and wins over the legacy alias; the alias alone works.
    monkeypatch.setenv("TMON_MARKETPLACE_URL", "https://canonical.example/c.json")
    monkeypatch.setenv("TOKENMONITOR_MARKETPLACE_URL", "https://legacy.example/c.json")
    assert updatecheck.marketplace_url() == "https://canonical.example/c.json"
    monkeypatch.delenv("TMON_MARKETPLACE_URL")
    assert updatecheck.marketplace_url() == "https://legacy.example/c.json"


def test_installed_version_root_precedence(monkeypatch, tmp_path):
    # TMON_PLUGIN_ROOT (launcher-exported) wins over host CLAUDE_PLUGIN_ROOT.
    def mk(root, version):
        d = tmp_path / root / ".claude-plugin"
        d.mkdir(parents=True)
        (d / "plugin.json").write_text(
            json.dumps({"name": "tokenmonitor", "version": version})
        )
        return str(tmp_path / root)

    tmon_root = mk("tmon", "1.2.3")
    claude_root = mk("claude", "4.5.6")
    monkeypatch.setenv("TMON_PLUGIN_ROOT", tmon_root)
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", claude_root)
    assert updatecheck.installed_version("0.0.0") == "1.2.3"
    monkeypatch.delenv("TMON_PLUGIN_ROOT")
    assert updatecheck.installed_version("0.0.0") == "4.5.6"
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT")
    assert updatecheck.installed_version("0.0.0") == "0.0.0"


def test_fetch_latest_reads_tokenmonitor_entry(monkeypatch):
    srv = _serve_catalog(
        {"plugins": [{"name": "other", "version": "1.0.0"},
                     {"name": "tokenmonitor", "version": "0.9.7"}]},
        monkeypatch,
    )
    try:
        assert updatecheck.fetch_latest() == "0.9.7"
    finally:
        srv.shutdown()


def test_fetch_latest_absent_entry_returns_empty(monkeypatch):
    srv = _serve_catalog({"plugins": [{"name": "other", "version": "1.0.0"}]}, monkeypatch)
    try:
        assert updatecheck.fetch_latest() == ""
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# status snapshot surfaces the verdict (omitted until known)
# ---------------------------------------------------------------------------


def test_snapshot_omits_update_until_known():
    st = State()
    d = st.snapshot().to_dict()
    assert "update_available" not in d
    assert "latest_version" not in d


def test_snapshot_carries_verdict_when_known():
    st = State()
    st.set_update(UpdateInfo(known=True, outdated=True, current="0.9.4", latest="0.9.5"))
    d = st.snapshot().to_dict()
    assert d["update_available"] is True
    assert d["latest_version"] == "0.9.5"


def test_snapshot_up_to_date_emits_false():
    st = State()
    st.set_update(UpdateInfo(known=True, outdated=False, current="0.9.4", latest="0.9.4"))
    d = st.snapshot().to_dict()
    assert d["update_available"] is False
    assert d["latest_version"] == "0.9.4"


# ---------------------------------------------------------------------------
# /device/<id>/sync body carries the fields when known
# ---------------------------------------------------------------------------


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


async def _sync_body(state, tmp_path):
    """Invoke the real _handle_device_sync handler with a signed request and
    return the decoded JSON body. Uses make_mocked_request so we exercise the
    handler's wire output without standing up the full aiohttp router."""
    cfg = Config()
    cfg.security.max_timestamp_skew_seconds = 10_000_000_000  # accept the fixed ts
    cache = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    reg = Registry(str(tmp_path / "devices"))
    device_id = "aabbccdd"
    psk_hex = "11" * 32
    reg.register(device_id, ConfigPayload(broker_url="http://localhost:8765", psk_hex=psk_hex))
    app = web.Application()
    app["cfg"] = cfg
    app["cache"] = cache
    app["state"] = state
    app["registry"] = reg
    path = f"/device/{device_id}/sync"
    headers = _sign_headers(bytes.fromhex(psk_hex), device_id, path)
    req = make_mocked_request("GET", path, headers=headers,
                              match_info={"device_id": device_id}, app=app)
    resp = await broker_server._handle_device_sync(req)
    assert resp.status == 200
    return json.loads(resp.body)


async def test_sync_includes_broker_fields_when_known(tmp_path):
    state = State()
    state.set_update(UpdateInfo(known=True, outdated=True, current="0.9.4", latest="0.9.5"))
    body = await _sync_body(state, tmp_path)
    assert body["broker_update_available"] is True
    assert body["broker_version"] == "0.9.4"
    assert body["broker_latest"] == "0.9.5"


async def test_sync_up_to_date_emits_false(tmp_path):
    state = State()
    state.set_update(UpdateInfo(known=True, outdated=False, current="0.9.4", latest="0.9.4"))
    body = await _sync_body(state, tmp_path)
    assert body["broker_update_available"] is False
    assert body["broker_version"] == "0.9.4"
    assert body["broker_latest"] == "0.9.4"


async def test_sync_omits_broker_fields_when_unknown(tmp_path):
    state = State()  # no update recorded -> unknown
    body = await _sync_body(state, tmp_path)
    assert "broker_update_available" not in body
    assert "broker_version" not in body
    assert "broker_latest" not in body
