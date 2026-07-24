"""Regression guard for the 3->2 re-configure provider bug (parity with the
Go internal/mcp/provision_providers_test.go).

When a provision names ANY provider, the broker must forward the WHOLE triple
so an unchecked provider reaches the device as an explicit ``false``. Forwarding
only the named providers left the device's NVS for the omitted provider
untouched (the firmware only overwrites keys present in the payload), so a
device dropped from 3 to 2 providers kept the third enabled.
"""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from tmon_mcp.mcp.server import Deps, _provision


def _capture(args: dict) -> dict:
    """Run _provision against a throwaway /provision endpoint and return the
    JSON body the broker POSTed to the device."""
    captured: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length", 0))
            captured.update(json.loads(self.rfile.read(n) or b"{}"))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true,"next":"rebooting"}')

        def log_message(self, *a):  # silence
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    port = srv.server_address[1]

    full = {
        "device_id": "ab12cd34",
        "provision_url": f"http://127.0.0.1:{port}/provision",
        "pairing_code": "071718",
        # Explicit psk_hex keeps _provision off the registry-reuse path so a
        # None registry is fine — we only care about the wire body here.
        "broker_url": "http://10.0.0.5:8787",
        "psk_hex": "0" * 64,
    }
    full.update(args)

    deps = Deps(cfg=None, state=None, logs=None, registry=None, version="test")
    asyncio.run(_provision(deps, full))
    srv.server_close()
    return captured


def test_provision_drops_unchecked_provider():
    body = _capture({"provider_claude": True, "provider_codex": True})
    # provider_antigravity omitted (user unchecked it) -> must arrive as false.
    assert body.get("providers") == {"claude": True, "codex": True, "gemini": False}


def test_provision_antigravity_alias_and_absent():
    body = _capture({"provider_gemini": True})  # legacy alias
    assert body.get("providers") == {"claude": False, "codex": False, "gemini": True}


def test_provision_antigravity_wins_over_gemini_alias():
    # Both the new arg and the deprecated alias present: provider_antigravity
    # wins, provider_gemini is ignored. All three runtimes must agree.
    body = _capture({"provider_antigravity": False, "provider_gemini": True})
    assert body.get("providers") == {"claude": False, "codex": False, "gemini": False}


def test_provision_no_provider_keys_omits_field():
    body = _capture({"city": "Madrid"})
    assert "providers" not in body
