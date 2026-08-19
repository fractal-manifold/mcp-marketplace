"""Size coverage for /device/{id}/settings (compat/SETTINGS_REPORT.md).

This cap had NO test in any of the three runtimes, and the value it carried —
512 bytes — was under the size of a perfectly ordinary report. A device that
remembered ~7 networks had every report rejected, and because the firmware's
dirty flag only clears on a 2xx, the rejection permanently vetoed every
broker-pushed display setting. test_full_report_with_eight_networks is the
regression that would have caught it. Mirrors the Go
device_settings_size_test.go contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tmon_mcp.broker import server as broker_server

from test_device_body_digest import DEVICE_ID, _app, _signed_post


def _full_report_body(n: int, ssid_len: int) -> bytes:
    """A settings report shaped exactly like the firmware's (config_sync.c:
    the flat device-owned fields plus wifi_known), with n remembered networks
    whose SSIDs are ssid_len characters long."""
    nets = [
        {
            "ssid": f"{i:02d}" + "w" * (ssid_len - 2),
            "verified": i % 2 == 0,
            "open": i % 3 == 0,
        }
        for i in range(n)
    ]
    return json.dumps(
        {
            "theme_mode": "night",
            "br_day": 100,
            "br_night": 30,
            "vol": 80,
            "autorotate_enabled": True,
            "autorotate_interval_s": 30,
            "pet_enabled": True,
            "panel_enabled": True,
            "pet_species": 2,
            "pet_name": "Mochi",
            "wifi_known": nets,
        },
        separators=(",", ":"),
    ).encode()


async def test_full_report_with_eight_networks(tmp_path: Path):
    """Eight networks is what the store holds (TMON_WIFI_MAX_NETS) and 32
    characters is the longest SSID 802.11 allows, so this is the largest report
    real firmware can produce from real inputs — it must be accepted, and the
    fields in it must actually land in the registry."""
    app, reg = _app(tmp_path)
    body = _full_report_body(8, 32)
    assert len(body) > 512, "test body no longer exercises the old cap"
    req = _signed_post(app, "settings", body)
    resp = await broker_server._handle_device_settings(req)
    assert resp.status == 204, f"body {len(body)} bytes rejected"
    dev = reg.load(DEVICE_ID)
    assert dev.active.payload.vol == 80
    assert len(dev.active.wifi_known or []) == 8


async def test_at_cap_accepted(tmp_path: Path):
    """A body sitting exactly on the cap is inside it, not over it — and must
    be APPLIED, not merely "not 413". Asserting 204 is what makes this test
    fail against the old 512-byte broker, which answered 400 here."""
    app, reg = _app(tmp_path)
    cap = broker_server._MAX_SETTINGS_BODY_BYTES
    # pet_name is length-clamped downstream, not rejected, so an at-cap body
    # built this way is a perfectly valid report.
    prefix, suffix = b'{"vol":42,"pet_name":"', b'"}'
    body = prefix + b"p" * (cap - len(prefix) - len(suffix)) + suffix
    assert len(body) == cap
    req = _signed_post(app, "settings", body)
    resp = await broker_server._handle_device_settings(req)
    assert resp.status == 204
    assert reg.load(DEVICE_ID).active.payload.vol == 42


async def test_over_cap_rejected_413(tmp_path: Path):
    """One byte over is 413 — a distinct answer from 400, because the device
    downgrades its own wifi_known budget on 413 and retries, whereas 400 means
    the bytes were unreadable and a shorter list would not help."""
    app, reg = _app(tmp_path)
    # EXACTLY one byte over. A body of cap+10 would still pass against an
    # implementation that let cap+1 through, which is the off-by-one this test
    # is here to catch.
    payload = b'{"vol":25}'
    cap = broker_server._MAX_SETTINGS_BODY_BYTES
    body = b" " * (cap + 1 - len(payload)) + payload
    assert len(body) == cap + 1
    req = _signed_post(app, "settings", body)
    resp = await broker_server._handle_device_settings(req)
    assert resp.status == 413
    assert reg.load(DEVICE_ID).active.payload.vol is None


async def test_oversize_without_content_length_caught_while_streaming(tmp_path: Path):
    """A chunked body has no Content-Length to check, so the cap has to hold
    while reading. Without that, req.read() buffers all the way up to aiohttp's
    own 1 MiB limit and then raises its own text/plain 413 — a different answer
    from the other two runtimes for the same request."""
    app, reg = _app(tmp_path)
    # Well past the cap, so "it stopped early" is observable. A body of only
    # cap+1 would not pin anything: an implementation reverted to
    # `raw = await req.read()` followed by a length check answers 413 there too.
    body = b"x" * (16 * broker_server._MAX_SETTINGS_BODY_BYTES)
    req = _signed_post(app, "settings", body, content_length=False)
    assert req.content_length is None, "the header check must not be what fires"
    resp = await broker_server._handle_device_settings(req)
    assert resp.status == 413
    assert json.loads(resp.body)["error"] == "settings body too large"
    assert reg.load(DEVICE_ID).active.payload.vol is None
    # The actual guarantee: it stopped reading rather than buffering the lot.
    # req.read() would have drained the stream to EOF.
    assert not req.content.at_eof(), (
        "the handler consumed the whole oversize body — the cap is being "
        "applied after the read, not while streaming"
    )


async def test_oversize_rejected_before_auth(tmp_path: Path):
    """The size gate runs before signature verification (the v3 canonical
    covers sha256(body), so the raw bytes are needed either way) — an oversize
    body from an unauthenticated peer must cost a size check, not a PSK
    comparison."""
    app, _ = _app(tmp_path)
    body = b"x" * (broker_server._MAX_SETTINGS_BODY_BYTES + 1)
    req = _signed_post(app, "settings", body, digest="0" * 64)
    resp = await broker_server._handle_device_settings(req)
    assert resp.status == 413


def test_cap_matches_cross_runtime_constant():
    """The three runtimes must not drift: go and js carry the same number under
    maxSettingsBodyBytes / MAX_SETTINGS_BODY_BYTES, and the firmware picks a
    smaller budget for itself so neither side depends on the other's value."""
    assert broker_server._MAX_SETTINGS_BODY_BYTES == 4 << 10
