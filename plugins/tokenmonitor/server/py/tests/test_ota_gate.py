"""Parity tests for the broker's copy of the device manifest gate.

These drive compat/ota/gate_manifest.json — the same rows
firmware/test/host/test_ota_gate.c runs against the shipping
tmon_ota_gate_decide() and go/internal/ota/gate_test.go runs against
PredictDeviceGate. Two (three) implementations of one policy only stay honest
if something checks them against the same table; without it the drift is
invisible, because a device that refuses a manifest says nothing at all.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from tmon_mcp import ota
from tmon_mcp.config import OTA, OTAKey, Config
from tmon_mcp.gate import GATE_OK, predict_device_gate
from tmon_mcp.registry.store import ConfigPayload, Registry

TEST_PSK = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee"
TEST_DEVICE = "ab12cd34"


def _find_compat(rel: str) -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "compat" / rel
        if cand.exists():
            return cand
    pytest.skip(f"compat/{rel} not available (standalone checkout)", allow_module_level=True)


VECTORS = json.loads(_find_compat("ed25519/vectors.json").read_text())
GATE_CASES = json.loads(_find_compat("ota/gate_manifest.json").read_text())["cases"]
BROKER_CASES = [c for c in GATE_CASES
                if not c.get("sides") or "broker" in c.get("sides", [])]


def test_the_vector_file_carries_broker_rows():
    assert BROKER_CASES, "no broker-side cases to run"


@pytest.mark.parametrize("case", BROKER_CASES, ids=[c["name"] for c in BROKER_CASES])
def test_predict_device_gate_vectors(case):
    # The row's manifest is the byte-exact canonical form the signer emits; the
    # broker reads fields out of it exactly as it does from a real index, never
    # re-encoding.
    mf = json.loads(case["manifest"])
    dev = {
        "floor": case["device"]["floor"],
        "sku": case["device"]["sku"],
        "is_dev": case["device"].get("is_dev", False),
    }
    verdict, why = predict_device_gate(mf, dev)
    want = "" if case["expect"] == "ok" else case["expect"]
    assert verdict == want, f"{case['name']}: got {verdict!r} ({why})"
    if verdict != GATE_OK:
        assert why.strip(), "a refusal must carry an explanation an operator can act on"


# --- decide()-level: the regression proper ----------------------------------


def _sign(sku: str, version: str, min_sv: int, channel: str = "",
          sha: str = "a" * 64) -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(VECTORS["test_keypair"]["seed_hex"]))
    head = f'{{"channel":"{channel}",' if channel else "{"
    canonical = (
        head
        + f'"key_id":"ed25519-2026-q2","min_secure_version":{min_sv},'
        + f'"sha256":"{sha}","size":2048,"sku":"{sku}","version":"{version}"}}'
    )
    return canonical, base64.b64encode(priv.sign(canonical.encode("utf-8"))).decode("ascii")


def _index(canonical: str, sig_b64: str, version: str, sku: str) -> dict:
    return {
        "version": version,
        "manifest_b64": base64.b64encode(canonical.encode("utf-8")).decode("ascii"),
        "signature_b64": sig_b64,
        "bin_url": f"https://dl.example/tmon-{sku}-{version}.bin",
    }


async def _mock_server(idx_by_sku: dict[str, dict]) -> TestServer:
    async def handler(request: web.Request) -> web.Response:
        asset = request.match_info["asset"]
        if not asset.startswith("update-") or not asset.endswith(".json"):
            return web.Response(status=404)
        idx = idx_by_sku.get(asset[len("update-"):-len(".json")])
        if idx is None:
            return web.Response(status=404)
        return web.json_response(idx)

    app = web.Application()
    app.router.add_get("/releases/latest/download/{asset}", handler)
    server = TestServer(app)
    await server.start_server()
    return server


def _cfg_for(repo_url: str) -> Config:
    pub = bytes.fromhex(VECTORS["test_keypair"]["pub_hex"])
    cfg = Config()
    cfg.ota = OTA(
        enabled=True,
        releases_repo=repo_url,
        poll_interval_minutes=60,
        keys=[OTAKey(key_id="ed25519-2026-q2",
                     pubkey_b64=base64.b64encode(pub).decode("ascii"))],
    )
    return cfg


def _registry_with_device(tmp_path, sku: str, min_sv: int) -> Registry:
    reg = Registry(str(tmp_path))
    reg.register(TEST_DEVICE, ConfigPayload(psk_hex=TEST_PSK,
                                            broker_url="https://broker.example"))
    reg.set_serial(TEST_DEVICE, "CWM-S1-MAD-2620-000001-0", sku)
    if min_sv > 0:
        reg.record_min_sv(TEST_DEVICE, min_sv)
    return reg


async def test_decide_refuses_manifest_below_device_floor(tmp_path):
    """A release the device WANTS (newer than its floor) whose manifest floor
    locks it out must be reported loudly and must not touch the install-loop
    streak. Before this, the broker staged it, the device refused it in silence,
    and five rounds later the release was tombstoned for that device — the shape
    the published 1.0.0 index put every unit at or past 0.12.0 into."""
    canonical, sig = _sign("S1", "1.0.1", ota.pack_semver("0.11.4"))
    server = await _mock_server({"S1": _index(canonical, sig, "1.0.1", "S1")})
    try:
        cfg = _cfg_for(str(server.make_url("/")).rstrip("/"))
        # A unit that has confirmed 1.0.0 and was then re-flashed down over USB:
        # tmon_min_sv is monotonic and survives the flash.
        reg = _registry_with_device(tmp_path, "S1", ota.pack_semver("1.0.0"))
        streaks: dict = {}
        # Staging five times in a row is what tombstones a version. Prove that a
        # manifest the device would refuse never gets that far, however often
        # the loop runs.
        for i in range(ota.MAX_AUTO_STAGES + 2):
            rep = await ota.check(cfg, reg, dry_run=False, streaks=streaks)
            got = rep["devices"][0]
            assert got["action"] == "skipped:min-sv-below-floor", (i, got)
            assert "min_secure_version" in got.get("reason", ""), got
            assert rep["staged"] == 0, (i, rep)
        dev = reg.load(TEST_DEVICE)
        assert not getattr(dev, "blocked_firmware_version", ""), \
            "a publishing mistake must never tombstone the release"
        assert dev.pending is None
    finally:
        await server.close()


async def test_decide_stages_conformant_manifest_at_same_floor(tmp_path):
    """The same release with the floor tmtools would have picked stages
    normally — same binary, same device, only the signed floor differs. This is
    the pair that makes the invariant concrete: lowering the floor subtracts
    devices and buys nothing."""
    canonical, sig = _sign("S1", "1.0.1", ota.pack_semver("1.0.1"))
    server = await _mock_server({"S1": _index(canonical, sig, "1.0.1", "S1")})
    try:
        cfg = _cfg_for(str(server.make_url("/")).rstrip("/"))
        reg = _registry_with_device(tmp_path, "S1", ota.pack_semver("1.0.0"))
        rep = await ota.check(cfg, reg, dry_run=False, streaks={})
        assert rep["devices"][0]["action"] == "staged", rep["devices"][0]
    finally:
        await server.close()
