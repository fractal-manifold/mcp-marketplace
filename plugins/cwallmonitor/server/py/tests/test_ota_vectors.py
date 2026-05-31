"""OTA poller: pack_semver, Ed25519 verify against the shared compat
vectors, and the staging decision against a mock release server.

Mirror of Go internal/ota/ota_test.go — both must agree on the byte-exact
manifest contract in compat/ed25519/vectors.json."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from cwm_mcp import ota
from cwm_mcp.config import OTA, OTAKey, Config
from cwm_mcp.registry.store import ConfigPayload, Registry

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


def test_pack_semver():
    cases = {
        "0.0.0": 0,
        "0.5.1": (5 << 16) | 1,
        "1.2.3": (1 << 24) | (2 << 16) | 3,
        "255.255.65535": (255 << 24) | (255 << 16) | 65535,
    }
    for v, want in cases.items():
        assert ota.pack_semver(v) == want, v
    for bad in ("", "1.2", "1.2.3.4", "1.2.x", "v1.2.3", "1..3", " 1.2.3",
                "01.2.3", "1.02.3", "1.2.03", "256.0.0", "0.256.0", "0.0.65536"):
        assert ota.pack_semver(bad) is None, bad


def test_verify_manifest_vectors():
    pub = bytes.fromhex(VECTORS["test_keypair"]["pub_hex"])
    for m in VECTORS["manifests"]:
        assert m.get("signature_hex"), f"{m['name']}: vector missing signature_hex"
        sig = bytes.fromhex(m["signature_hex"])
        body = m["canonical_string"].encode("utf-8")
        assert ota.verify_manifest(pub, body, sig), m["name"]
        # signature_b64 must decode to the same bytes.
        assert base64.b64decode(m["signature_b64"]) == sig, m["name"]
        # Tampered manifest fails.
        tampered = bytearray(body)
        tampered[0] ^= 0x01
        assert not ota.verify_manifest(pub, bytes(tampered), sig), m["name"]
        # Wrong key fails.
        wrong = bytearray(pub)
        wrong[0] ^= 0x01
        assert not ota.verify_manifest(bytes(wrong), body, sig), m["name"]


def _s1_vector() -> tuple[str, str]:
    for m in VECTORS["manifests"]:
        if "S1" in m["name"]:
            return m["canonical_string"], m["signature_b64"]
    raise AssertionError("no S1 manifest vector")


def _index(canonical: str, sig_b64: str, *, version="0.5.1", bin_url="https://dl.example/cwm-S1-0.5.1.bin") -> dict:
    return {
        "version": version,
        "manifest_b64": base64.b64encode(canonical.encode("utf-8")).decode("ascii"),
        "signature_b64": sig_b64,
        "bin_url": bin_url,
    }


async def _mock_server(idx_by_sku: dict[str, dict]) -> TestServer:
    async def handler(request: web.Request) -> web.Response:
        asset = request.match_info["asset"]
        if not asset.startswith("update-") or not asset.endswith(".json"):
            return web.Response(status=404)
        sku = asset[len("update-"):-len(".json")]
        idx = idx_by_sku.get(sku)
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
        keys=[OTAKey(key_id="ed25519-2026-q2", pubkey_b64=base64.b64encode(pub).decode("ascii"))],
    )
    return cfg


def _registry_with_device(tmp_path, sku: str, min_sv: int) -> Registry:
    reg = Registry(str(tmp_path))
    reg.register(TEST_DEVICE, ConfigPayload(psk_hex=TEST_PSK, broker_url="https://broker.example"))
    reg.set_serial(TEST_DEVICE, "CWM-S1-DEV-2620-000001-0", sku)
    if min_sv > 0:
        reg.bump_min_sv(TEST_DEVICE, min_sv)
    return reg


async def test_check_stages_update(tmp_path):
    canonical, sig_b64 = _s1_vector()
    server = await _mock_server({"S1": _index(canonical, sig_b64)})
    try:
        cfg = _cfg_for(str(server.make_url("/")).rstrip("/"))
        reg = _registry_with_device(tmp_path, "S1", 0)

        # Dry run: would_stage, nothing written.
        rep = await ota.check(cfg, reg, dry_run=True)
        assert rep["staged"] == 0
        assert len(rep["devices"]) == 1 and rep["devices"][0]["action"] == "would_stage"
        assert rep["per_sku"][0]["verified"] and rep["per_sku"][0]["latest_version"] == "0.5.1"
        assert reg.load(TEST_DEVICE).pending is None

        # Real run: stages with firmware fields.
        rep = await ota.check(cfg, reg, dry_run=False)
        assert rep["staged"] == 1 and rep["devices"][0]["action"] == "staged"
        dev = reg.load(TEST_DEVICE)
        assert dev.pending is not None
        p = dev.pending.payload
        assert p.firmware_version == "0.5.1"
        assert p.firmware_url == "https://dl.example/cwm-S1-0.5.1.bin"
        assert p.firmware_sha256 == "abc123"
        assert p.firmware_manifest_b64 == _index(canonical, sig_b64)["manifest_b64"]
        assert p.firmware_manifest_sig_b64 == sig_b64

        # Idempotence: pending already carries 0.5.1.
        rep = await ota.check(cfg, reg, dry_run=False)
        assert rep["staged"] == 0 and rep["devices"][0]["action"] == "skipped:already-pending"
    finally:
        await server.close()


async def test_check_up_to_date(tmp_path):
    canonical, sig_b64 = _s1_vector()
    server = await _mock_server({"S1": _index(canonical, sig_b64)})
    try:
        cfg = _cfg_for(str(server.make_url("/")).rstrip("/"))
        reg = _registry_with_device(tmp_path, "S1", ota.pack_semver("0.5.1"))
        rep = await ota.check(cfg, reg, dry_run=False)
        assert rep["staged"] == 0 and rep["devices"][0]["action"] == "up_to_date"
    finally:
        await server.close()


async def test_check_rejects_tampered_signature(tmp_path):
    canonical, sig_b64 = _s1_vector()
    bad = ("B" if sig_b64[0] == "A" else "A") + sig_b64[1:]
    server = await _mock_server({"S1": _index(canonical, bad)})
    try:
        cfg = _cfg_for(str(server.make_url("/")).rstrip("/"))
        reg = _registry_with_device(tmp_path, "S1", 0)
        rep = await ota.check(cfg, reg, dry_run=False)
        assert rep["staged"] == 0
        assert not rep["per_sku"][0]["verified"] and rep["per_sku"][0]["error"]
        assert rep["devices"][0]["action"] == "skipped:no-release"
    finally:
        await server.close()


async def test_check_inert_when_unconfigured(tmp_path):
    cfg = Config()
    cfg.ota = OTA(enabled=True, releases_repo="https://github.com/x/y", keys=[])
    reg = _registry_with_device(tmp_path, "S1", 0)
    rep = await ota.check(cfg, reg, dry_run=False)
    assert not rep["configured"]
    assert rep["staged"] == 0
    assert rep["note"]
    assert rep["devices"] == []
