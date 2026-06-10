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
    # Production (non-DEV) serial keeps these staging tests single-channel
    # (stable). Dual-channel dev routing has its own test.
    reg.set_serial(TEST_DEVICE, "CWM-S1-MAD-2620-000001-0", sku)
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
        # Floor strictly ABOVE the 0.5.1 release → device would refuse it
        # (packed < floor), so the broker must not stage. (Floor == release is
        # installable and covered by test_check_stages_when_release_at_floor.)
        reg = _registry_with_device(tmp_path, "S1", ota.pack_semver("0.5.2"))
        rep = await ota.check(cfg, reg, dry_run=False)
        assert rep["staged"] == 0 and rep["devices"][0]["action"] == "up_to_date"
    finally:
        await server.close()


async def test_check_stages_when_release_at_floor(tmp_path):
    # The device refuses only packed < floor (cwm_ota.c), so a release whose
    # base EQUALS the floor is installable and must be staged — not treated as
    # up_to_date. Mirrors a newer same-base dev canary after the floor matured.
    canonical, sig_b64 = _s1_vector()
    server = await _mock_server({"S1": _index(canonical, sig_b64)})
    try:
        cfg = _cfg_for(str(server.make_url("/")).rstrip("/"))
        reg = _registry_with_device(tmp_path, "S1", ota.pack_semver("0.5.1"))
        rep = await ota.check(cfg, reg, dry_run=True)
        assert rep["devices"][0]["action"] == "would_stage"
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


async def test_check_dev_unit_considers_both_channels(tmp_path):
    """A DEV-serial unit consumes BOTH stable and dev (candidate_channels).
    With only the stable channel served (dev asset 404s), it still stages
    stable. Exercises the per-device multi-channel gather + best-channel pick."""
    canonical, sig_b64 = _s1_vector()
    server = await _mock_server({"S1": _index(canonical, sig_b64)})  # stable only
    try:
        cfg = _cfg_for(str(server.make_url("/")).rstrip("/"))
        reg = _registry_with_device(tmp_path, "S1", 0)
        reg.set_serial(TEST_DEVICE, "CWM-S1-DEV-2620-000001-0", "S1")  # flip to DEV

        rep = await ota.check(cfg, reg, dry_run=True)
        by_chan = {s["channel"]: s for s in rep["per_sku"]}
        assert "stable" in by_chan and by_chan["stable"]["verified"]
        assert by_chan["stable"]["latest_version"] == "0.5.1"
        assert "dev" in by_chan and not by_chan["dev"]["verified"] and by_chan["dev"]["error"]
        assert len(rep["devices"]) == 1
        assert rep["devices"][0]["action"] == "would_stage"
        assert rep["devices"][0]["channel"] == "stable"
        assert rep["devices"][0]["to"] == "0.5.1"
    finally:
        await server.close()


def test_api_releases_url():
    assert ota.api_releases_url("https://github.com/fractal-manifold/cwm-ota-releases") == \
        "https://api.github.com/repos/fractal-manifold/cwm-ota-releases/releases?per_page=100"
    assert ota.api_releases_url("https://github.com/fractal-manifold/cwm-ota-releases/") == \
        "https://api.github.com/repos/fractal-manifold/cwm-ota-releases/releases?per_page=100"
    assert ota.api_releases_url("http://127.0.0.1:5000") == "http://127.0.0.1:5000/releases?per_page=100"


def test_dev_release_select_vectors():
    """Drive pick_dev_asset from the shared cross-runtime contract so Go, JS
    and Python pick the identical dev release."""
    fx = json.loads(_find_compat("ota/dev_release_select.json").read_text())
    assert fx["cases"], "fixture carries no cases"
    for c in fx["cases"]:
        for q in c["queries"]:
            got = ota.pick_dev_asset(c["releases"], q["sku"])
            if q["expect"] is None:
                assert got is None, (c["name"], q["sku"])
            else:
                assert got == (q["expect"]["version"], q["expect"]["tag"]), (c["name"], q["sku"])


def test_pick_dev_asset():
    def a(sku):
        return {"name": f"update-{sku}.json", "browser_download_url": f"u/{sku}"}
    rels = [
        {"tag_name": "v0.6.8-dev.202606022100", "prerelease": True, "assets": [a("S1")]},
        {"tag_name": "v0.9.0-dev.202609090000", "prerelease": True, "draft": True, "assets": [a("S1")]},  # draft → ignored
        {"tag_name": "v0.7.0", "prerelease": False, "assets": [a("S1")]},  # not prerelease
        {"tag_name": "v0.6.8-dev.202606021930", "prerelease": True, "assets": [a("S1"), a("S2")]},
        {"tag_name": "v0.6.7", "prerelease": True, "assets": [a("S1")]},  # plain version → ignored
    ]
    assert ota.pick_dev_asset(rels, "S1") == ("0.6.8-dev.202606022100", "v0.6.8-dev.202606022100")
    assert ota.pick_dev_asset(rels, "S2") == ("0.6.8-dev.202606021930", "v0.6.8-dev.202606021930")
    assert ota.pick_dev_asset(rels, "S9") is None
    assert ota.pick_dev_asset([], "S1") is None


def _dev_vector(name: str) -> tuple[str, str]:
    for m in VECTORS["manifests"]:
        if m["name"] == name:
            return m["canonical_string"], m["signature_b64"]
    raise AssertionError(f"no manifest vector named {name}")


async def _mock_server_full(stable_by_sku: dict[str, dict], devs: list[dict]) -> TestServer:
    """Serve the stable latest/download redirect AND the dev surface: the
    releases-list API at /releases plus each dev release's per-SKU asset at
    /releases/download/v<version>/update-<SKU>.json. devs: [{"version", "idx": {SKU: index}}]."""
    async def list_handler(request: web.Request) -> web.Response:
        out = []
        for d in devs:
            assets = [
                {"name": f"update-{sku}.json",
                 "browser_download_url": f"http://{request.host}/releases/download/v{d['version']}/update-{sku}.json"}
                for sku in d["idx"]
            ]
            out.append({"tag_name": f"v{d['version']}", "prerelease": True, "assets": assets})
        return web.json_response(out)

    async def dev_asset_handler(request: web.Request) -> web.Response:
        version = request.match_info["version"]
        asset = request.match_info["asset"]
        sku = asset[len("update-"):-len(".json")] if asset.startswith("update-") and asset.endswith(".json") else ""
        for d in devs:
            if d["version"] == version and sku in d["idx"]:
                return web.json_response(d["idx"][sku])
        return web.Response(status=404)

    async def stable_handler(request: web.Request) -> web.Response:
        asset = request.match_info["asset"]
        sku = asset[len("update-"):-len(".json")] if asset.startswith("update-") and asset.endswith(".json") else ""
        idx = stable_by_sku.get(sku)
        return web.json_response(idx) if idx is not None else web.Response(status=404)

    app = web.Application()
    app.router.add_get("/releases", list_handler)
    app.router.add_get("/releases/download/v{version}/{asset}", dev_asset_handler)
    app.router.add_get("/releases/latest/download/{asset}", stable_handler)
    server = TestServer(app)
    await server.start_server()
    return server


async def test_check_dev_unit_stages_dev_prerelease(tmp_path):
    """Full dev path: a DEV unit, the API listing advertises an immutable
    vX.Y.Z-dev.<ts> prerelease, and the broker resolves + verifies its signed
    manifest and stages it on the dev channel."""
    dev_ver = "0.6.8-dev.202606021930"
    canonical, sig_b64 = _dev_vector(f"ota-S1-dev-v{dev_ver}")
    dev_idx = _index(canonical, sig_b64, version=dev_ver, bin_url=f"https://dl.example/cwm-S1-{dev_ver}.bin")
    server = await _mock_server_full({}, [{"version": dev_ver, "idx": {"S1": dev_idx}}])
    try:
        cfg = _cfg_for(str(server.make_url("/")).rstrip("/"))
        # The dev manifest is signed under key_id "ed25519-dev" (same test key).
        cfg.ota.keys.append(OTAKey(key_id="ed25519-dev", pubkey_b64=cfg.ota.keys[0].pubkey_b64))
        reg = _registry_with_device(tmp_path, "S1", 0)
        reg.set_serial(TEST_DEVICE, "CWM-S1-DEV-2620-000001-0", "S1")  # flip to DEV

        rep = await ota.check(cfg, reg, dry_run=True)
        by_chan = {s["channel"]: s for s in rep["per_sku"]}
        assert "dev" in by_chan and by_chan["dev"]["verified"], by_chan
        assert by_chan["dev"]["latest_version"] == dev_ver
        assert len(rep["devices"]) == 1
        assert rep["devices"][0]["action"] == "would_stage"
        assert rep["devices"][0]["channel"] == "dev"
        assert rep["devices"][0]["to"] == dev_ver
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


def _resolved(version: str) -> dict:
    """A minimal resolved-release dict shaped like ota._resolve_sku output."""
    return {
        "mf": {"version": version, "sha256": "ab" * 32},
        "idx": {
            "bin_url": "https://downloads.example/cwm.bin",
            "manifest_b64": "bWFuaWZlc3Q=",
            "signature_b64": "c2ln",
        },
    }


def test_decide_skips_blocked_version(tmp_path: Path):
    """Revert tombstone: decide() must NOT auto-stage the exact version the
    device was reverted away from (blocked_firmware_version == release)."""
    reg = Registry(str(tmp_path))
    reg.register(TEST_DEVICE, ConfigPayload(broker_url="http://x", psk_hex="aa" * 32))
    reg.set_blocked_firmware_version(TEST_DEVICE, "0.9.1")
    dev = reg.load(TEST_DEVICE)

    out = ota._decide(reg, dev, _resolved("0.9.1"), dry_run=False)
    assert out["action"] == "skipped:blocked-version"
    assert reg.load(TEST_DEVICE).pending is None


def test_decide_stages_newer_than_blocked(tmp_path: Path):
    """The tombstone matches on version equality only — a NEWER fixed release
    over a blocked one must still stage."""
    reg = Registry(str(tmp_path))
    reg.register(TEST_DEVICE, ConfigPayload(broker_url="http://x", psk_hex="aa" * 32))
    reg.set_blocked_firmware_version(TEST_DEVICE, "0.9.1")
    dev = reg.load(TEST_DEVICE)

    out = ota._decide(reg, dev, _resolved("0.9.2"), dry_run=False)
    assert out["action"] == "staged"
    assert reg.load(TEST_DEVICE).pending.payload.firmware_version == "0.9.2"


def test_decide_no_tombstone_stages_normally(tmp_path: Path):
    """Sanity: with no tombstone a fresh release stages."""
    reg = Registry(str(tmp_path))
    reg.register(TEST_DEVICE, ConfigPayload(broker_url="http://x", psk_hex="aa" * 32))
    dev = reg.load(TEST_DEVICE)

    out = ota._decide(reg, dev, _resolved("0.9.1"), dry_run=False)
    assert out["action"] == "staged"


def test_semver_order_vectors():
    """Drive pack_semver + compare_semver from the shared cross-runtime
    contract so Go, JS and Python stay byte-for-byte aligned."""
    order = json.loads(_find_compat("ota/semver_order.json").read_text())
    for c in order["pack"]:
        got = ota.pack_semver(c["version"])
        if c["ok"]:
            assert got == c["packed"], c["version"]
        else:
            assert got is None, c["version"]
    for c in order["compare"]:
        assert ota.compare_semver(c["a"], c["b"]) == c["sign"], (c["a"], c["b"])
    for c in order["compare_unparseable"]:
        assert ota.compare_semver(c["a"], c["b"]) is None, (c["a"], c["b"])
    for c in order["valid"]:
        assert ota.valid_version(c["version"]) == c["valid"], c["version"]
