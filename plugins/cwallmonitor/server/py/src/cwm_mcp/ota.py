"""Broker-driven OTA update channel. Mirror of Go internal/ota/ota.go.

A periodic check of a public GitHub releases repo that auto-stages a
pending firmware update for matching registered devices.

Flow per check:

  1. Collect the distinct hardware SKUs of all registered devices.
  2. For each SKU, GET <repo>/releases/latest/download/update-<SKU>.json.
     GitHub 302-redirects this to the newest non-prerelease release's
     asset; aiohttp follows the redirect chain.
  3. Decode the index's manifest_b64 + signature_b64 and verify the
     Ed25519 signature against the configured keyring. Defense in depth —
     the device verifies the same signature again before it installs.
  4. For every device of that SKU whose installed version (mirrored in
     active.min_secure_version as packed 8.8.16) is older than the
     release, stage a pending carrying the firmware fields. The device
     picks it up on its next /device/<id>/sync.

The broker never holds a signing key — only public verification keys.
A compromised or misconfigured broker cannot forge a manifest, and the
on-device gate_manifest remains the ultimate authority.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import Config
from .registry.store import ConfigPayload, Registry

log = logging.getLogger("cwm_mcp.ota")

DEFAULT_POLL_MINUTES = 60
MIN_POLL_MINUTES = 5
INITIAL_DELAY_SECONDS = 30
HTTP_TIMEOUT_SECONDS = 10
MAX_INDEX_BODY = 64 * 1024  # an update-<SKU>.json is well under 1 KiB


def pack_semver(v: str) -> int | None:
    """Pack MAJOR.MINOR.PATCH into the 8.8.16 u32 layout the firmware uses
    for cwm_min_sv (major<<24 | minor<<16 | patch). Returns None on any
    malformed or out-of-range input. Mirrors PackSemver in Go and
    packed_semver() in tools/cwmtools/lib/manifest.py."""
    parts = v.split(".")
    if len(parts) != 3:
        return None
    nums = []
    for p in parts:
        # ASCII digits only — Python str.isdigit() also accepts unicode
        # digit chars (superscripts etc.) that int() then chokes on.
        if not p or any(c < "0" or c > "9" for c in p):
            return None
        # Reject leading zeros (except the literal "0") to match the
        # firmware's strict semver gate.
        if len(p) > 1 and p[0] == "0":
            return None
        nums.append(int(p))
    maj, mn, pat = nums
    if maj > 0xFF or mn > 0xFF or pat > 0xFFFF:
        return None
    return (maj << 24) | (mn << 16) | pat


def verify_manifest(pubkey: bytes, manifest: bytes, sig: bytes) -> bool:
    """Report whether sig is a valid Ed25519 signature over manifest bytes
    under pubkey (32-byte raw public key, 64-byte sig)."""
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, manifest)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


class _SkuError(Exception):
    pass


async def _fetch_index(session, repo: str, sku: str) -> dict:
    """GET the update-<SKU>.json release asset. aiohttp follows GitHub's
    cross-host redirect chain (github.com -> objects.githubusercontent.com)
    automatically."""
    url = repo.rstrip("/") + f"/releases/latest/download/update-{sku}.json"
    headers = {"Accept": "application/json", "User-Agent": "cwm-mcp-ota"}
    async with session.get(url, headers=headers) as resp:
        if resp.status != 200:
            raise _SkuError(f"fetch {url}: HTTP {resp.status}")
        body = await resp.content.read(MAX_INDEX_BODY)
    try:
        idx = json.loads(body)
    except json.JSONDecodeError as e:
        raise _SkuError(f"decode {url}: {e}") from e
    if not isinstance(idx, dict):
        raise _SkuError(f"{url}: not a JSON object")
    for k in ("version", "manifest_b64", "signature_b64", "bin_url"):
        if not idx.get(k):
            raise _SkuError(f"{url} missing required field {k}")
    return idx


def _resolve_sku(cfg: Config, idx: dict, sku: str) -> tuple[dict | None, dict]:
    """Verify + parse a fetched index. Returns (resolved_or_None, sku_result).
    sku_result mirrors Go SKUResult JSON."""
    sres: dict = {"sku": sku, "latest_version": idx.get("version", ""), "verified": False}
    try:
        man = base64.b64decode(str(idx["manifest_b64"]).strip(), validate=True)
    except (binascii.Error, ValueError):
        sres["error"] = "manifest_b64 decode failed"
        return None, sres
    if not man:
        sres["error"] = "manifest_b64 decode failed"
        return None, sres
    try:
        sig = base64.b64decode(str(idx["signature_b64"]).strip(), validate=True)
    except (binascii.Error, ValueError):
        sres["error"] = "signature_b64 decode failed or wrong length"
        return None, sres
    if len(sig) != 64:
        sres["error"] = "signature_b64 decode failed or wrong length"
        return None, sres
    try:
        mf = json.loads(man)
    except json.JSONDecodeError:
        sres["error"] = "manifest is not valid JSON"
        return None, sres
    key_id = str(mf.get("key_id", ""))
    pub = cfg.ota.pubkey(key_id)
    if pub is None:
        sres["error"] = f"no pubkey configured for key_id {key_id}"
        return None, sres
    if not verify_manifest(pub, man, sig):
        sres["error"] = "Ed25519 signature verify failed"
        return None, sres
    # Sanity: the manifest's SKU must match the index we asked for, and the
    # index version must match the manifest version (the index is untrusted
    # metadata; the manifest is the signed authority).
    if str(mf.get("sku", "")) != sku:
        sres["error"] = f"manifest sku {mf.get('sku')!r} != requested {sku!r}"
        return None, sres
    if str(idx["version"]) != str(mf.get("version", "")):
        sres["error"] = f"index version {idx['version']!r} != manifest version {mf.get('version')!r}"
        return None, sres
    if not str(idx["bin_url"]).startswith("https://"):
        sres["error"] = "bin_url must be HTTPS"
        return None, sres
    if pack_semver(str(mf.get("version", ""))) is None:
        sres["error"] = "manifest version is not MAJOR.MINOR.PATCH"
        return None, sres
    sres["verified"] = True
    return {"idx": idx, "mf": mf}, sres


def _decide(reg: Registry, dev, resolved: dict, dry_run: bool) -> dict:
    """Compute the action for one device against a resolved release,
    staging a pending when appropriate (unless dry_run). Mirrors Go decide."""
    mf = resolved["mf"]
    idx = resolved["idx"]
    out: dict = {"device_id": dev.device_id, "sku": dev.hw_sku, "to": str(mf.get("version", ""))}
    release_packed = pack_semver(str(mf.get("version", "")))
    if release_packed is None:
        out["action"] = "skipped:bad-version"
        return out
    out["from"] = dev.active.payload.firmware_version
    # Compare against the device's reported anti-rollback floor.
    if release_packed <= dev.active.payload.min_secure_version:
        out["action"] = "up_to_date"
        return out
    # Avoid churning the config version: if a pending already carries this
    # exact firmware version, leave it.
    if dev.pending is not None and dev.pending.payload.firmware_version == str(mf.get("version", "")):
        out["action"] = "skipped:already-pending"
        return out
    if dry_run:
        out["action"] = "would_stage"
        return out
    update = ConfigPayload(
        firmware_url=str(idx["bin_url"]),
        firmware_sha256=str(mf.get("sha256", "")),
        firmware_version=str(mf.get("version", "")),
        firmware_manifest_b64=str(idx["manifest_b64"]),
        firmware_manifest_sig_b64=str(idx["signature_b64"]),
    )
    try:
        reg.set_pending(dev.device_id, update)
    except Exception as e:  # noqa: BLE001
        out["action"] = "error:" + str(e)
        return out
    log.info("staged %s -> %s for device %s (sku=%s)", out["from"], mf.get("version"), dev.device_id, dev.hw_sku)
    out["action"] = "staged"
    return out


def _drop_empty(d: dict, keys: tuple[str, ...]) -> dict:
    """Drop falsy values for `keys` to mirror Go's omitempty."""
    for k in keys:
        if k in d and not d[k]:
            del d[k]
    return d


async def check(
    cfg: Config,
    reg: Registry | None,
    *,
    dry_run: bool,
    sku_filter: str = "",
    device_filter: str = "",
    session=None,
) -> dict:
    """Run one pass. dry_run=True reports without writing. sku_filter (if
    non-empty) restricts to one SKU; device_filter (if non-empty) restricts
    staging to one device id. Returns a dict mirroring Go Report JSON."""
    import aiohttp

    o = cfg.ota
    rep: dict = {
        "repo": o.releases_repo,
        "enabled": o.enabled,
        "configured": o.configured(),
        "dry_run": dry_run,
        "checked_at": _now_iso(),
        "per_sku": [],
        "devices": [],
        "staged": 0,
    }
    if not o.configured():
        rep["note"] = (
            "ota auto-staging is not active: set [ota].enabled, releases_repo "
            "and at least one [[ota.keys]] in cwm.toml"
        )
        return rep
    if reg is None:
        rep["note"] = "device registry unavailable"
        return rep

    sku_filter = sku_filter.strip().upper()
    device_filter = device_filter.strip().lower()
    wanted = []
    sku_set: set[str] = set()
    for dev in reg.list():
        if not dev.hw_sku:
            continue
        if device_filter and dev.device_id != device_filter:
            continue
        if sku_filter and dev.hw_sku != sku_filter:
            continue
        wanted.append(dev)
        sku_set.add(dev.hw_sku)

    own_session = session is None
    if own_session:
        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_SECONDS))
    try:
        resolved_by_sku: dict[str, dict] = {}
        for sku in sorted(sku_set):
            try:
                idx = await _fetch_index(session, o.releases_repo, sku)
                resolved, sres = _resolve_sku(cfg, idx, sku)
            except _SkuError as e:
                rep["per_sku"].append({"sku": sku, "verified": False, "error": str(e)})
                continue
            rep["per_sku"].append(_drop_empty(sres, ("latest_version", "error")))
            if resolved is not None:
                resolved_by_sku[sku] = resolved
    finally:
        if own_session:
            await session.close()

    for dev in wanted:
        resolved = resolved_by_sku.get(dev.hw_sku)
        if resolved is None:
            rep["devices"].append({"device_id": dev.device_id, "sku": dev.hw_sku, "action": "skipped:no-release"})
            continue
        res = _decide(reg, dev, resolved, dry_run)
        if res.get("action") == "staged":
            rep["staged"] += 1
        rep["devices"].append(_drop_empty(res, ("from", "to")))
    return rep


async def run(cfg: Config, reg: Registry | None, stop: asyncio.Event) -> None:
    """Background poll loop. Returns immediately (logging once) when OTA is
    not configured; otherwise checks every poll interval until `stop` is set
    (the leader losing the bind). Mirror of Go ota.Run."""
    if cfg is None or not cfg.ota.configured():
        log.info(
            "ota: auto-staging inactive (enabled=%s repo=%r keys=%d)",
            cfg.ota.enabled if cfg else False,
            cfg.ota.releases_repo if cfg else "",
            len(cfg.ota.keys) if cfg else 0,
        )
        return
    if reg is None:
        log.info("ota: registry unavailable, auto-staging disabled")
        return
    minutes = cfg.ota.poll_interval_minutes
    if minutes <= 0:
        minutes = DEFAULT_POLL_MINUTES
    if minutes < MIN_POLL_MINUTES:
        minutes = MIN_POLL_MINUTES
    interval = minutes * 60
    log.info("ota: auto-staging active, repo=%s interval=%dm", cfg.ota.releases_repo, minutes)

    # Initial settle delay, interruptible by stop.
    try:
        await asyncio.wait_for(stop.wait(), timeout=INITIAL_DELAY_SECONDS)
        return
    except asyncio.TimeoutError:
        pass

    while not stop.is_set():
        try:
            rep = await check(cfg, reg, dry_run=False)
            log.info(
                "ota: check done, staged=%d skus=%d devices=%d",
                rep["staged"], len(rep["per_sku"]), len(rep["devices"]),
            )
        except Exception as e:  # noqa: BLE001
            log.warning("ota: check failed: %s", e)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return
        except asyncio.TimeoutError:
            pass
