"""Broker-driven OTA update channel. Mirror of Go internal/ota/ota.go.

A periodic check of a public GitHub releases repo that auto-stages a
pending firmware update for matching registered devices.

Flow per check:

  1. Collect the distinct hardware SKUs of all registered devices.
  2. STABLE: GET <repo>/releases/latest/download/update-<SKU>.json; GitHub
     302-redirects to the newest non-prerelease asset (zero API). DEV: no
     "latest prerelease" redirect exists, so list releases via the GitHub
     API once per check and pick the newest vX.Y.Z-dev.<ts> prerelease
     carrying that SKU.
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
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import Config
from .registry.store import (
    ConfigPayload,
    Registry,
    candidate_channels,
    effective_channel,
)

log = logging.getLogger("cwm_mcp.ota")

DEFAULT_POLL_MINUTES = 60
MIN_POLL_MINUTES = 5
INITIAL_DELAY_SECONDS = 30
HTTP_TIMEOUT_SECONDS = 10
MAX_INDEX_BODY = 64 * 1024  # an update-<SKU>.json is well under 1 KiB
# MAX_RELEASES_BODY caps the GitHub releases-list JSON read to resolve the
# newest dev prerelease; RELEASES_PER_PAGE requests the newest N in one page
# (GitHub returns releases newest-first, so the newest dev tag is always on
# page 1 — we never paginate). Bound caveat: a SKU whose newest dev build is
# >N releases back would be missed — irrelevant in practice, since a dev
# publish ships every SKU together at an hourly cadence.
MAX_RELEASES_BODY = 4 * 1024 * 1024
RELEASES_PER_PAGE = 100


def pack_semver(v: str) -> int | None:
    """Pack the MAJOR.MINOR.PATCH base into the 8.8.16 u32 layout the firmware
    uses for cwm_min_sv (major<<24 | minor<<16 | patch). An optional
    "-dev.<ts>" development prerelease suffix is ignored (the anti-rollback
    floor is base-level). Returns None on any malformed or out-of-range input.
    Mirrors PackSemver in Go and packed_semver() in
    tools/cwmtools/lib/manifest.py."""
    base = v.split("-", 1)[0]
    parts = base.split(".")
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


def dev_prerelease(v: str) -> int | None:
    """Extract the numeric timestamp from a "-dev.<12 digits>" development
    prerelease suffix (a YYYYMMDDhhmm value). Returns the timestamp when present
    and well-formed, or None when the string carries no such suffix OR it is
    malformed (not exactly 12 digits, trailing junk). The fixed 12-digit width
    keeps the value identical across the Go (uint64) and JS (BigInt) brokers."""
    marker = "-dev."
    i = v.find(marker)
    if i < 0:
        return None
    ts = v[i + len(marker):]
    if len(ts) != 12 or any(c < "0" or c > "9" for c in ts):
        return None
    return int(ts)


def valid_version(v: str) -> bool:
    """Report whether v is a well-formed firmware version: MAJOR.MINOR.PATCH
    (packable) with an OPTIONAL "-dev.<12 digits>" suffix and nothing else. The
    broker gates signed manifests on this so it never stages a version the
    firmware's stricter semver_ok() would refuse. Lock-step with Go
    ValidVersion / JS validVersion and semver_ok() in cwm_manifest.c."""
    if pack_semver(v) is None:
        return False
    i = v.find("-")
    if i < 0:
        return True
    return dev_prerelease(v[i:]) is not None


def compare_semver(a: str, b: str) -> int | None:
    """Order two version strings under the project's SemVer subset: the
    MAJOR.MINOR.PATCH base plus an optional "-dev.<ts>" development prerelease.
    Returns -1/0/1 (a<b / a==b / a>b), or None if either string isn't a
    parseable version. Ordering: a differing base wins; with equal bases a
    final build (no suffix) is NEWER than a prerelease, and two prereleases
    compare by their numeric <ts> (larger = newer) — the SemVer rule
    (X.Y.Z-pre < X.Y.Z). Wire-identical to the Go/JS brokers."""
    pa = pack_semver(a)
    pb = pack_semver(b)
    if pa is None or pb is None:
        return None
    if pa != pb:
        return -1 if pa < pb else 1
    ta = dev_prerelease(a)
    tb = dev_prerelease(b)
    if ta is None and tb is None:
        return 0
    if ta is None:  # a final, b prerelease -> a newer
        return 1
    if tb is None:  # a prerelease, b final -> a older
        return -1
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


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


async def _read_capped(resp, limit: int) -> bytes:
    """Read the response body fully, up to `limit` bytes — mirrors Go's
    io.LimitReader(resp.Body, limit). aiohttp's StreamReader.read(n) can
    UNDER-read a body that spans multiple network reads (it returns whatever is
    buffered), so a single .read(limit) would silently truncate a larger
    listing; loop to EOF instead."""
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        chunk = await resp.content.read(65536)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)[:limit]


def _github_token() -> str:
    """Optional API token from the environment to lift the unauthenticated
    rate limit; empty is fine for a public repo."""
    return (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()


def _is_github_repo(repo: str) -> bool:
    return repo.rstrip("/").startswith("https://github.com/")


def api_releases_url(repo: str) -> str:
    """Map the public releases repo URL to the GitHub Releases API listing
    endpoint. A github.com repo rewrites to api.github.com/repos/.../releases;
    any other host (self-hosted mirror / test server) gets /releases appended
    so a test can intercept the same path shape. Mirror of Go apiReleasesURL."""
    base = repo.rstrip("/")
    gh = "https://github.com/"
    q = f"?per_page={RELEASES_PER_PAGE}"
    if base.startswith(gh):
        return f"https://api.github.com/repos/{base[len(gh):]}/releases{q}"
    return base + "/releases" + q


def pick_dev_asset(rels: list, sku: str) -> tuple[str, str] | None:
    """Select, among the dev prereleases, the NEWEST one (by compare_semver on
    the tag's version) that carries an update-<SKU>.json asset, returning
    (version, tag) or None. A release qualifies only if it is flagged
    prerelease (and NOT draft) and its tag is a valid X.Y.Z-dev.<ts> version.
    Per-SKU (not "the newest dev release"): a dev publish shipping only S1 must
    not hide an older S2 dev build. Returns the TAG (not the listing's
    browser_download_url) so the caller builds the asset URL from the TRUSTED
    repo base — the listing is untrusted metadata. Mirror of Go pickDevAsset."""
    want = f"update-{sku}.json"
    best: tuple[str, str] | None = None
    for r in rels or []:
        if not isinstance(r, dict) or r.get("prerelease") is not True or r.get("draft") is True:
            continue
        tag = str(r.get("tag_name", ""))
        ver = tag[1:] if tag.startswith("v") else tag
        dash = ver.find("-")
        if dash < 0:  # a final X.Y.Z is never a dev build
            continue
        if dev_prerelease(ver[dash:]) is None or not valid_version(ver):
            continue
        has = False
        for a in r.get("assets", []) or []:
            if isinstance(a, dict) and a.get("name") == want:
                has = True
                break
        if not has:
            continue
        if best is None:
            best = (ver, tag)
            continue
        cmp = compare_semver(ver, best[0])
        if cmp is not None and cmp > 0:
            best = (ver, tag)
    return best


async def _list_dev_releases(session, repo: str) -> list:
    """Fetch the newest page of releases (newest-first, as GitHub orders them).
    Called only when a dev device is in scope; stable resolution never hits the
    API. Mirror of Go listDevReleases."""
    import aiohttp
    url = api_releases_url(repo)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "cwm-mcp-ota",
    }
    # Only ever send a GitHub credential to GitHub itself — never leak it to a
    # self-hosted mirror configured as releases_repo.
    tok = _github_token() if _is_github_repo(repo) else ""
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    try:
        async with session.get(url, headers=headers) as resp:
            if resp.status != 200:
                raise _SkuError(f"list releases {url}: HTTP {resp.status}")
            body = await _read_capped(resp, MAX_RELEASES_BODY)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        # Transport failure → a per-check dev error (Go/JS record it and keep
        # resolving stable), not an exception that aborts the whole check.
        raise _SkuError(f"list releases {url}: {e}") from e
    try:
        rels = json.loads(body)
    except json.JSONDecodeError as e:
        raise _SkuError(f"decode releases {url}: {e}") from e
    if not isinstance(rels, list):
        raise _SkuError(f"{url}: not a JSON array")
    return rels


async def _fetch_index(session, repo: str, sku: str, channel: str = "stable", dev_rels: list | None = None) -> dict:
    """GET the update-<SKU>.json release asset for one (SKU, channel).

    Stable rides GitHub's latest/download redirect (newest non-prerelease,
    zero API). Dev resolves the newest immutable vX.Y.Z-dev.<ts> prerelease
    carrying this SKU from the pre-fetched `dev_rels` listing, then GETs that
    release's asset — so a dev device never sees a stable build and a stable
    device never sees a prerelease. aiohttp follows GitHub's cross-host
    redirect chain (github.com -> objects.githubusercontent.com)
    automatically."""
    import aiohttp
    base = repo.rstrip("/")
    if channel and channel != "stable":
        picked = pick_dev_asset(dev_rels or [], sku)
        if picked is None:
            raise _SkuError(
                f"no dev prerelease carrying update-{sku}.json among "
                f"{len(dev_rels or [])} release(s)")
        # Build the asset URL from the TRUSTED repo base + tag (same shape as
        # the stable latest/download path), not from the listing's
        # browser_download_url — never let untrusted listing metadata point the
        # fetch at an arbitrary host.
        url = base + f"/releases/download/{picked[1]}/update-{sku}.json"
    else:
        url = base + f"/releases/latest/download/update-{sku}.json"
    headers = {"Accept": "application/json", "User-Agent": "cwm-mcp-ota"}
    try:
        async with session.get(url, headers=headers) as resp:
            if resp.status != 200:
                raise _SkuError(f"fetch {url}: HTTP {resp.status}")
            body = await _read_capped(resp, MAX_INDEX_BODY)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        raise _SkuError(f"fetch {url}: {e}") from e
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


def _resolve_sku(cfg: Config, idx: dict, sku: str, channel: str = "stable") -> tuple[dict | None, dict]:
    """Verify + parse a fetched index. Returns (resolved_or_None, sku_result).
    sku_result mirrors Go SKUResult JSON. `channel` is the device's
    effective channel; `want` collapses "" to "stable" defensively."""
    want = channel if (channel and channel != "stable") else "stable"
    sres: dict = {"sku": sku, "channel": want, "latest_version": idx.get("version", ""), "verified": False}
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
    # Channel must match what we asked for. Stable manifests OMIT the field
    # (absent == stable); dev manifests carry channel:"dev". This is a
    # sanity check on the signed authority — the device re-checks it too,
    # and refuses a dev manifest outright on a production unit.
    man_chan = str(mf.get("channel")) if mf.get("channel") else "stable"
    if man_chan != want:
        sres["error"] = f"manifest channel {man_chan!r} != requested {want!r}"
        return None, sres
    if not str(idx["bin_url"]).startswith("https://"):
        sres["error"] = "bin_url must be HTTPS"
        return None, sres
    if not valid_version(str(mf.get("version", ""))):
        sres["error"] = "manifest version is not MAJOR.MINOR.PATCH[-dev.<12 digits>]"
        return None, sres
    sres["verified"] = True
    return {"idx": idx, "mf": mf}, sres


def _decide(reg: Registry, dev, resolved: dict, dry_run: bool) -> dict:
    """Compute the action for one device against a resolved release,
    staging a pending when appropriate (unless dry_run). Mirrors Go decide."""
    mf = resolved["mf"]
    idx = resolved["idx"]
    out: dict = {"device_id": dev.device_id, "sku": dev.hw_sku, "channel": effective_channel(dev), "to": str(mf.get("version", ""))}
    release_packed = pack_semver(str(mf.get("version", "")))
    if release_packed is None:
        out["action"] = "skipped:bad-version"
        return out
    out["from"] = dev.active.payload.firmware_version
    # Release not strictly newer than the version the device is actually
    # RUNNING? Then it's up to date even if the anti-rollback floor hasn't
    # caught up yet. This matters during a dev unit's canary window (the
    # floor bump is deferred, so the min_secure_version comparison alone
    # would re-stage the running build every poll) and for USB-flashed
    # images whose floor lags the installed version. Uses compare_semver (not
    # raw packed base) so dev iteration works: two "0.6.8-dev.<ts>" builds share
    # a base, and the newer timestamp must still stage over the older. Mirrors
    # Go/JS decide.
    cmp = compare_semver(str(mf.get("version", "")), str(dev.active.payload.firmware_version or ""))
    if cmp is not None and cmp <= 0:
        out["action"] = "up_to_date"
        return out
    # Compare against the device's reported anti-rollback floor. The device
    # refuses only packed(version) STRICTLY BELOW the floor (cwm_ota.c:
    # `mf_packed < floor`), so mirror that with `<` — NOT `<=`. A release
    # packing EQUAL to the floor is installable on-device; `<=` would wrongly
    # skip a newer same-base dev canary (X.Y.Z-dev.<ts2> packs to the same base
    # as a matured X.Y.Z floor) that the device accepts.
    if release_packed < dev.active.payload.min_secure_version:
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
    # One release lookup per distinct (SKU, channel): a dev S1 device and a
    # stable S1 device pull different assets, so the SKU alone is not the key.
    targets: dict[str, tuple[str, str]] = {}
    for dev in reg.list():
        if not dev.hw_sku:
            continue
        if device_filter and dev.device_id != device_filter:
            continue
        if sku_filter and dev.hw_sku != sku_filter:
            continue
        wanted.append(dev)
        # A dev unit consumes BOTH stable and dev (candidate_channels), so it
        # can contribute two targets; the newest-wins choice is made per
        # device below.
        for channel in candidate_channels(dev):
            targets[f"{dev.hw_sku}/{channel}"] = (dev.hw_sku, channel)

    own_session = session is None
    if own_session:
        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_SECONDS))
    try:
        # Dev resolution needs the GitHub releases listing (no "latest
        # prerelease" redirect exists). Fetch it ONCE per check, and only if a
        # dev target is in scope — a stable-only fleet makes zero API calls. A
        # listing failure is surfaced per dev SKU below.
        dev_rels: list | None = None
        dev_err: _SkuError | None = None
        if any(ch and ch != "stable" for _, ch in targets.values()):
            try:
                dev_rels = await _list_dev_releases(session, o.releases_repo)
            except _SkuError as e:
                dev_err = e

        resolved_by_key: dict[str, dict] = {}
        for key in sorted(targets):
            sku, channel = targets[key]
            if channel and channel != "stable" and dev_err is not None:
                rep["per_sku"].append({"sku": sku, "channel": "dev", "verified": False, "error": str(dev_err)})
                continue
            try:
                idx = await _fetch_index(session, o.releases_repo, sku, channel, dev_rels)
                resolved, sres = _resolve_sku(cfg, idx, sku, channel)
            except _SkuError as e:
                rep["per_sku"].append({"sku": sku, "channel": channel, "verified": False, "error": str(e)})
                continue
            rep["per_sku"].append(_drop_empty(sres, ("latest_version", "error")))
            if resolved is not None:
                resolved_by_key[key] = resolved
    finally:
        if own_session:
            await session.close()

    for dev in wanted:
        # Across the device's candidate channels, pick the resolved release
        # with the NEWEST version by SemVer: a final X.Y.Z beats a same-base
        # X.Y.Z-dev.<ts> prerelease, and a newer dev timestamp beats an older
        # one. A dev unit thus rides whichever of stable/dev is ahead (so a
        # freshly cut stable graduates it off an older dev tip); a production
        # unit only ever resolves stable. Ties prefer stable (first in
        # candidate_channels).
        best: dict | None = None
        best_channel = effective_channel(dev)
        for channel in candidate_channels(dev):
            resolved = resolved_by_key.get(f"{dev.hw_sku}/{channel}")
            if resolved is None:
                continue
            if best is None:
                best = resolved
                best_channel = channel
                continue
            cmp = compare_semver(str(resolved["mf"].get("version", "")), str(best["mf"].get("version", "")))
            if cmp is not None and cmp > 0:
                best = resolved
                best_channel = channel
        if best is None:
            rep["devices"].append({"device_id": dev.device_id, "sku": dev.hw_sku, "channel": effective_channel(dev), "action": "skipped:no-release"})
            continue
        res = _decide(reg, dev, best, dry_run)
        res["channel"] = best_channel
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
