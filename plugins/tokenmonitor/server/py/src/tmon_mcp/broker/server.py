"""HTTP broker: /credentials, /credentials/codex, /device/<id>/sync,
/firmware-logs, /usage/{claude,codex,antigravity} (deprecated "gemini" alias
accepted), /spend/{claude,codex} (antigravity not implemented).

Wire-compatible with tokenmonitor-mcp/internal/broker/server.go.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Awaitable, Callable

import aiohttp
from aiohttp import web

from .. import auth, creds, devlog, spend, usage
from .. import usbprov
from ..config import Config, firmware_path
from ..registry import crypto as reg_crypto
from ..registry import store as registry  # alias kept for parity with Go broker
from ..registry.store import NotFound, Registry, valid_device_id

log = logging.getLogger("tmon_mcp.broker")

FirmwareLogSource = Callable[[int], dict]  # returns {connected, total, lines}


def _error(status: int, msg: str) -> web.Response:
    return web.json_response({"error": msg}, status=status)


def _snapshot_body(snap: Any) -> dict:
    """asdict(snap) but with `degraded` emitted only when true — so the wire
    matches Go (omitempty) and JS (property set only when true). Harmless for
    snapshots (e.g. spend) that never carry the field."""
    body = asdict(snap)
    if not body.get("degraded"):
        body.pop("degraded", None)
    return body


def _stale_response(snap: Any, reason: str) -> web.Response:
    """200 + last-good snapshot + X-Tmon-Stale-Reason, mirroring Go/JS
    stale-with-200 (go/internal/broker/server.go ~586-600,
    js/src/broker/server.js ~291-295). reason is the upstream error message."""
    snap.fetched_at_unix = snap.fetched_at_unix or int(time.time())
    resp = web.json_response(_snapshot_body(snap))
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Tmon-Stale-Reason"] = reason
    return resp


def _map_usage_error(e: "usage.UsageError") -> tuple[int, web.Response]:
    """Map a UsageError with NO last-good snapshot to (status, response).
    Caller handles the stale-with-200 case before reaching here."""
    if isinstance(e, usage.NotImplementedProvider):
        return 501, _error(501, "provider not enabled")
    if isinstance(e, usage.CredsMissing):
        return 404, _error(404, "creds file missing")
    if isinstance(e, usage.TokenExpired):
        return 503, _error(503, "token expired, refresh on laptop")
    if isinstance(e, usage.Unauthorized):
        return 401, _error(401, "upstream rejected token")
    if isinstance(e, usage.RateLimited):
        r = _error(429, "rate limited")
        if e.retry_after > 0:
            r.headers["Retry-After"] = str(e.retry_after)
        return 429, r
    # 502 bodies are FIXED strings (Go parity, usageErrorToHTTP): the detail
    # goes to a server log, never to the client, so the wire body matches.
    if isinstance(e, usage.Transport):
        log.warning("usage transport error: %s", e)
        return 502, _error(502, "transport error")
    if isinstance(e, (usage.Upstream, usage.ParseUpstream)):
        log.warning("usage upstream error: %s", e)
        return 502, _error(502, "upstream error")
    # Unknown UsageError subclass: internal error (Go default), logged.
    log.warning("usage internal error: %s", e)
    return 500, _error(500, "internal error")


def make_app(
    cfg: Config,
    cache: auth.NonceCache,
    state,
    fw_logs: FirmwareLogSource | None,
    registry: Registry | None,
    usage_cache: usage.Cache | None = None,
    spend_cache: spend.Cache | None = None,
    lease: "usbprov.LeaseManager | None" = None,
) -> web.Application:
    app = web.Application()
    app["cfg"] = cfg
    app["cache"] = cache
    app["state"] = state
    app["fw_logs"] = fw_logs
    app["registry"] = registry
    app["usage_cache"] = usage_cache
    app["spend_cache"] = spend_cache
    # Leader-mediated serial-lease table (None on a host with no serial device
    # configured → 503 so the follower falls back to a direct exclusive open).
    app["lease"] = lease
    # One shared aiohttp.ClientSession so connections to upstream APIs
    # (Anthropic/ChatGPT/Google) are pooled across requests. Created on
    # startup so we don't pay TLS handshake on every /usage hit.
    async def _start(_app: web.Application) -> None:
        _app["http"] = aiohttp.ClientSession()

    async def _cleanup(_app: web.Application) -> None:
        sess = _app.get("http")
        if sess is not None:
            await sess.close()

    # Reap lapsed leases (leader-scoped) so a follower that crashed mid-session
    # cannot wedge the tailer off its port forever. Mirrors the Go broker's
    # 1s ReapExpired ticker. Only runs when a lease manager is wired.
    async def _start_reaper(_app: web.Application) -> None:
        lm = _app.get("lease")
        if lm is None:
            return

        async def _reap_loop() -> None:
            try:
                while True:
                    await asyncio.sleep(1.0)
                    lm.reap_expired()
            except asyncio.CancelledError:
                return

        _app["lease_reaper"] = asyncio.create_task(_reap_loop())

    async def _stop_reaper(_app: web.Application) -> None:
        task = _app.get("lease_reaper")
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    app.on_startup.append(_start)
    app.on_startup.append(_start_reaper)
    app.on_cleanup.append(_cleanup)
    app.on_cleanup.append(_stop_reaper)

    app.router.add_get("/credentials", _handle_credentials)
    app.router.add_get("/credentials/codex", _handle_credentials_codex)
    app.router.add_get("/firmware-logs", _handle_firmware_logs)
    # Leader-mediated serial-port lease (compat/PROVISION_WIRE.md §6). Exact
    # paths (no trailing slash); one handler dispatches on the path after auth.
    # Registered for ALL methods so a wrong method still reaches the handler
    # (503-before-403-before-405 ordering), mirroring the Go mux.
    app.router.add_route("*", usbprov.leasewire.LEASE_PATH, _handle_serial_lease)
    app.router.add_route("*", usbprov.leasewire.LEASE_RENEW_PATH, _handle_serial_lease)
    app.router.add_route("*", usbprov.leasewire.LEASE_RELEASE_PATH, _handle_serial_lease)
    app.router.add_get("/device/{device_id}/sync", _handle_device_sync)
    app.router.add_get("/device/{device_id}/panel", _handle_device_panel)
    app.router.add_post("/device/{device_id}/logs", _handle_device_logs)
    app.router.add_post("/device/{device_id}/settings", _handle_device_settings)
    app.router.add_get("/usage/{provider}", _handle_usage)
    app.router.add_get("/spend/{provider}", _handle_spend)
    # add_get registers HEAD too (allow_head=True by default), routed to the
    # same handler — FileResponse serves HEAD (headers only) correctly. A
    # separate add_head() would double-register HEAD on the resource and
    # raise "method HEAD is already registered" on modern aiohttp.
    app.router.add_get("/firmware/{name}", _handle_firmware)
    # Catch-all: a "*" route shadows aiohttp's own 405, so distinguish a wrong
    # method on a KNOWN path (405) from an unknown path (404) manually, keeping
    # the JSON error shape. Matches the Go/JS routers.
    app.router.add_route("*", "/{tail:.*}", _not_found_or_405)
    return app


# (regex, allowed methods) for every registered route, used by the catch-all
# to return 405 on a method mismatch instead of 404.
_ROUTE_METHODS: list[tuple[re.Pattern[str], set[str]]] = [
    (re.compile(r"^/credentials$"), {"GET"}),
    (re.compile(r"^/credentials/codex$"), {"GET"}),
    (re.compile(r"^/firmware-logs$"), {"GET"}),
    (re.compile(r"^/device/[^/]+/sync$"), {"GET"}),
    (re.compile(r"^/device/[^/]+/panel$"), {"GET"}),
    (re.compile(r"^/device/[^/]+/logs$"), {"POST"}),
    (re.compile(r"^/device/[^/]+/settings$"), {"POST"}),
    (re.compile(r"^/usage/[^/]+$"), {"GET"}),
    (re.compile(r"^/spend/[^/]+$"), {"GET"}),
    (re.compile(r"^/firmware/[^/]+$"), {"GET", "HEAD"}),
]


async def _not_found_or_405(req: web.Request) -> web.Response:
    for pat, methods in _ROUTE_METHODS:
        if pat.match(req.path):
            if req.method not in methods:
                return _error(405, "method not allowed")
            break
    return _error(404, "not found")


# Bounds a lease request body. Lease JSON is a port path or a 32-hex id plus a
# TTL — tiny; the cap just stops a malformed peer streaming.
_MAX_LEASE_BODY_BYTES = 4 << 10

# Bounds a device settings report. The report is a small flat object plus
# `wifi_known` (8 entries of ~42 bytes plus an SSID), but an SSID is 32
# arbitrary octets and cJSON escapes control bytes as \u00XX — six bytes each —
# so the honest worst case is ~2.2 KB. 4 KiB clears it. The previous 512 wedged
# real devices: past ~7 remembered networks every report was rejected, and the
# firmware dirty flag, which only clears on a 2xx, then vetoed every
# broker-pushed display setting forever. Raising it repairs deployed firmware.
_MAX_SETTINGS_BODY_BYTES = 4 << 10


def _is_loopback_peer(req: web.Request) -> bool:
    """Whether the real TCP peer is a loopback IP. Uses the transport peername
    (never a spoofable Host / X-Forwarded-For header); a missing/unparseable
    host fails closed (not loopback)."""
    host = ""
    tr = req.transport
    if tr is not None:
        peer = tr.get_extra_info("peername")
        if peer:
            host = peer[0]
    if not host:
        host = req.remote or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    # Unmap an IPv4-mapped IPv6 address (::ffff:127.0.0.1) so a loopback follower
    # arriving over a dual-stack IPv6 socket is still recognised as loopback —
    # Go's net.IP.IsLoopback does this; Python's is_loopback did not before 3.13.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


async def _handle_serial_lease(req: web.Request) -> web.Response:
    """Service the three leader-mediated serial-lease endpoints
    (compat/PROVISION_WIRE.md §6): a follower asks the leader to suspend its
    tailer. `lease` is None on a host with no serial device (503). Auth is the
    shared-PSK loopback HMAC with a MANDATORY body digest — an absent
    X-Tmon-Body-Sha256 is 401, never a silent v2 downgrade. Mirrors the Go
    broker's serial_lease.go byte-for-byte."""
    cfg: Config = req.app["cfg"]
    cache: auth.NonceCache = req.app["cache"]
    lease: "usbprov.LeaseManager | None" = req.app.get("lease")

    if lease is None:
        return _error(503, "serial port not configured on this host")
    # Loopback-only, INDEPENDENT of the broker's bind address: the lease grants
    # control of a HOST-LOCAL resource; the PSK must not implicitly confer remote
    # serial-ownership control. A follower always dials 127.0.0.1.
    if not _is_loopback_peer(req):
        log.info("lease %s rejected: non-loopback peer %s", req.path, req.remote)
        return _error(403, "serial lease is loopback-only")
    if req.method != "POST":
        return _error(405, "method not allowed")

    # Body FIRST (bounded), then body-aware auth — the v3 signature covers
    # sha256(body). Reading before auth is safe: nothing is acted on until it
    # checks out. Cap the read at _MAX_LEASE_BODY_BYTES streaming (like Go's
    # http.MaxBytesReader), so a missing/lying Content-Length can't make an
    # unauthenticated peer buffer an oversized body.
    if req.content_length is not None and req.content_length > _MAX_LEASE_BODY_BYTES:
        return _error(413, "body too large")
    buf = bytearray()
    try:
        async for chunk in req.content.iter_chunked(4096):
            buf += chunk
            if len(buf) > _MAX_LEASE_BODY_BYTES:
                return _error(413, "body too large")
    except Exception:  # noqa: BLE001
        return _error(400, "bad request body")
    raw = bytes(buf)

    body_sha = req.headers.get("X-Tmon-Body-Sha256", "")
    if not body_sha:
        # These endpoints mutate port ownership; refuse an unsigned body rather
        # than fall back to the v2 (body-blind) canonical.
        log.info("lease %s from %s: missing body digest", req.path, req.remote)
        return _error(401, "unauthorized")
    try:
        auth.verify_multi_body(
            [cfg.psk()],
            "POST", req.path,
            req.headers.get("X-Tmon-Timestamp", ""),
            req.headers.get("X-Tmon-Nonce", ""),
            req.headers.get("X-Tmon-Signature", ""),
            req.headers.get("X-Tmon-Device", ""),
            req.headers.get("X-Tmon-Config-Version", ""),
            body_sha,
            raw,
            cache,
            cfg.security.max_timestamp_skew_seconds,
        )
    except auth.AuthError as e:
        log.info("auth rejected %s from %s: %s", req.path, req.remote, e)
        return _error(401, "unauthorized")

    if req.path == usbprov.leasewire.LEASE_PATH:
        return await _handle_lease_grant(lease, raw)
    if req.path == usbprov.leasewire.LEASE_RENEW_PATH:
        return _handle_lease_renew(lease, raw)
    if req.path == usbprov.leasewire.LEASE_RELEASE_PATH:
        return _handle_lease_release(lease, raw)
    return _error(404, "not found")


def _lease_ttl_ms(req_obj: dict) -> int:
    """Extract ttl_ms with Go-parity strictness: JSON int only. bool, string and
    fractional-float values are rejected (400), matching a Go json.Unmarshal into
    int64. A missing key is 0 (the manager then applies its default/clamp)."""
    v = req_obj.get("ttl_ms", 0)
    if v is None:
        return 0
    # bool is an int subclass in Python; Go would reject `true` for an int64.
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("ttl_ms must be an integer")
    # Python ints are unbounded, Go's int64 is not: a value Go answers 400 for
    # must not quietly clamp to the max here, or the same request gets two
    # different answers depending on which runtime is leader.
    if not (-(2**63) <= v < 2**63):
        raise ValueError("ttl_ms out of int64 range")
    return v


async def _handle_lease_grant(lease: "usbprov.LeaseManager", raw: bytes) -> web.Response:
    try:
        req_obj = json.loads(raw)
        port = req_obj.get("port", "")
        ttl_ms = _lease_ttl_ms(req_obj)
    except (ValueError, TypeError, AttributeError):
        return _error(400, "bad lease request")
    if not port or not isinstance(port, str):
        return _error(400, "bad lease request")
    # Canonicalise on the leader (abspath + realpath) so the lease slot key
    # matches what the tailer and the follower's open_exclusive both compute.
    try:
        canonical = usbprov.canonical_port(port)
    except OSError:
        return _error(400, "unresolvable port")
    # grant() can BLOCK: it calls the tailer's suspend_port, which waits for the
    # reader to close its fd + flock. Run it off the event loop so a suspend
    # doesn't stall every other broker request on this single-threaded loop.
    try:
        lease_id, granted, _expires = await asyncio.to_thread(
            lease.grant, canonical, ttl_ms / 1000.0
        )
    except usbprov.LeaseBusy:
        # PROVISION_WIRE §6: the 409 body is {"error":"busy","holder":...}, not
        # a plain error string. The port is always busy on a competing lease
        # here (grant suspends the tailer before recording), so holder="lease".
        return web.json_response({"error": "busy", "holder": "lease"}, status=409)
    except Exception as e:  # noqa: BLE001
        log.warning("lease grant %s: %s", canonical, e)
        return _error(503, "cannot yield port")
    return web.json_response(
        {
            "lease_id": lease_id,
            # "port" echoes the CANONICAL path the leader keyed the lease on,
            # which is not necessarily the alias the follower asked for.
            "port": canonical,
            "ttl_ms": int(round(granted * 1000)),
            "expires_unix_ms": int((time.time() + granted) * 1000),
        }
    )


def _handle_lease_renew(lease: "usbprov.LeaseManager", raw: bytes) -> web.Response:
    # The renew request carries ONLY the lease id (PROVISION_WIRE §6). Any
    # ttl_ms in the body is ignored, deliberately: the leader re-applies the
    # TTL it originally granted so a renew can never shrink the window.
    try:
        req_obj = json.loads(raw)
        lease_id = req_obj.get("lease_id", "")
    except (ValueError, TypeError, AttributeError):
        return _error(400, "bad renew request")
    if not lease_id or not isinstance(lease_id, str):
        return _error(400, "bad renew request")
    try:
        granted, _expires = lease.renew(lease_id)
    except usbprov.LeaseUnknown:
        # 410 Gone: the lease lapsed or never existed → the follower MUST abort
        # its session (the port may already be back with the tailer). This is a
        # KNOWN route with an unknown lease, distinct from the grant path's 404
        # (an old leader lacking the route entirely → direct-open fallback).
        return _error(410, "lease unknown or expired")
    except Exception as e:  # noqa: BLE001
        log.warning("lease renew: %s", e)
        return _error(500, "renew error")
    return web.json_response(
        {
            "ttl_ms": int(round(granted * 1000)),
            "expires_unix_ms": int((time.time() + granted) * 1000),
        }
    )


def _handle_lease_release(lease: "usbprov.LeaseManager", raw: bytes) -> web.Response:
    try:
        req_obj = json.loads(raw)
        lease_id = req_obj.get("lease_id", "")
    except (ValueError, TypeError, AttributeError):
        return _error(400, "bad release request")
    if not lease_id or not isinstance(lease_id, str):
        return _error(400, "bad release request")
    # Idempotent: an unknown/expired id is still a success.
    lease.release(lease_id)
    return web.json_response({"ok": True})


_firmware_sha_cache: dict[str, tuple[float, int, str]] = {}


def _firmware_sha(path: Path) -> str:
    st = path.stat()
    key = str(path)
    cached = _firmware_sha_cache.get(key)
    if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
        return cached[2]
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    hexed = h.hexdigest()
    _firmware_sha_cache[key] = (st.st_mtime, st.st_size, hexed)
    return hexed


async def _handle_firmware(req: web.Request) -> web.Response:
    """Serve binaries from ``firmware_path()`` to OTA-armed devices.

    HMAC-authenticated with the same canonical-v2 scheme as
    ``/credentials``. Accepts global PSK and, when X-Tmon-Device is
    set, the device's active and pending PSKs. Supports Range:
    requests via aiohttp's FileResponse so resume-on-reconnect works.
    """
    cfg: Config = req.app["cfg"]
    cache: auth.NonceCache = req.app["cache"]
    registry: Registry | None = req.app["registry"]

    name = req.match_info.get("name", "")
    if not name or "/" in name or "\\" in name:
        return _error(400, "invalid filename")

    base = Path(firmware_path()).resolve()
    full = (base / name).resolve()
    # Path traversal: every legitimate file lives directly under `base`.
    try:
        full.relative_to(base)
    except ValueError:
        return _error(400, "invalid path")

    signed_path = req.path
    psks: list[bytes | None] = [cfg.psk()]
    if registry is not None:
        dev_id = req.headers.get("X-Tmon-Device", "")
        if valid_device_id(dev_id):
            try:
                a, p = registry.psks_for(dev_id)
                if a:
                    psks.append(a)
                if p:
                    psks.append(p)
            except NotFound:
                pass
            except Exception as e:
                log.warning("registry lookup %s: %s", dev_id, e)
    try:
        auth.verify_multi(
            psks,
            "GET", signed_path,
            req.headers.get("X-Tmon-Timestamp", ""),
            req.headers.get("X-Tmon-Nonce", ""),
            req.headers.get("X-Tmon-Signature", ""),
            req.headers.get("X-Tmon-Device", ""),
            req.headers.get("X-Tmon-Config-Version", ""),
            cache,
            cfg.security.max_timestamp_skew_seconds,
        )
    except auth.AuthError as e:
        log.info("auth rejected /firmware/%s from %s: %s", name, req.remote, e)
        return _error(401, "unauthorized")

    if not full.is_file():
        return _error(404, "firmware not found")

    headers = {"Cache-Control": "no-store", "Content-Type": "application/octet-stream"}
    try:
        sha = _firmware_sha(full)
        headers["ETag"] = f'"{sha}"'
        headers["X-Tmon-Firmware-SHA256"] = sha
    except OSError:
        pass
    # FileResponse handles Range:, If-None-Match, mtime → 304.
    return web.FileResponse(path=full, headers=headers)


async def _handle_credentials(req: web.Request) -> web.Response:
    cfg: Config = req.app["cfg"]
    cache: auth.NonceCache = req.app["cache"]
    state = req.app["state"]
    registry: Registry | None = req.app["registry"]

    status_to_record = 200
    try:
        device_id = req.headers.get("X-Tmon-Device", "")
        if registry is not None and device_id:
            if not valid_device_id(device_id):
                status_to_record = 400
                return _error(400, "invalid device_id")
            try:
                active, pending = registry.psks_for(device_id)
            except NotFound:
                status_to_record = 404
                return _error(404, "unknown device")
            except Exception as e:
                log.warning("registry lookup %s: %s", device_id, e)
                status_to_record = 500
                return _error(500, "registry error")
            try:
                res = auth.verify_multi(
                    [active, pending],
                    "GET", "/credentials",
                    req.headers.get("X-Tmon-Timestamp", ""),
                    req.headers.get("X-Tmon-Nonce", ""),
                    req.headers.get("X-Tmon-Signature", ""),
                    req.headers.get("X-Tmon-Device", ""),
                    req.headers.get("X-Tmon-Config-Version", ""),
                    cache,
                    cfg.security.max_timestamp_skew_seconds,
                )
            except auth.AuthError as e:
                log.info("auth rejected /credentials device=%s from %s: %s", device_id, req.remote, e)
                status_to_record = 401
                return _error(401, "unauthorized")
            obs = _parse_uint32(req.headers.get("X-Tmon-Config-Version", ""))
            try:
                registry.maybe_promote(device_id, obs, res.psk_index == 1)
            except Exception as e:
                log.warning("registry promote %s: %s", device_id, e)
            try:
                registry.touch(device_id)
            except Exception as e:
                log.warning("registry touch %s: %s", device_id, e)
        else:
            try:
                auth.verify(
                    cfg.psk(),
                    "GET", "/credentials",
                    req.headers.get("X-Tmon-Timestamp", ""),
                    req.headers.get("X-Tmon-Nonce", ""),
                    req.headers.get("X-Tmon-Signature", ""),
                    req.headers.get("X-Tmon-Device", ""),
                    req.headers.get("X-Tmon-Config-Version", ""),
                    cache,
                    cfg.security.max_timestamp_skew_seconds,
                )
            except auth.AuthError as e:
                log.info("auth rejected /credentials from %s: %s", req.remote, e)
                status_to_record = 401
                return _error(401, "unauthorized")

        try:
            c = creds.load(cfg.oauth_path_abs())
        except creds.CredsFileMissing:
            status_to_record = 404
            return _error(404, "credentials file missing")
        except creds.CredsParse as e:
            log.warning("cannot parse credentials: %s", e)
            status_to_record = 500
            return _error(500, "cannot read credentials")

        if c.is_expired(int(time.time() * 1000)):
            status_to_record = 503
            return _error(503, "token expired, refresh on laptop")

        body = {"access_token": c.access_token, "expires_at": c.expires_at_iso()}
        resp = web.json_response(body)
        resp.headers["Cache-Control"] = "no-store"
        return resp
    finally:
        try:
            state.record_request(req.remote or "", status_to_record)
        except Exception:
            pass


async def _verify_for_path(req: web.Request, path: str) -> tuple[bool, web.Response | None]:
    """Run the same HMAC dance as /credentials but for an arbitrary path.

    Returns (ok, error_response). When ok is False, error_response is the
    web.Response the caller should return immediately.
    """
    cfg: Config = req.app["cfg"]
    cache: auth.NonceCache = req.app["cache"]
    registry: Registry | None = req.app["registry"]

    device_id = req.headers.get("X-Tmon-Device", "")
    if registry is not None and device_id:
        if not valid_device_id(device_id):
            return False, _error(400, "invalid device_id")
        try:
            active, pending = registry.psks_for(device_id)
        except NotFound:
            return False, _error(404, "unknown device")
        except Exception as e:
            log.warning("registry lookup %s: %s", device_id, e)
            return False, _error(500, "registry error")
        try:
            res = auth.verify_multi(
                [active, pending],
                "GET", path,
                req.headers.get("X-Tmon-Timestamp", ""),
                req.headers.get("X-Tmon-Nonce", ""),
                req.headers.get("X-Tmon-Signature", ""),
                req.headers.get("X-Tmon-Device", ""),
                req.headers.get("X-Tmon-Config-Version", ""),
                cache,
                cfg.security.max_timestamp_skew_seconds,
            )
        except auth.AuthError as e:
            log.info("auth rejected %s device=%s from %s: %s", path, device_id, req.remote, e)
            return False, _error(401, "unauthorized")
        obs = _parse_uint32(req.headers.get("X-Tmon-Config-Version", ""))
        try:
            registry.maybe_promote(device_id, obs, res.psk_index == 1)
        except Exception as e:
            log.warning("registry promote %s: %s", device_id, e)
        try:
            registry.touch(device_id)
        except Exception as e:
            log.warning("registry touch %s: %s", device_id, e)
        return True, None

    try:
        auth.verify(
            cfg.psk(),
            "GET", path,
            req.headers.get("X-Tmon-Timestamp", ""),
            req.headers.get("X-Tmon-Nonce", ""),
            req.headers.get("X-Tmon-Signature", ""),
            req.headers.get("X-Tmon-Device", ""),
            req.headers.get("X-Tmon-Config-Version", ""),
            cache,
            cfg.security.max_timestamp_skew_seconds,
        )
    except auth.AuthError as e:
        log.info("auth rejected %s from %s: %s", path, req.remote, e)
        return False, _error(401, "unauthorized")
    return True, None


async def _handle_credentials_codex(req: web.Request) -> web.Response:
    cfg: Config = req.app["cfg"]
    state = req.app["state"]
    status_to_record = 200
    try:
        # Authenticate BEFORE revealing whether codex is enabled — otherwise an
        # unsigned probe distinguishes enabled (401) from disabled (404),
        # leaking the provider's enablement to unauthenticated callers. Matches
        # the Go reference (handleCodexCredentials: verify, then enabled).
        ok, err_resp = await _verify_for_path(req, "/credentials/codex")
        if not ok:
            status_to_record = err_resp.status
            return err_resp
        if not cfg.codex.enabled:
            status_to_record = 404
            return _error(404, "codex provider disabled")
        try:
            c = creds.load_codex(cfg.codex_auth_path_abs())
        except creds.CredsFileMissing:
            status_to_record = 503
            return _error(503, "codex credentials file missing")
        except creds.CredsParse as e:
            log.warning("cannot parse codex credentials: %s", e)
            status_to_record = 500
            return _error(500, "cannot read codex credentials")
        if c.is_expired(int(time.time() * 1000)):
            status_to_record = 503
            return _error(503, "codex token expired, refresh on laptop")
        body = {
            "access_token": c.access_token,
            "expires_at": c.expires_at_iso(),
            "account_id": c.account_id,
        }
        resp = web.json_response(body)
        resp.headers["Cache-Control"] = "no-store"
        return resp
    finally:
        try:
            state.record_request(req.remote or "", status_to_record)
        except Exception:
            pass


async def _handle_usage(req: web.Request) -> web.Response:
    """Serve a synthesised usage snapshot at /usage/{provider}.

    The broker caches per-provider results in usage.Cache; on cache miss
    or stale entry the fetcher hits upstream. Errors map to HTTP via the
    same convention as /credentials, with the addition that a last-good
    snapshot is preferred over an error response (the firmware logs the
    X-Tmon-Stale-Reason header but keeps rendering the bars).
    """
    state = req.app["state"]
    usage_cache: usage.Cache | None = req.app["usage_cache"]
    http: aiohttp.ClientSession = req.app["http"]
    provider = req.match_info["provider"]
    status_to_record = 200
    try:
        ok, err_resp = await _verify_for_path(req, f"/usage/{provider}")
        if not ok:
            status_to_record = err_resp.status
            return err_resp
        # HMAC was verified against the literal path above; only now fold the
        # deprecated "gemini" wire alias onto the canonical "antigravity" key
        # for cache/fetcher lookup. Old firmware that signs /usage/gemini keeps
        # working; new firmware uses /usage/antigravity directly.
        provider = usage.canonical_provider(provider)
        if usage_cache is None:
            status_to_record = 503
            return _error(503, "usage disabled (no providers configured)")

        # NOTE: the per-device Antigravity model override was removed (bug 27).
        # fetch_with_models ignored its models arg since the quota went grouped,
        # so the override was a pure cache bypass (two upstream Google calls per
        # poll for an identical result). The gemini_models registry→device wire
        # plumbing is unrelated (device-side config) and is kept.
        try:
            snap = await usage_cache.get(http, provider)
        except usage.UsageError as e:
            # Stale-with-200: when a last-good snapshot exists the cache
            # attaches it to the error. Surface 200 + X-Tmon-Stale-Reason
            # instead of the error (Go/JS parity). No snapshot → normal
            # error mapping.
            if getattr(e, "stale_snapshot", None) is not None:
                return _stale_response(e.stale_snapshot, str(e))
            status_to_record, r = _map_usage_error(e)
            return r
        body = _snapshot_body(snap)
        resp = web.json_response(body)
        resp.headers["Cache-Control"] = "no-store"
        return resp
    finally:
        try:
            state.record_request(req.remote or "", status_to_record)
        except Exception:
            pass


async def _handle_spend(req: web.Request) -> web.Response:
    """Serve locally-computed token cost at /spend/{provider}.

    Same HMAC envelope as /usage. The payload is parsed from the CLI logs
    on this host (no admin key). See compat/SPEND_WIRE.md.
    """
    state = req.app["state"]
    spend_cache: spend.Cache | None = req.app["spend_cache"]
    provider = req.match_info["provider"]
    status_to_record = 200
    try:
        ok, err_resp = await _verify_for_path(req, f"/spend/{provider}")
        if not ok:
            status_to_record = err_resp.status
            return err_resp
        # Canonicalize the deprecated "gemini" alias AFTER HMAC verification.
        provider = spend.canonical_provider(provider)
        if provider not in (spend.PROVIDER_CLAUDE, spend.PROVIDER_CODEX, spend.PROVIDER_ANTIGRAVITY):
            status_to_record = 404
            return _error(404, "unknown spend provider")
        if spend_cache is None:
            status_to_record = 501
            return _error(501, "spend disabled")
        try:
            snap = await spend_cache.get(provider)
        except spend.SpendError as e:
            # Stale-with-200: the cache attaches the last-good snapshot when
            # one exists; surface 200 + X-Tmon-Stale-Reason (Go/JS parity).
            if getattr(e, "stale_snapshot", None) is not None:
                return _stale_response(e.stale_snapshot, str(e))
            if isinstance(e, spend.NotImplementedProvider):
                status_to_record = 501
                return _error(501, "provider not enabled")
            if isinstance(e, spend.SpendUnavailable):
                status_to_record = 503
                return _error(503, "spend unavailable")
            # Any other SpendError is an internal fault (Go default), logged.
            log.warning("spend handler error: %s", e)
            status_to_record = 500
            return _error(500, "internal")
        resp = web.json_response(asdict(snap))
        resp.headers["Cache-Control"] = "no-store"
        return resp
    finally:
        try:
            state.record_request(req.remote or "", status_to_record)
        except Exception:
            pass


async def _handle_firmware_logs(req: web.Request) -> web.Response:
    cfg: Config = req.app["cfg"]
    cache: auth.NonceCache = req.app["cache"]
    fw_logs: FirmwareLogSource | None = req.app["fw_logs"]
    try:
        auth.verify(
            cfg.psk(),
            "GET", "/firmware-logs",
            req.headers.get("X-Tmon-Timestamp", ""),
            req.headers.get("X-Tmon-Nonce", ""),
            req.headers.get("X-Tmon-Signature", ""),
            req.headers.get("X-Tmon-Device", ""),
            req.headers.get("X-Tmon-Config-Version", ""),
            cache,
            cfg.security.max_timestamp_skew_seconds,
        )
    except auth.AuthError as e:
        log.info("auth rejected /firmware-logs from %s: %s", req.remote, e)
        return _error(401, "unauthorized")

    limit = 200
    try:
        raw = req.query.get("limit")
        if raw is not None:
            n = int(raw)
            limit = max(1, min(2000, n))
    except ValueError:
        pass
    if fw_logs is None:
        body = {"connected": False, "total_available": 0, "lines": []}
    else:
        body = fw_logs(limit)
    resp = web.json_response(body)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# Bounds the served panel document; the device parses into fixed buffers.
# Keep in sync with compat/PANEL_WIRE.md and the Go panelMaxBytes.
_PANEL_MAX_BYTES = 8 * 1024

# mtime+size cache mirroring _firmware_sha_cache: a program rewriting the file
# in place is picked up on the next poll.
_panel_cache: dict[str, tuple[float, int, bytes]] = {}


def _resolve_panel_path(cfg: Config, device_id: str) -> str:
    """Pick the file to serve for device_id, most specific first: the explicit
    [panel.file].<id> entry, then <dir>/<id>.json, then <dir>/default.json,
    then the [panel.file].default entry (a.k.a. the legacy bare file). "" = off.

    device_id has passed valid_device_id (no slashes) so <id>.json is safe."""
    explicit = cfg.panel_file_explicit_abs(device_id)
    if explicit:
        return explicit
    d = cfg.panel_dir_abs()
    if d:
        if device_id:
            p = Path(d) / f"{device_id}.json"
            if p.is_file():
                return str(p)
        p = Path(d) / "default.json"
        if p.is_file():
            return str(p)
    f = cfg.panel_file_default_abs()
    if f:
        return f
    return ""


def _read_panel_file(path: str) -> tuple[bytes | None, int, str]:
    """Return (body, err_status, err_msg). 404 absent, 422 oversize/non-JSON."""
    p = Path(path)
    try:
        st = p.stat()
    except FileNotFoundError:
        return None, 404, "no panel"
    except OSError as e:
        log.warning("panel stat %s: %s", path, e)
        return None, 500, "panel read error"
    if not p.is_file():
        return None, 404, "no panel"
    if st.st_size > _PANEL_MAX_BYTES:
        return None, 422, f"panel too large ({st.st_size} > {_PANEL_MAX_BYTES} bytes)"

    cached = _panel_cache.get(path)
    if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
        return cached[2], 0, ""

    try:
        raw = p.read_bytes()
    except OSError as e:
        log.warning("panel read %s: %s", path, e)
        return None, 500, "panel read error"
    try:
        json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None, 422, "panel is not valid JSON"

    _panel_cache[path] = (st.st_mtime, st.st_size, raw)
    return raw, 0, ""


async def _handle_device_panel(req: web.Request) -> web.Response:
    """GET /device/{id}/panel — serve the user-authored panel doc verbatim.

    Same HMAC envelope as /device/{id}/sync. Purely additive: not configured
    or file absent ⇒ 404, so the firmware has one "no panel" code path."""
    cfg: Config = req.app["cfg"]
    cache: auth.NonceCache = req.app["cache"]
    registry: Registry | None = req.app["registry"]
    if registry is None:
        return _error(404, "device registry not configured")

    device_id = req.match_info["device_id"]
    if not valid_device_id(device_id):
        return _error(400, "invalid device_id")

    try:
        active, pending = registry.psks_for(device_id)
    except NotFound:
        return _error(404, "unknown device")
    except Exception as e:
        log.warning("registry lookup %s: %s", device_id, e)
        return _error(500, "registry error")

    try:
        auth.verify_multi(
            [active, pending],
            "GET", req.path,
            req.headers.get("X-Tmon-Timestamp", ""),
            req.headers.get("X-Tmon-Nonce", ""),
            req.headers.get("X-Tmon-Signature", ""),
            req.headers.get("X-Tmon-Device", ""),
            req.headers.get("X-Tmon-Config-Version", ""),
            cache,
            cfg.security.max_timestamp_skew_seconds,
        )
    except auth.AuthError as e:
        log.info("auth rejected /device/%s/panel from %s: %s", device_id, req.remote, e)
        return _error(401, "unauthorized")

    path = _resolve_panel_path(cfg, device_id)
    if not path:
        return _error(404, "panel not configured")
    body, err_status, err_msg = _read_panel_file(path)
    if body is None:
        return _error(err_status, err_msg)
    resp = web.Response(body=body, content_type="application/json")
    resp.headers["Cache-Control"] = "no-store"
    return resp


async def _handle_device_sync(req: web.Request) -> web.Response:
    cfg: Config = req.app["cfg"]
    cache: auth.NonceCache = req.app["cache"]
    state = req.app["state"]
    registry: Registry | None = req.app["registry"]
    if registry is None:
        return _error(404, "device registry not configured")

    device_id = req.match_info["device_id"]
    if not valid_device_id(device_id):
        return _error(400, "invalid device_id")

    status_to_record = 200
    try:
        try:
            active, pending = registry.psks_for(device_id)
        except NotFound:
            status_to_record = 404
            return _error(404, "unknown device")
        except Exception as e:
            log.warning("registry lookup %s: %s", device_id, e)
            status_to_record = 500
            return _error(500, "registry error")

        signed_path = req.path  # canonical: full path as routed
        try:
            res = auth.verify_multi(
                [active, pending],
                "GET", signed_path,
                req.headers.get("X-Tmon-Timestamp", ""),
                req.headers.get("X-Tmon-Nonce", ""),
                req.headers.get("X-Tmon-Signature", ""),
                req.headers.get("X-Tmon-Device", ""),
                req.headers.get("X-Tmon-Config-Version", ""),
                cache,
                cfg.security.max_timestamp_skew_seconds,
            )
        except auth.AuthError as e:
            log.info("auth rejected /device/%s/sync from %s: %s", device_id, req.remote, e)
            status_to_record = 401
            return _error(401, "unauthorized")

        observed = _parse_uint32(req.headers.get("X-Tmon-Config-Version", ""))
        try:
            registry.maybe_promote(device_id, observed, res.psk_index == 1)
        except Exception as e:
            log.warning("registry promote %s: %s", device_id, e)
        try:
            registry.touch(device_id)
        except Exception as e:
            log.warning("registry touch %s: %s", device_id, e)
        # Schema v2: capture factory identity from headers. Not bound to
        # HMAC — metadata only. The Ed25519 manifest enforces SKU.
        serial_hdr = req.headers.get("X-Tmon-Serial", "")
        if serial_hdr:
            try:
                registry.set_serial(device_id, serial_hdr,
                                    req.headers.get("X-Tmon-Sku", ""))
            except Exception as e:
                log.warning("registry set_serial %s: %s", device_id, e)
        # Mirror anti-rollback floor. bump_min_sv is monotonic, so a
        # spoofed-high value only locks the device into rejecting
        # downgrades — it can't enable one.
        min_sv_hdr = req.headers.get("X-Tmon-Min-Sv", "")
        if min_sv_hdr:
            try:
                sv = int(min_sv_hdr)
                if 0 <= sv <= 0xFFFFFFFF:
                    registry.bump_min_sv(device_id, sv)
            except (ValueError, Exception) as e:
                log.warning("registry bump_min_sv %s: %s", device_id, e)
        # Persist the firmware version the device reports running into
        # Active.firmware_version (only-on-change). ota.decide() keys off it,
        # so this stops auto-discovery re-staging the same release after a
        # canary revert. Unsigned metadata, like serial/sku/min-sv above.
        fw_hdr = req.headers.get("X-Tmon-Fw-Version", "")
        if fw_hdr:
            try:
                registry.set_active_firmware_version(device_id, fw_hdr)
            except Exception as e:
                log.warning("registry set_active_firmware_version %s: %s", device_id, e)

        dev = registry.load(device_id)

        # Install-loop breaker, device-reported half. X-Tmon-Ota-Fail carries
        # the firmware's own verdict on an image it downloaded and booted but
        # that never self-confirmed — the device is the only party that can see
        # a rollback, since from the broker's side every step succeeded. The
        # stage-streak counter in ota.decide() catches the same loop without
        # any device change, but only at the hourly poll and only while the
        # broker stays up; either trigger alone closes the loop. Mirror of Go's
        # block in handleDeviceSync.
        fail = _parse_ota_fail(req.headers.get("X-Tmon-Ota-Fail", ""))
        if (
            fail is not None
            and fail[0] != fw_hdr
            and dev.blocked_firmware_version != fail[0]
        ):
            try:
                registry.set_blocked_firmware_version(device_id, fail[0])
                dev.blocked_firmware_version = fail[0]
                log.warning(
                    "device %s reports %s failed to install %d times (%s); "
                    "blocking that version — publish a newer one to clear it",
                    device_id, fail[0], fail[1], fail[2],
                )
            except Exception as e:
                log.warning("registry set_blocked_firmware_version %s: %s", device_id, e)

        resp_body: dict[str, Any] = {"active_version": dev.active.payload.version}
        # Advertise the broker self-version-check verdict on every 200 so the
        # device can surface a "broker outdated" banner. Only once known — an
        # unchecked/unreachable verdict stays absent (no false banner). Mirror
        # of Go's syncResponse omitempty fields.
        try:
            u = state.update()
        except Exception:
            u = None
        if u is not None and u.known:
            resp_body["broker_update_available"] = u.outdated
            resp_body["broker_version"] = u.current
            resp_body["broker_latest"] = u.latest
        if dev.pending is not None and observed < dev.pending.payload.version:
            if active is None or len(active) != 32:
                status_to_record = 500
                return _error(500, "broker config invalid")
            pt = _pending_payload_json(dev.pending.payload).encode("utf-8")
            pending_version = dev.pending.payload.version
            # Gate on the LIVE firmware version the device reports, never on
            # registry state: a device running >= PENDING_GCM_MIN_FW carries
            # the GCM decrypt path, so emit "enc":"gcm". Older firmware (or
            # an unparseable / absent header) gets the legacy 16-byte-IV CTR
            # blob. dev builds "0.9.0-dev.<ts>" pass the gate (same code).
            if reg_crypto.gcm_fw_gate_open(req.headers.get("X-Tmon-Fw-Version", "")):
                nonce, ct = reg_crypto.encrypt_pending_gcm(active, pt, pending_version)
                resp_body["pending"] = {
                    "version": pending_version,
                    "enc": "gcm",
                    "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                    "payload_b64": base64.b64encode(ct).decode("ascii"),
                }
            else:
                nonce, ct = reg_crypto.encrypt_pending(active, pt)
                resp_body["pending"] = {
                    "version": pending_version,
                    "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                    "payload_b64": base64.b64encode(ct).decode("ascii"),
                }
        resp = web.json_response(resp_body)
        resp.headers["Cache-Control"] = "no-store"
        return resp
    finally:
        try:
            state.record_request(req.remote or "", status_to_record)
        except Exception:
            pass


async def _handle_device_logs(req: web.Request) -> web.Response:
    """Receive a diagnostic log batch the device POSTs and append it to the
    per-device log file. Auth is identical to /sync; when the device sends
    X-Tmon-Body-Sha256 the signature also covers the body (HMAC v3, see
    compat/HMAC_CANONICAL.md). Body is size-capped and read before auth —
    safe, since nothing is parsed or stored until the signature checks out."""
    cfg: Config = req.app["cfg"]
    cache: auth.NonceCache = req.app["cache"]
    registry: Registry | None = req.app["registry"]
    if registry is None:
        return _error(404, "device registry not configured")

    device_id = req.match_info["device_id"]
    if not valid_device_id(device_id):
        return _error(400, "invalid device_id")

    try:
        active, pending = registry.psks_for(device_id)
    except NotFound:
        return _error(404, "unknown device")
    except Exception as e:
        log.warning("registry lookup %s: %s", device_id, e)
        return _error(500, "registry error")

    # Body FIRST (size-bounded), then body-aware auth.
    if req.content_length is not None and req.content_length > devlog.MAX_BODY_BYTES:
        return _error(413, "body too large")
    raw = await req.read()
    if len(raw) > devlog.MAX_BODY_BYTES:
        return _error(413, "body too large")

    signed_path = req.path
    try:
        auth.verify_multi_body(
            [active, pending],
            "POST", signed_path,
            req.headers.get("X-Tmon-Timestamp", ""),
            req.headers.get("X-Tmon-Nonce", ""),
            req.headers.get("X-Tmon-Signature", ""),
            req.headers.get("X-Tmon-Device", ""),
            req.headers.get("X-Tmon-Config-Version", ""),
            req.headers.get("X-Tmon-Body-Sha256", ""),
            raw,
            cache,
            cfg.security.max_timestamp_skew_seconds,
        )
    except auth.AuthError as e:
        log.info("auth rejected /device/%s/logs from %s: %s", device_id, req.remote, e)
        return _error(401, "unauthorized")

    lines = devlog.stamp_lines(raw.decode("utf-8", errors="replace"))
    try:
        devlog.append(registry.dir, device_id, lines)
    except Exception as e:
        log.warning("devlog append %s: %s", device_id, e)
        return _error(500, "log store error")
    return web.json_response({"stored": len(lines)}, status=202)


async def _handle_device_settings(req: web.Request) -> web.Response:
    """Apply a device-reported display-settings update to the registry
    (compat/SETTINGS_REPORT.md). The device owns these fields, so this
    converges the broker's stored config — no version bump, no reverts. Auth is
    identical to /logs; when the device sends X-Tmon-Body-Sha256 the signature
    also covers the body (HMAC v3)."""
    cfg: Config = req.app["cfg"]
    cache: auth.NonceCache = req.app["cache"]
    registry: Registry | None = req.app["registry"]
    if registry is None:
        return _error(404, "device registry not configured")

    device_id = req.match_info["device_id"]
    if not valid_device_id(device_id):
        return _error(400, "invalid device_id")

    try:
        active, pending = registry.psks_for(device_id)
    except NotFound:
        return _error(404, "unknown device")
    except Exception as e:
        log.warning("registry lookup %s: %s", device_id, e)
        return _error(500, "registry error")

    # Body FIRST (size-bounded), then body-aware auth — the v3 signature covers
    # sha256(body). Cap the read at _MAX_SETTINGS_BODY_BYTES *streaming*, the
    # same shape as the lease handler above and as Go's http.MaxBytesReader:
    # req.read() would buffer a chunked body with no Content-Length all the way
    # up to aiohttp's own 1 MiB limit, and then raise its own text/plain 413
    # instead of this endpoint's JSON error.
    if req.content_length is not None and req.content_length > _MAX_SETTINGS_BODY_BYTES:
        return _error(413, "settings body too large")
    buf = bytearray()
    try:
        async for chunk in req.content.iter_chunked(4096):
            buf += chunk
            if len(buf) > _MAX_SETTINGS_BODY_BYTES:
                return _error(413, "settings body too large")
    except Exception:  # noqa: BLE001
        return _error(400, "bad settings body")
    raw = bytes(buf)

    signed_path = req.path
    try:
        auth.verify_multi_body(
            [active, pending],
            "POST", signed_path,
            req.headers.get("X-Tmon-Timestamp", ""),
            req.headers.get("X-Tmon-Nonce", ""),
            req.headers.get("X-Tmon-Signature", ""),
            req.headers.get("X-Tmon-Device", ""),
            req.headers.get("X-Tmon-Config-Version", ""),
            req.headers.get("X-Tmon-Body-Sha256", ""),
            raw,
            cache,
            cfg.security.max_timestamp_skew_seconds,
        )
    except auth.AuthError as e:
        log.info("auth rejected /device/%s/settings from %s: %s", device_id, req.remote, e)
        return _error(401, "unauthorized")
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return _error(400, "bad settings body")
    # Canonical body handling shared with the Go/JS brokers: an empty
    # (or whitespace-only) body is a no-op; anything present must be a single
    # JSON object; null / arrays / scalars are rejected.
    if text == "":
        return web.Response(status=204)
    try:
        body = json.loads(text)
    except ValueError:
        return _error(400, "bad settings body")
    if not isinstance(body, dict):
        return _error(400, "bad settings body")

    # Type-validate the way Go's strongly-typed json.Decode does: a wrong JSON
    # type or an out-of-uint-range value is a 400, not a silent coercion.
    def _uint(key: str, max_v: int) -> int | None:
        v = body.get(key)
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > max_v:
            raise ValueError(f"bad {key}")
        return v

    try:
        theme_mode = body.get("theme_mode")
        if theme_mode is not None and not isinstance(theme_mode, str):
            raise ValueError("bad theme_mode")
        br_day = _uint("br_day", 255)
        br_night = _uint("br_night", 255)
        vol = _uint("vol", 255)
        autorotate_enabled = body.get("autorotate_enabled")
        if autorotate_enabled is not None and not isinstance(autorotate_enabled, bool):
            raise ValueError("bad autorotate_enabled")
        autorotate_interval_s = _uint("autorotate_interval_s", 65535)
        pet_enabled = body.get("pet_enabled")
        if pet_enabled is not None and not isinstance(pet_enabled, bool):
            raise ValueError("bad pet_enabled")
        panel_enabled = body.get("panel_enabled")
        if panel_enabled is not None and not isinstance(panel_enabled, bool):
            raise ValueError("bad panel_enabled")
        # pet_species is a uint (0..255 here); applyReported clamps to 0..9.
        # Absent → None → left untouched (device hasn't picked a species).
        pet_species = _uint("pet_species", 255)
        pet_name = body.get("pet_name")
        if pet_name is not None and not isinstance(pet_name, str):
            raise ValueError("bad pet_name")
        # Remembered networks, names only. Device input, so it is sanitised
        # before storage: entries with an empty or oversize SSID are dropped
        # and the list is truncated to what the on-device store can hold (8).
        # None (key absent) means firmware too old to report — distinct from
        # an empty list, which means "I remember none".
        wifi_known = body.get("wifi_known")
        if wifi_known is not None:
            if not isinstance(wifi_known, list):
                raise ValueError("bad wifi_known")
            cleaned = []
            for n in wifi_known:
                if not isinstance(n, dict):
                    continue
                ssid = n.get("ssid")
                # Bytes, not characters: the 802.11 SSID field is 32 OCTETS,
                # which is how the device and the Go broker both measure it.
                if (not isinstance(ssid, str) or not ssid
                        or len(ssid.encode("utf-8")) > 32):
                    continue
                verified, is_open = n.get("verified", False), n.get("open", False)
                # Strict, not truthy: Go's typed decode rejects a non-boolean
                # outright, and a coerced "false" string would silently flip a
                # network to open and make set_wifi refuse it forever.
                if not isinstance(verified, bool) or not isinstance(is_open, bool):
                    raise ValueError("bad wifi_known")
                cleaned.append({"ssid": ssid, "verified": verified, "open": is_open})
                if len(cleaned) == 8:
                    break
            wifi_known = cleaned
    except ValueError:
        return _error(400, "bad settings body")

    try:
        registry.report_settings(
            device_id,
            theme_mode=theme_mode,
            br_day=br_day,
            br_night=br_night,
            vol=vol,
            autorotate_enabled=autorotate_enabled,
            autorotate_interval_s=autorotate_interval_s,
            pet_enabled=pet_enabled,
            panel_enabled=panel_enabled,
            pet_species=pet_species,
            pet_name=pet_name,
            wifi_known=wifi_known,
        )
    except NotFound:
        return _error(404, "unknown device")
    except (ValueError, TypeError):
        return _error(400, "bad settings body")
    except Exception as e:
        log.warning("report settings %s: %s", device_id, e)
        return _error(500, "registry error")
    return web.Response(status=204)


# How many failed installs the DEVICE must report before the broker stops
# offering that version. See _parse_ota_fail.
#
# Two thresholds, mirroring TMON_OTA_MAX_INSTALLS / _SOFT in the firmware. They
# MUST match: the device gives up at its own threshold, and a broker that
# tombstoned earlier would silently shorten the device's retry budget — a
# version the firmware was still willing to try twice more would stop being
# offered after the first two circumstantial failures.
#
# Hard states are faults we can pin on the image (it crashed or hung before
# confirming); everything else — a brownout, a power cut before the confirm
# window closed, a reset we could not attribute — is circumstantial and needs
# more evidence before condemning a build that may well be fine.
#
# Unrecognised states get the SOFT threshold rather than being rejected:
# firmware and broker version independently, so a future firmware adding a
# state must not silently disable the breaker.
MIN_FAILED_INSTALLS_HARD = 2
MIN_FAILED_INSTALLS_SOFT = 4
_HARD_STATES = ("panic", "wdt")


def _ota_fail_threshold(state: str) -> int:
    return MIN_FAILED_INSTALLS_HARD if state in _HARD_STATES else MIN_FAILED_INSTALLS_SOFT


def _parse_ota_fail(h: str) -> tuple[str, int, str] | None:
    """Parse X-Tmon-Ota-Fail ("<version>:<installs>:<state>").

    Returns (version, installs, state) ONLY when the value is a well-formed
    report of a version that has definitively failed to install. Everything
    else — "none", an empty header, a malformed value, a still-in-flight
    "pending" state, or a count below the threshold — returns None.

    The header is unsigned metadata (like X-Tmon-Fw-Version and X-Tmon-Serial
    alongside it), so it is parsed defensively and fails closed: the worst a
    spoofer can achieve is to deny UPDATES to one device it can already
    impersonate, never to cause an install. See compat/SECURITY.md.

    Byte-for-byte mirror of Go parseOTAFail / JS parseOtaFail.
    """
    from ..ota import valid_version  # lazy: avoid import cycle (ota → registry)

    h = h.strip()
    if not h or h == "none" or len(h) > 64:
        return None
    parts = h.split(":")
    if len(parts) != 3:
        return None
    version, state = parts[0], parts[2]
    # Must name a real version, or a garbage string could be written into the
    # tombstone and then never match (and never clear) a published release.
    if not valid_version(version):
        return None
    # Strict digits, matching Go's strconv.Atoi. Bare int() would also accept
    # "1_0" (== 10) and surrounding whitespace, which Go rejects — and this
    # parser has to agree across all three runtimes byte for byte.
    if not re.fullmatch(r"[+-]?[0-9]+", parts[1]):
        return None
    n = int(parts[1])
    # The firmware stores installs as 0..255 (tmon_ota_fail_parse enforces it),
    # so anything outside that is not a record we wrote. Python ints are
    # unbounded, so without this an absurd count would sail past the threshold.
    if n < 0 or n > 255:
        return None
    # "pending" means the device armed the image but has not yet reported back
    # on it — the install may still succeed, so it is not evidence of failure.
    if not state or state == "pending":
        return None
    if n < _ota_fail_threshold(state):
        return None
    return version, n, state


def _parse_uint32(s: str) -> int:
    if not s:
        return 0
    try:
        v = int(s)
        if v < 0 or v > 0xFFFFFFFF:
            return 0
        return v
    except ValueError:
        return 0


def _pending_payload_json(p) -> str:
    wire: dict[str, Any] = {"version": int(p.version)}
    if p.broker_url:
        wire["broker_url"] = p.broker_url
    if p.psk_hex:
        wire["psk_hex"] = p.psk_hex
    if p.city:
        wire["city"] = p.city
    # br_day / br_night have documented ranges 10..100 / 5..100, so 0 is
    # out of range and treated as "no change". vol however accepts 0
    # (mute) — only None means "no change", to stay consistent with the
    # Go and JS impls.
    if p.br_day:
        wire["br_day"] = int(p.br_day)
    if p.br_night:
        wire["br_night"] = int(p.br_night)
    if p.vol is not None:
        wire["vol"] = int(p.vol)
    # Emit the rich provider_modes enum AND a derived legacy providers bool
    # map. New firmware reads provider_modes; pre-mode-split firmware only
    # understands the bool map. Both derive from the same source so they
    # never disagree (enabled == mode is neither "" nor "disabled").
    if p.provider_modes is not None:
        pm = p.provider_modes

        def _en(m: str) -> bool:
            return m not in ("", "disabled")

        # Dual-emit the Antigravity provider under BOTH the new "antigravity"
        # key and the deprecated "gemini" key. Firmware after the rename reads
        # "antigravity"; deployed firmware still reads "gemini". Both derive
        # from the same provider_modes.gemini field so they never disagree.
        # Drop the "gemini" key once the fleet has updated.
        wire["provider_modes"] = {
            "claude": pm.claude,
            "codex": pm.codex,
            "antigravity": pm.gemini,
            "gemini": pm.gemini,
        }
        wire["providers"] = {
            "claude": _en(pm.claude),
            "codex": _en(pm.codex),
            "antigravity": _en(pm.gemini),
            "gemini": _en(pm.gemini),
        }
    if p.autorotate_enabled is not None:
        wire["autorotate_enabled"] = bool(p.autorotate_enabled)
    if p.autorotate_interval_s is not None:
        wire["autorotate_interval_s"] = int(p.autorotate_interval_s)
    # firmware/config_sync.c reads "theme_mode" from the decrypted blob
    # and writes it to KEY_THEME_MD. Omitting it here would silently
    # no-op /tokenmonitor:theme switches.
    if getattr(p, "theme_mode", ""):
        wire["theme_mode"] = p.theme_mode
    if p.pet_enabled is not None:
        wire["pet_enabled"] = bool(p.pet_enabled)
    if p.panel_enabled is not None:
        wire["panel_enabled"] = bool(p.panel_enabled)
    if p.pet_species is not None:
        wire["pet_species"] = int(p.pet_species)
    if p.pet_name:
        wire["pet_name"] = str(p.pet_name)
    if p.wifi_ssid:
        wire["wifi_ssid"] = str(p.wifi_ssid)
        # Emitted ONLY alongside an SSID, and only when non-empty. A bare
        # wifi_pass is meaningless, and an empty one is not "open network"
        # here the way it is over the cable — the device never auto-joins an
        # open network, so the only thing an empty string could do is
        # overwrite a good stored password with nothing. Absent means "switch
        # to a network you already remember".
        if p.wifi_pass:
            wire["wifi_pass"] = str(p.wifi_pass)
    gm = getattr(p, "gemini_models", None)
    if gm is not None and len(gm) > 0:
        # Dual-emit the per-device model override CSV under the new
        # "antigravity_models" key and the deprecated "gemini_models" key.
        # firmware/config_sync.c (post-rename) reads "antigravity_models";
        # deployed firmware reads "gemini_models".
        csv = ",".join(str(m) for m in gm)
        wire["antigravity_models"] = csv
        wire["gemini_models"] = csv
    if getattr(p, "log_enabled", None) is not None:
        # firmware/config_sync.c reads "log_enabled" → NVS key tmon_log_en.
        wire["log_enabled"] = bool(p.log_enabled)
    # OTA staging fields. All three must be present or the device
    # ignores the bundle entirely (see firmware/components/net/src/
    # config_sync.c promote_candidate). Mirror that all-or-nothing on
    # the wire so the firmware never sees a partial spec.
    fu = getattr(p, "firmware_url", "")
    fs = getattr(p, "firmware_sha256", "")
    fv = getattr(p, "firmware_version", "")
    if fu and fs and fv:
        wire["firmware_url"] = fu
        wire["firmware_sha256"] = fs
        wire["firmware_version"] = fv
    # Schema v2 manifest envelope. Forwarded whichever fields are
    # present; the device-side gate enforces "both or neither".
    mb = getattr(p, "firmware_manifest_b64", "")
    ms = getattr(p, "firmware_manifest_sig_b64", "")
    if mb:
        wire["firmware_manifest_b64"] = mb
    if ms:
        wire["firmware_manifest_sig_b64"] = ms
    # Key-sorted, compact JSON so the plaintext is deterministic *within*
    # this runtime. NOTE: the encrypted bytes are NOT guaranteed identical
    # across impls — the SEMANTICS match, the bytes need not. Go's
    # json.Marshal HTML-escapes <>&, Python json with ensure_ascii=True
    # escapes non-ASCII as \uXXXX, and JS JSON.stringify emits raw UTF-8.
    # The device decodes whatever its own broker sent; cross-impl
    # byte-identity is not a requirement here.
    return json.dumps(wire, separators=(",", ":"), sort_keys=True)
