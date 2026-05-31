"""HTTP broker: /credentials, /credentials/codex, /device/<id>/sync,
/firmware-logs, /usage/{claude,codex,gemini}.

Wire-compatible with cwm-mcp/internal/broker/server.go.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import socket
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Awaitable, Callable

import aiohttp
from aiohttp import web

from .. import auth, creds, usage
from ..config import Config, firmware_path
from ..registry import crypto as reg_crypto
from ..registry import store as registry  # alias kept for parity with Go broker
from ..registry.store import NotFound, Registry, valid_device_id

log = logging.getLogger("cwm_mcp.broker")

FirmwareLogSource = Callable[[int], dict]  # returns {connected, total, lines}


def _error(status: int, msg: str) -> web.Response:
    return web.json_response({"error": msg}, status=status)


def make_app(
    cfg: Config,
    cache: auth.NonceCache,
    state,
    fw_logs: FirmwareLogSource | None,
    registry: Registry | None,
    usage_cache: usage.Cache | None = None,
) -> web.Application:
    app = web.Application()
    app["cfg"] = cfg
    app["cache"] = cache
    app["state"] = state
    app["fw_logs"] = fw_logs
    app["registry"] = registry
    app["usage_cache"] = usage_cache
    # One shared aiohttp.ClientSession so connections to upstream APIs
    # (Anthropic/ChatGPT/Google) are pooled across requests. Created on
    # startup so we don't pay TLS handshake on every /usage hit.
    async def _start(_app: web.Application) -> None:
        _app["http"] = aiohttp.ClientSession()

    async def _cleanup(_app: web.Application) -> None:
        sess = _app.get("http")
        if sess is not None:
            await sess.close()

    app.on_startup.append(_start)
    app.on_cleanup.append(_cleanup)

    app.router.add_get("/credentials", _handle_credentials)
    app.router.add_get("/credentials/codex", _handle_credentials_codex)
    app.router.add_get("/firmware-logs", _handle_firmware_logs)
    app.router.add_get("/device/{device_id}/sync", _handle_device_sync)
    app.router.add_get("/usage/{provider}", _handle_usage)
    app.router.add_get("/firmware/{name}", _handle_firmware)
    app.router.add_head("/firmware/{name}", _handle_firmware)
    app.router.add_route("*", "/{tail:.*}", lambda r: _error(404, "not found"))
    return app


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
    ``/credentials``. Accepts global PSK and, when X-Cwm-Device is
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
        dev_id = req.headers.get("X-Cwm-Device", "")
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
            req.headers.get("X-Cwm-Timestamp", ""),
            req.headers.get("X-Cwm-Nonce", ""),
            req.headers.get("X-Cwm-Signature", ""),
            req.headers.get("X-Cwm-Device", ""),
            req.headers.get("X-Cwm-Config-Version", ""),
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
        headers["X-Cwm-Firmware-SHA256"] = sha
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
        device_id = req.headers.get("X-Cwm-Device", "")
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
                    req.headers.get("X-Cwm-Timestamp", ""),
                    req.headers.get("X-Cwm-Nonce", ""),
                    req.headers.get("X-Cwm-Signature", ""),
                    req.headers.get("X-Cwm-Device", ""),
                    req.headers.get("X-Cwm-Config-Version", ""),
                    cache,
                    cfg.security.max_timestamp_skew_seconds,
                )
            except auth.AuthError as e:
                log.info("auth rejected /credentials device=%s from %s: %s", device_id, req.remote, e)
                status_to_record = 401
                return _error(401, "unauthorized")
            obs = _parse_uint32(req.headers.get("X-Cwm-Config-Version", ""))
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
                    req.headers.get("X-Cwm-Timestamp", ""),
                    req.headers.get("X-Cwm-Nonce", ""),
                    req.headers.get("X-Cwm-Signature", ""),
                    req.headers.get("X-Cwm-Device", ""),
                    req.headers.get("X-Cwm-Config-Version", ""),
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

    device_id = req.headers.get("X-Cwm-Device", "")
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
                req.headers.get("X-Cwm-Timestamp", ""),
                req.headers.get("X-Cwm-Nonce", ""),
                req.headers.get("X-Cwm-Signature", ""),
                req.headers.get("X-Cwm-Device", ""),
                req.headers.get("X-Cwm-Config-Version", ""),
                cache,
                cfg.security.max_timestamp_skew_seconds,
            )
        except auth.AuthError as e:
            log.info("auth rejected %s device=%s from %s: %s", path, device_id, req.remote, e)
            return False, _error(401, "unauthorized")
        obs = _parse_uint32(req.headers.get("X-Cwm-Config-Version", ""))
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
            req.headers.get("X-Cwm-Timestamp", ""),
            req.headers.get("X-Cwm-Nonce", ""),
            req.headers.get("X-Cwm-Signature", ""),
            req.headers.get("X-Cwm-Device", ""),
            req.headers.get("X-Cwm-Config-Version", ""),
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
        if not cfg.codex.enabled:
            status_to_record = 404
            return _error(404, "codex provider disabled")
        ok, err_resp = await _verify_for_path(req, "/credentials/codex")
        if not ok:
            status_to_record = err_resp.status
            return err_resp
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


def _device_gemini_models(reg: Registry, device_id: str) -> list[str]:
    """Return the per-device Gemini model override (pending first, then
    active). Empty list when no override is configured.
    """
    try:
        dev = reg.load(device_id)
    except NotFound:
        return []
    except Exception:
        return []
    if dev.pending is not None and dev.pending.payload.gemini_models:
        return list(dev.pending.payload.gemini_models)
    if dev.active.payload.gemini_models:
        return list(dev.active.payload.gemini_models)
    return []


async def _handle_usage(req: web.Request) -> web.Response:
    """Serve a synthesised usage snapshot at /usage/{provider}.

    The broker caches per-provider results in usage.Cache; on cache miss
    or stale entry the fetcher hits upstream. Errors map to HTTP via the
    same convention as /credentials, with the addition that a last-good
    snapshot is preferred over an error response (the firmware logs the
    X-Cwm-Stale-Reason header but keeps rendering the bars).
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
        if usage_cache is None:
            status_to_record = 503
            return _error(503, "usage disabled (no providers configured)")

        # Per-device Gemini override: when the device has a non-empty
        # gemini_models list, bypass the cache and fetch with that
        # slice. Token cache inside the GeminiFetcher is preserved, so
        # this is only one extra upstream round-trip per poll.
        reg: registry.Registry | None = req.app.get("registry")
        device_id = req.headers.get("X-Cwm-Device", "")
        if (
            provider == usage.PROVIDER_GEMINI
            and reg is not None
            and device_id
            and registry.valid_device_id(device_id)
        ):
            models = _device_gemini_models(reg, device_id)
            if models:
                gem = usage_cache.gemini_fetcher() if hasattr(usage_cache, "gemini_fetcher") else None
                if gem is not None:
                    try:
                        snap = await gem.fetch_with_models(http, models)
                    except usage.NotImplementedProvider:
                        status_to_record = 501
                        return _error(501, "provider not enabled")
                    except usage.CredsMissing:
                        status_to_record = 404
                        return _error(404, "creds file missing")
                    except usage.TokenExpired:
                        status_to_record = 503
                        return _error(503, "token expired, refresh on laptop")
                    except usage.Unauthorized:
                        status_to_record = 401
                        return _error(401, "upstream rejected token")
                    except usage.RateLimited as e:
                        status_to_record = 429
                        r = _error(429, "rate limited")
                        if e.retry_after > 0:
                            r.headers["Retry-After"] = str(e.retry_after)
                        return r
                    except (usage.Upstream, usage.ParseUpstream, usage.Transport) as e:
                        status_to_record = 502
                        return _error(502, f"upstream error: {e}")
                    snap.fetched_at_unix = int(time.time())
                    body = asdict(snap)
                    resp = web.json_response(body)
                    resp.headers["Cache-Control"] = "no-store"
                    return resp

        try:
            snap = await usage_cache.get(http, provider)
        except usage.NotImplementedProvider:
            status_to_record = 501
            return _error(501, "provider not enabled")
        except usage.CredsMissing as e:
            status_to_record = 404
            return _error(404, "creds file missing")
        except usage.TokenExpired:
            status_to_record = 503
            return _error(503, "token expired, refresh on laptop")
        except usage.Unauthorized:
            status_to_record = 401
            return _error(401, "upstream rejected token")
        except usage.RateLimited as e:
            status_to_record = 429
            r = _error(429, "rate limited")
            if e.retry_after > 0:
                r.headers["Retry-After"] = str(e.retry_after)
            return r
        except (usage.Upstream, usage.ParseUpstream, usage.Transport) as e:
            status_to_record = 502
            return _error(502, f"upstream error: {e}")
        body = asdict(snap)
        resp = web.json_response(body)
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
            req.headers.get("X-Cwm-Timestamp", ""),
            req.headers.get("X-Cwm-Nonce", ""),
            req.headers.get("X-Cwm-Signature", ""),
            req.headers.get("X-Cwm-Device", ""),
            req.headers.get("X-Cwm-Config-Version", ""),
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
                req.headers.get("X-Cwm-Timestamp", ""),
                req.headers.get("X-Cwm-Nonce", ""),
                req.headers.get("X-Cwm-Signature", ""),
                req.headers.get("X-Cwm-Device", ""),
                req.headers.get("X-Cwm-Config-Version", ""),
                cache,
                cfg.security.max_timestamp_skew_seconds,
            )
        except auth.AuthError as e:
            log.info("auth rejected /device/%s/sync from %s: %s", device_id, req.remote, e)
            status_to_record = 401
            return _error(401, "unauthorized")

        observed = _parse_uint32(req.headers.get("X-Cwm-Config-Version", ""))
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
        serial_hdr = req.headers.get("X-Cwm-Serial", "")
        if serial_hdr:
            try:
                registry.set_serial(device_id, serial_hdr,
                                    req.headers.get("X-Cwm-Sku", ""))
            except Exception as e:
                log.warning("registry set_serial %s: %s", device_id, e)
        # Mirror anti-rollback floor. bump_min_sv is monotonic, so a
        # spoofed-high value only locks the device into rejecting
        # downgrades — it can't enable one.
        min_sv_hdr = req.headers.get("X-Cwm-Min-Sv", "")
        if min_sv_hdr:
            try:
                sv = int(min_sv_hdr)
                if 0 <= sv <= 0xFFFFFFFF:
                    registry.bump_min_sv(device_id, sv)
            except (ValueError, Exception) as e:
                log.warning("registry bump_min_sv %s: %s", device_id, e)

        dev = registry.load(device_id)
        resp_body: dict[str, Any] = {"active_version": dev.active.payload.version}
        if dev.pending is not None and observed < dev.pending.payload.version:
            if active is None or len(active) != 32:
                status_to_record = 500
                return _error(500, "broker config invalid")
            pt = _pending_payload_json(dev.pending.payload).encode("utf-8")
            nonce, ct = reg_crypto.encrypt_pending(active, pt)
            resp_body["pending"] = {
                "version": dev.pending.payload.version,
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
    if p.providers is not None:
        wire["providers"] = {"claude": p.providers.claude, "codex": p.providers.codex, "gemini": p.providers.gemini}
    if p.autorotate_enabled is not None:
        wire["autorotate_enabled"] = bool(p.autorotate_enabled)
    if p.autorotate_interval_s is not None:
        wire["autorotate_interval_s"] = int(p.autorotate_interval_s)
    # firmware/config_sync.c reads "theme_mode" from the decrypted blob
    # and writes it to KEY_THEME_MD. Omitting it here would silently
    # no-op /wall-monitor:theme switches.
    if getattr(p, "theme_mode", ""):
        wire["theme_mode"] = p.theme_mode
    gm = getattr(p, "gemini_models", None)
    if gm is not None and len(gm) > 0:
        # firmware/config_sync.c reads "gemini_models" as a CSV string
        # and writes it to NVS key cwm_gem_mdls.
        wire["gemini_models"] = ",".join(str(m) for m in gm)
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
    # Go's json.Marshal on map[string]any sorts keys alphabetically;
    # mirror it so the AES-CTR ciphertext is deterministic across impls.
    return json.dumps(wire, separators=(",", ":"), sort_keys=True)
