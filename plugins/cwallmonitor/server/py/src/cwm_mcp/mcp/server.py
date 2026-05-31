"""MCP stdio server. Implements the 10 wall_monitor_* tools.

Loads tool schemas from ../../compat/tool-schemas.json so all three
implementations agree on the same shape.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import auth, creds
from ..config import Config
from ..logbuf import Buffer
from ..registry.store import NotFound, Registry, valid_device_id, ConfigPayload, ProviderSet
from ..state import State

log = logging.getLogger("cwm_mcp.mcp")


def _compat_dir() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "compat" / "tool-schemas.json"
        if cand.is_file():
            return parent / "compat"
    raise RuntimeError("could not locate ../compat/ relative to cwm_mcp module")


def load_tool_schemas() -> list[dict]:
    return json.loads((_compat_dir() / "tool-schemas.json").read_text())["tools"]


@dataclass
class Deps:
    cfg: Config
    state: State
    logs: Buffer
    registry: Registry | None
    version: str


def _broker_addr(cfg: Config) -> str:
    return f"{cfg.server.bind}:{cfg.server.port}"


def _self_host(cfg: Config) -> str:
    h = cfg.server.bind
    return "127.0.0.1" if h in ("0.0.0.0", "") else h


def _fresh_hex_nonce() -> str:
    return secrets.token_hex(16)


def _config_info(cfg: Config) -> dict:
    return {
        "max_timestamp_skew_seconds": cfg.security.max_timestamp_skew_seconds,
        "nonce_cache_ttl_seconds": cfg.security.nonce_cache_ttl_seconds,
        "auth_mode": "passphrase" if cfg.auth.psk_passphrase else "psk_hex",
        "logging_level": cfg.logging.level,
    }


def _provider_names(p: ProviderSet | None) -> list[str]:
    if p is None:
        return []
    out = []
    if p.claude:
        out.append("claude")
    if p.codex:
        out.append("codex")
    if p.gemini:
        out.append("gemini")
    return out


def _device_summary(dev) -> dict:
    out: dict[str, Any] = {
        "device_id": dev.device_id,
        "active_version": dev.active.payload.version,
        "has_pending": dev.pending is not None,
    }
    if getattr(dev, "serial_number", ""):
        out["serial_number"] = dev.serial_number
    if getattr(dev, "hw_sku", ""):
        out["hw_sku"] = dev.hw_sku
    if dev.active.payload.min_secure_version:
        out["min_secure_version"] = dev.active.payload.min_secure_version
    if dev.active.payload.broker_url:
        out["active_broker_url"] = dev.active.payload.broker_url
    if dev.active.payload.city:
        out["active_city"] = dev.active.payload.city
    names = _provider_names(dev.active.payload.providers)
    if names:
        out["active_providers"] = names
    if dev.active.last_seen:
        out["last_seen"] = dev.active.last_seen.isoformat().replace("+00:00", "Z")
    if dev.pending is not None:
        out["pending_version"] = dev.pending.payload.version
        out["pending_created_at"] = dev.pending.created_at.isoformat().replace("+00:00", "Z")
        out["pending_changes"] = _pending_changes(dev.active.payload, dev.pending.payload)
    return out


def _pending_changes(active: ConfigPayload, pending: ConfigPayload) -> list[str]:
    diffs: list[str] = []
    if pending.broker_url and pending.broker_url != active.broker_url:
        diffs.append("broker_url")
    if pending.psk_hex and pending.psk_hex != active.psk_hex:
        diffs.append("psk_hex (key rotation)")
    if pending.city and pending.city != active.city:
        diffs.append("city")
    if pending.br_day and pending.br_day != active.br_day:
        diffs.append("br_day")
    if pending.br_night and pending.br_night != active.br_night:
        diffs.append("br_night")
    if pending.vol and pending.vol != active.vol:
        diffs.append("vol")
    if pending.providers is not None and (active.providers is None or pending.providers != active.providers):
        diffs.append("providers")
    if pending.autorotate_enabled is not None and (active.autorotate_enabled is None or pending.autorotate_enabled != active.autorotate_enabled):
        diffs.append("autorotate_enabled")
    if pending.autorotate_interval_s is not None and (active.autorotate_interval_s is None or pending.autorotate_interval_s != active.autorotate_interval_s):
        diffs.append("autorotate_interval_s")
    if pending.theme_mode and pending.theme_mode != active.theme_mode:
        diffs.append("theme_mode")
    if pending.gemini_models is not None:
        am = list(active.gemini_models or [])
        pm = list(pending.gemini_models or [])
        if am != pm:
            diffs.append("gemini_models")
    return diffs


def _local_ipv4s() -> list[str]:
    """Best-effort enumeration of non-loopback IPv4s. Falls back to a route hack."""
    out: set[str] = set()
    try:
        # Linux: parse /proc/net/fib_trie isn't portable; use socket as fallback
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, family=socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                out.add(ip)
    except Exception:
        pass
    if not out:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 1))
            out.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    return sorted(out)


def _registry_unavailable_text() -> str:
    return "device registry is not configured on this cwm-mcp install; configure ~/.config/claude-wall-monitor/devices/ and retry"


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))


async def serve(deps: Deps) -> None:
    """Run the MCP stdio loop. Returns when the peer closes stdio."""
    from mcp.server import Server  # lazy import
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool

    schemas = load_tool_schemas()
    by_name = {t["name"]: t for t in schemas}

    server = Server("cwm-mcp")

    @server.list_tools()
    async def _list() -> list[Tool]:
        return [
            Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"])
            for t in schemas
        ]

    @server.call_tool()
    async def _call(name: str, arguments: dict | None) -> list[TextContent]:
        args = arguments or {}
        result = await _dispatch(deps, name, args)
        if isinstance(result, str):
            return [TextContent(type="text", text=result)]
        return [TextContent(type="text", text=json.dumps(result))]

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


async def _dispatch(deps: Deps, name: str, args: dict) -> Any:
    if name == "wall_monitor_status":
        return _status(deps)
    if name == "wall_monitor_health":
        return await _health(deps)
    if name == "wall_monitor_recent_logs":
        return _recent_logs(deps, args)
    if name == "wall_monitor_firmware_logs":
        return await _firmware_logs(deps, args)
    if name == "wall_monitor_provision_hint":
        return _provision_hint(deps)
    if name == "wall_monitor_list_devices":
        return _list_devices(deps)
    if name == "wall_monitor_register_device":
        return _register_device(deps, args)
    if name == "wall_monitor_set_device_pending":
        return _set_device_pending(deps, args)
    if name == "wall_monitor_publish_firmware":
        return _publish_firmware(deps, args)
    if name == "wall_monitor_revert_firmware":
        return _revert_firmware(deps, args)
    if name == "wall_monitor_discover_devices":
        return await _discover_devices(args)
    if name == "wall_monitor_provision":
        return await _provision(deps, args)
    return {"error": f"unknown tool {name}"}


def _status(deps: Deps) -> dict:
    snap = deps.state.snapshot()
    return {
        "version": deps.version,
        "addr": _broker_addr(deps.cfg),
        "oauth_path": deps.cfg.oauth_path_abs(),
        "config": _config_info(deps.cfg),
        "snapshot": snap.to_dict(),
    }


async def _health(deps: Deps) -> dict:
    checks = []
    try:
        c = creds.load(deps.cfg.oauth_path_abs())
        if c.is_expired(int(time.time() * 1000)):
            checks.append({"name": "credentials", "pass": False, "detail": f"token expired at {c.expires_at_iso()}"})
        else:
            checks.append({"name": "credentials", "pass": True, "detail": f"valid until {c.expires_at_iso()}"})
    except Exception as e:
        checks.append({"name": "credentials", "pass": False, "detail": str(e)})

    checks.append(await _self_ping(deps))

    snap = deps.state.snapshot()
    if snap.requests_total == 0:
        checks.append({"name": "observed_traffic", "pass": False, "detail": "no requests received yet"})
    elif snap.last_request_status == 200:
        checks.append({"name": "observed_traffic", "pass": True, "detail": f"last request OK at {snap.last_request_at}"})
    else:
        checks.append({"name": "observed_traffic", "pass": False, "detail": f"last request returned {snap.last_request_status}"})

    ok = all(c["pass"] for c in checks)
    return {"ok": ok, "role": snap.role, "checks": checks}


async def _self_ping(deps: Deps) -> dict:
    import aiohttp

    url = f"http://{_self_host(deps.cfg)}:{deps.cfg.server.port}/credentials"
    ts = str(int(time.time()))
    nonce = "1111111111111111deadbeefdeadbeef"
    sig = auth.compute_signature(deps.cfg.psk(), "GET", "/credentials", ts, nonce, "", "")
    headers = {"X-Cwm-Timestamp": ts, "X-Cwm-Nonce": nonce, "X-Cwm-Signature": sig}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as s:
            async with s.get(url, headers=headers) as resp:
                if resp.status == 200:
                    return {"name": "self_ping", "pass": True, "detail": "broker answered 200"}
                if resp.status == 503:
                    return {"name": "self_ping", "pass": False, "detail": "broker says token expired (503)"}
                if resp.status == 404:
                    return {"name": "self_ping", "pass": False, "detail": "broker says credentials file missing (404)"}
                if resp.status == 401:
                    return {"name": "self_ping", "pass": False, "detail": "broker rejected our signature (401) — PSK mismatch?"}
                return {"name": "self_ping", "pass": False, "detail": f"broker returned {resp.status}"}
    except Exception as e:
        return {"name": "self_ping", "pass": False, "detail": f"broker unreachable: {e}"}


def _recent_logs(deps: Deps, args: dict) -> dict:
    limit = 50
    raw = args.get("limit")
    if raw:
        try:
            limit = _clamp(int(raw), 1, 500)
        except ValueError:
            pass
    return {"total_available": len(deps.logs), "lines": deps.logs.tail(limit)}


async def _firmware_logs(deps: Deps, args: dict) -> dict:
    import aiohttp

    limit = 200
    raw = args.get("limit")
    if raw:
        try:
            limit = _clamp(int(raw), 1, 2000)
        except ValueError:
            pass
    url = f"http://{_self_host(deps.cfg)}:{deps.cfg.server.port}/firmware-logs?limit={limit}"
    ts = str(int(time.time()))
    nonce = _fresh_hex_nonce()
    sig = auth.compute_signature(deps.cfg.psk(), "GET", "/firmware-logs", ts, nonce, "", "")
    headers = {"X-Cwm-Timestamp": ts, "X-Cwm-Nonce": nonce, "X-Cwm-Signature": sig}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as s:
            async with s.get(url, headers=headers) as resp:
                body = await resp.text()
                if resp.status != 200:
                    return {"ok": False, "http_status": resp.status, "body": body}
                try:
                    return json.loads(body)
                except json.JSONDecodeError:
                    return {"ok": False, "body": body}
    except Exception as e:
        return {"ok": False, "error": f"broker unreachable: {e}"}


def _provision_hint(deps: Deps) -> dict:
    ips = _local_ipv4s()
    port = deps.cfg.server.port
    urls = [f"http://{ip}:{port}" for ip in ips]
    warning = ""
    if deps.cfg.server.bind in ("127.0.0.1", "localhost"):
        warning = "broker is bound to 127.0.0.1; the device can only reach it from this host. Switch bind to 0.0.0.0 in cwm.toml."
    out: dict[str, Any] = {"port": port, "bind": deps.cfg.server.bind, "hosts": ips, "urls": urls}
    if warning:
        out["warning"] = warning
    return out


def _list_devices(deps: Deps) -> dict:
    if deps.registry is None:
        return {"error": _registry_unavailable_text()}
    devs = deps.registry.list()
    return {"count": len(devs), "devices": [_device_summary(d) for d in devs]}


def _register_device(deps: Deps, args: dict) -> dict:
    if deps.registry is None:
        return {"error": _registry_unavailable_text()}
    device_id = (args.get("device_id") or "").strip().lower()
    broker_url = (args.get("broker_url") or "").strip()
    psk_hex = (args.get("psk_hex") or "").strip().lower()
    if not valid_device_id(device_id):
        return {"error": "device_id must be 8 lowercase hex chars"}
    if not broker_url:
        return {"error": "broker_url required"}
    if len(psk_hex) != 64:
        return {"error": "psk_hex must be exactly 64 hex chars"}
    try:
        bytes.fromhex(psk_hex)
    except ValueError:
        return {"error": "psk_hex is not valid hex"}
    payload = ConfigPayload(broker_url=broker_url, psk_hex=psk_hex, city=(args.get("city") or "").strip())
    if (v := args.get("br_day")):
        try:
            payload.br_day = _clamp(int(v), 10, 100)
        except (TypeError, ValueError):
            pass
    if (v := args.get("br_night")):
        try:
            payload.br_night = _clamp(int(v), 5, 100)
        except (TypeError, ValueError):
            pass
    if (v := args.get("vol")) is not None and v != "":
        try:
            payload.vol = _clamp(int(v), 0, 100)
        except (TypeError, ValueError):
            pass
    try:
        dev = deps.registry.register(device_id, payload)
    except Exception as e:
        return {"error": str(e)}
    return {"ok": True, "device": _device_summary(dev)}


def _set_device_pending(deps: Deps, args: dict) -> dict:
    if deps.registry is None:
        return {"error": _registry_unavailable_text()}
    device_id = (args.get("device_id") or "").strip().lower()
    if not valid_device_id(device_id):
        return {"error": "device_id must be 8 lowercase hex chars"}
    update = ConfigPayload()
    if (v := (args.get("broker_url") or "").strip()):
        update.broker_url = v
    if (v := (args.get("psk_hex") or "").strip().lower()):
        if len(v) != 64:
            return {"error": "psk_hex must be exactly 64 hex chars"}
        try:
            bytes.fromhex(v)
        except ValueError:
            return {"error": "psk_hex is not valid hex"}
        update.psk_hex = v
    if (v := (args.get("city") or "").strip()):
        update.city = v
    for k, lo, hi in [("br_day", 10, 100), ("br_night", 5, 100), ("vol", 0, 100)]:
        if (raw := args.get(k)) is not None and raw != "":
            try:
                setattr(update, k, _clamp(int(raw), lo, hi))
            except (TypeError, ValueError):
                pass
    has_provider = any(k in args for k in ("provider_claude", "provider_codex", "provider_gemini"))
    if has_provider:
        try:
            cur = deps.registry.load(device_id)
        except Exception as e:
            return {"error": str(e)}
        base = ProviderSet(claude=True)
        if cur.pending is not None and cur.pending.payload.providers is not None:
            base = ProviderSet(**vars(cur.pending.payload.providers))
        elif cur.active.payload.providers is not None:
            base = ProviderSet(**vars(cur.active.payload.providers))
        if "provider_claude" in args:
            base.claude = bool(args["provider_claude"])
        if "provider_codex" in args:
            base.codex = bool(args["provider_codex"])
        if "provider_gemini" in args:
            base.gemini = bool(args["provider_gemini"])
        update.providers = base
    if "autorotate_enabled" in args:
        update.autorotate_enabled = bool(args["autorotate_enabled"])
    if "autorotate_interval_s" in args:
        try:
            update.autorotate_interval_s = _clamp(int(args["autorotate_interval_s"]), 1, 300)
        except (TypeError, ValueError):
            pass
    if (v := (args.get("theme_mode") or "").strip().lower()):
        if v not in ("day", "night", "auto"):
            return {"error": "theme_mode must be one of: day, night, auto"}
        update.theme_mode = v
    if "gemini_models" in args:
        raw = args["gemini_models"]
        if raw is None:
            raw = ""
        parts = [p.strip() for p in str(raw).split(",") if p.strip()]
        if len(parts) > 3:
            return {"error": "gemini_models must list at most 3 entries"}
        update.gemini_models = parts  # empty list clears the override
    # Firmware fields: all-or-nothing. Mirror Go's validation so a
    # malformed partial spec fails fast instead of being silently
    # dropped by the device.
    fu = (args.get("firmware_url") or "").strip()
    fs = (args.get("firmware_sha256") or "").strip().lower()
    fv = (args.get("firmware_version") or "").strip()
    if fu or fs or fv:
        if not (fu and fs and fv):
            return {"error": "firmware_url, firmware_sha256 and firmware_version must be supplied together"}
        if not fu.startswith("https://"):
            return {"error": "firmware_url must be HTTPS"}
        if len(fs) != 64:
            return {"error": "firmware_sha256 must be 64 lowercase hex chars"}
        try:
            bytes.fromhex(fs)
        except ValueError:
            return {"error": "firmware_sha256 is not valid hex"}
        if len(fv) > 31:
            return {"error": "firmware_version must be ≤31 chars"}
        update.firmware_url = fu
        update.firmware_sha256 = fs
        update.firmware_version = fv
    # Schema v2 manifest envelope. Optional in pending calls so DEV
    # builds can still stage unsigned firmware, but a production device
    # built without CWM_OTA_UNSIGNED will refuse an OTA whose pending
    # lacks these. Paired: both or neither.
    mb = (args.get("firmware_manifest_b64") or "").strip()
    ms = (args.get("firmware_manifest_sig_b64") or "").strip()
    if mb and len(mb) > 4096:
        return {"error": "firmware_manifest_b64 exceeds 4 KiB"}
    if ms and len(ms) > 128:
        return {"error": "firmware_manifest_sig_b64 looks wrong (Ed25519 sig ~88 base64 chars)"}
    if bool(mb) != bool(ms):
        return {"error": "firmware_manifest_b64 and firmware_manifest_sig_b64 must be supplied together"}
    if mb:
        update.firmware_manifest_b64 = mb
        update.firmware_manifest_sig_b64 = ms
    try:
        dev = deps.registry.set_pending(device_id, update)
    except NotFound:
        return {"error": f"device {device_id} not registered — call wall_monitor_register_device first"}
    except Exception as e:
        return {"error": str(e)}
    return {"ok": True, "device": _device_summary(dev)}


def _revert_firmware(deps: Deps, args: dict) -> dict:
    """Mirror of Go's handleRevertFirmware. See compat/tool-schemas.json."""
    if deps.registry is None:
        return {"error": _registry_unavailable_text()}
    device_id = (args.get("device_id") or "").strip().lower()
    if not valid_device_id(device_id):
        return {"error": "device_id must be 8 lowercase hex chars"}
    fu = (args.get("firmware_url") or "").strip()
    fs = (args.get("firmware_sha256") or "").strip().lower()
    fv = (args.get("firmware_version") or "").strip()
    mb = (args.get("firmware_manifest_b64") or "").strip()
    ms = (args.get("firmware_manifest_sig_b64") or "").strip()
    target_sv = int(args.get("target_min_secure_version") or 0)
    if not (fu and fs and fv and mb and ms):
        return {"error": "revert requires firmware_url, firmware_sha256, firmware_version, firmware_manifest_b64 and firmware_manifest_sig_b64"}
    if not fu.startswith("https://"):
        return {"error": "firmware_url must be HTTPS"}
    if len(fs) != 64:
        return {"error": "firmware_sha256 must be 64 lowercase hex chars"}
    try:
        bytes.fromhex(fs)
    except ValueError:
        return {"error": "firmware_sha256 is not valid hex"}
    try:
        dev = deps.registry.load(device_id)
    except NotFound:
        return {"error": f"device {device_id} not registered"}
    except Exception as e:
        return {"error": str(e)}
    floor = dev.active.payload.min_secure_version
    if target_sv and target_sv < floor:
        return {"error": (
            f"revert blocked by anti-rollback: target min_secure_version={target_sv} "
            f"< device floor={floor}. To downgrade, issue a new firmware with "
            f"min_secure_version below {floor}, signed by the KSK."
        )}
    upd = ConfigPayload()
    upd.firmware_url = fu
    upd.firmware_sha256 = fs
    upd.firmware_version = fv
    upd.firmware_manifest_b64 = mb
    upd.firmware_manifest_sig_b64 = ms
    try:
        dev2 = deps.registry.set_pending(device_id, upd)
    except Exception as e:
        return {"error": str(e)}
    return {"ok": True, "reverts_to": fv, "device": _device_summary(dev2)}


def _publish_firmware(deps: Deps, args: dict) -> dict:
    """Mirror of Go's handlePublishFirmware. Copies the .bin into
    ``firmware_path()``, computes its SHA-256, then stages a pending
    update pointing at this broker's /firmware/<file>. Use
    ``external_url`` to point at an off-broker host instead."""
    import hashlib
    import shutil
    from ..config import firmware_path

    if deps.registry is None:
        return {"error": _registry_unavailable_text()}
    device_id = (args.get("device_id") or "").strip().lower()
    if not valid_device_id(device_id):
        return {"error": "device_id must be 8 lowercase hex chars"}
    version = (args.get("firmware_version") or "").strip()
    if not version:
        return {"error": "firmware_version is required"}
    if len(version) > 31:
        return {"error": "firmware_version must be ≤31 chars"}
    if any(ch in version for ch in " \t/\\"):
        return {"error": "firmware_version must not contain whitespace or path separators"}

    try:
        dev = deps.registry.load(device_id)
    except NotFound:
        return {"error": f"device {device_id} not registered — call wall_monitor_register_device first"}
    except Exception as e:
        return {"error": str(e)}

    external = (args.get("external_url") or "").strip()
    if external:
        if not external.startswith("https://"):
            return {"error": "external_url must be HTTPS"}
        sha_hex = (args.get("sha256_hex") or "").strip().lower()
        if len(sha_hex) != 64:
            return {"error": "sha256_hex required (64 hex chars) when external_url is set"}
        try:
            bytes.fromhex(sha_hex)
        except ValueError:
            return {"error": "sha256_hex is not valid hex"}
        firmware_url = external
    else:
        bin_path = (args.get("bin_path") or "").strip()
        if not bin_path:
            return {"error": "bin_path required when external_url is not set"}
        from pathlib import Path

        src = Path(bin_path)
        if not src.is_file():
            return {"error": f"cannot open bin_path: {bin_path}"}
        firmware_dir = Path(firmware_path())
        firmware_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        file_name = f"cwm-{version}.bin"
        dst = firmware_dir / file_name
        tmp = dst.with_suffix(dst.suffix + ".tmp")
        h = hashlib.sha256()
        with src.open("rb") as fin, tmp.open("wb") as fout:
            for chunk in iter(lambda: fin.read(64 * 1024), b""):
                h.update(chunk)
                fout.write(chunk)
            fout.flush()
            try:
                import os as _os

                _os.fsync(fout.fileno())
            except OSError:
                pass
        tmp.replace(dst)
        sha_hex = h.hexdigest()
        base = (dev.active.payload.broker_url or "").rstrip("/")
        if not base:
            return {"error": "device has no active broker_url; cannot build firmware_url. Re-register the device first."}
        firmware_url = f"{base}/firmware/{file_name}"

    update = ConfigPayload()
    update.firmware_url = firmware_url
    update.firmware_sha256 = sha_hex
    update.firmware_version = version
    try:
        dev2 = deps.registry.set_pending(device_id, update)
    except Exception as e:
        return {"error": str(e)}
    return {
        "ok": True,
        "firmware_url": firmware_url,
        "firmware_sha256": sha_hex,
        "firmware_version": version,
        "device": _device_summary(dev2),
    }


async def _discover_devices(args: dict) -> dict:
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except Exception as e:
        return {"error": f"zeroconf unavailable: {e}"}
    timeout = 4.0
    raw = args.get("timeout_seconds")
    if raw:
        try:
            timeout = float(raw)
            timeout = max(1.0, min(15.0, timeout))
        except (TypeError, ValueError):
            pass

    found: dict[str, dict] = {}

    class _Listener:
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name, timeout=int(timeout * 1000))
            if not info:
                return
            txt = {k.decode("ascii", "replace").lower(): (v.decode("utf-8", "replace") if v else "") for k, v in (info.properties or {}).items()}
            device_id = (txt.get("device_id") or "").lower().strip()
            if not device_id or device_id in found:
                return
            ips: list[str] = []
            for raw in info.addresses or []:
                if len(raw) == 4:
                    ips.append(".".join(str(b) for b in raw))
            host = ips[0] if ips else (info.server.rstrip(".") if info.server else "")
            port = info.port or 80
            base = f"http://{host}:{port}"
            found[device_id] = {
                "device_id": device_id,
                "state": txt.get("state", ""),
                "fw": txt.get("fw", ""),
                "host": (info.server.rstrip(".") if info.server else ""),
                "port": port,
                "ipv4": ips,
                "provision_url": base + "/provision",
                "info_url": base + "/info",
            }

        def update_service(self, *a, **k): pass
        def remove_service(self, *a, **k): pass

    zc = Zeroconf()
    try:
        ServiceBrowser(zc, "_cwm._tcp.local.", _Listener())
        await asyncio.sleep(timeout)
    finally:
        zc.close()
    devices = list(found.values())
    return {"count": len(devices), "devices": devices}


async def _provision(deps: Deps, args: dict) -> dict:
    import aiohttp

    device_id = (args.get("device_id") or "").strip().lower()
    provision_url = (args.get("provision_url") or "").strip()
    code = (args.get("pairing_code") or "").strip()
    if not valid_device_id(device_id):
        return {"error": "device_id must be 8 lowercase hex chars"}
    if not provision_url.endswith("/provision"):
        return {"error": "provision_url must end in /provision (use wall_monitor_discover_devices to get it)"}
    if len(code) != 6:
        return {"error": "pairing_code must be 6 digits"}

    broker_url = (args.get("broker_url") or "").strip()
    psk_hex = (args.get("psk_hex") or "").strip().lower()
    psk_generated = False
    if psk_hex:
        if len(psk_hex) != 64:
            return {"error": "psk_hex must be 64 hex chars"}
        try:
            bytes.fromhex(psk_hex)
        except ValueError:
            return {"error": "psk_hex is not valid hex"}
    elif broker_url:
        # No PSK supplied — generate one. crypto-strong 32 bytes; the user
        # never has to memorise a passphrase, and the secret stays on the
        # broker registry + device NVS only.
        import secrets
        psk_hex = secrets.token_hex(32)
        psk_generated = True

    payload: dict[str, Any] = {"pairing_code": code}
    if broker_url:
        payload["broker_url"] = broker_url
    if psk_hex:
        payload["psk_hex"] = psk_hex
    if (v := (args.get("city") or "").strip()):
        payload["city"] = v
    for k, lo, hi in [("br_day", 10, 100), ("br_night", 5, 100), ("vol", 0, 100)]:
        raw = args.get(k)
        if raw is not None and raw != "":
            try:
                payload[k] = _clamp(int(raw), lo, hi)
            except (TypeError, ValueError):
                pass
    providers: dict[str, bool] = {}
    for name in ("claude", "codex", "gemini"):
        key = f"provider_{name}"
        if key in args:
            providers[name] = bool(args[key])
    if providers:
        payload["providers"] = providers

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=6)) as s:
            async with s.post(provision_url, json=payload) as resp:
                body_text = await resp.text()
                if resp.status != 200:
                    return {"ok": False, "http_status": resp.status, "body": body_text}
                try:
                    device_resp: Any = json.loads(body_text)
                except json.JSONDecodeError:
                    device_resp = body_text
    except Exception as e:
        return {"error": f"POST /provision: {e}"}

    out: dict[str, Any] = {"ok": True, "device_id": device_id, "registered": False, "device_response": device_resp}
    if psk_generated:
        out["psk_generated"] = True
    if deps.registry is not None and broker_url and psk_hex:
        reg_payload = ConfigPayload(broker_url=broker_url, psk_hex=psk_hex, city=payload.get("city", ""))
        for k in ("br_day", "br_night", "vol"):
            if k in payload:
                setattr(reg_payload, k, payload[k])
        if providers:
            reg_payload.providers = ProviderSet(claude=providers.get("claude", False), codex=providers.get("codex", False), gemini=providers.get("gemini", False))
        try:
            deps.registry.register(device_id, reg_payload)
            out["registered"] = True
        except Exception as e:
            msg = str(e)
            if "already exists" in msg:
                try:
                    deps.registry.set_pending(device_id, reg_payload)
                    out["reregistered"] = True
                except Exception as e2:
                    out["note"] = f"re-register failed: {e2}"
            else:
                out["note"] = f"device provisioned but registry write failed: {msg}"
    return out
