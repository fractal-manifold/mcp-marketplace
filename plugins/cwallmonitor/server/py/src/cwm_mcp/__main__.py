"""Entry point. Same CLI flags as cwm-mcp Go: --daemon, --once, --status, --logs, --version, --probe."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import socket
import sys
import time

from aiohttp import web

from . import RUNTIME, __version__
from . import auth, creds
from . import usage
from .broker.server import make_app
from .config import devices_path, load
from .leader import try_bind, run as leader_run
from .logbuf import Buffer, LogbufHandler
from .mcp.server import Deps as McpDeps, serve as mcp_serve
from .mdns import Publisher as MdnsPublisher
from .registry.store import Registry
from .serial_tailer import Tailer
from .state import Role, State


def _build_logger(logs: Buffer, level: str) -> logging.Logger:
    root = logging.getLogger("cwm_mcp")
    root.setLevel(getattr(logging, level, logging.INFO))
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    if not root.handlers:
        stderr = logging.StreamHandler(sys.stderr)
        stderr.setFormatter(fmt)
        root.addHandler(stderr)
        teed = LogbufHandler(logs)
        teed.setFormatter(fmt)
        root.addHandler(teed)
    return root


def _open_registry(logger: logging.Logger) -> Registry | None:
    try:
        return Registry(devices_path())
    except Exception as e:
        logger.warning("registry: %s (per-device control plane disabled)", e)
        return None


def _run_once(cfg) -> int:
    try:
        c = creds.load(cfg.oauth_path_abs())
    except Exception as e:
        print(f"creds: {e}", file=sys.stderr)
        return 1
    if c.is_expired(int(time.time() * 1000)):
        print(f"creds: expired at {c.expires_at_iso()}", file=sys.stderr)
        return 1
    print(f"creds OK (expires_at={c.expires_at_iso()})")
    return 0


def _run_status(cfg) -> int:
    addr = f"{cfg.server.bind}:{cfg.server.port}"
    host = "127.0.0.1" if cfg.server.bind in ("0.0.0.0", "") else cfg.server.bind
    url = f"http://{host}:{cfg.server.port}/credentials"
    nonce = "0123456789abcdef0123456789abcdef"
    ts = str(int(time.time()))
    sig = auth.compute_signature(cfg.psk(), "GET", "/credentials", ts, nonce, "", "")
    headers = {"X-Cwm-Timestamp": ts, "X-Cwm-Nonce": nonce, "X-Cwm-Signature": sig}
    out: dict = {"addr": addr, "probe_url": url}
    try:
        import urllib.request
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=2) as resp:
            status = resp.status
            if status == 200:
                out["broker"] = "leader_elsewhere"
            else:
                out["broker"] = "up_but_rejecting"
            out["http_status"] = status
    except Exception as e:
        out["broker"] = "down"
        out["error"] = str(e)
    print(json.dumps(out))
    return 0


async def _run_daemon(cfg, logs: Buffer, logger: logging.Logger) -> int:
    state = State()
    state.set_role(Role.LEADER)
    cache = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    registry = _open_registry(logger)
    tailer: Tailer | None = None
    fw_buf = Buffer(cfg.serial.lines or 2000)
    if cfg.serial.device:
        tailer = Tailer(cfg.serial.device, fw_buf, baud=cfg.serial.baud)
        tailer.start()

    def fw_logs(limit: int) -> dict:
        return {"connected": tailer.connected() if tailer else False, "total_available": len(fw_buf), "lines": fw_buf.tail(limit)}

    usage_cache = usage.build_cache(cfg)
    app = make_app(cfg, cache, state, fw_logs, registry, usage_cache)
    sock = try_bind(cfg.server.bind, cfg.server.port)
    if sock is None:
        logger.error("listen %s:%d: address in use", cfg.server.bind, cfg.server.port)
        return 1
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.SockSite(runner, sock)
    await site.start()
    logger.info("broker: serving on %s:%d", cfg.server.bind, cfg.server.port)
    mdns_pub: MdnsPublisher | None = None
    if registry is not None:
        try:
            mdns_pub = await MdnsPublisher.start(cfg.server.bind, cfg.server.port, registry)
        except Exception as e:  # noqa: BLE001
            logger.warning("mdns: %s (broker discovery disabled)", e)
    try:
        await asyncio.Event().wait()
    finally:
        if mdns_pub is not None:
            await mdns_pub.close()
        if tailer:
            tailer.stop()
        await runner.cleanup()
    return 0


async def _run_mcp(cfg, logs: Buffer, logger: logging.Logger) -> int:
    state = State()
    cache = auth.NonceCache(cfg.security.nonce_cache_ttl_seconds)
    fw_buf = Buffer(cfg.serial.lines or 2000)
    tailer: Tailer | None = None

    def fw_logs(limit: int) -> dict:
        return {"connected": tailer.connected() if tailer else False, "total_available": len(fw_buf), "lines": fw_buf.tail(limit)}

    stop = asyncio.Event()

    async def on_leader(sock: socket.socket) -> None:
        nonlocal tailer
        registry = _open_registry(logger)
        if cfg.serial.device:
            tailer = Tailer(cfg.serial.device, fw_buf, baud=cfg.serial.baud)
            tailer.start()
        usage_cache = usage.build_cache(cfg)
        app = make_app(cfg, cache, state, fw_logs, registry, usage_cache)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.SockSite(runner, sock)
        await site.start()
        mdns_pub: MdnsPublisher | None = None
        if registry is not None:
            try:
                mdns_pub = await MdnsPublisher.start(cfg.server.bind, cfg.server.port, registry)
            except Exception as e:  # noqa: BLE001
                logger.warning("mdns: %s (broker discovery disabled)", e)
        try:
            await stop.wait()
        finally:
            if mdns_pub is not None:
                await mdns_pub.close()
            if tailer:
                tailer.stop()
                tailer = None
            await runner.cleanup()

    broker_task = asyncio.create_task(leader_run(cfg.server.bind, cfg.server.port, state, on_leader, stop))

    deps = McpDeps(cfg=cfg, state=state, logs=logs, registry=_open_registry(logger), version=__version__)
    try:
        await mcp_serve(deps)
    finally:
        stop.set()
        await broker_task
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="cwm-mcp-py", add_help=True)
    parser.add_argument("--config", default="", help="Path to cwm.toml (default: ~/.config/claude-wall-monitor/cwm.toml)")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--logs", action="store_true")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--probe", action="store_true")
    args = parser.parse_args()

    if args.version:
        print(__version__)
        return 0
    if args.probe:
        # Launcher convention: report to stderr, exit 0 only if module imports succeeded.
        # We do a soft check on critical deps so a half-installed env fails fast.
        try:
            import aiohttp  # noqa: F401
            import cryptography  # noqa: F401
            import tomli_w  # noqa: F401
            import mcp  # noqa: F401
        except Exception as e:
            print(f"python probe: missing dependency: {e}", file=sys.stderr)
            return 1
        print(f"{RUNTIME} {__version__}", file=sys.stderr)
        return 0

    try:
        cfg = load(args.config or None)
    except Exception as e:
        print(f"config: {e}", file=sys.stderr)
        return 2

    logs = Buffer(200)
    logger = _build_logger(logs, cfg.logging.level)

    if args.once:
        return _run_once(cfg)
    if args.status:
        return _run_status(cfg)
    if args.daemon:
        return asyncio.run(_run_daemon(cfg, logs, logger))
    return asyncio.run(_run_mcp(cfg, logs, logger))


if __name__ == "__main__":
    sys.exit(main())
