"""Entry point. Same CLI flags as tokenmonitor-mcp Go: --daemon, --once, --status, --logs, --version, --probe."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import socket
import sys
import time
from contextlib import suppress

from aiohttp import web

from . import RUNTIME, __version__
from . import auth, creds
from . import ota
from . import spend
from . import usage
from .broker.server import make_app
from .config import devices_path, load, unusable_config
from .leader import try_bind, run as leader_run
from .logbuf import Buffer, LogbufHandler
from .mcp.server import Deps as McpDeps, serve as mcp_serve
from .mdns import Publisher as MdnsPublisher
from .panel_generator import PanelGenerator
from .registry.store import Registry
from .serial_tailer import Tailer
from .state import Role, State
from . import updatecheck


def _build_logger(logs: Buffer, level: str) -> logging.Logger:
    root = logging.getLogger("tmon_mcp")
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
    headers = {"X-Tmon-Timestamp": ts, "X-Tmon-Nonce": nonce, "X-Tmon-Signature": sig}
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

    # Serial-lease table: followers ask this leader (the sole tailer owner) to
    # yield the USB port. The controller is the live tailer when a serial device
    # is configured, else a NopController (every port is already free).
    from .usbprov import LeaseManager, NopController
    lease = LeaseManager(tailer if tailer is not None else NopController(), 0)

    usage_cache = usage.build_cache(cfg)
    spend_cache = spend.build_cache(cfg, logger)
    app = make_app(cfg, cache, state, fw_logs, registry, usage_cache, spend_cache, lease)
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
            mdns_pub = await MdnsPublisher.start(
                cfg.server.bind, cfg.server.port, registry,
                state.last_request_at_epoch)
        except Exception as e:  # noqa: BLE001
            logger.warning("mdns: %s (broker discovery disabled)", e)
    # Pull-OTA poller (inert unless [ota] is configured). This process is the
    # leader by construction in daemon mode (it owns the bound socket).
    ota_stop = asyncio.Event()
    ota_task = asyncio.create_task(ota.run(cfg, registry, ota_stop))
    # Custom-panel generators: leader-scoped (daemon is always the leader).
    # No-op when [panel.command] is unconfigured.
    panel_gen = PanelGenerator(cfg, registry, logger)
    panel_gen.start()
    # Broker self-version check: best-effort poll of the marketplace catalog so
    # /sync (and tokenmonitor_health/status) can advertise "broker outdated".
    update_task = asyncio.create_task(updatecheck.run(state, logger, stop=ota_stop))
    # SIGTERM/SIGINT → graceful shutdown so the finally runs and children are
    # reaped. Without this, the default SIGTERM disposition kills the process
    # abruptly and leaves the start_new_session generators orphaned (Go gets
    # this via signal.NotifyContext).
    shutdown = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with suppress(NotImplementedError):
            loop.add_signal_handler(sig, shutdown.set)
    try:
        await shutdown.wait()
    finally:
        ota_stop.set()
        await ota_task
        await update_task
        await panel_gen.stop()
        if mdns_pub is not None:
            await mdns_pub.close()
        if tailer:
            tailer.stop()
        await runner.cleanup()
    return 0


async def _run_mcp(cfg, logs: Buffer, logger: logging.Logger, cfg_err: Exception | None = None) -> int:
    if cfg_err is not None:
        # Degraded start: tools up so the user can be told what is wrong, but
        # no broker. The config we are holding is invented (unusable_config),
        # so serving devices with it would answer every signed request with the
        # wrong key — worse than not answering at all. It also must never win
        # leader election and displace a healthy peer that CAN serve.
        logger.error("config: %s", cfg_err)
        logger.error(
            "config: starting degraded — MCP tools only, broker NOT started. "
            "Fix the config and restart; run tokenmonitor_health for details."
        )
        deps = McpDeps(
            cfg=cfg,
            state=State(),
            logs=logs,
            registry=_open_registry(logger),
            version=__version__,
            config_err=cfg_err,
        )
        await mcp_serve(deps)
        return 0

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
        # Serial-lease table: followers ask this leader (the sole tailer owner)
        # to yield the USB port for a provisioning session.
        from .usbprov import LeaseManager, NopController
        lease = LeaseManager(tailer if tailer is not None else NopController(), 0)
        usage_cache = usage.build_cache(cfg)
        spend_cache = spend.build_cache(cfg, logger)
        app = make_app(cfg, cache, state, fw_logs, registry, usage_cache, spend_cache, lease)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.SockSite(runner, sock)
        await site.start()
        mdns_pub: MdnsPublisher | None = None
        if registry is not None:
            try:
                mdns_pub = await MdnsPublisher.start(
                    cfg.server.bind, cfg.server.port, registry,
                    state.last_request_at_epoch)
            except Exception as e:  # noqa: BLE001
                logger.warning("mdns: %s (broker discovery disabled)", e)
        # Pull-OTA poller, scoped to leadership: it shares the same `stop`
        # event, so losing the bind tears it down alongside mDNS/the tailer.
        ota_task = asyncio.create_task(ota.run(cfg, registry, stop))
        # Custom-panel generators, scoped to leadership: torn down (SIGTERM →
        # SIGKILL) when this peer loses the bound port.
        panel_gen = PanelGenerator(cfg, registry, logger)
        panel_gen.start()
        try:
            await stop.wait()
        finally:
            await ota_task
            await panel_gen.stop()
            if mdns_pub is not None:
                await mdns_pub.close()
            if tailer:
                tailer.stop()
                tailer = None
            await runner.cleanup()

    broker_task = asyncio.create_task(leader_run(cfg.server.bind, cfg.server.port, state, on_leader, stop))

    # Broker self-version check runs once at startup, NOT leader-scoped (mirror
    # of Go main.go): both the MCP tools and any /sync we later serve as leader
    # read the same shared verdict. Shares `stop` so it tears down with serve.
    update_task = asyncio.create_task(updatecheck.run(state, logger, stop=stop))

    deps = McpDeps(cfg=cfg, state=state, logs=logs, registry=_open_registry(logger), version=__version__)
    try:
        await mcp_serve(deps)
    finally:
        stop.set()
        await broker_task
        await update_task
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="tokenmonitor-mcp-py", add_help=True)
    parser.add_argument("--config", default="", help="Path to tokenmonitor.toml (default: ~/.config/tokenmonitor/tokenmonitor.toml)")
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

    cfg_err: Exception | None = None
    try:
        cfg = load(args.config or None)
    except Exception as e:
        # Every mode but stdio MCP has a human reading stderr, so a broken
        # config stays fatal there. In MCP mode exiting is the worst possible
        # response: the client never sees `initialize`, drops the server from
        # the session, and the user is told nothing. Start degraded instead —
        # tools up, broker down (see _run_mcp).
        if args.once or args.status or args.daemon:
            print(f"config: {e}", file=sys.stderr)
            return 2
        cfg_err = e
        cfg = unusable_config()

    logs = Buffer(200)
    logger = _build_logger(logs, cfg.logging.level)

    # A partially-loaded config still serves, but the user has to be told which
    # of their settings are not in effect — otherwise "it works" quietly means
    # "it works, ignoring half of what you wrote".
    if cfg.salvaged:
        logger.warning(
            "config: loaded with %d section(s) ignored: %s",
            len(cfg.salvaged) - 1,
            "; ".join(cfg.salvaged),
        )

    if args.once:
        return _run_once(cfg)
    if args.status:
        return _run_status(cfg)
    if args.daemon:
        return asyncio.run(_run_daemon(cfg, logs, logger))
    return asyncio.run(_run_mcp(cfg, logs, logger, cfg_err))


if __name__ == "__main__":
    sys.exit(main())
