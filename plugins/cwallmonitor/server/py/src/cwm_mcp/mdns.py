"""Advertise the cwm-mcp broker on the local network.

Wire-compatible with cwm-mcp/internal/mdns/publish.go and cwm-mcp-js's
broker mDNS publisher: service type ``_cwm-broker._tcp``, TXT keys
``v``, ``runtime`` and ``devs``.

Identity vs location: the device's PSK is the cryptographic identity of
the pair; mDNS only answers "where is the broker right now?". Listing
device_ids (which travel publicly in the ``X-Cwm-Device`` header) lets
the device filter "is my broker on this LAN?" without leaking secrets.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import socket
from typing import Protocol

from zeroconf import IPVersion, ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

log = logging.getLogger("cwm_mcp.mdns")

SERVICE_TYPE = "_cwm-broker._tcp.local."
RUNTIME = "python"
_REFRESH_SECONDS = 30
_MAX_TXT = 255  # single DNS RR string length limit

# Interface name prefixes the WiFi device cannot reach: container
# bridges, VM tunnels, VPN endpoints. The Go and JS impls keep the same
# list — keep them in sync.
_VIRTUAL_IFACE_PREFIXES = (
    "docker", "br-", "veth", "virbr", "vnet", "tun", "tap",
    "vmnet", "tailscale", "wg", "zt",
)


def _is_virtual_iface(name: str) -> bool:
    return any(name.startswith(p) for p in _VIRTUAL_IFACE_PREFIXES)


def _physical_ipv4s() -> list[bytes]:
    """IPv4 addresses on LAN-reachable interfaces, in zeroconf wire form.

    Uses the ``ifaddr`` adapter enumeration that ships with zeroconf so we
    don't add a new runtime dependency.
    """
    try:
        from zeroconf._utils.net import ifaddr  # type: ignore
    except Exception:
        return []
    out: list[bytes] = []
    for adapter in ifaddr.get_adapters():
        if _is_virtual_iface(adapter.name):
            continue
        for ip in adapter.ips:
            addr = ip.ip
            if isinstance(addr, tuple):
                continue
            if not addr or addr.startswith("127.") or addr == "0.0.0.0":
                continue
            try:
                out.append(socket.inet_aton(addr))
            except OSError:
                continue
    return out


class DeviceIDLister(Protocol):
    def list_device_ids(self) -> list[str]: ...


def _host_short() -> str:
    """6-hex tag stable across reboots so two laptops on the same LAN
    don't collide on ``cwm-broker.local``."""
    try:
        h = socket.gethostname() or ""
    except Exception:
        h = ""
    if not h:
        return "anon00"
    return hashlib.sha256(h.encode("utf-8")).hexdigest()[:6]


def _is_loopback(bind: str) -> bool:
    if not bind or bind in ("0.0.0.0", "::"):
        return False
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return False


def _build_txt(devs: list[str]) -> dict[bytes, bytes]:
    """Return a dict suitable for ``ServiceInfo(properties=...)``.

    The ``devs=`` value is truncated from the right when it would push
    a single TXT string past 255 bytes — the lowest IDs (alphabetical)
    win, which is fine for the home/lab fleets we target.
    """
    devs_sorted = sorted(set(devs))
    joined = ",".join(devs_sorted)
    cap = _MAX_TXT - len("devs=")
    if len(joined) > cap:
        joined = joined[:cap]
        cut = joined.rfind(",")
        if cut > 0:
            joined = joined[:cut]
    return {
        b"v": b"1",
        b"runtime": RUNTIME.encode("ascii"),
        b"devs": joined.encode("ascii"),
    }


class Publisher:
    """Advertise the broker until ``close()`` is awaited.

    Construct via ``await Publisher.start(...)``. The refresh task polls
    the registry every 30 s and re-announces TXT iff the device list
    changed — readdir is cheap enough that filesystem watching would be
    overkill.
    """

    def __init__(self) -> None:
        self._zc: AsyncZeroconf | None = None
        self._info: ServiceInfo | None = None
        self._task: asyncio.Task | None = None
        self._last_txt: dict[bytes, bytes] | None = None

    @classmethod
    async def start(
        cls,
        bind: str,
        port: int,
        lister: DeviceIDLister,
    ) -> "Publisher":
        if _is_loopback(bind):
            log.info("mdns: bind=%s is loopback, skipping broker advertisement", bind)
            return cls()
        if lister is None:
            raise ValueError("mdns: nil registry")

        self = cls()
        try:
            devs = lister.list_device_ids()
        except Exception as e:  # noqa: BLE001
            log.warning("mdns: initial device list: %s", e)
            devs = []
        txt = _build_txt(devs)

        instance = f"cwm-broker-{_host_short()}"
        full_name = f"{instance}.{SERVICE_TYPE}"
        host_name = f"{instance}.local."
        # Bind-aware addresses: when bind is 0.0.0.0/empty/::, advertise
        # only the LAN-reachable physical IPv4s (skip Docker bridges,
        # VPN tunnels, etc — they'd announce IPs the device can't route
        # to). When pinned to a literal IP, use that.
        if not bind or bind in ("0.0.0.0", "::"):
            addresses = _physical_ipv4s() or None
            ip_version = IPVersion.V4Only
        else:
            try:
                addresses = [socket.inet_aton(bind)]
                ip_version = IPVersion.V4Only
            except OSError:
                addresses = None
                ip_version = IPVersion.All
        self._info = ServiceInfo(
            type_=SERVICE_TYPE,
            name=full_name,
            port=port,
            properties=txt,
            server=host_name,
            addresses=addresses,
        )
        self._zc = AsyncZeroconf(ip_version=ip_version)
        try:
            await self._zc.async_register_service(self._info)
        except Exception:
            await self._zc.async_close()
            self._zc = None
            raise
        self._last_txt = txt
        log.info(
            "mdns: published %s port=%d devs=%d",
            full_name,
            port,
            len(devs),
        )
        self._task = asyncio.create_task(self._refresh_loop(lister))
        return self

    async def _refresh_loop(self, lister: DeviceIDLister) -> None:
        try:
            while True:
                await asyncio.sleep(_REFRESH_SECONDS)
                try:
                    devs = lister.list_device_ids()
                except Exception as e:  # noqa: BLE001
                    log.warning("mdns: refresh device list: %s", e)
                    continue
                txt = _build_txt(devs)
                if txt == self._last_txt:
                    continue
                self._last_txt = txt
                info = self._info
                zc = self._zc
                if info is None or zc is None:
                    return
                info.properties = txt
                try:
                    await zc.async_update_service(info)
                except Exception as e:  # noqa: BLE001
                    log.warning("mdns: update service: %s", e)
                    continue
                log.info("mdns: TXT updated, devs=%d", len(devs))
        except asyncio.CancelledError:
            return

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._zc is not None and self._info is not None:
            try:
                await self._zc.async_unregister_service(self._info)
            except Exception:
                pass
        if self._zc is not None:
            await self._zc.async_close()
            self._zc = None
        self._info = None
