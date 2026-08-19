"""Advertise the tokenmonitor-mcp broker on the local network.

Wire-compatible with tokenmonitor-mcp/internal/mdns/publish.go and tokenmonitor-mcp-js's
broker mDNS publisher: service type ``_tmon-broker._tcp``, TXT keys
``v``, ``runtime`` and ``devs``.

Identity vs location: the device's PSK is the cryptographic identity of
the pair; mDNS only answers "where is the broker right now?". Listing
device_ids (which travel publicly in the ``X-Tmon-Device`` header) lets
the device filter "is my broker on this LAN?" without leaking secrets.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import socket
import time
from typing import Callable, Protocol

from zeroconf import IPVersion, ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

log = logging.getLogger("tmon_mcp.mdns")

SERVICE_TYPE = "_tmon-broker._tcp.local."
RUNTIME = "python"
_REFRESH_SECONDS = 30

# Idle-liveness watchdog. If no device has hit the broker for _IDLE_SECONDS we
# re-announce, on the theory that our own advertisement is what went stale — an
# interface that flapped, a zeroconf stack that wedged, an announcement lost in
# a lossy multicast domain. Bounded by a doubling backoff so a device that is
# simply switched off does not have us multicasting every 30 s forever. The
# backoff mirrors the device's own discovery backoff (see
# firmware/components/core/src/tmon_discovery.c) — same shape, so the two sides
# of this recovery read the same way. Wire-compatible with the Go and JS
# publishers.
_IDLE_SECONDS = 30
_REANNOUNCE_MIN_S = 30
_REANNOUNCE_MAX_S = 300


def _reannounce_gap(attempts: int) -> float:
    """Wait after ``attempts`` idle re-announcements: the floor for the first,
    doubling to the ceiling thereafter."""
    gap = float(_REANNOUNCE_MIN_S)
    for _ in range(1, attempts):
        if gap >= _REANNOUNCE_MAX_S / 2:
            return float(_REANNOUNCE_MAX_S)
        gap *= 2
    return gap


def _should_reannounce(now: float, last_req: float, last_reannounce: float,
                       attempts: int, devs: int) -> bool:
    """Pure decision behind the watchdog. ``last_req`` must already be
    normalised by the caller (the broker's start time stands in before any
    device has ever hit us); ``last_reannounce`` of 0.0 means "never".

    ``devs`` of 0 means no device is registered here, so there is nobody our
    advertisement could help and no reason to put packets on the LAN."""
    if devs == 0:
        return False
    if now - last_req < _IDLE_SECONDS:
        return False
    if last_reannounce == 0.0:
        return True
    return now - last_reannounce >= _reannounce_gap(attempts)
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
    don't collide on ``tmon-broker.local``."""
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


def _advertised_addresses(bind: str) -> tuple[list[bytes] | None, IPVersion]:
    """Addresses to pin into the ServiceInfo A records.

    Wildcard bind advertises the LAN-reachable physical IPv4s (skipping
    Docker bridges, VPN tunnels, etc — they'd announce IPs the device
    can't route to); a literal bind advertises exactly that address. The
    wildcard set is re-read on every refresh tick so a DHCP renew or a
    network switch re-announces the new address.
    """
    if not bind or bind in ("0.0.0.0", "::"):
        return (_physical_ipv4s() or None, IPVersion.V4Only)
    try:
        return ([socket.inet_aton(bind)], IPVersion.V4Only)
    except OSError:
        return (None, IPVersion.All)


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
        self._last_addrs: list[bytes] | None = None
        self._bind: str = ""
        self._port: int = 0
        self._instance: str = ""
        # Idle-liveness watchdog state; see _take_idle_reannounce.
        self._last_req: Callable[[], float] | None = None
        self._started_at: float = 0.0
        self._last_seen_req: float = 0.0   # _last_req as of the previous check
        self._idle_attempts: int = 0
        self._last_reannounce: float = 0.0

    def _take_idle_reannounce(self, now: float, devs: int) -> tuple[bool, float]:
        """Is an idle re-announce due right now? When it is, consume it: the
        caller must go on to republish. Returns how long we have been idle,
        for the log line. Any request seen since the previous call resets the
        backoff to the floor, however old that request is by now."""
        if self._last_req is None:
            return False, 0.0
        last_req = self._last_req()
        if not last_req:
            last_req = self._started_at
        # Reset on a request we had not seen before, not on "the request we
        # can see is recent". The loop ticks at the same 30 s as the
        # threshold, so a request landing just after a tick is already 30 s
        # old by the next one: keying the reset on freshness would miss it to
        # scheduling jitter and leave the backoff out at five minutes.
        if last_req != self._last_seen_req:
            self._last_seen_req = last_req
            self._idle_attempts = 0
            self._last_reannounce = 0.0
        if not _should_reannounce(now, last_req, self._last_reannounce,
                                  self._idle_attempts, devs):
            return False, 0.0
        self._idle_attempts += 1
        self._last_reannounce = now
        return True, now - last_req

    async def _open(self, addresses: list[bytes] | None, ip_version: IPVersion,
                    txt: dict[bytes, bytes]) -> None:
        """Create a fresh AsyncZeroconf (its multicast sockets bind to the
        current interfaces here — reusing one across a network change
        would keep stale group memberships) and register the service.
        Records ``_last_txt``/``_last_addrs`` only on success; raises on
        failure with everything torn back down."""
        full_name = f"{self._instance}.{SERVICE_TYPE}"
        host_name = f"{self._instance}.local."
        self._info = ServiceInfo(
            type_=SERVICE_TYPE,
            name=full_name,
            port=self._port,
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
            self._info = None
            raise
        self._last_txt = txt
        self._last_addrs = addresses

    async def _teardown_zc(self) -> None:
        if self._zc is not None and self._info is not None:
            try:
                await self._zc.async_unregister_service(self._info)
            except Exception:
                pass
        if self._zc is not None:
            await self._zc.async_close()
            self._zc = None
        self._info = None

    @classmethod
    async def start(
        cls,
        bind: str,
        port: int,
        lister: DeviceIDLister,
        last_req: "Callable[[], float] | None" = None,
    ) -> "Publisher":
        """``last_req`` reports when a device last hit the broker (epoch
        seconds, 0.0 for never); it drives the idle re-announce watchdog and
        may be None to disable it."""
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

        self._bind = bind
        self._port = port
        self._instance = f"tmon-broker-{_host_short()}"
        self._last_req = last_req
        self._started_at = time.time()
        addresses, ip_version = _advertised_addresses(bind)
        await self._open(addresses, ip_version, txt)
        log.info(
            "mdns: published %s.%s port=%d devs=%d",
            self._instance,
            SERVICE_TYPE,
            port,
            len(devs),
        )
        self._task = asyncio.create_task(self._refresh_loop(lister))
        return self

    async def _tick(self, lister: DeviceIDLister) -> bool:
        """One refresh tick, extracted from the loop so a test can drive it.

        Each of the three causes below must independently produce a
        republish; an ``or idle`` quietly dropped from the condition is
        invisible to a test that only exercises _take_idle_reannounce.

        Returns False when the advertisement is gone for good and the refresh
        loop should stop — the loop used to express that as a bare ``return``
        from inside itself, and extracting the body would otherwise have
        turned it into "skip this tick".
        """
        try:
            devs = lister.list_device_ids()
        except Exception as e:  # noqa: BLE001
            log.warning("mdns: refresh device list: %s", e)
            return True
        txt = _build_txt(devs)

        # Interface addresses changed (DHCP renew, network
        # switch): the pinned A records and the multicast
        # sockets are both stale — tear the whole advertisement
        # down and republish fresh. This is what lets a device
        # rediscover the broker after the host moves LANs. A
        # ``None`` zc (previous republish failed) retries here.
        # Liveness: nobody has talked to us in a while, so
        # re-announce in case it is our own advertisement that went
        # stale. Consumed here so the backoff advances exactly once
        # per tick whatever the republish does.
        idle, idle_for = self._take_idle_reannounce(time.time(), len(devs))
        if idle:
            log.info("mdns: no device traffic for %ds, re-announcing",
                     int(idle_for))
        addresses, ip_version = _advertised_addresses(self._bind)
        if addresses != self._last_addrs or self._zc is None or idle:
            log.info("mdns: %s, republishing",
                     "idle" if idle else "addresses changed")
            await self._teardown_zc()
            try:
                await self._open(addresses, ip_version, txt)
            except Exception as e:  # noqa: BLE001
                # Leave _last_* unset so the next tick retries.
                self._last_addrs = None
                self._last_txt = None
                log.warning("mdns: republish: %s", e)
                return True
            log.info("mdns: republished, devs=%d", len(devs))
            return True

        if txt == self._last_txt:
            return True
        self._last_txt = txt
        info = self._info
        zc = self._zc
        if info is None or zc is None:
            return False
        info.properties = txt
        try:
            await zc.async_update_service(info)
        except Exception as e:  # noqa: BLE001
            log.warning("mdns: update service: %s", e)
            return True
        log.info("mdns: TXT updated, devs=%d", len(devs))
        return True

    async def _refresh_loop(self, lister: DeviceIDLister) -> None:
        try:
            while True:
                await asyncio.sleep(_REFRESH_SECONDS)
                if not await self._tick(lister):
                    return
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
        await self._teardown_zc()
