"""mDNS publisher helpers — TXT building, loopback gate, address pinning.

Mirrors go/internal/mdns/publish_test.go and js/test/mdns.test.js so the
three impls stay wire-compatible.
"""

import asyncio
import socket
import time

from zeroconf import IPVersion

from tmon_mcp import mdns


def test_build_txt_dedup_sort_and_runtime():
    txt = mdns._build_txt(["bb", "aa", "bb"])
    assert txt[b"v"] == b"1"
    assert txt[b"runtime"] == b"python"
    assert txt[b"devs"] == b"aa,bb"


def test_build_txt_caps_at_whole_id_boundary():
    ids = [f"{i:08x}" for i in range(40)]  # 40x9 bytes joined > 250 cap
    devs = mdns._build_txt(ids)[b"devs"].decode("ascii")
    assert len(devs) <= 255 - len("devs=")
    assert not devs.endswith(",")
    assert all(len(i) == 8 for i in devs.split(","))


def test_is_loopback():
    assert mdns._is_loopback("") is False
    assert mdns._is_loopback("0.0.0.0") is False
    assert mdns._is_loopback("::") is False
    assert mdns._is_loopback("127.0.0.1") is True
    assert mdns._is_loopback("::1") is True
    assert mdns._is_loopback("192.168.1.142") is False


def test_advertised_addresses_literal_bind_pinned_verbatim():
    addrs, ip_version = mdns._advertised_addresses("192.168.1.142")
    assert addrs == [socket.inet_aton("192.168.1.142")]
    assert ip_version == IPVersion.V4Only


def test_advertised_addresses_wildcard_reads_interfaces(monkeypatch):
    calls = []

    def fake_ipv4s():
        calls.append(1)
        return [socket.inet_aton("10.0.0.5")]

    monkeypatch.setattr(mdns, "_physical_ipv4s", fake_ipv4s)
    addrs, ip_version = mdns._advertised_addresses("0.0.0.0")
    assert addrs == [socket.inet_aton("10.0.0.5")]
    assert ip_version == IPVersion.V4Only
    # A second call re-reads — this is what lets the refresh loop see a
    # DHCP/network change instead of serving the boot-time snapshot.
    mdns._advertised_addresses("")
    assert len(calls) == 2


# --- idle-liveness watchdog -------------------------------------------
#
# The device recovers from a moved broker by querying us (see
# firmware/components/net/src/cred_client.c). This watchdog covers the other
# failure: our own advertisement went stale — flapping interface, wedged
# zeroconf stack, an announcement lost in a lossy multicast domain — so no
# query of theirs is answered. Everything below is about not turning that into
# a permanent multicast beacon aimed at a device that is simply off.
# Mirrors TestReannounceGap*/TestTakeIdleReannounce* in Go and JS.


def test_reannounce_gap_floor_doubles_to_ceiling():
    want = [30, 30, 60, 120, 240, 300, 300]
    got = [mdns._reannounce_gap(n) for n in range(len(want))]
    assert got == want


def test_should_reannounce_needs_an_idle_broker_with_devices():
    now = 1_700_000_000.0
    assert not mdns._should_reannounce(now, now - 3600, 0.0, 0, 0), \
        "no registered device: nobody our advertisement could help"
    assert not mdns._should_reannounce(now, now - 29, 0.0, 0, 1), \
        "29 s of quiet is not idle yet"
    assert mdns._should_reannounce(now, now - 30, 0.0, 0, 1)


def test_should_reannounce_respects_the_backoff():
    now = 1_700_000_000.0
    idle = now - 3600
    assert not mdns._should_reannounce(now, idle, now - 29, 1, 1)
    assert mdns._should_reannounce(now, idle, now - 30, 1, 1)
    # Third re-announce onwards the gap doubles: 60 s, not 30.
    assert not mdns._should_reannounce(now, idle, now - 59, 2, 1)
    assert mdns._should_reannounce(now, idle, now - 60, 2, 1)


def test_take_idle_reannounce_backs_off_then_resets_on_traffic():
    last_req = [1_700_000_000.0]
    pub = mdns.Publisher()
    pub._last_req = lambda: last_req[0]
    pub._started_at = last_req[0]

    now = last_req[0]
    assert pub._take_idle_reannounce(now + 29, 1)[0] is False

    now += 30
    fired, idle_for = pub._take_idle_reannounce(now, 1)
    assert fired and idle_for == 30

    for gap in (30, 60, 120, 240, 300, 300):
        assert pub._take_idle_reannounce(now + gap - 1, 1)[0] is False, \
            f"fired one second early inside a {gap}s gap"
        now += gap
        assert pub._take_idle_reannounce(now, 1)[0] is True, \
            f"did not fire at the end of a {gap}s gap"

    # A device comes back: the next tick must find the watchdog disarmed and
    # back at the floor, not still out at five minutes.
    last_req[0] = now + 1
    assert pub._take_idle_reannounce(now + 2, 1)[0] is False
    assert pub._take_idle_reannounce(now + 32, 1)[0] is True


def test_take_idle_reannounce_never_fires_without_devices_or_a_reader():
    last_req = 1_700_000_000.0
    pub = mdns.Publisher()
    pub._last_req = lambda: last_req
    pub._started_at = last_req
    assert pub._take_idle_reannounce(last_req + 3600, 0)[0] is False

    # The loopback no-op publisher has no reader at all.
    assert mdns.Publisher()._take_idle_reannounce(last_req + 3600, 3)[0] is False


def test_take_idle_reannounce_uses_start_time_before_any_request():
    # A broker that has never been hit still has registered devices — one may
    # be booting right now with a stale URL. Idle is measured from start.
    started = 1_700_000_000.0
    pub = mdns.Publisher()
    pub._last_req = lambda: 0.0
    pub._started_at = started
    assert pub._take_idle_reannounce(started + 29, 1)[0] is False
    assert pub._take_idle_reannounce(started + 30, 1)[0] is True


def test_take_idle_reannounce_resets_on_traffic_seen_only_between_ticks():
    # The loop ticks at the same 30 s as the idle threshold, so a request that
    # lands just after a tick is already ~30 s old when the next one looks at
    # it. Resetting on "is this request recent?" would miss it to scheduling
    # jitter and leave the backoff out at its five-minute ceiling.
    last_req = [1_700_000_000.0]
    pub = mdns.Publisher()
    pub._last_req = lambda: last_req[0]
    pub._started_at = last_req[0]

    now = last_req[0] + 30
    for gap in (0, 30, 60, 120, 240, 300):
        now += gap
        assert pub._take_idle_reannounce(now, 1)[0] is True, f"setup: expected a fire at +{gap}"

    # A device hits us, and the next tick lands 31 s later — never inside the
    # threshold, so only the "have I seen this request before?" test catches it.
    last_req[0] = now + 5
    assert pub._take_idle_reannounce(last_req[0] + 31, 1)[0] is True, \
        "traffic seen only between ticks must reset the backoff to the floor"


# --- the refresh tick actually republishes -----------------------------
# _take_idle_reannounce returning True proves nothing on its own: the tick
# has to go on and republish. Each of the three causes is exercised alone,
# so an ``or idle`` dropped from the condition fails exactly one of them.
# Mirrors go TestTickRepublishes* and js "tick republishes when ...".


class _OneDeviceLister:
    def list_device_ids(self):
        return ["aa11bb22"]


def _tick_harness(last_addrs, last_req, zc):
    pub = mdns.Publisher()
    pub._bind = "192.168.1.10"
    pub._last_addrs = last_addrs
    pub._last_txt = mdns._build_txt(["aa11bb22"])
    pub._last_req = last_req
    pub._started_at = last_req() if last_req else 0.0
    pub._zc = zc
    pub._info = object()
    calls = {"open": 0, "teardown": 0}

    async def _open(addresses, ip_version, txt):
        calls["open"] += 1
        pub._last_addrs = addresses
        pub._last_txt = txt
        pub._zc = zc or object()

    async def _teardown():
        calls["teardown"] += 1

    pub._open = _open
    pub._teardown_zc = _teardown
    return pub, calls


def _run_tick(pub):
    return asyncio.run(pub._tick(_OneDeviceLister()))


def test_tick_republishes_when_the_idle_watchdog_fires():
    addrs, _ = mdns._advertised_addresses("192.168.1.10")
    pub, calls = _tick_harness(addrs, lambda: time.time() - 60, object())
    assert _run_tick(pub) is True
    assert calls["open"] == 1, "an idle tick must republish"
    assert calls["teardown"] == 1, "and tear the old advertisement down first"


def test_tick_republishes_when_the_addresses_changed():
    pub, calls = _tick_harness([b"\x0a\x00\x00\x01"], time.time, object())
    assert _run_tick(pub) is True
    assert calls["open"] == 1, "a changed address set must republish"


def test_tick_republishes_when_nothing_is_published_yet():
    addrs, _ = mdns._advertised_addresses("192.168.1.10")
    pub, calls = _tick_harness(addrs, time.time, None)
    assert _run_tick(pub) is True
    assert calls["open"] == 1, "a down publisher must be retried"


def test_tick_is_quiet_when_nothing_changed():
    addrs, _ = mdns._advertised_addresses("192.168.1.10")
    pub, calls = _tick_harness(addrs, time.time, object())
    assert _run_tick(pub) is True
    assert calls["open"] == 0, "a quiet tick must not republish"
    assert calls["teardown"] == 0
