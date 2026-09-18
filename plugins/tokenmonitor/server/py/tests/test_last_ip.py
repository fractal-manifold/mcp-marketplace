"""active.last_ip: the source address a device was last seen from.

It exists for one job — publish_firmware has to hand out the one of THIS
host's addresses that is on the device's network. A laptop on WiFi and
Ethernet at once has several, and picking blind does not merely produce an
unreachable firmware_url: tmon_ota.c treats a foreign origin as reason to
withhold the HMAC headers, so the download 401s as well.

Mirrors Go's TestTouch_RecordsLastIPAndSurvivesRebuilds and
TestPickLocalIP_PrefersTheDevicesSubnet.
"""

from __future__ import annotations

from pathlib import Path

from tmon_mcp.mcp.server import _pick_local_ip, _route_source_ip
from tmon_mcp.registry.store import ConfigPayload, Registry, remote_ipv4

DEVICE_ID = "ab12cd34"
PSK_HEX = "aa" * 32


def _reg(tmp_path: Path) -> Registry:
    r = Registry(str(tmp_path / "devices"))
    r.register(DEVICE_ID, ConfigPayload(broker_url="http://x", psk_hex=PSK_HEX))
    return r


def test_remote_ipv4_accepts_the_shapes_a_peer_arrives_in():
    assert remote_ipv4("192.168.1.55") == "192.168.1.55"       # aiohttp req.remote
    assert remote_ipv4("192.168.1.55:41234") == "192.168.1.55"  # host:port
    # A dual-stack listener reports IPv4 peers in mapped form.
    assert remote_ipv4("::ffff:192.168.1.55") == "192.168.1.55"
    for bad in ("", "[fe80::1]:5000", "fe80::1", "not-an-address", "999.1.1.1"):
        assert remote_ipv4(bad) == "", bad
    # Loopback is this host talking to itself, not a device on the LAN.
    for lo in ("127.0.0.1", "127.0.0.1:8765", "::ffff:127.0.0.1"):
        assert remote_ipv4(lo) == "", lo


def test_touch_records_last_ip_and_survives_rebuilds(tmp_path: Path):
    r = _reg(tmp_path)
    r.touch(DEVICE_ID, "192.168.2.44")
    assert r.load(DEVICE_ID).active.last_ip == "192.168.2.44"

    # A peer we cannot use as an IPv4 literal must not erase what we know: one
    # request over IPv6 should not cost the OTA its hint.
    for bad in ("", "[fe80::1]:5000", "garbage"):
        r.touch(DEVICE_ID, bad)
        assert r.load(DEVICE_ID).active.last_ip == "192.168.2.44", bad

    r.set_pending(DEVICE_ID, ConfigPayload(city="Madrid"))
    r.maybe_promote(DEVICE_ID, 2, False)
    assert r.load(DEVICE_ID).active.last_ip == "192.168.2.44", "promote lost it"

    r.replace_active(DEVICE_ID, ConfigPayload(broker_url="http://x", psk_hex=PSK_HEX))
    assert r.load(DEVICE_ID).active.last_ip == "192.168.2.44", "re-provision lost it"


def test_last_ip_round_trips_through_toml(tmp_path: Path):
    r = _reg(tmp_path)
    r.touch(DEVICE_ID, "10.1.2.3")
    text = (tmp_path / "devices" / f"{DEVICE_ID}.toml").read_text()
    assert 'last_ip = "10.1.2.3"' in text
    assert Registry(str(tmp_path / "devices")).load(DEVICE_ID).active.last_ip == "10.1.2.3"


def test_pick_local_ip_falls_back_when_the_device_is_unknown():
    ips = ["10.0.0.5", "192.168.2.7"]
    for unknown in ("", "garbage", "fe80::1"):
        assert _pick_local_ip(ips, unknown) == "10.0.0.5", unknown


def test_route_source_ip_answers_for_loopback_and_refuses_junk():
    # 127.0.0.1 is the one destination every host can route, and its source is
    # loopback — which we deliberately reject, since a device can never reach
    # us there. So this pins both halves of the contract at once.
    assert _route_source_ip("127.0.0.1") == ""
    assert _route_source_ip("not-an-address") == ""
