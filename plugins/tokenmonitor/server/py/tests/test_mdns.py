"""mDNS publisher helpers — TXT building, loopback gate, address pinning.

Mirrors go/internal/mdns/publish_test.go and js/test/mdns.test.js so the
three impls stay wire-compatible.
"""

import socket

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
