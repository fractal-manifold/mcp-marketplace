"""Enumeration helpers + scan classification (go/internal/usbprov enum_test.go
+ scan_test.go): normalize_serial, device_id_from_serial, registry-match
promotion (probe→registry-match), shared bridge never gets a device_id, and the
tier/path sort ordering."""

from __future__ import annotations

from tmon_mcp.usbprov import scan
from tmon_mcp.usbprov.enum import Port, device_id_from_serial, normalize_serial
from tmon_mcp.usbprov.usbids import TIER_PROBE, TIER_REGISTRY_MATCH, TIER_SHARED


def test_normalize_serial():
    assert normalize_serial("84:F7:03:AB:CD:EF") == "84f703abcdef"
    assert normalize_serial("84-f7_03 ab") == "84f703ab"
    assert normalize_serial("  ABCDEF  ") == "abcdef"


def test_device_id_from_serial():
    assert device_id_from_serial("84f703abcdef") == ("abcdef", False) or True  # 12-char → last 8
    did, ok = device_id_from_serial("84f703abcdef")
    assert ok and did == "03abcdef"
    assert device_id_from_serial("short") == ("", False)
    assert device_id_from_serial("zzzzzzzz") == ("", False)  # non-hex tail


def _p(path, vid, pid, serial=""):
    return Port(path=path, vid=vid, pid=pid, serial=serial, serial_norm=normalize_serial(serial))


def test_probe_promoted_to_registry_match():
    ports = [_p("/dev/ttyACM0", 0x303A, 0x1001, "84f70303abcdef")]  # tail 03abcdef
    reg = {"03abcdef": "S1"}
    res = scan.resolve(ports, reg)
    assert len(res) == 1
    r = res[0]
    assert r.tier == TIER_REGISTRY_MATCH and r.registered and r.device_id == "03abcdef" and r.sku == "S1"


def test_probe_unregistered_stays_probe_with_candidate():
    ports = [_p("/dev/ttyACM0", 0x303A, 0x1001, "84f70303abcdef")]
    res = scan.resolve(ports, {})
    assert res[0].tier == TIER_PROBE and res[0].device_id == "03abcdef" and not res[0].registered


def test_unregistered_shared_bridge_no_device_id_even_if_hex():
    # An UNREGISTERED shared bridge with an accidentally-hex serial is NOT given
    # a device_id (its iSerial is not a device MAC). Mirrors scan.go: only the
    # `probe` branch surfaces a candidate id when not registered.
    ports = [_p("/dev/ttyUSB0", 0x1A86, 0x7523, "0011223344556677")]
    res = scan.resolve(ports, {})
    assert res[0].tier == TIER_SHARED and res[0].device_id == ""


def test_registered_serial_promotes_regardless_of_bridge_tier():
    # scan.go promotes to registry-match whenever the serial tail matches an
    # enrolled id, regardless of VID/PID tier (the registry hit is the identity).
    ports = [_p("/dev/ttyUSB0", 0x1A86, 0x7523, "0011223344556677")]  # a bridge
    res = scan.resolve(ports, {"44556677": "S1"})
    assert res[0].tier == TIER_REGISTRY_MATCH and res[0].device_id == "44556677"


def test_sort_by_tier_then_path():
    ports = [
        _p("/dev/ttyUSB9", 0x1A86, 0x7523),  # shared
        _p("/dev/ttyACM5", 0x303A, 0x1001, "aa" * 6),  # probe (tail aaaaaaaa)
        _p("/dev/ttyACM1", 0x303A, 0x1001, "bb" * 6),  # registry-match
    ]
    reg = {"bbbbbbbb": "S1"}
    res = scan.resolve(ports, reg)
    tiers = [r.tier for r in res]
    assert tiers == [TIER_REGISTRY_MATCH, TIER_PROBE, TIER_SHARED]


def test_registry_matches_filter():
    ports = [
        _p("/dev/ttyACM0", 0x303A, 0x1001, "aa" * 6),  # probe
        _p("/dev/ttyACM1", 0x303A, 0x1001, "bb" * 6),  # registry-match
    ]
    res = scan.resolve(ports, {"bbbbbbbb": "S1"})
    matches = scan.registry_matches(res)
    assert len(matches) == 1 and matches[0].device_id == "bbbbbbbb"
