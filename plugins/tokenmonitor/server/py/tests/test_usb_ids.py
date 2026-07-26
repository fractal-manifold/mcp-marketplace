"""Parity test: the hardcoded DEVICE_TABLE must match compat/usb-ids.json
byte-for-value (same VID/PID, tier, label, order, count). Mirrors
go/internal/usbprov/usbids_test.go — this is what makes "hardcoded, not loaded
at runtime" honest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tmon_mcp.usbprov import usbids


def _find_compat(rel: str) -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "compat" / rel
        if cand.exists():
            return cand
    pytest.skip(f"compat/{rel} not available (standalone checkout)", allow_module_level=True)


COMPAT = _find_compat("usb-ids.json")


def test_usbids_match_fixture():
    doc = json.loads(COMPAT.read_text())
    devices = doc["devices"]
    assert len(devices) == len(usbids.DEVICE_TABLE), "device count mismatch"
    for i, fd in enumerate(devices):
        vid = int(fd["vid"], 16)
        pid = int(fd["pid"], 16)
        hc = usbids.DEVICE_TABLE[i]
        assert (hc.vid, hc.pid) == (vid, pid), f"entry {i} id"
        assert hc.tier == fd["tier"], f"entry {i} tier"
        assert hc.label == fd["label"], f"entry {i} label"


def test_usbids_no_duplicates():
    seen: dict[int, int] = {}
    for i, e in enumerate(usbids.DEVICE_TABLE):
        key = (e.vid << 16) | e.pid
        assert key not in seen, f"duplicate (vid,pid) {e.vid:04x}:{e.pid:04x}"
        seen[key] = i


def test_usbids_known_tiers():
    for e in usbids.DEVICE_TABLE:
        assert e.tier in (usbids.TIER_PROBE, usbids.TIER_SHARED), (
            f"{e.vid:04x}:{e.pid:04x} has bad tier {e.tier}"
        )


def test_classify_vid_pid():
    assert usbids.classify_vid_pid(0x303A, 0x1001) == (usbids.TIER_PROBE, True)
    assert usbids.classify_vid_pid(0x1A86, 0x7523) == (usbids.TIER_SHARED, True)
    # An unknown serial device degrades to the most restrictive tier.
    assert usbids.classify_vid_pid(0xDEAD, 0xBEEF) == (usbids.TIER_SHARED, False)
