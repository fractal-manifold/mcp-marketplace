"""Validate serial-derived channel routing against the shared cross-runtime
contract (compat/registry/channel_routing.json). serial_is_dev mirrors the
firmware's tmon_serial_is_dev(); candidate_channels is the OTA-loop track set.
The go/py/js brokers MUST agree exactly."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tmon_mcp.registry.store import candidate_channels, serial_is_dev


def _find_compat(rel: str) -> Path:
    """Walk up to the authoritative monorepo `compat/<rel>`."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "compat" / rel
        if cand.exists():
            return cand
    pytest.skip(f"compat/{rel} not available (standalone checkout)", allow_module_level=True)


VECTORS = json.loads(_find_compat("registry/channel_routing.json").read_text())


def test_serial_is_dev_vectors():
    for c in VECTORS["serial_is_dev"]:
        assert serial_is_dev(c["serial"]) is c["expected"], f"serial_is_dev({c['serial']!r})"


def test_candidate_channels_vectors():
    for c in VECTORS["candidate_channels"]:
        dev = SimpleNamespace(serial_number=c["serial"], channel=c["channel"])
        assert candidate_channels(dev) == c["expected"], (
            f"candidate_channels(channel={c['channel']!r}, serial={c['serial']!r})"
        )
