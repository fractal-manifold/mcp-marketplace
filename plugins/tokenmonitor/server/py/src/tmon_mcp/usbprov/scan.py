"""Classify enumerated ports and resolve registry-match.

Port of tokenmonitor-mcp/internal/usbprov/scan.go. No port is opened here; the
scan tool decides whether to probe based on tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .enum import Port, device_id_from_serial
from .usbids import (
    TIER_PROBE,
    TIER_REGISTRY_MATCH,
    TIER_SHARED,
    classify_vid_pid,
    label_for,
)


@dataclass
class ScanResult:
    """One classified, resolved serial port."""

    port: Port = field(default_factory=Port)
    tier: str = TIER_SHARED
    label: str = ""
    device_id: str = ""
    registered: bool = False
    sku: str = ""


def resolve(ports: list[Port], registered: dict[str, str]) -> list[ScanResult]:
    """Classify enumerated ports and resolve registry-match. `registered` maps
    a registered device_id to its hardware SKU (SKU may be "" if unknown).
    Never opens a port. Results are sorted by descending trust (registry-match
    first, then probe, then shared) and then by path."""
    out: list[ScanResult] = []
    for p in ports:
        tier, _ = classify_vid_pid(p.vid, p.pid)
        r = ScanResult(port=p, tier=tier, label=label_for(p.vid, p.pid))

        candidate, ok = device_id_from_serial(p.serial_norm)
        if ok:
            if candidate in registered:
                # Registry-match: the strongest identity signal. Auto-selectable.
                r.tier = TIER_REGISTRY_MATCH
                r.registered = True
                r.device_id = candidate
                r.sku = registered[candidate]
            elif tier == TIER_PROBE:
                # A factory-fresh Espressif unit: surface the candidate id so
                # the user can tell two apart, but it stays a probe.
                r.device_id = candidate
            # A shared bridge with an accidentally-hex serial is NOT given a
            # device_id — its iSerial is not a device MAC.
        out.append(r)

    # Stable sort by (tier rank, path), mirroring Go's sort.SliceStable.
    out.sort(key=lambda r: (_tier_rank(r.tier), r.port.path))
    return out


def _tier_rank(t: str) -> int:
    if t == TIER_REGISTRY_MATCH:
        return 0
    if t == TIER_PROBE:
        return 1
    return 2  # TIER_SHARED and anything unknown


def registry_matches(results: list[ScanResult]) -> list[ScanResult]:
    """Return the subset that resolved to a registry-match — the only tier the
    usb_provision tool may auto-select when the caller omits an explicit
    port."""
    return [r for r in results if r.tier == TIER_REGISTRY_MATCH]
