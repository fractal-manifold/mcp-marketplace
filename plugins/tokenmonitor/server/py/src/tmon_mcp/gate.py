"""The broker's copy of the device's manifest gate. Mirror of Go
internal/ota/gate.go and JS src/gate.js.

The device runs tmon_ota_gate_decide()
(firmware/components/ota/src/ota_gate.c) before it installs anything. The
broker has to reach the same verdict BEFORE it stages, because a manifest the
device refuses is not merely a wasted cycle: the refusal is silent. tmon_ota.c
clears the pending, poisons nothing and reports nothing, so from here it looks
exactly like a device that keeps running the old version. The auto-discovery
loop then re-stages, five times, and tombstones a release that was never broken
— while every arm costs the device a reboot.

That is not hypothetical. The published 1.0.0 index declared
min_secure_version = packed(0.11.4) instead of the packed(version) default, so
every unit whose anti-rollback floor had climbed past 0.11.4 — which includes
any unit re-flashed over USB with NVS preserved, since tmon_min_sv is monotonic
and survives even a factory reset — refused it forever.

The rows in compat/ota/gate_manifest.json are the shared contract; this module
and firmware/components/ota/src/ota_gate.c must agree on every one marked
"broker".
"""

from __future__ import annotations

from .registry.store import serial_is_dev

# Verdicts name why a manifest cannot be installed on a given device, or "" when
# it can. These strings are the `expect` values in
# compat/ota/gate_manifest.json and are shared with tmon_ota_gate_verdict_str()
# on the device — they are contract, not log text.
GATE_OK = ""
GATE_SHA_MISMATCH = "sha-mismatch"
GATE_VERSION_MISMATCH = "version-mismatch"
GATE_SKU = "sku"
GATE_PRERELEASE_NOT_DEV = "prerelease-not-dev-channel"
GATE_UNKNOWN_CHANNEL = "unknown-channel"
GATE_DEV_CHANNEL_ON_PROD = "dev-channel-on-production"
GATE_MIN_SV_BELOW_FLOOR = "min-sv-below-floor"
GATE_UNPACKABLE = "unpackable-version"
GATE_VERSION_BELOW = "version-below-floor"


def gate_device_of(dev) -> dict:
    """Read the policy inputs out of a registry record.

    A dict rather than a class so the shared vectors can drive
    predict_device_gate directly, with no registry on disk.
    """
    return {
        "floor": int(dev.active.payload.min_secure_version or 0),
        "sku": dev.hw_sku or "",
        "is_dev": serial_is_dev(dev.serial_number),
    }


def predict_device_gate(mf: dict, dev: dict) -> tuple[str, str]:
    """Return the verdict the DEVICE will reach for this manifest, plus an
    operator-readable explanation. GATE_OK means "the device will accept it";
    anything else means staging it can only burn a reboot.

    It deliberately covers ONLY the gates whose inputs the broker actually
    holds. Transient conditions the device defers on — the battery/USB gate, an
    unfinished PENDING_VERIFY window, an unreachable download host — are NOT
    predicted here: those retry on their own and pre-skipping them would turn a
    delay into a refusal.

    The check order matches ota_gate.c so both sides name the same reason when a
    manifest trips several gates at once; compat/ota/gate_manifest.json pins it.
    """
    # Imported here rather than at module scope: ota imports this module, and
    # pack_semver lives there.
    from .ota import pack_semver

    version = str(mf.get("version", ""))
    channel = str(mf.get("channel", "") or "")
    min_sv = int(mf.get("min_secure_version", 0) or 0)
    floor = int(dev.get("floor", 0) or 0)
    dev_sku = str(dev.get("sku", "") or "")
    mf_sku = str(mf.get("sku", "") or "")

    # SKU. The auto-discovery path fetches update-<HWSku>.json, so a mismatch
    # here means a hand-staged manifest for the wrong hardware. The device
    # warns rather than refuses on a non-factory unit, but the broker has no
    # reliable read on that bit and an operator typo is worth failing closed
    # on — the message names exactly what to fix.
    if dev_sku and mf_sku != dev_sku:
        return GATE_SKU, (
            f"manifest is for sku {mf_sku} but the device reports {dev_sku}"
        )

    # A "-dev.<ts>" prerelease is a dev-channel artifact by definition; one that
    # omits channel:"dev" is a signer bug, and the device refuses it on every
    # unit so a prerelease can never masquerade as stable.
    if "-" in version and not channel:
        return GATE_PRERELEASE_NOT_DEV, (
            f"{version} is a prerelease but the manifest declares no channel; "
            "the device refuses these on every unit"
        )
    if channel:
        if channel != "dev":
            return GATE_UNKNOWN_CHANNEL, (
                f'manifest declares channel "{channel}"; the firmware only '
                'understands "dev" and refuses any other'
            )
        if not dev.get("is_dev"):
            return GATE_DEV_CHANNEL_ON_PROD, (
                "dev-channel firmware never installs on a production unit "
                "(the device gates on the serial's FAC field, not on config)"
            )

    # Anti-rollback (a): the signer-declared floor. This is the one the broker
    # never used to check, and the one that stranded 1.0.0.
    if min_sv < floor:
        return GATE_MIN_SV_BELOW_FLOOR, (
            f"manifest {version} declares min_secure_version={min_sv} but the "
            f"device's anti-rollback floor is {floor}, so it will refuse the "
            f"install and report nothing. Republish {version} with "
            f"min_secure_version >= {floor} — the tmtools default, "
            "packed(version), is always correct; lowering it can only lock "
            "devices out"
        )

    # Anti-rollback (b): the image itself.
    packed = pack_semver(version)
    if packed is None:
        return GATE_UNPACKABLE, f'manifest version "{version}" does not pack'
    if packed < floor:
        return GATE_VERSION_BELOW, (
            f"{version} packs to {packed}, below the device's anti-rollback "
            f"floor {floor}; a device can never be moved backwards over OTA"
        )

    return GATE_OK, ""


def predict_pending_cross_check(mf: dict, sha_hex: str, version: str) -> tuple[str, str]:
    """Mirror the device's gate step 2: the signed manifest must describe the
    very image the pending blob points at. The device compares the manifest's
    sha256/version against the pending's firmware_sha256/firmware_version and
    refuses on any disagreement, silently — the classic shape being a manifest
    left over from the previous build.

    Separate from predict_device_gate because the two have different inputs: the
    auto-discovery path derives the pending FROM the manifest, so it cannot
    disagree with itself, while a hand-staged pending carries operator-typed
    fields that can.
    """
    mf_sha = str(mf.get("sha256", "") or "")
    mf_ver = str(mf.get("version", "") or "")
    if sha_hex and mf_sha.lower() != sha_hex.lower():
        return GATE_SHA_MISMATCH, (
            f"the signed manifest covers sha256={mf_sha} but the pending points "
            f"at {sha_hex}; they must describe the same image (a manifest left "
            "over from an earlier build is the usual cause)"
        )
    if version and mf_ver != version:
        return GATE_VERSION_MISMATCH, (
            f"the signed manifest declares version {mf_ver} but the pending "
            f"says {version}"
        )
    return GATE_OK, ""
