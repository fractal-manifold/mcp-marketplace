---
name: firmware
description: cwallmonitor plugin — push a new firmware build to a registered C Wall Monitor device via OTA. Builds the .bin locally with `idf.py build`, then asks the broker to stage it as a pending update. The device downloads it, verifies its SHA-256, switches the boot slot and reboots; if the new image doesn't reach a healthy broker poll the bootloader rolls back automatically. Use when the user says "OTA the device", "push new firmware", "actualizar el firmware remoto", "publish 0.5.0 to the wall monitor", or after a `cwm_version.h` bump.
---

# /cwallmonitor:firmware

Roll a freshly-built firmware out to a registered wall monitor over the
existing control plane. The transport reuses `/device/<id>/sync` and
its encrypted pending blob, so there is no extra channel to set up.

## When to invoke

- "Push the new firmware to my device."
- "OTA `0.5.0` to device `ab12cd34`."
- "Actualiza el wall monitor de pared remotamente."
- After bumping `firmware/components/core/include/cwm_version.h` and
  `CONFIG_APP_PROJECT_VER` in `firmware/sdkconfig.defaults`.

## Prerequisites

- `cwm-mcp` is running and at least one device is registered. Confirm
  with `wall_monitor_list_devices` — if the device isn't there, stop
  and tell the user to run `/cwallmonitor:configure` first.
- The device's **active** broker URL must point at the laptop that
  will host the firmware file (the default flow). If they want to host
  the .bin elsewhere (S3, GitHub Releases), use the `external_url` arg
  instead and skip the build step.
- ESP-IDF 6 is on `PATH` and the device's partition table is the
  dual-OTA one shipped from version 0.4.0+. A device flashed with the
  pre-0.4.0 single-`factory` partition table will not pick up OTAs —
  re-flash it once via USB to migrate.

## Procedure

### 1. Confirm the device

```
wall_monitor_list_devices
```

Pick the right `device_id` and remember its `active_broker_url` — the
default URL for `firmware_url` will be `<active_broker_url>/firmware/cwm-<version>.bin`.

If the device's `active_version` is the same as the version they want
to push, ask before continuing — the device will detect the match and
no-op, but it's worth a sanity check.

### 2. Build the firmware

From the repo root:

```
cd firmware
idf.py build
```

The artifact lands at `firmware/build/cwm_wall_monitor.bin`
(≈1.8 MB). The build embeds `CONFIG_APP_PROJECT_VER` into the
`esp_app_desc_t` header — the device uses that string as the dedupe
key and refuses to install the same version twice.

If `idf.py build` fails, **do not** call `wall_monitor_publish_firmware`
with a stale .bin. Surface the build error to the user.

### 3. Publish

```
wall_monitor_publish_firmware
    device_id=<id>
    bin_path="<repo>/firmware/build/cwm_wall_monitor.bin"
    firmware_version="<version>"
```

What this does, in order:

1. Copies the .bin to `~/.config/claude-wall-monitor/firmware/cwm-<version>.bin`.
2. Computes the SHA-256 and caches it (also surfaced as the `ETag` and
   `X-Cwm-Firmware-SHA256` headers on subsequent `/firmware/<file>` requests).
3. Stages a pending update on the device's TOML record with the URL,
   SHA-256, and version. Bumps `pending.version` so the device sees a
   strictly newer config_version on its next poll.

The response includes the computed `firmware_url`, `firmware_sha256`
and the updated `device` summary (which now shows
`pending_changes: ["firmware: <version>"]`).

### 4. Watch the device come back

The cadence on the device side:

- `cfg_sync` polls every 60 s. On the next tick it pulls the pending
  blob, applies it, and reboots.
- `ota_task` wakes early in the next boot, sees `cwm_ota_url`/
  `cwm_ota_sha`/`cwm_ota_ver`, downloads the .bin, hashes the staged
  copy from flash, calls `esp_ota_set_boot_partition`, reboots.
- The new image boots in `ESP_OTA_IMG_PENDING_VERIFY`. On the first
  successful broker round-trip `poll_task` calls
  `cwm_ota_mark_running_valid()`, which commits the slot.

Total wall-clock from publish to committed: usually 60 – 120 s.

Stream logs while it happens:

```
wall_monitor_recent_logs limit=100
# or — if a USB cable is plugged in:
wall_monitor_firmware_logs limit=200
```

Look for:

- `cfg_sync candidate stored, version=N` — pending blob received.
- `cfg_sync promoted candidate ... OTA armed: version=<ver>` — keys
  written.
- `ota pending OTA: version=<ver>` — task picked them up.
- `ota downloaded N KB` — TLS download in progress.
- `ota OTA finished, image=N bytes, sha ok` — verification passed.
- `ota boot partition set to ota_1/ota_0, rebooting`.
- After the reboot: `ota no pending OTA` (already-installed branch)
  followed by `ota running image marked valid (rollback cancelled)`.

### 5. Rollback paths (no action required)

The device is responsible for rolling back, not the broker. The
mechanisms:

- **Download fails or SHA mismatch**: `ota_task` aborts the inactive
  slot and increments `cwm_ota_tries`. It retries on each subsequent
  boot up to 3 times, then clears the keys and gives up. The device
  keeps running the prior image. No-op for the operator.
- **New image boots but `poll_task` never reaches its first OK** (bad
  WiFi creds bundled, broker unreachable, crash before the call): the
  bootloader auto-reverts on the next reset. The user sees the prior
  version of the firmware after a power cycle.

If the user complains "I pushed the update but the device still shows
the old version", check `cwm_ota_tries` via
`wall_monitor_recent_logs` and the broker's `active_version` via
`wall_monitor_list_devices`. If `tries` reached 3 and the device is on
the old version, the SHA or URL was wrong — re-publish.

## External hosting variant

To pull from S3 / GitHub Releases instead of the broker:

```
wall_monitor_publish_firmware
    device_id=<id>
    firmware_version="<version>"
    external_url="https://github.com/.../releases/download/v<ver>/cwm_wall_monitor.bin"
    sha256_hex="<lowercase 64-hex SHA-256>"
```

Requirements:

- The TLS chain to that host must be reachable from the device's CA
  bundle. The firmware ships with IDF's CA store plus
  `firmware/extra_certs/anthropic_extra_roots.pem`; GitHub and AWS S3
  are covered by the standard set.
- You compute the SHA-256 ahead of time (`sha256sum
  cwm_wall_monitor.bin`) and pass it verbatim.

## Secure Boot v2

If the target device has Secure Boot v2 burned in eFuse (see
`firmware/components/ota/SECURE_BOOT.md`), the `.bin` you publish MUST
be signed. Build with the flag:

```
cd firmware
CWM_SECURE_BOOT=1 idf.py build
```

This requires `firmware/secrets/secure_boot_signing_key.pem` to exist.
A `.bin` without a valid signature is rejected by the device
(`ESP_ERR_OTA_VALIDATE_FAILED`) — `cwm_ota.c` retries 3 times then
gives up. The device keeps the prior firmware. The broker does not
know whether the bin is signed — that check is entirely on the device,
so `wall_monitor_publish_firmware` takes no extra argument.

Devices without SB burned accept both signed and unsigned bins, so
once SB infra is in the build pipeline you can leave `CWM_SECURE_BOOT=1`
set permanently in your shell — signed bins still flash fine on
unsecured devices.

## Notes / gotchas

- A device flashed before 0.4.0 has the legacy single-`factory`
  partition table. OTA arms successfully but the bootloader has no
  inactive slot to write into; the install fails on the device side.
  Migrate with a one-time USB re-flash.
- The first OTA after enabling `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`
  expects the running image to be marked valid; on a freshly-migrated
  device the running image may still be in `PENDING_VERIFY` —
  `poll_task` commits it on the first OK, so just let it run for a
  minute before publishing.
- Wire format: the firmware fields ride inside the AES-CTR-encrypted
  pending blob, so a captured `/sync` response cannot be tampered to
  redirect to a malicious URL without breaking the PSK seal. The
  .bin itself is served unsigned over HTTPS; integrity comes from the
  SHA-256 carried inside that encrypted blob.

