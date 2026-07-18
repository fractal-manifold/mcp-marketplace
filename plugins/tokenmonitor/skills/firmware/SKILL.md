---
name: firmware
description: tokenmonitor plugin — push a new firmware build to a registered TokenMonitor device via OTA. Builds the .bin locally with `idf.py build`, then asks the broker to stage it as a pending update. The device downloads it, verifies its SHA-256, switches the boot slot and reboots; if the new image doesn't reach a healthy broker poll the bootloader rolls back automatically. Use when the user says "OTA the device", "push new firmware", "actualizar el firmware remoto", "publish 0.5.0 to the wall monitor", or after a `tmon_version.h` bump.
---

# /tokenmonitor:firmware

Roll a freshly-built firmware out to a registered wall monitor over the
existing control plane. The transport reuses `/device/<id>/sync` and
its encrypted pending blob, so there is no extra channel to set up.

## When to invoke

- "Push the new firmware to my device."
- "OTA `0.5.0` to device `ab12cd34`."
- "Actualiza el wall monitor de pared remotamente."
- After bumping `firmware/components/core/include/tmon_version.h` and
  `CONFIG_APP_PROJECT_VER` in `firmware/sdkconfig.defaults`.

## Prerequisites

- `tokenmonitor-mcp` is running and at least one device is registered. Confirm
  with `tokenmonitor_list_devices` — if the device isn't there, stop
  and tell the user to run `/tokenmonitor:configure` first.
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
tokenmonitor_list_devices
```

Pick the right `device_id` and remember its `active_broker_url` — the
default URL for `firmware_url` will be `<active_broker_url>/firmware/tmon-<version>.bin`.

If the device's `active_version` is the same as the version they want
to push, ask before continuing — the device will detect the match and
no-op, but it's worth a sanity check.

### 2. Build the firmware

From the repo root:

```
cd firmware
idf.py build
```

The artifact lands at `firmware/build/tokenmonitor.bin`
(≈1.8 MB). The build embeds `CONFIG_APP_PROJECT_VER` into the
`esp_app_desc_t` header — the device uses that string as the dedupe
key and refuses to install the same version twice.

If `idf.py build` fails, **do not** call `tokenmonitor_publish_firmware`
with a stale .bin. Surface the build error to the user.

### 3. Sign the OTA manifest (REQUIRED on default / production builds)

On any build with `TMON_OTA_UNSIGNED=n` (the default, and all production
builds) the device gates the OTA on an **Ed25519-signed manifest** before
it will even download the .bin — see `gate_manifest()` in
`firmware/components/ota/src/tmon_ota.c`. The SHA-256 is *not* the trust
root; the signed manifest is. Sign it first so it can be staged together
with the .bin in one call (next step):

```
python tools/tmtools/lib/manifest.py sign \
    --bin firmware/build/tokenmonitor.bin \
    --version <version> \
    --sku <SKU> \
    --channel dev \
    --key firmware/secrets/ota_signing_key.pem \
    --out /tmp/tmon-manifest.json
```

`--channel dev` for development units (a production unit refuses a
`channel:dev` manifest; omit the flag / use `--channel stable` for
factory SKUs). `--sku` is the **hardware** SKU (`S1`, `S2`, …); dev units
still pass their real hardware SKU — `DEV` is a serial FAC value (dev-ness
keys on the serial's FAC field), never a SKU. The output JSON carries
`manifest_b64` and `signature_b64`.

### 4. Publish — bin + SHA + version + signed manifest in ONE call

```
tokenmonitor_publish_firmware
    device_id=<id>
    bin_path="<repo>/firmware/build/tokenmonitor.bin"
    firmware_version="<version>"
    firmware_manifest_b64="<manifest_b64 from /tmp/tmon-manifest.json>"
    firmware_manifest_sig_b64="<signature_b64 from /tmp/tmon-manifest.json>"
```

What this does, in order:

1. Copies the .bin to `~/.config/tokenmonitor/firmware/tokenmonitor-<version>.bin`.
2. Computes the SHA-256 and caches it (also surfaced as the `ETag` and
   `X-Tmon-Firmware-SHA256` headers on subsequent `/firmware/<file>` requests).
3. Stages a pending update on the device's TOML record with the URL,
   SHA-256, version **and the signed manifest pair** — all in one blob.
   Bumps `pending.version` so the device sees a strictly newer
   config_version on its next poll. The response shows `"signed": true`.

The device verifies `sig(manifest)` against its trusted OTA pubkey,
checks the manifest SKU / version / `min_secure_version` (anti-rollback)
and only then downloads + hashes the .bin.

> **Do this in ONE call.** Passing the manifest to `publish_firmware`
> directly (rather than a second manifest-only `set_device_pending`)
> keeps `firmware_url` / `firmware_sha256` / `firmware_version` / manifest
> all consistent in a single pending blob. The old two-step split could
> leave `firmware_version` stale relative to the url/sha/manifest, so the
> device saw "already on this version" and never armed. If you must split
> (e.g. an `external_url` bin hosted elsewhere), re-send **all four**
> firmware fields on the second call, not the manifest alone.

Over the LAN the staged `firmware_url` is the broker's own
`http://<broker>/firmware/tokenmonitor-<version>.bin` — plain HTTP is
accepted by the device (`CONFIG_TMON_OTA_ALLOW_HTTP=y`, now on in the
production build too). Transport is decoupled from trust: the signed
manifest + on-device SHA-256 + anti-rollback + channel gate anchor the
image regardless of scheme, and the .bin is public so cleartext leaks
nothing.

#### Shortcut: the public-channel publisher

For the canary / public-channel flow the maintainer uses
`tmtools.ota.publish`, which signs the manifest and pushes a GitHub
release the broker auto-discovers (no manual `set_device_pending`):

```
python -m tmtools.ota.publish \
    --version <version> --sku S1 \
    --bin firmware/build/tokenmonitor.bin \
    --channel dev \
    --key firmware/secrets/ota_signing_key.pem
```

Run `python -m tmtools.ota.publish --help` for the full flag set
(`--dry-run` previews without touching git/GitHub). Dev builds must
carry a `-dev.<ts>` canary suffix baked into `tmon_version.h`. Devices
then pick it up via `tokenmonitor_check_updates` (or their own poll).
Use this for releases; use the `manifest.py sign` +
`set_device_pending` path above for a one-off push to a single
locally-registered device.

### 5. Watch the device come back

The cadence on the device side:

- `cfg_sync` polls every 60 s. On the next tick it pulls the pending
  blob, applies it, and reboots.
- `ota_task` wakes early in the next boot, sees `tmon_ota_url`/
  `tmon_ota_sha`/`tmon_ota_ver`, downloads the .bin, hashes the staged
  copy from flash, calls `esp_ota_set_boot_partition`, reboots.
- The new image boots in `ESP_OTA_IMG_PENDING_VERIFY`. On the first
  successful broker round-trip `poll_task` calls
  `tmon_ota_mark_running_valid()`, which commits the slot.

Total wall-clock from publish to committed: usually 60 – 120 s.

Stream logs while it happens:

```
tokenmonitor_recent_logs limit=100
# or — if a USB cable is plugged in:
tokenmonitor_firmware_logs limit=200
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

### 6. Rollback paths (no action required)

The device is responsible for rolling back, not the broker. The
mechanisms:

- **Download fails or SHA mismatch**: `ota_task` aborts the inactive
  slot and increments `tmon_ota_tries`. It retries on each subsequent
  boot up to 3 times, then clears the keys and gives up. The device
  keeps running the prior image. No-op for the operator.
- **New image boots but `poll_task` never reaches its first OK** (bad
  WiFi creds bundled, broker unreachable, crash before the call): the
  bootloader auto-reverts on the next reset. The user sees the prior
  version of the firmware after a power cycle.

If the user complains "I pushed the update but the device still shows
the old version", check `tmon_ota_tries` via
`tokenmonitor_recent_logs` and the broker's `active_version` via
`tokenmonitor_list_devices`. If `tries` reached 3 and the device is on
the old version, the SHA or URL was wrong — re-publish.

## External hosting variant

To pull from S3 / GitHub Releases instead of the broker:

```
tokenmonitor_publish_firmware
    device_id=<id>
    firmware_version="<version>"
    external_url="https://github.com/.../releases/download/v<ver>/tokenmonitor.bin"
    sha256_hex="<lowercase 64-hex SHA-256>"
    firmware_manifest_b64="<manifest_b64 signed over the uploaded .bin>"
    firmware_manifest_sig_b64="<signature_b64>"
```

Requirements:

- `external_url` must be **HTTPS** (the broker enforces this for
  off-broker hosts — only the broker's own `/firmware/` LAN endpoint may
  be plain HTTP). The TLS chain must be reachable from the device's CA
  bundle: the firmware ships IDF's CA store plus
  `firmware/extra_certs/anthropic_extra_roots.pem`; GitHub and AWS S3
  are covered by the standard set.
- You compute the SHA-256 ahead of time (`sha256sum
  tokenmonitor.bin`) and pass it verbatim.
- The **signed manifest is still mandatory** — pass `firmware_manifest_b64`
  + `firmware_manifest_sig_b64` in the same call (sign the exact .bin you
  uploaded; the manifest's SHA-256 must match the hosted file). For a
  public GitHub-release host, `tmtools.ota.publish` produces both the
  signed manifest and the release in one shot.

## Secure Boot v2

If the target device has Secure Boot v2 burned in eFuse (see
`firmware/components/ota/SECURE_BOOT.md`), the `.bin` you publish MUST
be signed. Build with the flag:

```
cd firmware
TMON_SECURE_BOOT=1 idf.py build
```

This requires `firmware/secrets/secure_boot_signing_key.pem` to exist.
A `.bin` without a valid signature is rejected by the device
(`ESP_ERR_OTA_VALIDATE_FAILED`) — `tmon_ota.c` retries 3 times then
gives up. The device keeps the prior firmware. The broker does not
know whether the bin is image-signed — that check is entirely on the
device, so `tokenmonitor_publish_firmware` takes no extra argument for
Secure Boot.

Note this is a **separate** signature from the OTA manifest in step 4:
Secure Boot v2 signs the *image* (bootloader-enforced); the Ed25519
**manifest** gates the OTA at the application layer
(`gate_manifest()`). On a default build the manifest step is required
regardless of whether Secure Boot is burned.

Devices without SB burned accept both signed and unsigned bins, so
once SB infra is in the build pipeline you can leave `TMON_SECURE_BOOT=1`
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
  redirect to a malicious URL without breaking the PSK seal. The .bin
  itself may be served over HTTP (broker LAN endpoint) or HTTPS
  (external host) — transport/host integrity is **not** the trust root:
  on a default build (`TMON_OTA_UNSIGNED=n`) the device installs the
  image only if the **Ed25519-signed manifest** verifies against its
  trusted OTA pubkey and the manifest's SHA-256 matches the downloaded
  bytes. The SHA-256 alone proves nothing about authenticity — it's the
  signature over the manifest (which carries that SHA-256) that does,
  and the anti-rollback floor (`tmon_min_sv`) blocks downgrades and the
  channel gate keeps dev-channel builds off production units. That is
  why plain HTTP is safe even on the production build. Only an
  `TMON_OTA_UNSIGNED=y` build skips the manifest gate.

