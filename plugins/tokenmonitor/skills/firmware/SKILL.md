---
name: firmware
description: tokenmonitor plugin — push a new firmware build to a registered TokenMonitor device via OTA. Builds the .bin locally with `make build-prod`, then asks the broker to stage it as a pending update. The device downloads it, verifies its SHA-256, switches the boot slot and reboots; if the new image doesn't reach a healthy broker poll the bootloader rolls back automatically. Use when the user says "OTA the device", "push new firmware", "actualizar el firmware remoto", "publish 0.5.0 to the wall monitor", or after a `tmon_version.h` bump.
---

# /tokenmonitor:firmware

Roll a freshly-built firmware out to a registered wall monitor over the
existing control plane. The transport reuses `/device/<id>/sync` and its
encrypted pending blob, so there is no extra channel to set up.

## Prerequisites

- **A checkout of the TokenMonitor monorepo**, with the OTA signing key. Every
  path below (`firmware/`, `tools/tmtools/`) is relative to its root; a
  standalone plugin install does not ship them, so this skill only applies to
  someone building the firmware themselves.
- `tokenmonitor-mcp` is running and the device is registered — confirm with
  `tokenmonitor_list_devices`; if it isn't there, stop and tell the user to run
  `/tokenmonitor:configure` first.
- The device's **active** broker URL points at the laptop that will host the
  .bin (the default flow). To host it elsewhere (S3, GitHub Releases) use
  `external_url` and skip the build step.
- ESP-IDF 6 is on `PATH`.
- **The device has the dual-OTA partition table shipped from 0.4.0+.** A
  pre-0.4.0 unit has the legacy single-`factory` table: the OTA arms fine but
  the bootloader has no inactive slot to write into, so the install fails
  device-side. Migrate with a one-time USB re-flash.
- On a freshly-migrated device the running image may still be in
  `ESP_OTA_IMG_PENDING_VERIFY`; `poll_task` commits it on the first OK, so let
  it run a minute before publishing.

## Procedure

### 1. Confirm the device

`tokenmonitor_list_devices` — pick the `device_id` and note its
`active_broker_url` (the staged `firmware_url` will be
`<active_broker_url>/firmware/tokenmonitor-<version>.bin`).

**`active_version` is NOT the firmware version.** It is a `uint32` counter for
the *config payload* generation, and comparing it against a semver like
`0.11.4` is meaningless. The device's running firmware version is reported
separately — read that field, or the device's own log, before deciding whether
a push is a no-op.

### 2. Build

```
make build-prod
```

Use this rather than `idf.py build` in the shared tree: `build-prod` builds
into `firmware/build/prod/` against its own `sdkconfig.sb`, so a Secure Boot
build can never leak its options into the sdkconfig everything else shares.
It sets `TMON_SECURE_BOOT=1` for you and therefore needs
`firmware/secrets/secure_boot_signing_key.pem` — and, on a flash-encrypted
target, the FE key too, unless you pass `TMON_FLASH_ENC=0`.

The artifact lands at `firmware/build/prod/tokenmonitor.bin` (**≈2.1 MB**, not
1.8 — the figure matters because it is what the device has to pull over the
air). The build
embeds `CONFIG_APP_PROJECT_VER` into the `esp_app_desc_t` header — the device
uses that string as the dedupe key and refuses to install the same version
twice. If the build fails, **do not** publish a stale .bin; surface the error.

### 3. Sign the OTA manifest (REQUIRED on default / production builds)

**Trust model — the one thing to get right.** On any build with
`TMON_OTA_UNSIGNED=n` (the default, and every production build) the device
installs an image only if an **Ed25519-signed manifest** verifies against its
trusted OTA pubkey and the manifest's SHA-256 matches the downloaded bytes (see
`gate_manifest()` in `firmware/components/ota/src/tmon_ota.c`). The SHA-256
alone proves nothing about authenticity — the signature over the manifest
carrying it does. Anti-rollback (`tmon_min_sv`) blocks downgrades and the
channel gate keeps dev-channel builds off production units. Transport is
therefore *not* the trust root, and the firmware fields ride inside the
AES-CTR-encrypted pending blob, so a captured `/sync` response can't be
tampered into a malicious URL without breaking the PSK seal. That is why plain
HTTP over the LAN is safe — but the device must also *allow* it: HTTP
`firmware_url`s need `CONFIG_TMON_OTA_ALLOW_HTTP=y`, now on in the production
build too. A device running firmware older than that fix rejects an http URL as
malformed and clears the pending silently; host over HTTPS for those.

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
`channel:dev` manifest; omit the flag or use `--channel stable` for factory
SKUs). `--sku` is the **hardware** SKU (`S1`, `S2`, …) — dev units still pass
their real hardware SKU, since `DEV` is a serial FAC value, never a SKU. The
output JSON carries `manifest_b64` and `signature_b64`.

### 4. Publish — bin + SHA + version + signed manifest in ONE call

```
tokenmonitor_publish_firmware
    device_id=<id>
    bin_path="<repo>/firmware/build/tokenmonitor.bin"
    firmware_version="<version>"
    firmware_manifest_b64="<manifest_b64 from /tmp/tmon-manifest.json>"
    firmware_manifest_sig_b64="<signature_b64 from /tmp/tmon-manifest.json>"
```

The response shows `"signed": true`. The SHA-256 the broker computes is also
served as the `ETag` and `X-Tmon-Firmware-SHA256` headers on subsequent
`/firmware/<file>` requests — handy for checking by hand what the device is
about to download.

> **Do this in ONE call.** Passing the manifest to `publish_firmware` directly
> (rather than a second manifest-only `set_device_pending`) keeps
> `firmware_url` / `firmware_sha256` / `firmware_version` / manifest consistent
> in a single pending blob. The old two-step split could leave
> `firmware_version` stale relative to the url/sha/manifest, so the device saw
> "already on this version" and never armed. If you must split (e.g. an
> `external_url` bin hosted elsewhere), re-send **all four** firmware fields on
> the second call, not the manifest alone.

#### Shortcut: the public-channel publisher

For the canary / public-channel flow the maintainer uses `tmtools.ota.publish`,
which signs the manifest and pushes a GitHub release the broker auto-discovers
— no manual staging:

```
python -m tmtools.ota.publish \
    --version <version> --sku S1 \
    --bin firmware/build/tokenmonitor.bin \
    --channel dev \
    --key firmware/secrets/ota_signing_key.pem
```

`--help` for the full flag set (`--dry-run` previews without touching
git/GitHub). Dev builds must carry a `-dev.<ts>` canary suffix baked into
`tmon_version.h`. Devices then pick it up via `tokenmonitor_check_updates` or
their own poll. Use this for releases; use `manifest.py sign` +
`tokenmonitor_publish_firmware` above for a one-off push to a single
locally-registered device.

### 5. Watch the device come back

`cfg_sync` polls every 60 s, pulls the pending blob and reboots; `ota_task`
wakes early in the next boot, downloads and hashes the .bin, calls
`esp_ota_set_boot_partition` and reboots again; the new image boots in
`PENDING_VERIFY` and `poll_task` calls `tmon_ota_mark_running_valid()` on the
first successful broker round-trip, committing the slot. Publish to committed
is usually **60–120 s**.

Stream with `tokenmonitor_device_logs limit="100"` (the device's own uploaded
ring — `tokenmonitor_recent_logs` is the *broker's* log and will not carry
these lines), or `tokenmonitor_firmware_logs limit="200"` if a USB cable is
plugged in. **Pass `limit` as a string**: the Go runtime reads it as a string
and silently ignores a number, so `limit=100` gets you the default page size
with no error. Look for, in order:

- `cfg_sync candidate stored, version=N` — pending blob received.
- `cfg_sync promoted candidate ... OTA armed: version=<ver>` — keys written.
- `ota pending OTA: version=<ver>` — task picked them up.
- `ota downloaded N KB` — download in progress.
- `ota OTA finished, image=N bytes, sha ok` — verification passed.
- `ota boot partition set to ota_1/ota_0, rebooting`.
- After the reboot: `ota no pending OTA` followed by
  `ota running image marked valid (rollback cancelled)`.

### 6. Rollback paths (no action required)

Rollback is the device's job, not the broker's. On download failure or SHA
mismatch, `ota_task` aborts the inactive slot and increments `tmon_ota_tries`,
retrying on each boot up to 3 times before clearing the keys and giving up —
the device keeps running the prior image. If the new image boots but
`poll_task` never reaches its first OK (broker unreachable, crash before the
call), the bootloader auto-reverts on the next reset.

If the user says "I pushed the update but it still shows the old version",
check `tmon_ota_tries` in `tokenmonitor_device_logs` and the reported firmware
version in `tokenmonitor_list_devices` (**not** `active_version`, which is the
config-payload counter). `tries` at 3 on the old version means the SHA or URL
was wrong — re-publish.

## External hosting variant

```
tokenmonitor_publish_firmware
    device_id=<id>
    firmware_version="<version>"
    external_url="https://github.com/.../releases/download/v<ver>/tokenmonitor.bin"
    sha256_hex="<lowercase 64-hex SHA-256>"
    firmware_manifest_b64="<manifest_b64 signed over the uploaded .bin>"
    firmware_manifest_sig_b64="<signature_b64>"
```

The broker enforces HTTPS for off-broker hosts (only its own `/firmware/` LAN
endpoint may be plain HTTP), and the TLS chain must be reachable from the
device's CA bundle — the firmware ships IDF's CA store plus
`firmware/extra_certs/anthropic_extra_roots.pem`, which covers GitHub and AWS
S3. Compute the SHA-256 yourself (`sha256sum tokenmonitor.bin`). The **signed
manifest is still mandatory**, signed over the exact .bin you uploaded. For a
public GitHub-release host, `tmtools.ota.publish` produces both the signed
manifest and the release in one shot.

## Secure Boot v2

If the target device has Secure Boot v2 burned in eFuse (see
`firmware/components/ota/SECURE_BOOT.md`), the `.bin` MUST be image-signed:

```
make build-prod
```

That is the same command as step 2 — `build-prod` is already the Secure Boot
build, in its own `build/prod/` tree with its own `sdkconfig.sb`. Do not run
`TMON_SECURE_BOOT=1 idf.py build` in the shared tree: it writes Secure Boot
options into the sdkconfig every other build reads.

It needs `firmware/secrets/secure_boot_signing_key.pem`, plus the flash-
encryption key on an FE target (or `TMON_FLASH_ENC=0` to skip that). An unsigned .bin is
rejected on-device (`ESP_ERR_OTA_VALIDATE_FAILED`) and retried 3 times before
giving up, keeping the prior firmware. The broker doesn't know whether the bin
is image-signed — that check is entirely device-side, so
`tokenmonitor_publish_firmware` takes no Secure Boot argument.

This is a **separate** signature from the OTA manifest in step 4: Secure Boot
v2 signs the *image* (bootloader-enforced), the Ed25519 **manifest** gates the
OTA at the application layer. The manifest step is required on a default build
regardless of whether Secure Boot is burned. Devices without SB accept both
signed and unsigned bins, so `TMON_SECURE_BOOT=1` is safe to leave set
permanently.
