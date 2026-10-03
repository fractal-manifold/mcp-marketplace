---
name: firmware
description: tokenmonitor plugin — push a new firmware build to a registered TokenMonitor device via OTA. Builds the production .bin locally with `make build-prod`, signs an Ed25519 manifest for it and asks the broker to stage it as a pending update. The device verifies the manifest signature and the SHA-256, switches the boot slot and reboots; if the new image never reaches the broker it stays uncommitted and the bootloader rolls back on the next reset. Releases go to the `dev` channel first (canary on test units, revertible) and then to `stable`. Use when the user says "OTA the device", "push new firmware", "actualizar el firmware remoto", "publish 1.0.2 to the wall monitor", or after a `tmon_version.h` bump.
---

# /tokenmonitor:firmware

Roll a freshly-built firmware out to a registered desk monitor over the
existing control plane. The transport reuses `/device/<id>/sync` and its
encrypted pending blob, so there is no extra channel to set up.

**One build, two channels.** There is a single production build
(`make build-prod`, Secure Boot v2 + Flash Encryption). It is released to the
`dev` channel first — a canary on test units (serial `FAC=DEV`), where a bad
build can still be reverted with `tokenmonitor_revert_firmware` — and only then
to `stable`. The channel decides *who gets it*, not *how it is built*: test
units run the same `build/prod` image as end-user units, and a plain / unsigned
build pushed to them does not install (it is rejected, and on the bench it has
crash-looped).

## Prerequisites

- **A checkout of the TokenMonitor monorepo**, with the OTA signing key. Every
  path below (`firmware/`, `tools/tmtools/`) is relative to its root; a
  standalone plugin install does not ship them, so this skill only applies to
  someone building the firmware themselves.
- `tokenmonitor-mcp` is running and the device is registered — confirm with
  `tokenmonitor_list_devices`; if it isn't there, stop and tell the user to run
  `/tokenmonitor:configure` first.
- **The device is polling this broker** (a recent `last_seen`).
  `tokenmonitor_publish_firmware` builds the download URL from the address the
  device last reached the broker on and reports which source it used in
  `firmware_url_origin`. A device that has never reached `/sync` cannot be
  handed a local URL it will authenticate — get it polling first, or host the
  .bin elsewhere (S3, GitHub Releases) with `external_url` (https).
  `active_broker_url` in the registry is only a last-known-address record; it
  is not used to build the URL.
- **Power**: the device starts the download only on USB power **or** with the
  battery at ≥ 60 %. Otherwise it keeps the pending and retries on its own
  (backing off from 1 min up to 1 h) without spending a retry.
- ESP-IDF 6 is on `PATH`.
- **The device has the dual-OTA partition table shipped from 0.4.0+.** A
  pre-0.4.0 unit has the legacy single-`factory` table: the OTA arms fine but
  the bootloader has no inactive slot to write into, so the install fails
  device-side. Migrate with a one-time USB re-flash.
- On a freshly-flashed device the running image may still be in
  `ESP_OTA_IMG_PENDING_VERIFY`; it is committed once WiFi has been up for 30 s
  and the broker has answered, so let it run a minute before publishing.

## Procedure

### 1. Confirm the device

`tokenmonitor_list_devices` — pick the `device_id`, check `last_seen` is
recent, and note `hw_sku`, `channel` and `min_secure_version`.

**`active_version` is NOT the firmware version.** It is a `uint32` counter for
the *config payload* generation, and comparing it against a semver like
`1.0.1` is meaningless. `list_devices` does not report the running firmware
version at all. What it does expose is `min_secure_version` (the packed
`MAJOR<<24 | MINOR<<16 | PATCH` anti-rollback floor — it lags the running
version on a dev unit during the 24 h canary window) and `pending_changes`
(`firmware: <ver>` while an OTA is staged). Read the running version from the
device's own log (`tokenmonitor_device_logs`) or its Settings → About screen
before deciding whether a push is a no-op.

### 2. Build

```
make build-prod
```

`build-prod` builds into its own `firmware/build/prod/` tree (CMake selects
`firmware/sdkconfig.sb` whenever `TMON_SECURE_BOOT=1`), so it never reuses the
dev `firmware/build/` tree. It needs
`firmware/secrets/secure_boot_signing_key.pem` and
`firmware/secrets/flash_encryption_key.bin`; `TMON_FLASH_ENC=0` is a QA-only
override.

The artifact lands at `firmware/build/prod/tokenmonitor.bin` (**≈2.2 MB** —
the figure matters because it is what the device has to pull over the air).
The version baked into the image comes from `TMON_VERSION_STRING` in
`firmware/components/core/include/tmon_version.h`; set it before building and
use that exact string in the manifest and the publish call. The device skips a
pending whose version equals the one it is already running. If the build
fails, **do not** publish a stale .bin; surface the error.

### 3. Sign the OTA manifest (REQUIRED)

**Trust model — the one thing to get right.** On any build with
`TMON_OTA_UNSIGNED=n` (the default, and every production build) the device
installs an image only if an **Ed25519-signed manifest** verifies against its
trusted OTA pubkey and the manifest's SHA-256 matches the downloaded bytes (see
`gate_manifest()` in `firmware/components/ota/src/tmon_ota.c`). The SHA-256
alone proves nothing about authenticity — the signature over the manifest
carrying it does. Anti-rollback (`tmon_min_sv`) blocks downgrades and the
channel gate keeps dev-channel builds off production units. Transport is
therefore *not* the trust root, and the firmware fields ride inside the
PSK-encrypted (AES-256-GCM) pending blob, so a captured `/sync` response can't
be tampered into a malicious URL. That is why plain HTTP over the LAN is safe —
but the device must also *allow* it: HTTP `firmware_url`s need
`CONFIG_TMON_OTA_ALLOW_HTTP=y`, on in the production build since 0.10.2.
`publish_firmware` refuses an http URL for a device reporting anything older
(it would drop the pending silently); host over HTTPS for those.

```
python tools/tmtools/lib/manifest.py sign \
    --bin firmware/build/prod/tokenmonitor.bin \
    --version <version> \
    --sku <SKU> \
    --channel dev \
    --key firmware/secrets/ota_signing_key.pem \
    --out /tmp/tmon-manifest.json
```

`--channel dev` for a canary on a test unit (a production unit refuses a
`channel:dev` manifest; omit the flag or use `--channel stable` for those). A
version carrying a `-dev.<ts>` suffix must be signed `--channel dev` — the
device refuses a prerelease that claims to be stable. `--sku` is the
**hardware** SKU (`S1`, `S2`, …) — dev units still pass their real hardware
SKU, since `DEV` is a serial FAC value, never a SKU. The output JSON carries
`manifest_b64` and `signature_b64`.

**Do not pass `--min-sv-raw`.** The default `min_secure_version =
packed(version)` is correct; the signer refuses a lower value, and a raised one
is a phased-rollout lever — never use it for a canary. The device accepts a
manifest only when both its `min_secure_version` and its packed version are ≥
the device's own floor (`min_secure_version` in `list_devices`). A manifest
that fails this is refused **silently** on-device (pending cleared, nothing
reported to the broker); `publish_firmware` predicts the gate and refuses up front with
`the device would refuse this update (…)`.

### 4. Publish — bin + SHA + version + signed manifest in ONE call

```
tokenmonitor_publish_firmware
    device_id=<id>
    bin_path="<repo>/firmware/build/prod/tokenmonitor.bin"
    firmware_version="<version>"
    firmware_manifest_b64="<manifest_b64 from /tmp/tmon-manifest.json>"
    firmware_manifest_sig_b64="<signature_b64 from /tmp/tmon-manifest.json>"
```

The response shows `"signed": true`, the `firmware_url` it staged and
`firmware_url_origin` (how that address was chosen). The SHA-256 the broker
computes is also served as the `ETag` and `X-Tmon-Firmware-SHA256` headers on
subsequent `/firmware/<file>` requests — handy for checking by hand what the
device is about to download.

> **Do this in ONE call.** Passing the manifest to `publish_firmware` directly
> keeps `firmware_url` / `firmware_sha256` / `firmware_version` / manifest /
> signature consistent in a single pending blob. `external_url` hosting is
> also a single `publish_firmware` call (see below). If you use
> `tokenmonitor_set_device_pending` instead, send all five fields together
> (`firmware_url` — https only — `firmware_sha256`, `firmware_version`,
> `firmware_manifest_b64`, `firmware_manifest_sig_b64`); a partial update can
> leave `firmware_version` stale, so the device sees "already on this version"
> and never arms.

#### Releases: dev channel first, then stable

For a release (as opposed to a one-off push to one locally-registered device)
use the make wrappers. They sign the manifest and cut a GitHub release that
the broker discovers on its own — no manual staging. `DRY=1` previews.

Stable — builds `build/prod`, verifies the Secure Boot signature, publishes:

```
make release-stable VERSION=X.Y.Z NOTES="One user-facing sentence."
```

Dev canary — stamps a transient `X.Y.Z-dev.<ts>` version, builds the same
`build/prod` tree, runs the same signature check, publishes to the `dev`
channel and restores `tmon_version.h`:

```
make release-dev NOTES="One user-facing sentence."
```

Add `DRY=1` to either to preview without publishing.

The follow-ups (commit / tag, recording the `ota-releases` pointer) are in
`docs/releasing.md`, Procedures A and B.

Devices do not discover releases themselves. The broker's leader loop does,
and stages a pending for each matching device — it needs `[ota]` enabled with
a releases repo and at least one `[[ota.keys]]` entry in `tokenmonitor.toml`.
Force it with `tokenmonitor_check_updates device_id=<id> dry_run=false` (the
default `dry_run=true` only previews). By default a test unit tracks the newest
of stable + dev and a production unit tracks stable only; the registry
`channel` override can pin a track, but a production unit still refuses a dev
manifest.

### 5. Watch the device come back

`cfg_sync` polls every 10 s, stores the pending as a candidate, promotes it
after three successful probes and reboots; `ota_task` wakes early in the next
boot, downloads and hashes the .bin, calls `esp_ota_set_boot_partition` and
reboots again; the new image boots in `PENDING_VERIFY` and is committed once
WiFi has been connected ≥ 30 s and the broker has answered at least once.
Publish to committed is usually a couple of minutes.

Follow it with `tokenmonitor_device_logs device_id=<id> limit="100"` (the
device's own uploaded ring — `tokenmonitor_recent_logs` is the *broker's* log
and will not carry these lines), or `tokenmonitor_firmware_logs limit="200"`
over USB. Both return a snapshot; call again to see progress. Factory units
ship with log upload off — enable it with
`tokenmonitor_set_device_pending device_id=<id> log_enabled=true`. `firmware_logs` needs
`[serial] device` set in `tokenmonitor.toml`, not just a cable. **Pass `limit`
as a string**: the Go runtime reads it as a string and silently ignores a
number, so `limit=100` gets you the default page size with no error. Look for,
in order:

- `cfg_sync candidate stored, version=N` — pending blob received.
- `cfg_sync OTA armed: version=<ver> (signed, manifest=<n>B)` — keys written.
- `cfg_sync promoted candidate to active, version=N` — then the reboot.
- `ota pending OTA: version=<ver>, tries=N` — task picked them up.
- `ota downloaded N KB` — download in progress.
- `ota OTA finished, image=N bytes, sha ok` — verification passed.
- `ota boot partition set to ota_1/ota_0, rebooting`.
- After the reboot: `ota running version (<ver>) matches pending — already
  installed`, followed by `ota running image marked valid (rollback
  cancelled; …)`.

### 6. Failure and rollback paths

The device protects itself; nothing to do in the normal case.

- **Download failure or SHA mismatch**: `ota_task` aborts the inactive slot,
  increments `tmon_ota_tries` and retries in-task with backoff. After 3
  attempts the version is **poisoned** on-device and the pending cleared — the
  device keeps running the prior image.
- **The new image boots but never reaches the broker**: it stays
  `PENDING_VERIFY` and the bootloader reverts on the next unexpected reset (a
  deliberate user restart or power-off from the device commits it instead). A version
  that repeatedly installs and fails to confirm is poisoned too, and the
  broker stops offering it (`blocked_firmware_version`).
- **Manifest gate refusal** (bad signature, wrong SKU or channel, floor): the
  pending is cleared with no poison and nothing reported to the broker; the
  only trace is a `manifest gate refused: …` line in the device log.

If the user says "I pushed the update but it still shows the old version",
read `tokenmonitor_device_logs` for the `ota` lines and the running version
(**not** `active_version`, which is the config-payload counter). A poisoned
version cannot be re-published — the device refuses to arm it again. Fix the
cause and push a **different** version (arming a different version clears the
poison; so does a factory reset).

To take a bad canary off a test unit within its 24 h window, stage the previous
build with `tokenmonitor_revert_firmware` (it needs that build's
`firmware_url`, `firmware_sha256`, `firmware_version` and signed manifest pair).
Production units raise their floor as soon as an image is confirmed, so there
the fix is always roll-forward: publish a higher version.

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
public GitHub-release host, the release wrappers in step 4 produce both the
signed manifest and the release in one shot.

## Secure Boot v2

A unit with Secure Boot v2 burned in eFuse (see
`firmware/components/ota/SECURE_BOOT.md`) only boots an image-signed `.bin`.
`make build-prod` (step 2) is that build — there is no separate command. Do
not run a bare `TMON_SECURE_BOOT=1 idf.py build`: it uses the right sdkconfig
but writes into the shared `firmware/build/` output tree.

An unsigned .bin is rejected on-device (`ESP_ERR_OTA_VALIDATE_FAILED`),
retried 3 times and then poisoned, keeping the prior firmware. The broker
doesn't know whether the bin is image-signed — that check is entirely
device-side, so `tokenmonitor_publish_firmware` takes no Secure Boot argument.

This is a **separate** signature from the OTA manifest in step 3: Secure Boot
v2 signs the *image* (bootloader-enforced), the Ed25519 **manifest** gates the
OTA at the application layer. Both are required.
