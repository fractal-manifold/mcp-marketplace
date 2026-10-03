---
name: theme
description: tokenmonitor plugin — switch a TokenMonitor device between Day, Night and Auto themes remotely. Each provider (Claude / Codex / Antigravity) has its own brand-tinted palette in both Day and Night flavours; Auto follows the sunrise/sunset of the configured city. Use this when the user says "switch the wall monitor to night mode", "make it dark", "use the day theme", "let it follow the sun", "change the theme on device X", or anything similar.
---

# /tokenmonitor:theme

Set the on-device theme mode. Thin wrapper around
`tokenmonitor_set_device_pending`'s `theme_mode` field; for anything else use
`/tokenmonitor:settings`.

```
/tokenmonitor:theme <day|night|auto> [--device <device_id>]
```

## Procedure

1. **Normalise the mode** to `day` / `night` / `auto`: `dark`→night,
   `light`→day, `sunset`/`sunrise`/`automatic`→auto. If still ambiguous, ask.

2. **Resolve the device** with `tokenmonitor_list_devices`: 0 → nothing is
   registered, suggest `/tokenmonitor:configure` and stop; 1 → use it; >1 →
   ask the user (with `AskUserQuestion` where the client has it), showing
   `device_id`, `last_seen` and `active_broker_url` (the registry's last-known
   address, may be absent), unless `--device` was given (validate it against
   the list).

3. **Queue** `tokenmonitor_set_device_pending device_id=<id> theme_mode=<mode>`.
   If `device.pending_changes` in the response does not include `theme_mode`,
   the device is already on that mode — say so and stop.

4. **Tell the user**: the device polls `/device/<id>/sync` every ~10 s, stores
   the blob as a candidate, probes it, and applies the theme **live** — no
   reboot, roughly 40 s end to end. (Only a `psk_hex` rotation, a WiFi change,
   a promote that arms an OTA or — on firmware older than 1.0.1 — a staged
   `broker_url` reboots the device; a theme is not one of them.) If they want to
   watch, `tokenmonitor_device_logs` carries the device's own log — note that
   is a different tool from `tokenmonitor_recent_logs`, which is the broker's.

## Mode semantics

Beyond the tool schema's definitions: **auto** falls back to Night when the
device's RTC has never been SNTP-synced or it has no sunrise/sunset data yet,
and applies ±90 s hysteresis at the
sunrise/sunset threshold. Each provider also keeps its own brand-tinted Day and
Night palette, so switching the active provider shifts colours *within* the
current mode — independent of this skill.
