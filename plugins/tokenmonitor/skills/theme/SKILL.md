---
name: theme
description: tokenmonitor plugin — switch a TokenMonitor device between Day, Night and Auto themes remotely. Each provider (Claude / Codex / Antigravity) has its own brand-tinted palette in both Day and Night flavours; Auto follows the sunrise/sunset of the configured city. Use this when the user says "switch the wall monitor to night mode", "make it dark", "use the day theme", "let it follow the sun", "change the theme on device X", or anything similar.
---

# /tokenmonitor:theme

Set the on-device theme mode. Thin wrapper around
`tokenmonitor_set_device_pending`'s `theme_mode` field; for anything else use
[[settings]].

```
/tokenmonitor:theme <day|night|auto> [--device <device_id>]
```

## Procedure

1. **Normalise the mode** to `day` / `night` / `auto`: `dark`→night,
   `light`→day, `sunset`/`sunrise`/`automatic`→auto. If still ambiguous, ask.

2. **Resolve the device** with `tokenmonitor_list_devices`: 0 → nothing is
   registered, suggest `/tokenmonitor:configure` and stop; 1 → use it; >1 →
   `AskUserQuestion` (show `device_id`, `active_broker_url`, `last_seen`)
   unless `--device` was given (validate it against the list).

3. **Queue** `tokenmonitor_set_device_pending device_id=<id> theme_mode=<mode>`.
   If the response's `pending_changes` does not include `theme_mode`, the
   device is already on that mode — say so and stop.

4. **Tell the user**: the device polls `/device/<id>/sync` every ~60 s, stores
   the blob as a candidate and reboots to apply it — roughly 90 s end to end.
   `tokenmonitor_recent_logs` shows the `rebooting to apply promoted config`
   line if they want to watch.

## Mode semantics

Beyond the tool schema's definitions: **auto** falls back to Night when the
device's RTC has never been SNTP-synced, and applies ±90 s hysteresis at the
sunrise/sunset threshold. Each provider also keeps its own brand-tinted Day and
Night palette, so switching the active provider shifts colours *within* the
current mode — independent of this skill.
