---
name: theme
description: claude-wall-monitor plugin — switch a Claude Wall Monitor device between Day, Night and Auto themes remotely. Each provider (Claude / Codex / Gemini) has its own brand-tinted palette in both Day and Night flavours; Auto follows the sunrise/sunset of the configured city. Use this when the user says "switch the wall monitor to night mode", "make it dark", "use the day theme", "let it follow the sun", "change the theme on device X", or anything similar.
---

# /wall-monitor:theme

Set the on-device theme mode (Day, Night or Auto) on a Claude Wall
Monitor device. The change is queued through the control plane and
applied on the device's next poll + reboot cycle.

## When to invoke

- "Switch the wall monitor to night mode."
- "Use the day theme on all devices."
- "Make the screen darker."
- "Let it auto-switch with sunrise."
- "Theme device ab12cd34 to night."

## Usage

```
/wall-monitor:theme <day|night|auto> [--device <device_id>]
```

If `--device` is omitted, list available devices with
`wall_monitor_list_devices` and ask which one to retarget (skip the
prompt if there is exactly one device registered).

## Procedure

### 1. Validate the mode

Accept exactly `day`, `night` or `auto` (case-insensitive). If the user
typed something else (e.g. "dark"), map intuitively: `dark` → `night`,
`light` → `day`, `sunset` / `sunrise` / `automatic` → `auto`. If still
ambiguous, ask.

### 2. Resolve the device

- Call `wall_monitor_list_devices`.
  - 0 devices → tell the user nothing is registered and stop (suggest
    `/wall-monitor:configure`).
  - 1 device → use it without asking.
  - >1 devices → if no `--device` flag was given, present the list with
    `AskUserQuestion` (show `device_id`, `active_broker_url`, last
    seen). If the user passed `--device`, validate it against the list
    and error out if not found.

### 3. Queue the change

Call:

```
wall_monitor_set_device_pending
  device_id: <id>
  theme_mode: <day|night|auto>
```

The broker stores it as a pending config blob and bumps `cfg_ver`. The
broker returns the updated `device` summary; check that
`pending_changes` includes `"theme_mode"`. If it does not, the active
theme already matches — tell the user "device is already on <mode>" and
stop.

### 4. Tell the user what happens next

The device polls `/device/<id>/sync` every ~60 s. When it sees the new
pending blob, it stores it as a candidate, reboots to apply it, then
probes the new config. The whole loop takes roughly **60–90 s** end to
end.

Tell the user:

> Queued `<mode>` for device `<device_id>`. The screen will reboot
> within ~90 s to apply the new theme. Run
> `wall_monitor_list_devices` afterwards to confirm.

If the user wants to verify immediately, suggest
`wall_monitor_recent_logs` to watch for the `rebooting to apply
promoted config` log line.

## Mode semantics

- **day** — locks the device on the Day palette regardless of clock.
- **night** — locks it on the Night palette regardless of clock.
- **auto** — uses the sunrise / sunset returned by Open-Meteo for the
  configured city. Falls back to Night if the device's RTC has not
  been set (no SNTP sync). Hysteresis of ±90 s prevents jitter at the
  threshold.

Each provider keeps its own brand-tinted Day and Night palette, so
switching the active provider (Claude / Codex / Gemini) also shifts
the colours within the current mode — that is independent of this
skill.

## Tools used (in order)

1. `wall_monitor_list_devices`     — resolve the target device.
2. `wall_monitor_set_device_pending` — queue `theme_mode`.

## Common errors

- **`theme_mode must be one of: day, night, auto`** — the broker
  rejected an unknown value. Re-read the user's request and map it
  to one of the three modes.
- **`device <id> not registered`** — the device was never registered
  on this broker. Run `/wall-monitor:configure` first, or
  `wall_monitor_register_device` if it was registered elsewhere.
- **`registry disabled`** — the user's broker is running without a
  registry path. They need to configure
  `~/.config/claude-wall-monitor/devices/` and restart the broker.
