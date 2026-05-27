---
name: settings
description: cwallmonitor plugin — remotely change any on-device setting that the Settings panel exposes (city, day / night brightness, alert volume, enabled providers, auto-rotation, broker URL, passphrase) on a C Wall Monitor device. Equivalent to long-pressing the mascot on the dashboard and editing a row, but driven from Claude Code via the control plane. Use this when the user says "set the wall monitor city to Madrid", "lower the night brightness", "mute the alerts", "disable Codex on device X", "rotate providers every 60 s", "rotate the broker passphrase", "change the broker URL", or any similar reconfiguration of an already-provisioned device.
---

# /cwallmonitor:settings

Push a runtime configuration change to an already-provisioned C Wall
Monitor device. The change is queued through the control plane and
applied on the device's next 60 s poll (with the candidate / promote
safety net — a bad config rolls back automatically).

This is the remote equivalent of the on-device Settings panel
(long-press the mascot on the dashboard). For *first-time* provisioning
of a brand-new device, use [[configure]] instead. For the dedicated
theme shortcut, [[theme]] is a thin wrapper around the `theme_mode`
field here.

## When to invoke

- "Set the wall monitor city to Madrid."
- "Lower the night brightness to 15."
- "Mute the alerts." / "Set alert volume to 0."
- "Enable / disable Codex on the wall monitor."
- "Rotate providers every 60 s."
- "Stop rotating providers." / "Pin the dashboard to Claude."
- "Change the broker URL on device `<id>`."
- "Rotate the broker passphrase on the wall monitor."
- "Update the wall monitor settings."

## Out of scope

- **WiFi SSID and password are NOT remotely changeable.** The control
  plane intentionally never advertises them: a wrong WiFi push would
  brick the device because it loses connectivity *before* it can
  rollback. Tell the user they have to either open the on-device
  Settings panel (long-press the mascot) or factory-reset the device
  and re-run `/cwallmonitor:configure`.
- **First-time provisioning** (the device is showing "Waiting for
  setup"): use [[configure]] — this skill needs a device that is
  already registered in the broker's registry.

## Procedure

### 1. Resolve the device

Call `wall_monitor_list_devices`.

- 0 devices → tell the user nothing is registered and stop (suggest
  `/cwallmonitor:configure`).
- 1 device → use it without asking.
- >1 devices → if the user did not name one, present the list with
  `AskUserQuestion` (show `device_id`, `active_broker_url`,
  `last_seen`).

### 2. Resolve the fields to change

For each setting the user mentioned, map to the `wall_monitor_set_device_pending`
argument from the table below. **Only send arguments the user actually
asked to change** — every other field is left as-is on the device
(omitted arguments mean "keep current").

On the device the Settings screen is grouped into five visible
sections; the same grouping is reflected here so it's easy to find
the matching MCP argument when the user references "the Display
section" or "the Audio settings".

#### Providers

| User intent                       | MCP argument               | Valid range / format               |
| --------------------------------- | -------------------------- | ---------------------------------- |
| Enable Claude provider            | `provider_claude`          | bool                               |
| Enable Codex provider             | `provider_codex`           | bool                               |
| Enable Gemini provider            | `provider_gemini`          | bool                               |

#### Display

| User intent                       | MCP argument               | Valid range / format               |
| --------------------------------- | -------------------------- | ---------------------------------- |
| Auto-rotate enabled               | `autorotate_enabled`       | bool                               |
| Auto-rotate interval (seconds)    | `autorotate_interval_s`    | int, 10..300                       |
| Theme (day / night / auto)        | `theme_mode`               | one of `day`, `night`, `auto`      |
| Day brightness                    | `br_day`                   | int, 10..100 (% of backlight)      |
| Night brightness                  | `br_night`                 | int, 5..100 (% of backlight)       |

#### Network

| User intent                       | MCP argument               | Valid range / format               |
| --------------------------------- | -------------------------- | ---------------------------------- |
| City (weather / sunrise)          | `city`                     | string, 1..64 chars                |
| Broker URL                        | `broker_url`               | full URL (e.g. `http://10.0.0.5:8787`) |
| Pairing passphrase / PSK rotation | `psk_hex`                  | exactly 64 lowercase hex chars     |

#### Audio

| User intent                       | MCP argument               | Valid range / format               |
| --------------------------------- | -------------------------- | ---------------------------------- |
| Alert volume                      | `vol`                      | int, 0..100 (% of audio level)     |

#### About (read-only on the device)

The device's Settings screen also exposes an **About** section with
Device ID, running firmware version, IP address and active broker
URL. These are diagnostic readouts — there is no MCP argument to
change them (Device ID is assigned at first boot, firmware comes
from the running image, IP from DHCP, and Broker URL mirrors the
editable `broker_url` above). If the user asks "what's the IP /
firmware / device ID of my wall monitor", call
`wall_monitor_list_devices` and read the active fields from the
registry — do NOT queue a pending change.

Clamp numeric values to the listed ranges and warn the user if you had
to clamp. For `theme_mode`, normalise (`dark`→`night`, `light`→`day`,
`automatic`/`sunset`/`sunrise`→`auto`); if still ambiguous, ask.

If the user asks to **disable all providers**, refuse: the dashboard
has nothing to show and the device will fall back to "no provider".
Require at least one provider remain enabled. To get the current set
of enabled providers, read `active_providers` from
`wall_monitor_list_devices`.

If the user asks to **disable auto-rotate while only one provider is
enabled**, just queue `autorotate_enabled: false` — that is the natural
state. Conversely, if the user enables a second provider, suggest also
enabling autorotation if it is currently off.

### 3. Special-case: passphrase rotation

If the user wants to rotate the passphrase / PSK:

1. Ask whether they want a freshly-generated PSK (recommended) or to
   supply their own. If freshly generated, derive
   `psk_hex = secrets.token_hex(32)` locally — the broker's
   `set_device_pending` does not auto-generate one (unlike `provision`).
2. Send `psk_hex` only. The broker keeps accepting the OLD PSK until
   the device promotes the new one (via `auth.VerifyMulti`), so a
   rotation does not lock you out mid-flight.
3. Warn the user: if the device fails to promote (three OKs within
   five minutes), it rolls back to the old PSK automatically — they
   should run `wall_monitor_list_devices` after ~5 min to confirm the
   `pending_changes` list no longer mentions `psk_hex (key rotation)`.

### 4. Special-case: broker_url change

A `broker_url` change is a *move-to-another-broker* operation. Before
queueing it, ask the user to confirm the new broker is reachable from
the device's network — if not, the candidate will fail to probe and
the device rolls back. If the new broker URL belongs to a *different*
machine, the registry on the new machine also needs a matching device
entry; suggest the user run `wall_monitor_register_device` over there
with the same `device_id` and `psk_hex` first.

### 5. Queue the change

Call:

```
wall_monitor_set_device_pending
  device_id: <id>
  <only the fields the user asked to change>
```

The broker stores the diff as a pending config blob and bumps
`cfg_ver`. The response includes the updated `device` summary; verify
that `pending_changes` lists the fields you sent. If `pending_changes`
is empty, the values already matched the active config — tell the user
"already set to <value>" and stop.

### 6. Tell the user what happens next

```
Queued <fields> on device <device_id>.
The device polls every ~60 s; it will pick up the change, probe it
against its own broker, and either promote (~90 s end to end) or
roll back automatically if it can't confirm three healthy fetches
within 5 minutes.
```

If the change requires a reboot (anything that touches `broker_url`,
`psk_hex`, `theme_mode`, providers, or autorotate settings), mention
that the screen will go through a brief reboot before settling. Pure
"live" fields (`br_day`, `br_night`, `vol`, `city`) apply without a
reboot — the next ambient / backlight tick picks them up.

For verification, the user can run `wall_monitor_list_devices` to
watch `pending_changes` drain, or `wall_monitor_recent_logs` to see
`rebooting to apply promoted config`.

## Examples

### Bump night brightness

```
wall_monitor_set_device_pending
  device_id: ab12cd34
  br_night: 15
```

### Mute the alerts

```
wall_monitor_set_device_pending
  device_id: ab12cd34
  vol: 0
```

### Disable Codex, keep Claude and Gemini, rotate every 45 s

```
wall_monitor_set_device_pending
  device_id: ab12cd34
  provider_codex: false
  autorotate_enabled: true
  autorotate_interval_s: 45
```

### Rotate the passphrase

```
wall_monitor_set_device_pending
  device_id: ab12cd34
  psk_hex: <64 hex chars>
```

## Tools used (in order)

1. `wall_monitor_list_devices`       — resolve the device + read
   current active providers (for the "don't disable everything" check).
2. `wall_monitor_set_device_pending` — queue the diff.
3. `wall_monitor_list_devices`       — (optional, suggested to user)
   confirm `pending_changes` drained.

## Common errors

- **`device <id> not registered`** — the device was never registered
  on this broker. The user has to either run
  `/cwallmonitor:configure` (if it's a fresh device on the LAN) or
  `wall_monitor_register_device` (if the device is alive but its
  registry entry was lost).
- **`psk_hex must be exactly 64 hex chars`** — the user's passphrase
  string was passed raw. Either generate `secrets.token_hex(32)` or
  hash a passphrase with SHA-256 first; never pass arbitrary text.
- **`theme_mode must be one of: day, night, auto`** — see
  normalisation rules in step 2.
- **`registry disabled`** — the broker is running without a registry
  path; the user has to configure
  `~/.config/claude-wall-monitor/devices/` and restart `cwm-mcp`.
- **`pending_changes` never drains** — most often the new candidate
  fails to probe (wrong `broker_url`, wrong `psk_hex`). Check
  `wall_monitor_recent_logs` for `candidate probe failed`; the device
  will roll back automatically after 5 minutes.
