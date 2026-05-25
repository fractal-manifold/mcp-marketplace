---
name: configure
description: cwallmonitor plugin — provision or reconfigure a C Wall Monitor device from the LAN. Discovers devices in BOOT_NEEDS_CONFIG via mDNS (`_cwm._tcp.local.`), prompts the user for the 6-digit pairing code shown on the device's screen, then pushes the broker URL and an auto-generated PSK to it. Also registers the device in the local cwm-mcp registry so future control-plane polls (/device/<id>/sync) recognise it. Use this when the user says they have a new wall monitor, the device shows "Waiting for setup", they reset a device, or they ask to "configure", "provision" or "set up" a wall monitor.
---

# /cwallmonitor:configure

Provision a C Wall Monitor device that has just connected to WiFi
but does not yet know which broker to talk to. The device sits at the
"Waiting for setup" screen, showing its IP and a 6-digit pairing
code; this skill bridges that gap end-to-end without leaving Claude Code.

## When to invoke

- "I just plugged in a new wall monitor."
- "The device says 'Waiting for setup'."
- "I reset the device, configure it again."
- "Pair this device to my broker."

## Prerequisites

- `cwm-mcp` is running on the user's laptop (the `cwallmonitor`
  plugin's MCP server registers it). Verify with
  `wall_monitor_status` — if it errors, tell the user to install/start
  `cwm-mcp` and stop. `cwm-mcp` is a launcher: it auto-selects one of
  Go / Python / JS implementations. If the user reports that
  `wall_monitor_status` errors with "no working implementation found",
  ask them to run `cwm-mcp --probe` in a terminal — the stderr output
  identifies which runtime got picked or which install hint applies.
- The device is on the same LAN segment as the laptop (mDNS does not
  cross VLANs).
- The user is physically in front of the device — the pairing code is
  shown only on its screen, never on the network.

## Procedure

### 1. Discover the device

Call `wall_monitor_discover_devices` (default 4-second scan). If no
devices come back, ask the user to confirm the device finished its WiFi
connection (the screen should read "Waiting for setup" and show a
6-digit pairing code). Retry once with `timeout_seconds: 8` before
giving up.

Each entry in the result includes:
- `device_id` — 8 hex chars; also visible on the device's `/info`
  endpoint and in the future on a sticker.
- `ipv4` — primary LAN address. Show this and the corresponding URL to
  the user so they can confirm it's the right unit if more than one
  appears.
- `provision_url` — what step 3 below POSTs to.

If multiple devices are returned, use `AskUserQuestion` to ask which
one. Show device_id and IP side by side.

### 2. Get the pairing code from the user

Ask: "What 6-digit code is shown on the device's screen?" The code is
intentionally not retrievable over the network — typing it proves the
user is physically present. The on-device label displays it grouped
3+3 (e.g. "071 718") for legibility; the user can type it with or
without the space.

### 3. Choose the config to push

Resolve only the broker URL before asking the user anything else:

- **broker_url** — default to the laptop's reachable broker. Run
  `wall_monitor_provision_hint` to get the laptop's non-loopback IPv4
  + port; pick the first entry that's on the same `/24` as the device's
  IP (so the device doesn't end up pointed at an interface it can't
  reach). If `wall_monitor_provision_hint` warns that the broker is
  bound to `127.0.0.1`, stop and tell the user to edit
  `~/.config/claude-wall-monitor/service.toml` (`[server] bind =
  "0.0.0.0"`) and restart the broker.
- **psk_hex** — DO NOT ask the user. The broker auto-generates a fresh
  32-byte random PSK on every `wall_monitor_provision` call where
  `psk_hex` is omitted (recommended). The PSK lives on the broker
  registry + device NVS only; the user never has to memorise or pick
  one. Pass `psk_hex` only if reproducing a known key (e.g. migrating
  a device between brokers).
- **city** — optional, but recommended (drives ambient weather).
  Default to nothing and let the user fill it in later via
  `wall_monitor_set_device_pending` if they don't want to think about
  it now.
- **brightness / volume** — only ask if the user volunteers
  preferences. Defaults on the device are sensible.
- **providers** — REQUIRED. The device tracks usage from one or more of
  Claude, Codex and Gemini; only the ones enabled here are polled and
  shown on the dashboard. Default selection rules:
    - **Claude is always pre-selected.** If this skill is running at
      all, it is running inside Claude Code (this plugin only exists as
      a Claude Code plugin), so Claude is definitely an active provider
      — no detection needed.
    - **Codex** → pre-select if `~/.codex/auth.json` exists, or
      `~/.config/codex/` exists, or `OPENAI_API_KEY` is set in the
      environment.
    - **Gemini** → pre-select if `~/.gemini/oauth_creds.json` exists,
      or `~/.config/gemini-cli/` exists, or `GEMINI_API_KEY` /
      `GOOGLE_API_KEY` are set.

  Then call `AskUserQuestion` with `multiSelect: true`, pre-marking
  Claude plus whichever of Codex/Gemini were detected, with options:
    - "Claude (Claude Code)"
    - "Codex (OpenAI)"
    - "Gemini (Google)"

  The user can still uncheck Claude if they really want to (e.g. they
  use Claude Code for other work but don't want it tracked on the
  device). Require at least one provider selected.

  Send `provider_claude`, `provider_codex`, `provider_gemini` flags
  (`true` for selected, omit for not-selected — the broker treats the
  absence as "keep current", which on a fresh provision means disabled).

- **rotation** — if the final selection has **2 or more providers**,
  enable autorotation by passing `rotation_enabled: true` (a single
  provider doesn't need rotation; passing it would just animate one
  card swap into itself). Leave `rotation_interval_seconds` at the
  broker's default (30 s) unless the user volunteers a number.

### 4. POST the provision

Call `wall_monitor_provision` with the values from steps 1–3 (do not
pass `psk_hex` — let the broker generate it; do pass each selected
provider as `provider_claude=true` / `provider_codex=true` /
`provider_gemini=true`). Expected return on success:

```json
{
  "ok": true,
  "device_id": "ab12cd34",
  "registered": true,
  "psk_generated": true,
  "device_response": { "ok": true, "device_id": "ab12cd34", "next": "rebooting" }
}
```

`psk_generated: true` confirms the broker created a fresh random PSK
and stored it in the registry; nothing else is needed from the user.

If `registered` is false and `note` is present, tell the user the
device was provisioned but the local registry write failed (rare; e.g.
disk full). The device will still come online but
`wall_monitor_set_device_pending` won't recognise it until they run
`wall_monitor_register_device` manually.

If the response has `http_status: 401`, the pairing code was wrong —
ask the user to re-read the screen and retry.

### 5. Confirm

The device reboots (~3 s). After ~15 s, suggest the user run
`wall_monitor_list_devices` to confirm the device appears with the
expected `active_broker_url` and a recent `last_seen`. If `last_seen`
stays empty after 60 s, the device is not reaching the broker — check
firewall on the laptop, double-check the chosen broker_url, or run
`wall_monitor_recent_logs` to look for 401s (PSK mismatch).

## Tools used (in order)

1. `wall_monitor_status`         — sanity check that the broker is up.
2. `wall_monitor_discover_devices` — find devices in BOOT_NEEDS_CONFIG.
3. `wall_monitor_provision_hint` — pick the right broker URL.
4. `wall_monitor_provision`      — push the config + register.
5. `wall_monitor_list_devices`   — confirm the device polled.

## Reconfiguring an existing device

If the user wants to change a setting on an *already-provisioned* device
(it does not show "Waiting for setup"), this skill is the wrong
tool. Direct them to either:

- the on-device Settings panel (long-press the mascot on the dashboard), or
- `wall_monitor_set_device_pending <device_id> {…fields…}` for remote
  changes; the device picks up the pending payload on its next
  control-plane poll (≤60 s) and applies it under the candidate/
  rollback safety net.

To start over from scratch on the device side, the user must `idf.py
erase-flash` or use the on-device "Restablecer" button in Settings,
which forces a return to BOOT_NEEDS_WIFI on the next boot.
