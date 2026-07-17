---
name: configure
description: tokenmonitor plugin — provision or reconfigure a TokenMonitor device from the LAN. Discovers devices in BOOT_NEEDS_CONFIG via mDNS (`_tmon._tcp.local.`), prompts the user for the 6-digit pairing code shown on the device's screen, then pushes the broker URL and an auto-generated PSK to it. Also registers the device in the local tokenmonitor-mcp registry so future control-plane polls (/device/<id>/sync) recognise it. Use this when the user says they have a new wall monitor, the device shows "Waiting for setup", they reset a device, or they ask to "configure", "provision" or "set up" a wall monitor.
---

# /tokenmonitor:configure

Provision a TokenMonitor device that has just connected to WiFi
but does not yet know which broker to talk to. The device sits at the
"Waiting for setup" screen, showing its IP and a 6-digit pairing
code; this skill bridges that gap end-to-end without leaving Claude Code.

## When to invoke

- "I just plugged in a new wall monitor."
- "The device says 'Waiting for setup'."
- "I reset the device, configure it again."
- "Pair this device to my broker."

## Prerequisites

- The `tokenmonitor` plugin's MCP server is up. The plugin **bundles**
  the server under its `server/` directory and runs it directly
  (`${CLAUDE_PLUGIN_ROOT}/server/tokenmonitor-mcp`) — installing the plugin is
  enough, there is no separate `go install` / `pipx` / `npm` step.
  Verify with `tokenmonitor_status`. If it errors, the bundled server
  failed to start: the launcher (`server/tokenmonitor-mcp`) auto-selects one of
  the Go / Python / JS impls and needs ONE language toolchain on the
  user's PATH (node+npm, python3+uv/pip, or go), resolving that runtime's
  dependencies on first launch (one-time, can be slow). It logs the
  chosen runtime — or an install hint when none is usable — to stderr,
  visible in Claude Code's MCP server logs for `tokenmonitor`. Tell the
  user to make sure a toolchain is installed and reload the plugin, then
  stop.
- The device is on the same LAN segment as the laptop (mDNS does not
  cross VLANs).
- The user is physically in front of the device — the pairing code is
  shown only on its screen, never on the network.

## Procedure

### 1. Discover the device

Call `tokenmonitor_discover_devices` (default 4-second scan). If no
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
  `tokenmonitor_provision_hint` to get the laptop's non-loopback IPv4
  + port; pick the first entry that's on the same `/24` as the device's
  IP (so the device doesn't end up pointed at an interface it can't
  reach). If `tokenmonitor_provision_hint` warns that the broker is
  bound to `127.0.0.1`, stop and tell the user to edit
  `~/.config/tokenmonitor/tokenmonitor.toml` (`[server] bind =
  "0.0.0.0"`) and restart the broker. (The legacy `service.toml` is
  still read for back-compat, but `tokenmonitor.toml` is the primary config.)
- **psk_hex** — DO NOT ask the user. When `psk_hex` is omitted
  (recommended), the broker mints a fresh 32-byte random PSK **only for a
  device it has never seen**. Re-running provision on a device already in
  the registry **reuses its existing PSK** (and re-pushes it) rather than
  rotating the key — so a benign reconfigure can't desync a working device
  whose push silently fails. The response echoes `psk_generated: true`
  (new device) or `psk_reused: true` (existing device). The PSK lives on
  the broker registry + device NVS only; the user never has to memorise or
  pick one. Pass `psk_hex` explicitly only to force a specific key (e.g.
  migrating a device between brokers or a deliberate rotation).
- **city** — **ASK the user** for their city during setup (it drives the
  ambient weather widget). Pose a short free-text question, e.g. "¿En qué
  ciudad está el dispositivo? (para el tiempo en pantalla)". The user may
  decline / leave it blank — that's fine, omit `city` and they can set it
  later via `tokenmonitor_set_device_pending` or on-device Settings.
  **Whatever they give, it MUST geocode before you send it**: the device
  feeds the string verbatim to Open-Meteo, whose `name=` parameter takes a
  single place name — a comma-separated descriptor like
  `"Torrevieja, España"` or `"Pinto, Madrid, Spain"` is unreliable and can
  return zero results, leaving the device on default coordinates. So:
    1. Strip to a **bare town name** (`"Torrevieja"`, `"Pinto"`,
       `"Getafe"`) — drop the province/country the user may have typed.
    2. Verify it resolves with
       `curl -s "https://geocoding-api.open-meteo.com/v1/search?name=<city>&count=1&language=es&format=json"`
       (non-empty `results[]`); show the user the matched
       `name, admin1, country` to confirm it's the right place.
    3. Pass the bare name as `city` in the provision call.
  See the [[settings]] skill's "City — geocoding pre-check" for the full
  normalisation / nearest-city fallback procedure.
- **brightness / volume** — only ask if the user volunteers
  preferences. Defaults on the device are sensible.
- **theme / pet** — optional display preferences, also changeable later
  from the device's on-screen Settings menu (and via
  `tokenmonitor_set_device_pending`, which uses these same field names).
  Only ask if the user volunteers a preference; otherwise omit and let
  the sensible defaults stand.
    - `theme_mode` — `"day"` (light palette), `"night"` (dark palette) or
      `"auto"` (follows sunrise/sunset). Device default is `"auto"`.
    - `pet_enabled` — `true` shows the virtual ASCII pet on the
      dashboard, `false` hides it. Device default is `true` (shown). Pass
      `false` only if the user explicitly doesn't want it.
    - `panel_enabled` — `true` enables the swipe-up custom-panel screen
      (broker-fed charts/tables; the data comes from a local file the
      broker serves via `GET /device/<id>/panel`, configured in the
      broker's `[panel]` section — see `docs/custom-panel.md`). Device
      default is `false` (opt-in). Pass `true` only if the user set up a
      panel data source.
- **providers** — REQUIRED. The device tracks usage from one or more of
  Claude, Codex and Antigravity; only the ones enabled here are polled and
  shown on the dashboard. Default selection rules:
    - **Claude is always pre-selected.** If this skill is running at
      all, it is running inside Claude Code (this plugin only exists as
      a Claude Code plugin), so Claude is definitely an active provider
      — no detection needed.
    - **Codex** → pre-select if `~/.codex/auth.json` exists, or
      `~/.config/codex/` exists, or `OPENAI_API_KEY` is set in the
      environment.
    - **Antigravity** → pre-select if the `agy` binary is on `PATH`, or
      `~/.gemini/antigravity-cli/` exists, or
      `~/.gemini/oauth_creds.json` exists (the OAuth file is shared with
      the old Gemini CLI and still used), or `GEMINI_API_KEY` /
      `GOOGLE_API_KEY` are set. (Antigravity is Google's successor to the
      Gemini CLI; it still runs the Gemini-family models.)

  Then call `AskUserQuestion` with `multiSelect: true`, pre-marking
  Claude plus whichever of Codex/Antigravity were detected, with options:
    - "Claude (Claude Code)"
    - "Codex (OpenAI)"
    - "Antigravity (Google)"

  The user can still uncheck Claude if they really want to (e.g. they
  use Claude Code for other work but don't want it tracked on the
  device). Require at least one provider selected.

  Send `provider_claude`, `provider_codex`, `provider_antigravity` flags
  (`true` for selected, omit for not-selected — the broker treats the
  absence as "keep current", which on a fresh provision means disabled).
  The legacy `provider_gemini` flag is still accepted as an alias, but
  prefer `provider_antigravity`.

- **rotation** — `tokenmonitor_provision` does NOT accept rotation
  fields (its schema is `additionalProperties: false`; passing them
  fails the call). If the final selection has **2 or more providers**
  and you want autorotation on at setup, enable it as a **follow-up**
  `tokenmonitor_set_device_pending` call after the provision succeeds,
  using the real fields `autorotate_enabled: true` and (optionally)
  `autorotate_interval_s` (seconds, 1..300; leave it unset for the
  device default unless the user volunteers a number). A single provider
  doesn't need rotation.

### 4. POST the provision

Call `tokenmonitor_provision` with the values from steps 1–3 (do not
pass `psk_hex` — let the broker generate it; do pass each selected
provider as `provider_claude=true` / `provider_codex=true` /
`provider_antigravity=true`; pass `theme_mode` / `pet_enabled` /
`panel_enabled` only if the user expressed a preference, otherwise omit
them so the device defaults stand). Expected return on success:

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
and stored it in the registry; `psk_reused: true` instead means this
device was already registered and kept its existing PSK (a re-run that
did not rotate the key). Either way nothing else is needed from the user.

If `registered` is false and `note` is present, tell the user the
device was provisioned but the local registry write failed (rare; e.g.
disk full). The device will still come online but
`tokenmonitor_set_device_pending` won't recognise it until they run
`tokenmonitor_register_device` manually.

If the response has `http_status: 401`, the pairing code was wrong —
ask the user to re-read the screen and retry.

### 5. Confirm

The device reboots (~3 s). After ~15 s, suggest the user run
`tokenmonitor_list_devices` to confirm the device appears with the
expected `active_broker_url` and a recent `last_seen`. If `last_seen`
stays empty after 60 s, the device is not reaching the broker — check
firewall on the laptop, double-check the chosen broker_url, or run
`tokenmonitor_recent_logs` to look for 401s (PSK mismatch).

### 6. Tell the user what they can tune later

Once the device is online, **tell the user what they can change from
here** so they know the device is customisable. Keep it short — a few
bullets — and mention both ways to change them: the on-device **Settings**
panel (long-press the mascot on the dashboard) and remotely via the
**`/tokenmonitor:settings`** skill (driven from Claude Code). Cover at
least:

- **City** — the ambient weather location (if they skipped it at setup).
- **Brightness** — separate **day** and **night** levels.
- **Alert volume** — or mute.
- **Providers & mode** — enable/disable Claude / Codex / Antigravity, and set
  each one's mode: **Auto**, **Subscription** (plan/quota usage) or
  **API key** (pay-as-you-go spend).
- **Auto-rotation** — when 2+ providers are on, cycle the active one every
  N seconds (or freeze on one).
- **Virtual pet** — show/hide it, change species, or rename it.
- **Theme** — Day / Night / Auto (follows the city's sunrise/sunset).
- **Broker URL / passphrase** — advanced; rarely needed.

If the user expresses any of these preferences in the same breath, apply
them right away with `tokenmonitor_set_device_pending` rather than making
them ask again.

## Tools used (in order)

1. `tokenmonitor_status`         — sanity check that the broker is up.
2. `tokenmonitor_discover_devices` — find devices in BOOT_NEEDS_CONFIG.
3. `tokenmonitor_provision_hint` — pick the right broker URL.
4. `tokenmonitor_provision`      — push the config + register.
5. `tokenmonitor_list_devices`   — confirm the device polled.

## Reconfiguring an existing device

If the user wants to change a setting on an *already-provisioned* device
(it does not show "Waiting for setup"), this skill is the wrong
tool. Direct them to either:

- the on-device Settings panel (long-press the mascot on the dashboard), or
- `tokenmonitor_set_device_pending <device_id> {…fields…}` for remote
  changes; the device picks up the pending payload on its next
  control-plane poll (≤60 s) and applies it under the candidate/
  rollback safety net.

To start over from scratch on the device side, the user must `idf.py
erase-flash` or use the on-device "Restablecer" button in Settings,
which forces a return to BOOT_NEEDS_WIFI on the next boot.
