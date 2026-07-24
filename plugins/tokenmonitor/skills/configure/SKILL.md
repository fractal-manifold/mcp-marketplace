---
name: configure
description: tokenmonitor plugin — provision or reconfigure a TokenMonitor device from the LAN. Discovers devices in BOOT_NEEDS_CONFIG via mDNS (`_tmon._tcp.local.`), prompts the user for the 6-digit pairing code shown on the device's screen, then pushes the broker URL and an auto-generated PSK to it. Also registers the device in the local tokenmonitor-mcp registry so future control-plane polls (/device/<id>/sync) recognise it. Use this when the user says they have a new wall monitor, the device shows "Waiting for setup", they reset a device, or they ask to "configure", "provision" or "set up" a wall monitor.
---

# /tokenmonitor:configure

Provision a TokenMonitor device that has connected to WiFi but does not yet
know which broker to talk to. The device sits at the "Waiting for setup"
screen showing its IP and a 6-digit pairing code; this skill bridges that gap
end-to-end without leaving Claude Code.

## Prerequisites

- **The MCP server is up.** Verify with `tokenmonitor_status`. The plugin
  bundles the server under `server/` and runs it directly — no separate
  `go install` / `pipx` / `npm` step. If it errors, the bundled launcher could
  not resolve a runtime: it needs EITHER a language toolchain on `PATH`
  (node+npm, python3+uv/pip, or go) OR network access plus curl/wget to
  download a verified prebuilt Go binary. Either way it resolves on first
  launch — **one-time, and it can be slow**, so don't diagnose a compiling or
  downloading launcher as hung. It logs the chosen runtime — or an install hint
  — to stderr, visible in Claude Code's MCP logs for `tokenmonitor`. Tell the
  user to provide one of those and reload the plugin, then stop.
- The device is on the same LAN segment as the laptop (mDNS does not cross
  VLANs).
- **The user is physically in front of the device** — the pairing code is shown
  only on its screen, never on the network.

## Procedure

### 1. Discover the device

Call `tokenmonitor_discover_devices` (default 4-second scan). If nothing comes
back, ask the user to confirm the device finished its WiFi connection (the
screen should read "Waiting for setup" with a 6-digit code), then retry once
with `timeout_seconds: 8` before giving up. If several devices are returned,
use `AskUserQuestion` showing `device_id` and `ipv4` side by side so the user
can confirm the right unit — the `device_id` is also readable from the device's
`/info` endpoint.

### 2. Get the pairing code from the user

Ask: "What 6-digit code is shown on the device's screen?" It is intentionally
not retrievable over the network — typing it proves physical presence. The
device displays it grouped 3+3 (e.g. "071 718"); accept it with or without the
space.

### 3. Choose the config to push

**Resolve the broker URL first, before asking the user anything else** — if the
broker isn't reachable there is no point collecting preferences.

- **broker_url** — run `tokenmonitor_provision_hint` for the laptop's
  non-loopback IPv4 + port, and pick the first entry on the same `/24` as the
  device's IP (so the device isn't pointed at an interface it can't reach). If
  the hint warns the broker is bound to `127.0.0.1`, **stop** and tell the user
  to set `[server] bind = "0.0.0.0"` in
  `~/.config/tokenmonitor/tokenmonitor.toml` and restart the broker. (Legacy
  `service.toml` is still read, but `tokenmonitor.toml` is primary.)

- **psk_hex** — **DO NOT ask the user and do not pass it.** Omitted, the broker
  mints a fresh 32-byte random PSK for a device it has never seen, and
  **reuses the existing PSK** for a device already in the registry (so a benign
  reconfigure can't desync a working device whose push silently fails). The
  response echoes `psk_generated: true` or `psk_reused: true`. The PSK lives
  only in the broker registry and the device's NVS — the user never has to see,
  pick or memorise one. Pass `psk_hex` explicitly only to force a specific key
  — migrating a device between brokers, or a deliberate rotation.

- **city** — **ASK the user** (it drives the ambient weather widget), e.g.
  "¿En qué ciudad está el dispositivo? (para el tiempo en pantalla)". They may
  decline — omit `city`, they can set it later. Whatever they give **must
  geocode before you send it**: the device feeds the string verbatim to
  Open-Meteo, whose `name=` parameter takes a single place name, so a
  comma-separated descriptor like `"Torrevieja, España"` can return zero
  results and strand the device on default coordinates. Strip to a bare town
  name, verify it resolves with
  `curl -s "https://geocoding-api.open-meteo.com/v1/search?name=<city>&count=1&language=es&format=json"`
  (non-empty `results[]`), show the user the matched `name, admin1, country`,
  and pass the bare name. Full normalisation / nearest-city fallback: the
  "City — geocoding pre-check" section of [[settings]].

- **brightness / volume / theme / pet / panel** — only pass these if the user
  volunteers a preference; the schema's device defaults are sensible, and all
  of them are changeable later from the device or via
  `tokenmonitor_set_device_pending`. Note `panel_enabled` also needs a panel
  data source configured broker-side to show anything.

- **providers** — REQUIRED; only enabled ones are polled and shown. Pre-select
  by detection, then confirm with `AskUserQuestion` (`multiSelect: true`,
  options "Claude (Claude Code)" / "Codex (OpenAI)" / "Antigravity (Google)"):
    - **Claude** is always pre-selected — if this skill is running it is
      running inside Claude Code, so Claude is definitely active.
    - **Codex** → pre-select if `~/.codex/auth.json` or `~/.config/codex/`
      exists, or `OPENAI_API_KEY` is set.
    - **Antigravity** → pre-select if `agy` is on `PATH`, or
      `~/.gemini/antigravity-cli/` or `~/.gemini/oauth_creds.json` exists (that
      OAuth file is shared with the old Gemini CLI and still used), or
      `GEMINI_API_KEY` / `GOOGLE_API_KEY` are set. (Antigravity is Google's
      successor to the Gemini CLI; it still runs Gemini-family models.)

  The user may uncheck Claude if they don't want it tracked. Require at least
  one. Send `provider_claude` / `provider_codex` / `provider_antigravity` as
  `true` for selected and **omit** the others (on a fresh provision, absent
  means disabled).

- **rotation** — `tokenmonitor_provision` does **not** accept rotation fields
  (`additionalProperties: false`; passing them fails the call). With 2+
  providers selected, enable it as a follow-up `tokenmonitor_set_device_pending`
  after the provision succeeds: `autorotate_enabled: true` plus optionally
  `autorotate_interval_s`. A single provider doesn't need rotation.

### 4. POST the provision

Call `tokenmonitor_provision` with the values from steps 1–3. On success
`psk_generated` or `psk_reused` confirms the key handling; nothing else is
needed from the user.

- `registered: false` with a `note` → the device was provisioned but the local
  registry write failed (rare, e.g. disk full). It will come online, but
  `tokenmonitor_set_device_pending` won't recognise it until the user runs
  `tokenmonitor_register_device` manually.
- `http_status: 401` → wrong pairing code; ask the user to re-read the screen
  and retry.

### 5. Confirm

The device reboots (~3 s). After ~15 s, suggest `tokenmonitor_list_devices` to
confirm it appears with the expected `active_broker_url` and a recent
`last_seen`. If `last_seen` is still empty after 60 s the device is not
reaching the broker — check the laptop's firewall, re-check the chosen
broker_url, or look for 401s (PSK mismatch) in `tokenmonitor_recent_logs`.

### 6. Tell the user what they can tune later

Keep it to a few bullets, and mention both routes: the on-device **Settings**
panel (long-press the mascot) and the **`/tokenmonitor:settings`** skill.
Cover: city; separate day/night brightness; alert volume or mute; which
providers are on and each one's mode (Auto / Subscription / API key);
auto-rotation when 2+ providers are on; the virtual pet (show, species, name);
theme (Day / Night / Auto); and — advanced, rarely needed — broker URL and
passphrase. If the user voices any of these in the same breath, apply them
right away with `tokenmonitor_set_device_pending` instead of making them ask
again.

## Reconfiguring an existing device

If the device is *already provisioned* (it does not show "Waiting for setup"),
this is the wrong skill — direct the user to the on-device Settings panel or
to `/tokenmonitor:settings`. To start over from scratch, they must
`idf.py erase-flash` or press "Restablecer" in on-device Settings, which forces
a return to BOOT_NEEDS_WIFI on the next boot.
