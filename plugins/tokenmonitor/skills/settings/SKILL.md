---
name: settings
description: tokenmonitor plugin — remotely change any on-device setting the Settings panel exposes (city, day / night brightness, alert volume, providers and their modes, auto-rotation, theme, virtual pet, custom panel, broker URL, passphrase) on a TokenMonitor device. Equivalent to tapping the gear on the dashboard and editing a row, but driven from Claude Code via the control plane. Use this when the user says "set the wall monitor city to Madrid", "lower the night brightness", "mute the alerts", "disable Codex on device X", "rotate providers every 60 s", "change/rename/hide the pet", "rotate the broker passphrase", "change the broker URL", "enable/disable the custom (swipe-up) panel", "change what the panel shows", or any similar reconfiguration of an already-provisioned device.
---

# /tokenmonitor:settings

Push a runtime configuration change to an already-provisioned TokenMonitor
device. The change is queued through the control plane and applied on the
device's next poll, under the candidate/promote safety net — a bad config
rolls back automatically. The poll runs every **10 s**, not 60.

This is the remote equivalent of the on-device Settings panel (tap the gear on
the dashboard — there is no long-press gesture; the mascot it used to live on
is not on that screen any more). For *first-time* provisioning use
[[configure]]; [[theme]] is a thin wrapper around the `theme_mode` field here.

## Out of scope

- **WiFi is not changed with THIS tool** — but it *is* remotely changeable.
  Use **`tokenmonitor_set_wifi`**, which exists in all three broker runtimes
  and which the device applies with a remembered-network fallback. Do not tell
  the user WiFi can only be changed on the device or by factory reset; that was
  true once and is not true now. The care that rule was protecting is real
  though: a WiFi push the device cannot join costs connectivity *before* it can
  roll back, which is why `set_wifi` prefers a network the device already
  remembers and asks for a password only when it must.
- **First-time provisioning** (device shows "Waiting for setup") → [[configure]].
  This skill needs a device already in the broker's registry.

## Procedure

### 1. Resolve the device

Call `tokenmonitor_list_devices`. 0 devices → tell the user nothing is
registered and stop (suggest `/tokenmonitor:configure`). 1 → use it without
asking. >1 → if the user did not name one, present the list with
`AskUserQuestion` (`device_id`, `active_broker_url`, `last_seen`).

### 2. Map the request to `tokenmonitor_set_device_pending` arguments

**Only send arguments the user actually asked to change** — omitted fields keep
their current value on the device. The tool schema carries the ranges, enums
and precedence rules; consult it rather than guessing, and clamp numeric values
to its ranges, warning the user when you had to clamp. Two constraints the
schema does **not** state: every numeric field is an **integer** on the wire
(the broker stores them as `uint8`, so `br_day: 42.5` silently truncates), and
`city` is capped at **64 bytes** (the firmware clips it UTF-8-aware rather than
rejecting, so an over-long name is silently shortened).

The device's Settings screen groups these into **six** sections, so the user may
reference "the Display section" or "the Audio settings". Note the first one is
**Content**, not "Providers", and the custom panel lives there rather than
under Display — what a Content row decides is whether a *page exists at all*,
where Display only changes how the existing pages are drawn:

- **Content** — `provider_mode_{claude,codex,antigravity}` (fine-grained:
  auto / disabled / subscription / api_key) or the legacy coarse booleans
  `provider_{claude,codex,antigravity}`. "Disable Codex" →
  `provider_mode_codex=disabled`; "show Claude as API spend" →
  `provider_mode_claude=api_key`. Also `antigravity_models` (dashboard model
  hints). The third provider was renamed **Gemini → Antigravity**; the
  `*_gemini` names still work as aliases but prefer `*_antigravity`. Note
  `auto` keeps the provider **enabled** and lets the broker pick the data
  source/mode; a provider with no login shows "--", it is *not* disabled.
  `disabled` is the only mode that hides a provider.
  …and `panel_enabled`, which sits here with the providers for the reason above.
- **Display** — `autorotate_enabled`, `autorotate_interval_s`, `theme_mode`,
  `br_day`, `br_night`. For `theme_mode`, normalise first
  (`dark`→`night`, `light`→`day`, `automatic`/`sunset`/`sunrise`→`auto`); ask
  if still ambiguous.
- **Virtual pet** — `pet_enabled`, `pet_species` (int enum in the schema; map
  the named animal to its number, or pick the closest / ask when the user names
  a species that isn't in the list), `pet_name`.
- **Network** — `city` (**run the geocoding pre-check below first**),
  `broker_url`, `psk_hex`.
- **Audio** — `vol`.

Pet and panel settings are **device-owned**: the user can also change them on
the device, which reports its choice back via `POST /device/<id>/settings`, so
a control-plane push and an on-device edit converge. A device that has not
picked a species yet simply omits `pet_species` from its report — normal, and
it leaves the stored value untouched.

**About** (Device ID, firmware version, IP, active broker URL) is read-only
diagnostics. If the user asks for any of it, read the fields from
`tokenmonitor_list_devices` — do NOT queue a pending change.

**Custom panel**: it has two independent switches — the device flag
`panel_enabled` *and* a panel JSON file the broker serves at
`GET /device/<id>/panel`. Both must be on for the screen to show data.
Changing *what the panel shows* is a broker-side file edit, **not** a pending.
If the broker is too old to expose `panel_enabled` in the tool schema, the only
way to disable the panel is to remove the content broker-side so the endpoint
404s. Before doing anything panel-related, read `custom-panel.md` next to this
file (in this skill's directory) for the full procedure.

#### City — geocoding pre-check (REQUIRED before sending `city`)

The device re-geocodes the string you push: on the next ambient cycle the
firmware calls Open-Meteo with that exact string. Open-Meteo's `name=`
parameter expects a **single place name**, not a comma-separated descriptor —
`"Pinto, Madrid, Spain"` returns zero results and the device silently falls
back to its build-time default coordinates (`geocoding: no results for
'<city>'` in `tokenmonitor_device_logs`). There is **no lat/lon field in the
control plane today**, so pushing a string that geocodes is the only fix.

1. Run the firmware's exact query so you see what the device will see:

   ```
   curl -s "https://geocoding-api.open-meteo.com/v1/search?name=<URL-encoded>&count=1&language=es&format=json"
   ```

   Non-empty `results[]` → push the string verbatim.

2. If empty, test simpler candidates in order, taking the first that resolves:
   the first comma-segment (`"Pinto, Madrid, Spain"` → `"Pinto"`), then the
   bare town with no region/country words. Push the form that resolved (the
   device must resolve the identical string) and tell the user you normalised
   `"<original>"` → `"<resolved>"`, showing the matched `name` / `admin1` /
   `country_code` / `latitude,longitude`.

3. If nothing resolves, widen the search (`count=5`, drop `language=es`) and
   use `AskUserQuestion` to let the user pick — offer the closest indexed town
   **or the nearest larger city** (e.g. Pinto → Getafe, ~5 km, pop 187k).
   **Never queue a `city` you could not geocode.**

4. "Use coordinates instead" is **not possible remotely**: the firmware stores
   `tmon_lat`/`tmon_lon` but the pending payload has no lat/lon field, and
   writing `tmon_city` erases them so the device re-geocodes. Exact coordinates
   for an unindexed spot need the on-device captive portal / Settings panel; a
   nearby indexed city is the remote-friendly answer.

#### Provider sanity rules

If the user asks to **disable all providers**, refuse — the dashboard would
have nothing to show. Require at least one to remain enabled; read
`active_providers` from `tokenmonitor_list_devices` for the current set. **Never
disable a provider merely because the broker reports no credentials or usage
for it** — that is a "--" display, not a reason to turn it off; disable only on
explicit user request. Disabling auto-rotate while only one provider is enabled
is fine (that is the natural state); conversely, if the user enables a second
provider, suggest turning autorotation on if it is currently off.

### 3. Special case — passphrase rotation

1. Ask whether they want a freshly-generated PSK (recommended) or their own.
   If generated, derive `psk_hex = secrets.token_hex(32)` **locally** —
   `set_device_pending` does not auto-generate one (unlike `provision`).
2. Send `psk_hex` only. The broker keeps accepting the OLD PSK until the device
   promotes the new one (`auth.VerifyMulti`), so rotation cannot lock you out
   mid-flight.
3. Warn the user: if the device fails to promote (three OKs within five
   minutes) it rolls back to the old PSK automatically — they should run
   `tokenmonitor_list_devices` after ~5 min to confirm `pending_changes` no
   longer mentions `psk_hex (key rotation)`.

### 4. Special case — broker_url change

This is a *move-to-another-broker* operation. Confirm with the user that the
new broker is reachable from the device's network, or the candidate fails to
probe and the device rolls back. If the new URL belongs to a *different*
machine, that machine's registry also needs a matching entry — suggest running
`tokenmonitor_register_device` there first with the same `device_id` and
`psk_hex`.

### 5. Queue the change

Call `tokenmonitor_set_device_pending` with `device_id` plus only the fields
the user asked to change. Verify the response's `pending_changes` lists what
you sent; if it is empty the values already matched the active config — tell
the user "already set to <value>" and stop.

### 6. Tell the user what happens next

> Queued <fields> on device <device_id>. The device polls every ~10 s; it will
> pick the change up, probe it against its own broker, and either promote
> (~40 s end to end) or roll back automatically if it can't confirm three
> healthy fetches within 5 minutes.

**Almost nothing needs a reboot.** Only a change to `broker_url`, `psk_hex` or
WiFi reboots the device (it has to re-establish the very channel it is being
reconfigured through), plus a promote that arms an OTA. `theme_mode`,
providers, autorotate, `br_day`, `br_night`, `vol`, `city` and the pet fields
all apply **live** — do not warn the user about a blank screen for those.

To verify, the user can watch `pending_changes` drain via
`tokenmonitor_list_devices`, or read the device's own log with
`tokenmonitor_device_logs` (the ring the firmware uploads).
`tokenmonitor_recent_logs` is the *broker's* log, a different thing, and it
will not show the device's promote lines.

## Common errors

- **`device <id> not registered`** — run `/tokenmonitor:configure` (fresh
  device on the LAN) or `tokenmonitor_register_device` (device alive but its
  registry entry was lost).
- **`psk_hex must be exactly 64 hex chars`** — a raw passphrase was passed.
  Generate `secrets.token_hex(32)` or SHA-256 the passphrase first; never pass
  arbitrary text.
- **`registry disabled`** — the broker runs without a registry path; the user
  must configure `~/.config/tokenmonitor/devices/` and restart
  `tokenmonitor-mcp`.
- **`pending_changes` never drains** — usually the candidate fails to probe
  (wrong `broker_url` or `psk_hex`). Check `tokenmonitor_device_logs` for
  `candidate probe transport failure` — that is the string the firmware
  actually emits; there is no "candidate probe failed" line to grep for. The
  device rolls back after 5 minutes.
- **A display setting is queued, promotes, and the device ignores it** — the
  device owns `br_day`, `br_night`, `vol`, `autorotate_*`, `theme_mode`,
  `panel_enabled` and the pet fields, and it vetoes a broker push while it has
  an un-acknowledged local change of its own. That veto lifts by itself after
  ~10 minutes of the device failing to report, so this is transient; check
  `tokenmonitor_device_logs` for `settings report status=` to see why its own
  report is not landing.
- **City accepted but weather/location is wrong** — the device log shows
  `geocoding: no results for '<city>'` and `ambient: location: ~40,-4
  (build-time default)`. Re-run the geocoding pre-check and push the
  normalised bare name.
