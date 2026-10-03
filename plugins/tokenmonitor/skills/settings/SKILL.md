---
name: settings
description: tokenmonitor plugin — remotely change any on-device setting the Settings panel exposes (city, day / night brightness, alert volume, providers and their modes, auto-rotation, theme, virtual pet, custom panel, passphrase) on a TokenMonitor device. Equivalent to tapping the gear on the dashboard and editing a row, but driven from the AI client via the control plane. Use this when the user says "set the wall monitor city to Madrid", "lower the night brightness", "mute the alerts", "disable Codex on device X", "rotate providers every 60 s", "change/rename/hide the pet", "rotate the broker passphrase", "move the device to another broker" / "change the broker URL" (depends on firmware: 1.0.1+ finds the broker by mDNS, older units need the address), "enable/disable the custom (swipe-up) panel", "change what the panel shows", or any similar reconfiguration of an already-provisioned device.
---

# /tokenmonitor:settings

Push a runtime configuration change to an already-provisioned TokenMonitor
device. The change is queued through the control plane and applied on the
device's next poll, under the candidate/promote safety net — a bad config
rolls back automatically. The poll runs every **10 s**, not 60.

This is the remote equivalent of the on-device Settings panel (tap the gear on
the dashboard — there is no long-press gesture; the mascot it used to live on
is not on that screen any more). For *first-time* provisioning use
`/tokenmonitor:configure`; `/tokenmonitor:theme` is a thin wrapper around the
`theme_mode` field here.

## Out of scope

- **WiFi is not changed with THIS tool** — but it *is* remotely changeable.
  Use **`tokenmonitor_set_wifi`**, which exists in all three broker runtimes
  and which the device applies with a remembered-network fallback. Do not tell
  the user WiFi can only be changed on the device or by factory reset; that was
  true once and is not true now. The care that rule was protecting is real
  though: a WiFi push the device cannot join costs connectivity *before* it can
  roll back, which is why `set_wifi` prefers a network the device already
  remembers and asks for a password only when it must.
- **First-time provisioning** (device shows "Waiting for setup") →
  `/tokenmonitor:configure`. This skill needs a device already in the broker's
  registry.
- **Firmware updates** → `/tokenmonitor:firmware`. The `firmware_*` arguments of
  `tokenmonitor_set_device_pending` belong to that skill — never set them here.

## Procedure

### 1. Resolve the device

Call `tokenmonitor_list_devices`. 0 devices → tell the user nothing is
registered and stop (suggest `/tokenmonitor:configure`). 1 → use it without
asking. >1 → if the user did not name one, ask the user (with
`AskUserQuestion` where the client has it), showing `device_id`, `last_seen`
and `active_broker_url` — the registry's last-known address for the device,
not necessarily the one it resolved, and it may be absent.

### 2. Map the request to `tokenmonitor_set_device_pending` arguments

**Only send arguments the user actually asked to change** — omitted fields keep
their current value on the device. The tool schema carries the ranges, enums
and precedence rules; consult it rather than guessing, and clamp numeric values
to its ranges, warning the user when you had to clamp. Two constraints the
schema does **not** state: every numeric field is an **integer** on the wire
(the broker stores them as `uint8`, `autorotate_interval_s` as `uint16`, so
`br_day: 42.5` silently truncates), and
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
  hints; control-plane only, there is no on-device row for it). The third provider was renamed **Gemini → Antigravity**; the
  `*_gemini` names still work as aliases but prefer `*_antigravity`. Note
  `auto` keeps the provider **enabled** and lets the broker pick the data
  source/mode; a provider with no login shows "--", it is *not* disabled.
  `disabled` is the only mode that hides a provider.
  …and `panel_enabled`, which sits here with the providers for the reason above.
- **Display** — `autorotate_enabled`, `autorotate_interval_s`, `theme_mode`,
  `br_day`, `br_night`. For `theme_mode`, normalise first
  (`dark`→`night`, `light`→`day`, `automatic`/`sunset`/`sunrise`→`auto`); ask
  if still ambiguous.
- **Audio** — `vol`.
- **Pet** — `pet_enabled`, `pet_species` (int enum in the schema; map
  the named animal to its number, or pick the closest / ask when the user names
  a species that isn't in the list), `pet_name`.
- **Network** — `city` (**run the geocoding pre-check below first**),
  `psk_hex`, and `broker_url` — a **legacy re-point for firmware older than
  1.0.1 only**; from 1.0.1 the device finds its broker by mDNS and the tool
  refuses the argument (step 4 has the whole story, read it before sending
  one). The device's own Network section carries an editable **Service URL**
  row: on firmware ≥ 1.0.1 it is only a cache of the last proven address that
  discovery overwrites, so do not send the user there; on firmware < 1.0.1 it
  is the authoritative pin and editing it is a valid fix. The WiFi rows of
  this section are `tokenmonitor_set_wifi`, not this tool.
- **About** — read-only, see below.

Two more arguments of the same tool have no Settings row: `log_enabled`
(device diagnostic-log upload) and `channel` (`stable` / `dev`; applied
immediately on the broker, not staged as a pending). Send them only when the
user asks for exactly that.

Pet and panel settings are **device-owned**: the user can also change them on
the device, which reports its choice back via `POST /device/<id>/settings`, so
a control-plane push and an on-device edit converge. A device that has not
picked a species yet simply omits `pet_species` from its report — normal, and
it leaves the stored value untouched.

**About** (Serial, Device ID, Firmware, IP address, Broker URL, Broker version)
is read-only diagnostics — do NOT queue a pending change for any of it.
`tokenmonitor_list_devices` gives `device_id`, `serial_number` and
`active_broker_url` (the registry's last-known address, which may be absent and
is not necessarily the one the device resolved). It does **not** return the
firmware version or the IP — `active_version` is the *config* version — so for
those, point the user at the About section on the device itself (or, for the
firmware the device last reported to the broker, the `firmware_version` key
under `[active]` in `~/.config/tokenmonitor/devices/<device_id>.toml`).

**Custom panel**: it has two independent switches — the device flag
`panel_enabled` *and* a panel JSON file the broker serves at
`GET /device/<id>/panel`. Both must be on for the screen to get data.
Turning the flag off stops the polling, but a document already on screen stays
until the content 404s or the device reboots. Changing *what the panel shows* is a broker-side file edit, **not** a pending.
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
   ask the user (with `AskUserQuestion` where the client has it) to pick — offer the closest indexed town
   **or the nearest larger city** (e.g. Pinto → Getafe, ~5 km, pop 187k).
   **Never queue a `city` you could not geocode.**

4. "Use coordinates instead" is **not possible remotely**: the firmware stores
   `tmon_lat`/`tmon_lon` but the pending payload has no lat/lon field, and
   writing `tmon_city` erases them so the device re-geocodes. No interface
   accepts raw coordinates — the captive portal collects WiFi only and the
   on-device City row geocodes the same way — so a nearby indexed city is the
   only answer.

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
   minutes) it rolls back to the old PSK automatically. They should run
   `tokenmonitor_list_devices` after ~5 min: `psk_hex (key rotation)` gone from
   `pending_changes` = promoted. Still listed = not promoted yet: either the
   device never picked it up (offline — check `last_seen`), or it timed out and
   went back to the old key locally. In both cases the pending stays queued on
   the broker and the device takes it (again) on its next sync, until it
   promotes or you replace it.

### 4. Special case — moving a device to another broker / changing the broker URL

What works depends on the device's firmware, so find that out first.
`tokenmonitor_list_devices` does not show it. Read it from the device (Settings
→ About → Firmware), or from the version the device last reported to the
broker: `firmware_version` under `[active]` in
`~/.config/tokenmonitor/devices/<device_id>.toml`. The broker compares the
numeric `MAJOR.MINOR.PATCH` only, so `1.0.1-dev.<ts>` counts as 1.0.1. If you
cannot tell, the tool tells you: a `broker_url` call is refused, staged or held
according to that same reported version (below).

**Firmware ≥ 1.0.1 — there is no address to set.** The device discovers its
broker by mDNS on whatever subnet it lands on and adopts only the one that
proves the pairing (a response signed with the device's PSK), so "which broker"
is decided by **which registry holds this device's PSK**, not by an address.
To move it to another machine: run `tokenmonitor_register_device` on the new
machine with the same `device_id` and `psk_hex` (`broker_url` is optional
there — only a last-known-address record), run that broker on the device's
network, and stop the old one (two brokers on the same LAN both holding the
PSK is ambiguous — the device adopts the first candidate that proves the
pairing). No reboot and no pending change is involved; the device re-resolves
within ~30 s. A broker that is not on the device's own L2 cannot be found, so
"a broker on a different network" is not supported. Do not suggest the
on-device Service URL row here: discovery overwrites it.

**Firmware 1.0.0** — also finds the broker by mDNS, but adopts on a `devs=`
TXT entry naming its `device_id`, with no proof, and it looks again only after
consecutive *transport* failures against its stored address.

**Firmware ≤ 0.12.0** — needs the address. It too rediscovers only after
repeated *transport* failures.

On both of these lines (everything older than 1.0.1), a unit whose stored URL
points at another broker that is still running gets HTTP 401s, which are not
transport failures, so it never rediscovers on its own.

For any device **older than 1.0.1** the routes to a new address are:

1. `tokenmonitor_set_device_pending broker_url=<url>` — only when it is **this
   same broker** (same registry) that now lives at a new address. The device
   probes the new address and promotes only if the broker there serves the
   same pending version, so pointing it at a *different* broker's registry
   leaves it where it is. The URL must be `http://` or `https://`, at most
   127 bytes; take it from `tokenmonitor_provision_hint`. On promote the device
   writes the address and **reboots** onto it.
2. Re-provision with `broker_url` via `/tokenmonitor:configure` — the route
   for a genuinely different broker.
3. The on-device Settings → Network → **Service URL** row, which on this
   firmware is the authoritative pin.

What `broker_url` on `tokenmonitor_set_device_pending` does, by the firmware
the device last reported:

- **< 1.0.1** — staged and sent; `pending_changes` shows `broker_url`.
- **≥ 1.0.1** — the whole call is refused and nothing is staged:
  `broker_url cannot be staged for device <id>: it reports firmware <fw>, and
  firmware 1.0.1 or newer resolves the broker by mDNS and does not take a
  pushed address. Nothing was staged.` Explain the ≥ 1.0.1 flow above instead.
- **unknown** (no version reported yet) — staged but **held**; the response
  carries a top-level `note` and `pending_changes` shows
  `broker_url (held: sent only if the device's next poll reports firmware
  older than 1.0.1)`. Relay the note to the user.
- A device whose next poll reports ≥ 1.0.1 (or no readable version) has the
  staged address dropped unsent, and `tokenmonitor_list_devices` then shows the
  URL as `broker_url_dropped` — tell the user it was not applied and why. (One
  exception: a poll that already acknowledges the pending's version applied
  it while still legacy, so nothing is dropped.) If the device upgraded to
  ≥ 1.0.1 *after* the staging, the label before that poll reads
  `broker_url (will be dropped: firmware 1.0.1 or newer resolves the broker by
  mDNS)`.

### 5. Queue the change

Call `tokenmonitor_set_device_pending` with `device_id` plus only the fields
the user asked to change. Verify `device.pending_changes` in the response
covers what you sent. Its entries are labels, not argument names: any provider
argument shows as `providers`, a PSK as `psk_hex (key rotation)`, a legacy
`broker_url` under one of the three labels in step 4, and `channel`
never appears (it is applied immediately, so a `channel`-only call
legitimately returns no pending). Otherwise, if the list is absent or empty the
values already matched the active config — tell the user "already set to
<value>" and stop.

### 6. Tell the user what happens next

> Queued <fields> on device <device_id>. The device polls every ~10 s; it will
> pick the change up, probe it against its own broker, and either promote
> (~40 s end to end) or roll back automatically if it can't confirm three
> healthy fetches within 5 minutes.

**Almost nothing needs a reboot.** Only a change to `psk_hex` or
WiFi reboots the device (it has to re-establish the very channel it is being
reconfigured through), plus a promote that arms an OTA and — on firmware older
than 1.0.1 — a staged `broker_url`. `theme_mode`,
providers, autorotate, `br_day`, `br_night`, `vol`, `city`, `panel_enabled`,
`log_enabled` and the pet fields all apply **live** — do not warn the user about a blank screen for those.

To verify, the user can watch `pending_changes` drain via
`tokenmonitor_list_devices`, or read the device's own log with
`tokenmonitor_device_logs` (the ring the firmware uploads).
`tokenmonitor_recent_logs` is the *broker's* log, a different thing, and it
will not show the device's promote lines.

## Common errors

- **`device <id> not registered — call tokenmonitor_register_device first`** —
  run `/tokenmonitor:configure` (fresh
  device on the LAN) or `tokenmonitor_register_device` (device alive but its
  registry entry was lost).
- **`broker_url cannot be staged for device <id>: it reports firmware <fw>, …
  Nothing was staged.`** — the device is on 1.0.1 or newer, where the address
  is not a setting; see step 4. **`broker_url must be an http:// or https://
  URL of at most 127 bytes`** — fix the value.
- **`psk_hex must be exactly 64 hex chars`** — a raw passphrase was passed.
  Generate `secrets.token_hex(32)` or SHA-256 the passphrase first; never pass
  arbitrary text.
- **`device registry is not configured on this tokenmonitor-mcp install; …`**
  (the Go runtime prefixes it with `registry disabled:`) — the broker runs
  without a registry path; the user must configure
  `~/.config/tokenmonitor/devices/` and restart `tokenmonitor-mcp`.
- **`pending_changes` never drains** — usually the candidate fails to probe
  (wrong `psk_hex`, or the broker is not reachable on the device's network).
  Check `tokenmonitor_device_logs`: a healthy probe logs
  `candidate probe ok (n/3)`, a failing one `candidate probe transport failure`
  (that is the string the firmware actually emits; there is no "candidate probe
  failed" line to grep for), and expiry `timeout — rolling back to active`. The
  device rolls back after 5 minutes and picks the still-queued pending up again
  on its next sync.
- **A display setting is queued, promotes, and the device ignores it** — the
  device owns `br_day`, `br_night`, `vol`, `autorotate_*`, `theme_mode`,
  `panel_enabled` and the pet fields, and it vetoes a broker push while it has
  an un-acknowledged local change of its own. That veto lifts by itself after
  60 consecutive failed report attempts (~10 minutes at the 10 s cadence,
  longer while the sync itself is failing), so this is transient; check
  `tokenmonitor_device_logs` for `settings report status=` to see why its own
  report is not landing.
- **City accepted but weather/location is wrong** — the device log shows
  `geocoding: no results for '<city>'` and `ambient: location: ~40,-4
  (build-time default)`. Re-run the geocoding pre-check and push the
  normalised bare name.
