---
name: configure
description: tokenmonitor plugin — provision or reconfigure a TokenMonitor device over the LAN or a USB cable. LAN path discovers devices in BOOT_NEEDS_CONFIG via mDNS (`_tmon._tcp.local.`); USB path (developer / rescue / reconfiguration) enumerates the device over the serial cable, works across VLANs and guest networks, and can change WiFi on an already-configured device without a factory reset — including the headline flow of pointing the device at the same WiFi the computer is on. The LAN path prompts for the 6-digit pairing code on the device's screen; the USB path needs no code at all, because the cable is itself the physical-presence proof. Both then push broker URL + an auto-generated PSK, and register the device in the local tokenmonitor-mcp registry. Use this when the user says they have a new wall monitor, the device shows "Waiting for setup", they reset a device, they want to change its WiFi, or they ask to "configure", "provision", "set up" or "reconfigure" a wall monitor — over WiFi or USB.
---

# /tokenmonitor:configure

Provision a TokenMonitor device that has connected to WiFi but does not yet
know which broker to talk to. The device sits at the "Waiting for setup"
screen showing its IP and a 6-digit pairing code; this skill bridges that gap
end-to-end without leaving Claude Code.

## Choosing a transport

Two ways to reach the device — pick before you start:

- **LAN (mDNS)** — the consumer path. Use it for a device that has **already
  joined WiFi** and is sitting at "Waiting for setup" on the **same LAN
  segment** as the laptop. Steps 1–6 below.
- **USB cable** — the developer / rescue / reconfiguration path. Use it when:
  the device and laptop **can't share a LAN** (guest WiFi, client isolation, or
  VLANs that block mDNS); the device is **already configured** and the user wants
  to **change its WiFi** or broker without a factory reset; or the user simply
  has a data cable plugged in. USB is network-independent and its headline flow
  is **"point the device at the WiFi this computer is on."** See
  [USB transport](#usb-transport) below.

**A device straight out of the box is on neither path yet.** It has no WiFi, so
there is nothing for mDNS to find. Its first screen is the setup screen, which
offers the user three routes, and only the third is this skill:

1. **Setup WiFi** — join the device's own WPA2 access point (`TokenMonitor-XXXX`,
   password shown on its screen) and fill in the captive portal at
   `http://192.168.4.1/`. Asks for SSID and WiFi password only.
2. **On this device** — pick the network and type the password on the
   touchscreen. No second device involved.
3. **Over USB** — plug a data cable into the computer. **No code to read or
   type**: the cable is the physical-presence proof, so the device does not ask
   for one on this transport. `tokenmonitor_usb_provision` can carry WiFi,
   broker URL and PSK in **one** payload, which is the only route that
   configures a brand-new device completely in a single step.

After routes 1 or 2 the device reboots onto WiFi and lands on "Waiting for
setup" — that is when the LAN path becomes available.

If the user hasn't said which, and a device is enumerable over USB (a quick
`tokenmonitor_usb_scan`), offer both with `AskUserQuestion`; otherwise default to
USB for a brand-new device (one step instead of two), LAN for a device already
showing "Waiting for setup", and USB for a "change the WiFi / it's on a
different network" request.

**USB works on Linux and macOS today; Windows is still deferred.** Linux
enumerates via sysfs; macOS via `ioreg` (IORegistry → `/dev/cu.*` callout
nodes). Both open the port exclusively (flock + TIOCEXCL). All three runtimes
(go/py/js) implement the same two platforms, so switching runtime does not
change what is supported. On Windows, `tokenmonitor_usb_scan` answers:

> USB scan is not supported on this OS yet (Linux and macOS are supported;
> Windows enumeration is deferred). Use SoftAP + LAN provisioning instead.

Take that at face value and use a LAN path — do not go looking for a cable
problem. WSL2 is a separate matter: it is a Hyper-V VM that receives no USB
devices at all unless the user installs `usbipd-win` (admin) and runs
`usbipd bind` + `usbipd attach --wsl` after each replug. So on WSL2 the scan can
come up empty even though the OS check passed; say so and fall back to LAN.

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

- **providers** — REQUIRED; only enabled ones are polled and shown. **Enable
  all three by default** — pre-mark Claude, Codex *and* Antigravity in
  `AskUserQuestion` (`multiSelect: true`, options "Claude (Claude Code)" /
  "Codex (OpenAI)" / "Antigravity (Google)"). **Do NOT inspect local credential
  files or disable a provider because you can't find a login.** Credential
  storage is platform-specific — plain files, environment variables, or the
  macOS Keychain — and the broker resolves it; a filesystem probe from here is
  both incomplete (it misses the Keychain) and irrelevant to the default. A
  provider with no usable login stays enabled and simply shows "--" on the
  dashboard until its CLI logs in. The user may uncheck any (require at least
  one). (Antigravity is Google's successor to the Gemini CLI; it still runs
  Gemini-family models.) Send **all three** of `provider_claude` /
  `provider_codex` / `provider_antigravity` **explicitly** — `true` for the
  selected ones, `false` for the unchecked ones. **Do not omit the unchecked
  ones:** the device's provision handler only overwrites a provider's stored
  state when its key is present in the payload, so on a *re-configure* an
  omitted provider keeps whatever it already was — dropping a device from three
  providers to two by omission would silently leave the third enabled. An
  explicit `false` is what actually disables it.

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

## USB transport

Configure or reconfigure over the serial cable — network-independent, and the
only in-Claude way to change a device's WiFi without a factory reset.

### U1. Scan

Call `tokenmonitor_usb_scan`. Each port comes back with a `tier`:

- **`registry-match`** — the port's iSerial (MAC-derived) matches a device
  already in the local registry. Unambiguous identity; **safe to auto-select**
  when it's the only one. This is the good path for reconfiguring an enrolled
  unit.
- **`probe`** — an Espressif USB-Serial/JTAG VID/PID (`303a:1001`). This pair is
  burned into **every** ESP32-S3/C3/C6 — every devkit on the desk, and the stock
  firmware on an un-provisioned box. The scan sends it **one bounded HELLO** to
  read its `device_id`/`fw`/`state`, but you must **never auto-select it**: if
  there is more than one, or you're unsure it's the intended unit, **list them
  and ask** with `AskUserQuestion` (show `path`, `device_id`, `fw`, `state`).
- **`shared`** — a generic USB-UART bridge (CH340/CP210x/FTDI) shared with
  thousands of unrelated products (someone's 3D printer, an Arduino). The scan
  **never writes a byte** to it. Only use it if the user **explicitly names the
  port**, and warn them first.

If the scan errors with "not supported on this OS yet", enumeration for that
platform isn't implemented — fall back to LAN.

### U2. No pairing code

**Skip it.** Unlike the LAN path, USB asks for nothing: the device does not
require a pairing code on the serial transport, because being able to write to
its port already proves you are holding it. Do not ask the user for a code, do
not tell them to look at the screen, and do not pass `pairing_code` — in the
case USB exists to solve (a device whose WiFi is wrong), the screen is showing
a dashboard that will never load, so there is no code on it to read.

### U3. Choose the config — the WiFi headline flow

The point-at-my-WiFi flow is the reason USB exists for most users:

- **wifi_ssid** — **prefill from the computer's current network** so the device
  joins the same one. Detect it (do not ask if you can read it):
  `nmcli -t -f active,ssid dev wifi | grep '^yes' | cut -d: -f2` (Linux),
  `networksetup -getairportnetwork en0` (macOS), or
  `netsh wlan show interfaces` (Windows). Show the user the SSID you found and
  let them override.
- **wifi_pass** — **ASK the user.** Reading the saved WiFi password off the OS
  needs elevated permissions (Keychain / `nmcli -s` as root / `netsh ... key=clear`)
  and is intrusive — just prompt for it. `wifi_ssid` and `wifi_pass` **must be
  sent together**; a bare `wifi_ssid` is rejected. For a deliberately open
  network, pass `wifi_pass` as an explicit empty string `""`.
- **broker_url / psk_hex / city / providers / display** — identical rules to LAN
  step 3. **psk_hex**: don't ask, don't pass — it's reused-or-minted. Note that
  over USB, setting `broker_url` needs the device's PSK to be resolvable, which
  means **either `device_id`** (so the registry's PSK can be reused or derived)
  **or an explicit `psk_hex`**. Pass `device_id` from the scan in the normal
  case; without either, the call refuses rather than minting a PSK it cannot
  persist, which would orphan the device. For the pure "just change my WiFi" case, send **only** `wifi_ssid` +
  `wifi_pass` — the broker URL and PSK are preserved untouched.

The remembered-networks store keeps up to 8 networks, so adding one over USB
doesn't forget the others — the device roams between them.

### U4. Provision

Call `tokenmonitor_usb_provision`:

- **port** — omit it only when exactly one `registry-match` exists (it
  auto-selects); otherwise pass the explicit `path` from the scan.
- **pairing_code** — **don't ask for it and don't send one.** USB needs no code:
  the cable is itself the physical-presence proof, so the device never checks
  one on the serial transport and ignores it if sent. Never send the user
  hunting for digits on a screen that, in the case USB exists to solve, is
  showing a dashboard that will never load. (The argument is still accepted so
  older callers keep working; if you do pass it, it must be six digits. The LAN
  path, `tokenmonitor_provision`, still requires a real one.)
- plus the fields from U3.

The tool runs the serial session behind a **leader-mediated port lease** so it
never collides with the broker's live log tailer — that's automatic, nothing to
manage. On success the device persists to NVS and reboots (~3 s); the result
echoes `psk_generated` / `psk_reused` and, when a broker was set,
`registered` / `reregistered`.

**If the result has `outcome_unknown: true`** — PROVISION was sent but no RESULT
came back (a lost reply, or the device reset after applying). **Do NOT blindly
re-run** — a fresh session could double-apply or burn a pairing attempt. Instead
reconnect and read the device's state (`tokenmonitor_usb_scan` shows its
`state`, or check the screen), and only re-provision as a deliberate fresh action
if it clearly didn't take.

### U5. Confirm

Same as LAN step 5 — after ~15 s, `tokenmonitor_list_devices` (if a broker was
set) or re-scan to confirm the new `state`. Then U6 = LAN step 6 (what to tune
later).

## Reconfiguring an existing device

If the device is *already provisioned* (it does not show "Waiting for setup"):

- **To change its WiFi or broker** — use the **USB transport** above. That's the
  whole reason it exists: `tokenmonitor_usb_provision` with a `registry-match`
  port rewrites credentials in place, no factory reset, preserving broker + PSK
  when you send only WiFi fields.
- **For display/provider tweaks over the LAN** — the on-device **Settings** panel
  (long-press the mascot) or `/tokenmonitor:settings`.
- **To start over from scratch** — `idf.py erase-flash` or "Restablecer" in
  on-device Settings, which forces a return to BOOT_NEEDS_WIFI on the next boot.
