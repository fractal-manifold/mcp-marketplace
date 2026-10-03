---
name: configure
description: tokenmonitor plugin — provision or reconfigure a TokenMonitor desk monitor over the LAN or a USB cable. LAN path discovers devices in BOOT_NEEDS_CONFIG via mDNS (`_tmon._tcp.local.`) and prompts for the 6-digit pairing code on the device's screen. USB path works across VLANs and guest networks and can change WiFi on an already-configured device without a factory reset (e.g. point it at the WiFi the computer is on); it needs no pairing code, but an already-configured online device must first be put in pairing mode (hold BOOT at least 3 s, release before 10 s). Pairing enrols the device (auto-generated PSK plus an entry in the local tokenmonitor-mcp registry); `enroll=false` changes settings only. Use this when the user says they have a new wall monitor, the device shows "Waiting for setup", they reset a device, they want to change its WiFi, or they ask to "configure", "provision", "set up" or "reconfigure" a wall monitor — over WiFi or USB.
---

# /tokenmonitor:configure

Provision a TokenMonitor desk monitor that has connected to WiFi but is not yet
paired with a broker (it has no PSK). The device sits at the "Waiting for setup"
screen showing its IP and a 6-digit pairing code; this skill bridges that gap
end-to-end from the coding assistant, and also reconfigures a device that is
already set up.

## Choosing a transport

Two ways to reach the device — pick before you start:

- **LAN (mDNS)** — the consumer path. Use it for a device that has **already
  joined WiFi** and is sitting at "Waiting for setup" on the **same LAN
  segment** as the laptop. Steps 1–6 below.
- **USB cable** — the developer / rescue / reconfiguration path. Use it when:
  the device and laptop **can't share a LAN** (guest WiFi, client isolation, or
  VLANs that block mDNS); the device is **already configured** but offline or
  unreachable and the user wants to **change its WiFi** without a factory reset;
  or the user simply has a data cable plugged in. USB is network-independent and its headline flow
  is **"point the device at the WiFi this computer is on."** It needs the device
  to be **in pairing mode** first — see
  [The cable only listens in pairing mode](#the-cable-only-listens-in-pairing-mode)
  and [USB transport](#usb-transport) below.

### The cable only listens in pairing mode

**Plugging the cable in is not enough.** The serial transport
(`tmon_prov_serial_start()`) runs **only inside a pairing session**, and a
device that is provisioned *and* online has none open. The USB-Serial/JTAG port
still enumerates — that peripheral is in silicon — so the port appears in a
scan while **nothing on the device answers a HELLO**. Do not read that as a hub,
cable, lease, leader or broker problem: it is the normal state of a working
device.

The cable is already listening in exactly these states:

- **Brand-new / no WiFi** — the captive-portal boot opens the session before it
  paints the screen.
- **BOOT_NEEDS_CONFIG** — WiFi remembered, but either no PSK is stored or no
  broker has been found and proven yet; "Waiting for setup".
- **Provisioned but no IP yet** — a session opens on every boot and is retired
  the moment an address arrives. This is the "I carried it somewhere its WiFi
  doesn't exist" case, and it is why a misplaced unit is still reachable — but
  on a device that is happily online it closes within a second of boot, so
  never plan on it.

**On an already-configured, online device, tell the user to open the door
first:**

> Hold the **BOOT** button (the side button that is *not* the power button) for
> **at least 3 seconds and release before 10 seconds**. The device reboots into a screen headed
> "Pairing"; the window stays open **10 minutes**.

Releasing before 3 s does nothing; reaching 10 s while still holding raises the
**factory reset** confirmation instead — say the range out loud when you ask. (Settings → "Pairing
mode" on the touchscreen is the equivalent route if the user prefers it.) There
is no way to open this window from the computer: pairing mode needs a reboot,
because at runtime the poll / ambient / panel tasks hold the internal DRAM the
serial reader would need.

Ignore the pairing code the screen shows — the cable never checks one
([U2](#u2-no-pairing-code)). The code exists for the LAN transport.

**A device straight out of the box cannot use the LAN path yet.** It has no
WiFi, so there is nothing for mDNS to find; USB already works from its setup
screen. That first screen offers the user three routes, and only the third is
this skill:

1. **Setup WiFi** — join the device's own WPA2 access point (`TokenMonitor-XXXX`,
   password shown on its screen) and fill in the captive portal at
   `http://192.168.4.1/`. Asks for SSID and WiFi password only.
2. **On this device** — pick the network and type the password on the
   touchscreen. No second device involved.
3. **Over USB** — plug a data cable into the computer. **No code to read or
   type**: the cable is the physical-presence proof, so the device does not ask
   for one on this transport. `tokenmonitor_usb_provision` can carry WiFi
   and the pairing (PSK) in **one** payload, which is the only route that
   configures a brand-new device completely in a single step. On *this* screen
   the cable is already listening — no BOOT press needed — because a device with
   no broker opens the session at boot and keeps it open.

After routes 1 or 2 the device reboots onto WiFi and lands on "Waiting for
setup" — that is when the LAN path becomes available.

If the user hasn't said which, and a device is enumerable over USB (a quick
`tokenmonitor_usb_scan`), offer both — ask the user (with `AskUserQuestion`
where the client has it); otherwise default to USB for a brand-new device (one
step instead of two) and LAN for a device already showing "Waiting for setup".
For a "change the WiFi" request on a device that is online and registered,
prefer `tokenmonitor_set_wifi` (see
[Reconfiguring an existing device](#reconfiguring-an-existing-device)); use USB
when the device is offline or on a network the computer cannot reach.

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
  — to stderr, visible in the client's MCP logs for `tokenmonitor`. Tell the
  user to provide one of those and reload the plugin, then stop.
- **LAN path only:** the device is on the same LAN segment as the laptop (mDNS
  does not cross VLANs).
- **LAN path only:** the user is physically in front of the device — the pairing
  code is shown only on its screen, never on the network. (USB needs neither;
  it needs the cable and an open pairing session.)

## Procedure (LAN)

### 1. Discover the device

Call `tokenmonitor_discover_devices` (default 4-second scan). If nothing comes
back, ask the user to confirm the device finished its WiFi connection (the
screen should read "Waiting for setup" with a 6-digit code), then retry once
with `timeout_seconds: 8` before giving up. If several devices are returned,
ask the user (with `AskUserQuestion` where the client has it), showing
`device_id` and `ipv4` side by side so they can confirm the right unit — the `device_id` is also readable from the device's
`/info` endpoint.

### 2. Get the pairing code from the user

Ask: "What 6-digit code is shown on the device's screen?" It is intentionally
not retrievable over the network — typing it proves physical presence. The
device displays it grouped 3+3 (e.g. "071 718"); accept it with or without the
space.

### 3. Choose the config to push

**Check the broker is reachable on the LAN first, before asking the user
anything else** — if it isn't, there is no point collecting preferences.

- **broker_url** — **normally omit it.** Firmware 1.0.0 and newer finds its
  broker by mDNS on its own subnet (and from 1.0.1 only talks to the one that
  can prove the pairing), so a DHCP lease change never strands it; firmware
  older than 1.0.0 cannot leave "Waiting for setup" without an address (see
  [Older firmware](#older-firmware)). The tool covers both: whenever it pushes a
  PSK over the LAN and you gave no `broker_url`, it adds this host's address on
  the route to the device and reports it as `broker_url_seeded`. On new
  firmware that is only a cache seed the device drops when it stops working.
  If the tool cannot work that address out it refuses:

  > could not work out an address of this broker that the device can reach, and
  > firmware older than 1.0.0 cannot pair without one. Nothing was written. Pass
  > broker_url (see tokenmonitor_provision_hint)

  Then pass the `urls[]` entry from `tokenmonitor_provision_hint` that is on the
  device's subnet (compare with the device's `ipv4`; do not assume a `/24`).

  Run `tokenmonitor_provision_hint` in any case, because it answers the
  question that matters on every firmware: if it warns the broker is bound to
  `127.0.0.1`, **stop** and tell the user to set `[server] bind = "0.0.0.0"` in
  `~/.config/tokenmonitor/tokenmonitor.toml` and restart the broker — a
  loopback-bound broker publishes no mDNS advertisement and is invisible to
  the device. (Legacy `service.toml` is still read, but `tokenmonitor.toml` is
  primary.)

  Passing `broker_url` yourself has two side effects an auto-seeded one does
  not, both only when a PSK is being pushed (`enroll: false` still leaves PSK
  and registry untouched): it counts as asking to pair a device this registry
  does not know and that cannot say whether it holds a PSK, and it **converges
  the registry record** to what this call sent. Re-pairing a
  device the registry already holds (e.g. after a factory reset) *without* it
  re-sends the same PSK and leaves the record — and so its old settings —
  exactly as they were.

- **enroll** — there is **no default**; what the tool does when you omit it
  depends on what it knows about the device:
  - **In this registry** → its own PSK is re-sent. Nothing to pass.
  - **Not in this registry** → over the LAN the device cannot say whether it
    already holds a PSK, so the tool will not guess. **For a first pairing pass
    `enroll: true`.** Without it (and without `psk_hex` or `broker_url`) the
    call is refused before anything is sent:

    > this device is not in the registry and nothing says whether it is already
    > paired with another broker. Nothing was written. Pass enroll=true to pair
    > it with this broker (replacing any PSK it holds), or enroll=false to
    > change settings only

    If you get that, ask the user: *"Is this device new (or reset), or is it
    already set up with a TokenMonitor broker on another computer?"* New / reset
    / "move it here" → `enroll: true`. Set up elsewhere and staying there →
    `enroll: false`.
  - `enroll: true` pairs the device here regardless, **replacing any PSK it
    holds** — a first pairing, or deliberately taking a device over from
    another broker.
  - `enroll: false` pushes no PSK, seeds no address and never touches the
    registry: a settings-only change on a device paired with a **different**
    broker. It cannot be combined with `psk_hex` (`enroll=false cannot be
    combined with psk_hex`).

  The registry is written only after the device confirms it applied the
  payload.

- **psk_hex** — **DO NOT ask the user and do not pass it.** Omitted, the tool
  **reuses the PSK the registry already holds** for that `device_id` (so a
  benign reconfigure can't desync a working device whose push silently fails),
  and mints a fresh 32-byte random one for a device it is pairing for the first
  time. The response echoes `psk_generated: true` or `psk_reused: true`. The PSK
  lives only in the broker registry and the device's NVS — the user never has to
  see, pick or memorise one. Pass `psk_hex` explicitly only to force a specific
  key — pairing the device with a registry that already holds that key (moving
  it to another broker — see `/tokenmonitor:settings` §4), or a deliberate
  rotation. On an install with **no device registry**, nothing can keep a minted
  key, so no PSK is pushed unless you pass `psk_hex`; the result's `note` says
  so.

- **city** — **ASK the user** (it drives the ambient weather widget), e.g.
  "¿En qué ciudad está el dispositivo? (para el tiempo en pantalla)". They may
  decline — omit `city`, they can set it later. Whatever they give **must
  geocode before you send it**: the device feeds the string verbatim to
  Open-Meteo, whose `name=` parameter takes a single place name, so a
  comma-separated descriptor like `"Torrevieja, España"` can return zero
  results and strand the device on default coordinates. Strip to a bare town
  name, verify it resolves with
  `curl -s "https://geocoding-api.open-meteo.com/v1/search?name=<URL-encoded city>&count=1&language=es&format=json"`
  (non-empty `results[]`), show the user the matched `name, admin1, country`,
  and pass the bare name. Full normalisation / nearest-city fallback: the
  "City — geocoding pre-check" section of the `/tokenmonitor:settings`
  skill.

- **br_day / br_night / vol / theme_mode / pet_enabled** — only pass these if
  the user volunteers a preference; the device defaults are sensible, and all
  of them are changeable later from the device or via
  `tokenmonitor_set_device_pending`. `pet_species`, `pet_name` and
  `panel_enabled` are **not** provisioning fields: set them afterwards with
  `tokenmonitor_set_device_pending` (the LAN tool's schema accepts
  `panel_enabled`, but the device does not persist it at provision time, and
  the panel also needs a data source configured broker-side to show anything).

- **providers** — REQUIRED; only enabled ones are polled and shown. **Enable
  all three by default** — ask the user with Claude, Codex *and* Antigravity
  pre-marked (with `AskUserQuestion` where the client has it: `multiSelect:
  true`, options "Claude (Claude Code)" / "Codex (OpenAI)" / "Antigravity
  (Google)"). **Do NOT inspect local credential
  files or disable a provider because you can't find a login.** Credential
  storage is platform-specific — plain files, environment variables, or the
  macOS Keychain — and the broker resolves it; a filesystem probe from here is
  both incomplete (it misses the Keychain) and irrelevant to the default. A
  provider with no usable login stays enabled and simply shows "--" on the
  dashboard until its CLI logs in. The user may uncheck any (require at least
  one). (Antigravity is Google's successor to the Gemini CLI; it still runs
  Gemini-family models.) Send **all three** of `provider_claude` /
  `provider_codex` / `provider_antigravity` **explicitly** — `true` for the
  selected ones, `false` for the unchecked ones. Naming **any** provider makes
  the whole set authoritative — the tool fills an omitted one in as `false` —
  while omitting all three leaves the device's providers unchanged. Being
  explicit keeps what you send and what the user chose visibly the same.

- **rotation** — `tokenmonitor_provision` does **not** accept rotation fields
  (`additionalProperties: false`; passing them fails the call). With 2+
  providers selected, enable it as a follow-up `tokenmonitor_set_device_pending`
  after the provision succeeds: `autorotate_enabled: true` plus optionally
  `autorotate_interval_s`. A single provider doesn't need rotation.

### 4. POST the provision

Call `tokenmonitor_provision` with the values from steps 1–3 — for a first
pairing that includes `enroll: true`. A refusal quoted in step 3 means nothing
was sent; answer it and call again. On success
(`ok: true`) read **`enrolled`**: `true` means the registry now holds this
device with the PSK that was pushed, and nothing else is needed from the user.
`psk_generated` / `psk_reused` say where the key came from, and
`broker_url_seeded` is the address the tool added because you gave none.

- `registered` / `reregistered` only say *how* the record got there: a new
  record, or an existing one converged in place. **`registered: false` with
  `enrolled: true` is not a failure** — it is the normal answer when the
  registry already held this PSK and you passed no `broker_url` (a seeded one
  does not count), so the record was left untouched.
- **A result carrying `psk_hex` + `note`** → a PSK was *generated* and the
  registry does **not** hold it. That happens when the registry write failed
  after the device applied (`enrolled: false`), when the device answered a 5xx
  (a failed write can be partial), or when the `POST` itself died
  (`ok: false`, `outcome_unknown: true` — the request may have landed). Keep
  that key: it exists nowhere else on the host. What to do depends on which: after a 5xx (`could not persist
  configuration`) the write may be partial — resend the identical payload with
  that `psk_hex` passed explicitly, which completes it and enrols normally.
  After an unknown outcome, first check whether the device took it (is its
  screen still on "Waiting for setup"?). Once the device is known to hold the
  key and the registry still does not, fix whatever the `note` names and enrol
  it with `tokenmonitor_register_device` (`device_id` + that `psk_hex`; no
  `broker_url` needed). Treat the key as a secret — do not echo
  it beyond what the recovery needs. A PSK you supplied or the registry already
  held is never echoed back.
- `enrolled: false` with a `note` but **no** `psk_hex` → either the registry
  write failed for a key the registry or you already have (fix the cause and
  re-register with that key), or this install has no registry and no PSK was
  pushed at all (the `note` says which). With `enroll: false`, `enrolled: false`
  and no `note` is simply what you asked for.
- `http_status: 401` → wrong pairing code; ask the user to re-read the screen
  and retry. **Only five attempts are allowed**: the fifth failure locks the
  session, which then answers `423 Locked` with
  `{"error":"pairing_locked","reboot_required":true}` and the screen switches to
  "Pairing locked". Recovering needs a reboot (a fresh BOOT-hold session is one), so
  confirm the digits with the user before resending rather than retrying blind.

### 5. Confirm

The device reboots (~3 s) and, holding both the PSK and the seeded address,
goes straight to the dashboard. After ~15 s, suggest `tokenmonitor_list_devices`
to confirm it appears with a recent `last_seen`. If `last_seen` is still empty
after 60 s the device is not reaching the broker. Firmware 1.0.0+ re-resolves
it by mDNS when the seeded address fails, so the likely causes are: the laptop's firewall; a broker bound to
loopback (no advertisement); an AP with client isolation, which blocks the
multicast (the device shows "No broker on this network"); or a PSK mismatch,
which shows up as 401s in `tokenmonitor_recent_logs`.

### 6. Tell the user what they can tune later

Keep it to a few bullets, and mention both routes: the on-device **Settings**
panel (**tap the gear** at the bottom-right of the dashboard — the old
long-press-the-mascot route is gone) and the **`/tokenmonitor:settings`** skill.
Cover: city; WiFi (`tokenmonitor_set_wifi`); separate day/night brightness; alert volume or mute; which
providers are on and each one's mode (Auto / Subscription / API key);
auto-rotation when 2+ providers are on; the virtual pet (show, species, name);
theme (Day / Night / Auto); and — advanced, rarely needed — the
passphrase. If the user voices any of these in the same breath, apply them
right away — `tokenmonitor_set_wifi` for WiFi, `tokenmonitor_set_device_pending`
for the rest — instead of making them ask again.

## USB transport

Configure or reconfigure over the serial cable — network-independent. For a
device that is **online and registered**, prefer `tokenmonitor_set_wifi` to
change WiFi (no cable, no button); USB is for a device that is new, offline,
unregistered, on a network the computer cannot reach, or moving to a remembered
*open* network.

### U0. Make sure the device is listening

Read [The cable only listens in pairing
mode](#the-cable-only-listens-in-pairing-mode) before anything else. **If the
device is provisioned and currently online (it is showing a dashboard), have the
user hold BOOT for at least 3 s and release before 10 s, and wait for the "Pairing" screen** —
otherwise every step below fails at the handshake, with no clue that the reason
is on the device.

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
  and ask** the user (with `AskUserQuestion` where the client has it; show
  `path`, `device_id`, `fw`, `state`).
- **`shared`** — a generic USB-UART bridge (CH340/CP210x/FTDI) shared with
  thousands of unrelated products (someone's 3D printer, an Arduino). The scan
  **never writes a byte** to it. Only use it if the user **explicitly names the
  port**, and warn them first.

**`has_psk` is the field that answers "is this device already paired".** A
probed device on firmware newer than 1.0.1 reports it: `true` = it holds a PSK
(it is paired with *some* broker), `false` = it holds none. **Absent means
unknown, never false** — firmware up to and including 1.0.1 does not send it,
and newer firmware omits it when its NVS cannot answer.
`fw` is the firmware version from the same reply; U3 uses both.

**Do not read `state` as "is this device provisioned".** It is derived from the
in-session single-shot flag, which the session clears on open, so at HELLO time
it reads `needs_config` on **every** device — including a fully provisioned one.
It only ever flips to `provisioned` after a payload lands *in that same session*.
Show it if you like, but answer "is it already set up?" from `has_psk`,
`tokenmonitor_list_devices` or the device's screen, never from this field.

If the scan errors with "not supported on this OS yet", enumeration for that
platform isn't implemented — fall back to LAN.

**Read the `probe_error` text first.** "leased by another provisioning session"
or "held by another process" is host-side port contention — close the other
serial monitor and retry; it says nothing about the device.

**Otherwise a port that shows up but does not answer is the U0 problem, not a
hardware one.** Two shapes, one cause:

- a `probe` entry with a `probe_error` (HELLO timeout / "no valid HELLO_RESP")
  and no `device_id` / `fw` / `state`;
- a `registry-match` entry — matched on iSerial, which needs no reply at all —
  that then dies at the handshake in `tokenmonitor_usb_provision`.

On a unit you know is a TokenMonitor, both almost always mean **no pairing
session is open**. (The exceptions: a `probe` port can be some other ESP32
entirely, and a first-boot screen whose USB card reads "Not available on this
boot" means the serial reader failed to start — reboot the device.) Go back to
U0 and have the user press BOOT; do not re-scan repeatedly, switch ports, blame the hub, restart the
broker, or hunt for a lease/leader conflict. (A genuinely absent port is a
different symptom: nothing enumerates at all — then it's the cable, a
charge-only lead, or WSL2 without `usbipd`.)

### U2. No pairing code

**Skip it.** Unlike the LAN path, USB asks for nothing: the device does not
require a pairing code on the serial transport, because being able to write to
its port already proves you are holding it. Do not ask the user for a code, do
not tell them to look at the screen, and do not pass `pairing_code` — even when
the pairing screen is showing one, it is there for the LAN transport.

This is about the *code*, not about the *session*: the cable still has to have a
pairing session to talk to (U0). "No code" and "nothing to do on the device" are
not the same claim.

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
- **psk_hex / city / providers / display** — same rules as LAN
  step 3; `panel_enabled` is not accepted here at all (`additionalProperties:
  false`, so passing it — or `pet_species` / `pet_name` — is a hard schema error
  before any serial work happens; don't misread that as a cable fault).
  **psk_hex**: don't ask, don't pass — it's reused-or-minted.
- **broker_url** — normally omit it. Firmware 1.0.0+ needs none. For firmware
  older than 1.0.0 (or a version the tool cannot read) the tool seeds the
  address itself when it pushes a PSK — but over a cable it cannot see which
  interface faces the device, so it only does so when
  `tokenmonitor_provision_hint` lists exactly one URL. Otherwise it refuses:

  > this device's firmware (%s) is older than 1.0.0 and cannot find the broker
  > without an address, and this host has %d candidate addresses. Nothing was
  > written. Pass broker_url (see tokenmonitor_provision_hint), or enroll=false
  > to change settings without pairing

  Then ask the user which network the device is (or will be) on, and pass the
  hint URL on that network as `broker_url`.
- **enroll** — same three values as LAN step 3, but over USB the device
  identifies itself in the handshake, so the tool decides from better evidence
  and **no `device_id` is needed to enrol** (pass it only to assert which unit
  you mean; it is verified against the HELLO before anything is written). With
  `enroll` omitted:
  - **In this registry** → its own PSK is re-sent; the pairing does not change.
  - **Unknown here, `has_psk: false`** → it is paired with this broker. A first
    pairing of a new device needs no extra argument.
  - **Unknown here, `has_psk: true`** → refused, and `broker_url` does not
    override it:

    > the device already holds a PSK that this registry does not know — it may
    > be paired with another broker, or an earlier enrolment here was never
    > recorded. Nothing was written. Pass enroll=false to keep that pairing and
    > change settings only, enroll=true to re-pair the device with this broker,
    > or psk_hex if you have the key it holds

    Ask the user: *"This device is already paired with a broker this computer
    doesn't know. Keep that pairing and only change settings (WiFi), or re-pair
    it with this computer?"* Keep → `enroll: false`. Re-pair → `enroll: true`.
    If an earlier call here returned a `psk_hex` that was never registered,
    pass that `psk_hex` instead.
  - **Unknown here, `has_psk` absent** (firmware ≤ 1.0.1, or NVS could not
    answer) → refused unless you
    pass `enroll`, `psk_hex` or `broker_url`, with the same "this device is not
    in the registry and nothing says whether it is already paired…" message as
    on the LAN. Ask the same question as there: new / reset → `enroll: true`;
    set up with another computer's broker → `enroll: false`.

  Every refusal happens after the handshake and before anything is written, so
  the session is still open — just call again.
- **The pure "just change my WiFi" case** — send `wifi_ssid` + `wifi_pass` and
  nothing else to configure:
  - **Device in this registry** — omit `enroll`. The call re-sends the PSK the
    device already has and leaves the registry record untouched (`enrolled:
    true`, `registered: false`, `psk_reused: true`).
  - **Device paired with a different broker** (another computer's) — pass
    **`enroll: false`**. It is required: on firmware that reports `has_psk` the
    call is refused without it, and `enroll: true` would replace the device's
    real pairing.
  - **Device not paired with anything yet** — it is a first pairing; see the
    `enroll` bullet above.

The remembered-networks store keeps up to 8 networks and the device roams
between them. Adding a 9th evicts an unverified entry first, otherwise the
least-recently-used one. A remembered **open** network is stored but never
auto-joined on a later roam.

### U4. Provision

Call `tokenmonitor_usb_provision`:

- **port** — omit it only when exactly one `registry-match` exists (it
  auto-selects); otherwise pass the explicit `path` from the scan.
- **pairing_code** — **don't ask for it and don't send one.** USB needs no code:
  the cable is itself the physical-presence proof, so the device never checks
  one on the serial transport and ignores it if sent. (The argument is still
  accepted so older callers keep working; if you do pass it, it must be six
  digits. The LAN path, `tokenmonitor_provision`, still requires a real one.)
  The physical-presence proof the cable replaces is the *code* — not the BOOT
  press from U0, which is what makes anyone listen in the first place.
- plus the fields from U3.

The tool runs the serial session behind a **leader-mediated port lease** so it
never collides with the broker's live log tailer — that's automatic, nothing to
manage. Top-level `ok` is the device's own answer. On
`ok: true` the device persists to NVS and reboots (~3 s); the result carries
`enrolled`, `registered` / `reregistered` and `psk_generated` / `psk_reused`,
read exactly as in LAN step 4 (`registered: false` with `enrolled: true` is the
normal "already held this PSK" case; with `enroll: false` none of them apply),
plus `broker_url_seeded` when the tool added an address for old firmware.
A `psk_hex` + `note` on a successful result means the same as on the LAN: a
generated key the registry does not hold — keep it and use
`tokenmonitor_register_device`.

**`ok: false` without `outcome_unknown`** — nothing reached the registry. With
a `device_response` present, the device answered and refused; the reason is in
`error`. Without one, the session failed before PROVISION was sent (handshake
— see U0/U1 — or `device_mismatch: true`: the port's device is not the
`device_id` you named) and nothing was written. For a device refusal: a
rejected field (e.g. a bad WiFi pair) applied nothing: fix it and send again —
the session is still open. `could not persist configuration` is different: the
write failed part-way, so do not assume the device is unchanged — resend the
identical payload to complete it. If that result carries `psk_hex`, a generated
key may already be on the device: resend with that same `psk_hex` rather than
letting a new one be minted. `pairing_locked` is the exception: five wrong codes
on the LAN lock the cable out too, and only a reboot clears it (a fresh
BOOT-hold session is one).

**If the result has `outcome_unknown: true`** — PROVISION was sent but no RESULT
came back (a lost reply, or the device reset after applying). **Do NOT blindly
re-run** — a fresh session could double-apply. Instead find out whether it took,
**without trusting the scan's `state` field** (see U1 — it always says
`needs_config`): check the device's screen, and for a device the registry holds,
`tokenmonitor_list_devices` for a fresh `last_seen`.

If the result includes **`psk_hex`** (with a `note`), a PSK was freshly generated
and the registry was **not** updated, because nobody knows whether the device
took it. Keep that key: if the device did apply, it is already signing with it,
and a missing `last_seen` does not prove failure — enrol it with
`tokenmonitor_register_device` (`device_id` + that `psk_hex`; no `broker_url`
needed).

Only re-provision as a deliberate fresh action if it clearly didn't take. If the
"Pairing" screen is still up, the session is still open; otherwise the device
applied and rebooted, or the window closed — reopen it (BOOT at least 3 s,
release before 10 s).

### U5. Confirm

Same as LAN step 5 — after ~15 s, `tokenmonitor_list_devices` (when the result
said `enrolled: true`): a fresh `last_seen` is the proof. One difference: a
first pairing over USB on firmware 1.0.0+ carries no address, so after the
reboot the device shows the pairing screen briefly while it finds the broker by
mDNS, then restarts into the dashboard by itself ("No broker on this network"
means it found none — see the causes in step 5). Then U6 = LAN step 6 (what to tune
later).

**Re-scanning is not a confirmation.** Applying a payload reboots the device.
Once it is running normally nothing answers the HELLO; while it is still
looking for its broker (or its WiFi) it is back in a pairing session and does
answer — and either way `state` reads `needs_config` (see U1). So neither a
dead-looking scan nor a live one says whether the payload applied.
For a WiFi-only change, confirm on the device's screen (and, for a registered
device, with a fresh `last_seen`).

## Older firmware

The tools handle these differences themselves; this is what to tell a user who
asks why an old unit behaves differently. `fw` in a `tokenmonitor_usb_scan` probe says which line a unit is on.

- **Older than 1.0.0** — cannot leave "Waiting for setup" on a PSK alone: it
  needs a broker address at pairing. The LAN tool always seeds one; the USB
  tool seeds one when the host has exactly one candidate and otherwise asks for
  `broker_url`. If the broker's address later changes, such a unit does not
  find it again by itself the way newer firmware does.
- **1.0.0** — finds the broker by mDNS; an address is only a cache seed.
- **1.0.1 and newer** — the same, and it additionally adopts a broker only
  after the broker proves the pairing by signing its response with the
  device's PSK.
- **`has_psk` over USB** — reported only by firmware newer than 1.0.1.

## Reconfiguring an existing device

If the device is *already provisioned* (it does not show "Waiting for setup"):

- **To change its WiFi, device online and registered** — use
  `tokenmonitor_set_wifi`: send `device_id` + `ssid` first, and add `pass` when
  it answers `needs_password`, says the device has not reported its remembered
  networks, or the user wants to replace a stored password. No cable and nothing to press; if the new network fails the
  device falls back through its remembered ones. The on-device Settings panel
  (WiFi SSID row) does the same from the touchscreen.
- **To change its WiFi, device offline / on an unreachable network / moving to
  an open network** — use the **USB transport** above:
  `tokenmonitor_usb_provision` with a `registry-match` port rewrites the
  credentials in place, no factory reset, preserving the pairing when you send
  only WiFi fields (pass `enroll: false` if the device belongs to another
  broker — see U3). **Start by having the user hold BOOT at least 3 s and
  release before 10 s**
  ([U0](#u0-make-sure-the-device-is-listening)) — a provisioned device that is
  online is not listening on the cable, and the failure looks like a cable or
  broker fault rather than a device that was never asked to listen.
- **To move it to another broker** — on firmware 1.0.1+ there is no address to
  set: the device finds its broker by mDNS, and "which broker" is decided by
  which registry holds its `device_id` + PSK. Older firmware follows a stored
  address instead. Either way see `/tokenmonitor:settings` §4; re-pairing it
  from the new broker's computer with `enroll: true` also works.
- **For display/provider tweaks over the LAN** — the on-device **Settings** panel
  (**tap the gear**, bottom-right of the dashboard) or `/tokenmonitor:settings`.
- **To start over from scratch** — have the user **hold BOOT for ≥10 s**. That
  raises a touch confirmation on screen (it appears at 10 s, while still held), and confirming wipes the user keys in
  the `tmon` NVS namespace (the factory serial and anti-rollback state survive),
  returning the device to the first-boot setup screen (three routes) on the next
  boot. The registry still holds the device, so configuring it again reuses the
  same PSK — and, unless you pass `broker_url` yourself, keeps its old registry
  settings. There is **no reset
  row in on-device Settings** — its only action row is "Pairing mode". `idf.py
  erase-flash` is the developer equivalent, and unlike the button it also wipes
  the NVS-only state the reset preserves (anti-rollback floor, canary, rescue
  nonce); the eFuse serial survives.
