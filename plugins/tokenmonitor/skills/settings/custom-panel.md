# Custom panel — full reference

Read this only when the user wants to configure, enable or disable the
swipe-up custom-panel screen. Everything else in `/tokenmonitor:settings`
works without it.

## The two independent switches

1. **The device flag** `panel_enabled` (this skill, or on-device Settings →
   Display → Custom panel). Controls whether the device *polls for* and
   *renders* the swipe-up screen at all.
2. **The broker content** — a JSON file the broker serves at
   `GET /device/<id>/panel`. With no file the endpoint returns **404** and the
   page drops out of the rotation even when `panel_enabled` is true.

Both must be on for the screen to show data, and the two fail *differently*:
flag on but no file → the endpoint 404s and the page drops out of the rotation;
file present but flag off → the device never polls or renders it at all. The
empty-state message only appears when the device is polling a broker that
answers without usable panel content.

## Enabling

Send `panel_enabled: true` **and** make sure the broker has a panel file. With
only one of the two, the page shows nothing useful (see the failure modes
above).

## Disabling

Preferred: `panel_enabled: false` — the device stops polling and rendering,
which is what frees the RAM the panel's render buffers hold.

Fallback for brokers too old to advertise `panel_enabled` in the
`tokenmonitor_set_device_pending` schema (e.g. 0.9.6): you cannot toggle the
device flag remotely, so 404 the *content* instead —

- move/rename `<panel-dir>/<device-id>.json` aside, **and**
  `<panel-dir>/default.json` if present (otherwise the device falls back to the
  default file and the page stays); or
- comment out the whole `[panel]` section in the broker config and restart the
  broker.

The broker re-reads panel files on every request (mtime+size cache), so
removing a file 404s on the **next device poll (~20 s) with no broker
restart** — only editing the `[panel]` *section* of the config needs a
restart. Tell the user the panel flag itself is still on, and suggest bumping
the broker so `panel_enabled` becomes pushable.

## Configuring the content

A broker-side filesystem operation, **not** a device pending. If the user asks
to change *what the panel shows*, edit the file — do not queue a pending.

Resolve the location from the broker's `[panel]` section in
`~/.config/tokenmonitor/tokenmonitor.toml`:

- `dir` set → per-device `dir/<device-id>.json`, else `dir/default.json`;
- else `file` → one shared panel for every device.

Write valid PANEL_WIRE JSON there: `version: 1`, 1–4 `tiles` of type
`line` / `bar` / `pie` / `table` / `text`; caps are 4 tiles, 4 series, 64
points, 8 KB file; solid `#rrggbb` colours only. **Write atomically** (temp
file + rename) so the broker never serves a half-written file — it picks the
change up on the next request, no restart.

The full field list and examples live in the monorepo's `docs/custom-panel.md`
and `compat/PANEL_WIRE.md` (not bundled with a standalone plugin install).
