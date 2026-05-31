# cwallmonitor plugin

Registers the `cwm-mcp` MCP server with Claude Code. `cwm-mcp` is the
local broker that serves OAuth credentials to the C Wall Monitor
ESP32 device, exposes diagnostic tools to the model, and ships the
`/cwallmonitor:configure`, `/cwallmonitor:settings` and
`/cwallmonitor:theme` on-device skills.

**The plugin is self-contained.** It bundles the server under
[`server/`](./server/) and launches it directly via
`${CLAUDE_PLUGIN_ROOT}/server/cwm-mcp` — there is no separate
`go install` / `pipx` / `npm` step. You only need **one** language
toolchain on your `PATH`; that runtime's dependencies (including native
modules) are resolved on first launch into a per-user cache, so they are
built for your host rather than shipped in the plugin.

- Server source: bundled here under [`server/`](./server/) — this is the
  canonical home; edit it in place (no generation step).
- Device firmware & the shared wire contract (`compat/`):
  [`fractal-manifold/claude-wall-monitor`](https://github.com/fractal-manifold/claude-wall-monitor)

## Install

1. Make sure **one** of these toolchains is on your `PATH`. The bundled
   launcher tries them in order and uses the first that works:

   | Runtime | Needs on `PATH`            | First-run setup (cached afterwards)              |
   |---------|----------------------------|--------------------------------------------------|
   | JS      | `node` (≥20) + `npm`       | `npm install` (native modules built for the host)|
   | Python  | `python3` (≥3.11) + `uv` (or `pip`/`venv`) | virtualenv + dependency install  |
   | Go      | `go` (≥1.25)               | `go build` (compiled once, then cached)          |

   To pin a runtime, write `runtime=js` (or `python`, `go`) to
   `~/.config/claude-wall-monitor/launcher.conf`. Default order is
   `js → python → go`.

2. Configure `~/.config/claude-wall-monitor/cwm.toml` with the
   passphrase you typed into the device's captive portal. The same
   schema is read by all three runtimes; a legacy `service.toml` from a
   `service-go` install is read as a fallback.

3. Add this marketplace and install the plugin from Claude Code:

   ```text
   /plugin marketplace add fractal-manifold/mcp-marketplace
   /plugin install cwallmonitor
   ```

The **first** time the server starts it resolves the chosen runtime's
dependencies into `~/.cache/claude-wall-monitor/<version>/` (one-time,
per version — a fresh `npm install` / venv / `go build`). That run is
slower; subsequent launches are a cache hit. The launcher logs which
runtime it picked to stderr (`cwm-mcp launcher: using <runtime> (…)`).

### Advanced: standalone / PATH mode

If you would rather run a globally-installed binary (e.g. a systemd
daemon shared across sessions), the same `cwm-mcp` launcher auto-detects
"PATH mode" whenever it is run from outside the plugin and finds a
`cwm-mcp-go`, `cwm-mcp-py` or `cwm-mcp-js` on your `PATH`. There are no
longer published packages for these — build one from the bundled source
(e.g. `cd server/go && go build -o ~/.local/bin/cwm-mcp-go ./cmd/cwm-mcp`)
and put `server/cwm-mcp` and `server/install.sh` on your `PATH`.

## Tools exposed to the model

| Tool                          | What it does |
|-------------------------------|--------------|
| `wall_monitor_status`         | Role (leader/follower), last ESP32 request, request count. |
| `wall_monitor_health`         | Credentials file + signed self-ping + observed traffic — PASS/FAIL per component. |
| `wall_monitor_recent_logs`    | In-memory tail of the broker log. |
| `wall_monitor_provision_hint` | Laptop LAN IPv4s + broker port as URLs ready for the device's captive portal. |

Plus the control-plane tools the skills drive (`wall_monitor_list_devices`,
`wall_monitor_register_device`, `wall_monitor_set_device_pending`,
`wall_monitor_discover_devices`, `wall_monitor_provision`,
`wall_monitor_publish_firmware`, `wall_monitor_revert_firmware`).

## Coexistence with `service-go`

If you still have the older `service-go` systemd unit running, the
plugin's `cwm-mcp` arrives as a quiet follower (port 8765 is busy) and
the device keeps talking to the old daemon. Stop the daemon to let the
plugin take over within ~5 s.

## Runtime parity

All three implementations expose the same wire protocol and MCP tool
schemas (verified by shared test vectors under `compat/`; the bundle
carries the runtime slice at [`server/compat/`](./server/compat/)). A
device registered by one runtime is readable by the others. If
`wall_monitor_status` reports a different runtime than expected, check
`~/.config/claude-wall-monitor/launcher.conf`.

## Editing the server

`server/` is the canonical source — edit it directly. The only exceptions
are the two **vendored** files `server/VERSION` and
`server/compat/tool-schemas.json`, which are authoritative in the monorepo
root and copied here so the standalone-published plugin can start. Keep them
in sync from the monorepo:

```bash
cd tools && PYTHONPATH=. python -m cwmtools.plugin.vendor_contract          # re-vendor
cd tools && PYTHONPATH=. python -m cwmtools.plugin.vendor_contract --check  # verify (CI / pre-commit)
```
