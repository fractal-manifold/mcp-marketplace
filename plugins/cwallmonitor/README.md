# cwallmonitor plugin

Registers the `cwm-mcp` MCP server with Claude Code. `cwm-mcp` is the
local broker that serves OAuth credentials to the C Wall Monitor
ESP32 device, exposes four diagnostic tools to the model, and ships
two on-device skills (`/cwallmonitor:configure`,
`/cwallmonitor:theme`).

- Binary source & releases:
  [`fractal-manifold/cwm-mcp`](https://github.com/fractal-manifold/cwm-mcp)
- Device firmware:
  [`fractal-manifold/claude-wall-monitor`](https://github.com/fractal-manifold/claude-wall-monitor)

## Install

The plugin invokes the `cwm-mcp` launcher, which auto-selects one of
three interchangeable implementations (Go, Python, JavaScript). Install
at least one of them, plus the launcher itself.

1. Install **one** implementation (in preference order):

   ```bash
   # Go (preferred — single static binary, no runtime deps)
   go install github.com/fractal-manifold/cwm-mcp/cmd/cwm-mcp@latest
   # The Go build installs the binary as `cwm-mcp-go`.

   # Python (pipx isolated install)
   pipx install cwm-mcp-py

   # JavaScript (Node ≥ 20)
   npm install -g cwm-mcp-js
   ```

2. Install the launcher shim (one-time):

   ```bash
   curl -fsSL https://github.com/fractal-manifold/cwm-mcp/raw/main/cwm-mcp-launcher/install.sh | sh
   # Or: clone the repo and run cwm-mcp-launcher/install.sh
   ```

   The launcher tries Go → Python → JS by default. To pin a preferred
   runtime, write `runtime=go` (or `python`, `js`) to
   `~/.config/claude-wall-monitor/launcher.conf`. `runtime=auto` (or no
   file) is the default. Run `cwm-mcp --probe` to confirm which runtime
   is being selected (`cwm-mcp launcher: using <runtime> (<binary>)`
   goes to stderr).

3. Configure `~/.config/claude-wall-monitor/cwm.toml` with the
   passphrase you typed into the device's captive portal. The same
   schema is read by all three implementations; legacy `service.toml`
   from the `service-go` install is read as a fallback.

4. Add this marketplace and install the plugin from Claude Code:

   ```text
   /plugin marketplace add fractal-manifold/mcp-marketplace
   /plugin install cwallmonitor
   ```

## Tools exposed to the model

| Tool                          | What it does |
|-------------------------------|--------------|
| `wall_monitor_status`         | Role (leader/follower), last ESP32 request, request count. |
| `wall_monitor_health`         | Credentials file + signed self-ping + observed traffic — PASS/FAIL per component. |
| `wall_monitor_recent_logs`    | In-memory tail of the broker log. |
| `wall_monitor_provision_hint` | Laptop LAN IPv4s + broker port as URLs ready for the device's captive portal. |

## Coexistence with `service-go`

If you still have the older `service-go` systemd unit running, the
plugin's `cwm-mcp` arrives as a quiet follower (port 8765 is busy) and
the device keeps talking to the old daemon. Stop the daemon to let the
plugin take over within ~5 s.

## Runtime parity

All three implementations expose the same wire protocol and MCP tool
schemas (verified by shared test vectors under
[`compat/`](../../../compat/)). A device registered by `cwm-mcp-go` is
readable by `cwm-mcp-py`, and so on. If `wall_monitor_status` reports a
different runtime than expected, check
`~/.config/claude-wall-monitor/launcher.conf` and run
`cwm-mcp --probe`.
