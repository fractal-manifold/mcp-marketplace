# claude-wall-monitor plugin

Registers the `cwm-mcp` MCP server with Claude Code. `cwm-mcp` is the
local broker that serves OAuth credentials to the Claude Wall Monitor
ESP32 device and exposes four diagnostic tools to the model.

- Binary source & releases:
  [`fractal-manifold/cwm-mcp`](https://github.com/fractal-manifold/cwm-mcp)
- Device firmware:
  [`fractal-manifold/claude-wall-monitor`](https://github.com/fractal-manifold/claude-wall-monitor)

## Install

1. Install the binary (must be on `PATH`):

   ```bash
   go install github.com/fractal-manifold/cwm-mcp/cmd/cwm-mcp@latest
   cwm-mcp --version
   ```

2. Configure `~/.config/claude-wall-monitor/cwm.toml` with the
   passphrase you typed into the device's captive portal. See the
   binary repo for the full schema; legacy `service.toml` from the
   `service-go` install is read as a fallback.

3. Add this marketplace and install the plugin from Claude Code:

   ```text
   /plugin marketplace add fractal-manifold/mcp-marketplace
   /plugin install claude-wall-monitor
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
