# token-monitor-hud

The TokenMonitor desk display, inside Claude Code. A band above the prompt shows your
Claude 5-hour and 7-day subscription windows as colour-coded bars (green < 60 %,
yellow < 85 %, red ≥ 85 %), the time to each reset, where each window will be at reset
if you keep this pace, context-window fill and session cost. A second row shows your
**Codex** and **Antigravity** quotas, if those CLIs are signed in on this machine.

`/token-monitor-hud` opens a pane with the detail for every window: the burn rate over
the last 30 minutes and since the window opened (%/h), how far ahead of or behind a
linear spend you are, and how long until it hits 100 % if that comes before the reset.
A toast fires when any window crosses 80 % and 95 %.

`/token-monitor-hud band` hides or shows the band. `/token-monitor-hud text` prints the
report as text (the mobile app gets it this way, since it shows no panes).

No TokenMonitor device is needed. If you want this on your desk as a 4-inch always-on
display, see the [tokenmonitor plugin](../tokenmonitor) and the hardware.

## Install

At the prompt of a Claude Code terminal session:

```text
/plugin install token-monitor-hud --marketplace fractal-manifold/mcp-marketplace
```

Answer `y` to add the marketplace, then pick a scope. Or from a shell:

```bash
claude plugin install token-monitor-hud --marketplace fractal-manifold/mcp-marketplace
```

Claude Code only (it is a Claude Code mod; Codex and Antigravity have no equivalent).
Requires Claude Code 2.1.287 or later.

## Where the numbers come from

| Provider | Read from | Requested from | When |
|---|---|---|---|
| Claude | `$.session.usage()` and each API response, the same figures as Claude Code's status line | nothing | as they change |
| Codex | `$CODEX_HOME/auth.json`, else `~/.codex/auth.json` | `chatgpt.com/backend-api/wham/usage` | every 5 min, only if that file exists |
| Antigravity | agy's token in the OS keyring (`secret-tool` on Linux, the Keychain via `security` on macOS) | `daily-cloudcode-pa.googleapis.com` (`loadCodeAssist`, `retrieveUserQuotaSummary`) | every 5 min, only if agy is signed in |

These are the same requests the TokenMonitor broker makes. The mod:

- only ever reads the Codex and agy tokens. It never refreshes or writes them; Codex
  and agy own them. An expired sign-in shows as "sign-in expired" with the command
  that fixes it.
- keeps tokens in memory, only while a request is being made. They are not written
  to the session state, logged or shown.
- leaves a provider out entirely when it isn't signed in, without retrying every 5
  minutes (it looks again every 15). A Codex API-key login has no subscription quota,
  so it is left out too.
- shows "quota unavailable" when Antigravity answers but its quota call fails, and
  never a made-up 0 %.

On macOS the first Keychain read may ask you to allow it ("Always Allow").

Rate-limit windows only exist on a Claude subscription; with an API key the Claude row
shows context and cost only.

## Options

Both are on by default and can be changed in `/config`:

| Option | Off means |
|---|---|
| `codex` | `auth.json` is not read and chatgpt.com is never asked |
| `antigravity` | the keyring is not read and Google is never asked |

## License

MIT.
