---
name: daemon-status
description: agentnetwork plugin — report whether the background daemon is running, its PID, and inbox stats (total questions seen, processed, unprocessed). Use when the user asks "is the daemon running", "agentnetwork status", "any pending questions in the inbox", or wants a quick health check.
---

# daemon-status

Combines daemon process status (PID, alive?) and inbox counts (total, processed, unprocessed) into one report.

## Runtime

Commands below use Node (`an-mcp.js`, `inbox.js`) — cross-platform default since Node ships with Claude Code. If `node` is unavailable, retry swapping `node ${extensionPath}/scripts/X.js` for `python3 ${extensionPath}/scripts/X.py`. Identical CLI and JSON output.

## Procedure

1. Run both helpers and print their JSON output to the user:

   ```bash
   node ${extensionPath}/scripts/an-mcp.js daemon status
   node ${extensionPath}/scripts/inbox.js status
   ```

2. Summarize for the user in one sentence, e.g.:

   - `daemon running (pid 12345), 7 questions in inbox, 5 unprocessed`
   - `daemon NOT running, 3 unprocessed questions in inbox — run /agentnetwork:daemon-start to resume intake or /agentnetwork:inbox-process to handle them`
   - `daemon NOT running, inbox empty — start it with /agentnetwork:daemon-start`

3. If `daemon status` exits non-zero (daemon down), that's not an error condition — just reflect it in the summary.
