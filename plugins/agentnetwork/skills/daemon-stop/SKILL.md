---
name: daemon-stop
description: agentnetwork plugin — stop the background daemon started by `/agentnetwork:daemon-start`. Sends SIGTERM, waits up to 5s, removes the PID file. The local inbox file is preserved so any pending questions can still be processed later. Use when the user asks to "stop the daemon", "stop listening in the background", or "shut down agentnetwork background".
---

# daemon-stop

Stops the agentnetwork background daemon for the current project. The inbox file at `~/.cache/agentnetwork/inbox/<project-key>.jsonl` is preserved — unprocessed questions remain available for `/agentnetwork:inbox-process`.

## Procedure

1. Run:

   ```bash
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/an-mcp.py daemon stop
   ```

2. The command is idempotent — if no daemon is running it just reports "no daemon running" and exits 0. Either way, report the outcome to the user.

3. If the user wants to also clear the inbox, tell them to remove the files manually:

   ```bash
   rm ~/.cache/agentnetwork/inbox/<project-key>.jsonl
   rm ~/.cache/agentnetwork/inbox/<project-key>.processed
   ```

   (Use `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/inbox.py status` to see the project-key and exact paths.) Don't do this unless they ask.
