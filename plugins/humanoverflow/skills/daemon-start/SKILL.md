---
name: daemon-start
description: humanoverflow plugin — start the background daemon that long-polls the humanoverflow MCP server and writes incoming questions to a local JSONL inbox. One daemon per project/agent. The daemon survives the Claude Code session ending, so questions accumulate even when you're not at the terminal. Use when the user asks to "start the daemon", "listen in the background", "run humanoverflow in background", or wants 24/7 question intake without holding a Claude Code session open.
---

# daemon-start

Spawns the `hof-mcp.py daemon` as a detached background process. Idempotent — calling it again while it's already running is a no-op (and reports the existing PID).

The daemon:
- Holds a single MCP connection to the humanoverflow server.
- Long-polls `wait_for_questions(timeoutSeconds=300)` in a loop.
- Appends each matched question to `~/.cache/humanoverflow/inbox/<project-key>.jsonl`.
- Logs to `~/.cache/humanoverflow/daemon/<project-key>.log`.
- Exponential backoff on transient network errors; bails out on auth errors.

To consume the inbox from an interactive session use `/humanoverflow:inbox-process` (one-shot) or `/humanoverflow:listen` (loop). To stop the daemon use `/humanoverflow:daemon-stop`.

## Preconditions

- An agent must be registered for this project. The token is expected at `~/.config/humanoverflow/agents/<project-key>` (written by `/humanoverflow:setup`). If missing, run `/humanoverflow:setup` first.

## Procedure

1. Run:

   ```bash
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/hof-mcp.py daemon start --detach
   ```

   (Optionally pass `--base <url>` to override the server URL; defaults to `HOF_BASE_URL` env var, then `http://localhost:8088`.)

2. Then immediately call `daemon status` to confirm it's up and report PID + inbox path to the user:

   ```bash
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/hof-mcp.py daemon status
   ```

3. If `start` exits with code 2 ("no agent token"), tell the user to run `/humanoverflow:setup` and stop. Do NOT try to register the agent from here.

4. If `start` exits with code 0 but `status` reports `running: false`, the daemon died immediately — tail the last 20 lines of `~/.cache/humanoverflow/daemon/<project-key>.log` and surface the error.

## Notes

- The daemon survives `claude code` quitting. It only stops on `/humanoverflow:daemon-stop`, SIGTERM, or a hard auth failure.
- One daemon per project (keyed by SHA256 of the git toplevel). Running Claude Code from a different project starts a different daemon for that project's agent.
- The daemon does NOT consume questions — it only enqueues. The interactive skills (`inbox-process`, `listen`) do the answering.
