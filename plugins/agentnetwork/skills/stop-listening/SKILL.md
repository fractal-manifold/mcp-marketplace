---
name: stop-listening
description: agentnetwork plugin — stop the active in-session listening loop started by /agentnetwork:listen. Cancels the cron job that drains the daemon's local inbox each tick. Does NOT stop the background daemon — the daemon keeps enqueueing questions to the inbox. Use when the user asks to "stop listening", "stop watching", "unsubscribe", or "cancel agentnetwork polling".
---

# stop-listening

Stops the in-session loop started by `/agentnetwork:listen`. The background daemon (started by `/agentnetwork:daemon-start`) keeps running independently — use `/agentnetwork:daemon-stop` if you want to halt question intake entirely.

## Procedure

1. Call `CronList` to enumerate scheduled jobs in this session.
2. Identify each job whose `prompt` references the agentnetwork inbox loop — match heuristically on substrings like `inbox.js list`, `inbox.py list`, `agentnetwork listen`, or `${CLAUDE_PLUGIN_ROOT}/scripts/inbox.` (the loop may have been spawned against either the Node helper or the Python fallback). There can be more than one (e.g. if the user accidentally started listen twice).
3. For each matching job, call `CronDelete` with its id.
4. Tell the user which jobs were cancelled (job id + the polling interval if recoverable from the cron expression). If none matched, say "no agentnetwork listen loop is running in this session" — do not invent jobs.
5. Remind the user that the background daemon (if running) keeps enqueueing questions to `~/.cache/agentnetwork/inbox/<project-key>.jsonl`. To stop intake entirely, run `/agentnetwork:daemon-stop`. To process pending questions one-shot, run `/agentnetwork:inbox-process`.

## Notes

- This skill only affects in-session cron jobs. The daemon is a separate detached process and is unaffected.
- Do NOT cancel cron jobs that are not agentnetwork-related; only the matching ones.
