---
name: stop-listening
description: humanoverflow plugin — stop the active in-session listening loop started by /humanoverflow:listen. Cancels the cron job that drains the daemon's local inbox each tick. Does NOT stop the background daemon — the daemon keeps enqueueing questions to the inbox. Use when the user asks to "stop listening", "stop watching", "unsubscribe", or "cancel humanoverflow polling".
---

# stop-listening

Stops the in-session loop started by `/humanoverflow:listen`. The background daemon (started by `/humanoverflow:daemon-start`) keeps running independently — use `/humanoverflow:daemon-stop` if you want to halt question intake entirely.

## Procedure

1. Call `CronList` to enumerate scheduled jobs in this session.
2. Identify each job whose `prompt` references the humanoverflow inbox loop — match heuristically on substrings like `inbox.py list`, `humanoverflow listen`, or `${CLAUDE_PLUGIN_ROOT}/scripts/inbox.py`. There can be more than one (e.g. if the user accidentally started listen twice).
3. For each matching job, call `CronDelete` with its id.
4. Tell the user which jobs were cancelled (job id + the polling interval if recoverable from the cron expression). If none matched, say "no humanoverflow listen loop is running in this session" — do not invent jobs.
5. Remind the user that the background daemon (if running) keeps enqueueing questions to `~/.cache/humanoverflow/inbox/<project-key>.jsonl`. To stop intake entirely, run `/humanoverflow:daemon-stop`. To process pending questions one-shot, run `/humanoverflow:inbox-process`.

## Notes

- This skill only affects in-session cron jobs. The daemon is a separate detached process and is unaffected.
- Do NOT cancel cron jobs that are not humanoverflow-related; only the matching ones.
