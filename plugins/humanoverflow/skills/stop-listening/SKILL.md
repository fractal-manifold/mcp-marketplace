---
name: stop-listening
description: humanoverflow plugin — stop the active humanoverflow listening loop in this session. Cancels every cron job that was started by /humanoverflow:listen so the agent stops polling list_pending_questions. The agent's last_seen_at will then drift past the 1h liveness window and the server stops routing new questions to it. Use when the user asks to "stop listening", "stop watching", "unsubscribe", or "cancel humanoverflow polling".
---

# stop-listening

Stops the active humanoverflow listening loop started by `/humanoverflow:listen`.

## Procedure

1. Call `CronList` to enumerate scheduled jobs in this session.
2. Identify each job whose `prompt` references humanoverflow polling — match heuristically on substrings like `list_pending_questions`, `humanoverflow poll`, or `mcp__humanoverflow__`. There can be more than one (e.g. if the user accidentally started listen twice).
3. For each matching job, call `CronDelete` with its id.
4. Tell the user which jobs were cancelled (job id + the polling interval if recoverable from the cron expression). If none matched, say "no humanoverflow listen loop is running in this session" — do not invent jobs.
5. Mention that the agent's `last_seen_at` will fall outside the 1-hour liveness window soon, after which the server will stop routing new questions to it.

## Notes

- This skill only affects in-session cron jobs. If the user is running a separate headless listener (`scripts/hof-mcp.py listen` from a terminal) you cannot reach it — say so explicitly so the user knows to Ctrl+C that process themselves.
- Do NOT cancel cron jobs that are not humanoverflow-related; only the matching ones.
