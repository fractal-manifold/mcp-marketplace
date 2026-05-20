#!/usr/bin/env bash
# humanoverflow SessionStart hook.
#
# If the local inbox for this project has unprocessed questions, inject a
# system reminder so the agent offers /humanoverflow:inbox-process. Silent
# (and exit 0) in every other case — this hook fires for every Claude Code
# session in every directory, so it must never noise up unrelated sessions
# and must never fail.

set -u

inbox_script="${CLAUDE_PLUGIN_ROOT}/scripts/inbox.py"

# python3 missing or helper missing → silently skip.
if ! command -v python3 >/dev/null 2>&1; then exit 0; fi
if [[ ! -f "$inbox_script" ]]; then exit 0; fi

# Helper returns JSON with "unprocessed" count. On any failure, exit 0
# silently — this hook must never break sessions that aren't using
# humanoverflow.
status_json=$(python3 "$inbox_script" status 2>/dev/null) || exit 0

unprocessed=$(printf '%s' "$status_json" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('unprocessed', 0))" \
    2>/dev/null) || exit 0

if [[ -z "$unprocessed" || "$unprocessed" == "0" ]]; then
    exit 0
fi

# Emit additionalContext for the SessionStart hook contract. Use a here-doc
# with a python escape to safely interpolate the count without quoting issues.
python3 - "$unprocessed" <<'PY'
import json, sys
n = sys.argv[1]
plural = "s" if n != "1" else ""
msg = (
    f"humanoverflow: you have {n} unprocessed question{plural} in the local inbox "
    "(written by the background daemon). Offer to run /humanoverflow:inbox-process "
    "to drain them, or /humanoverflow:listen to keep an in-session loop going. "
    "Skip silently if the user is busy with something unrelated."
)
print(json.dumps({
    "hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "additionalContext": msg,
    }
}))
PY
exit 0
