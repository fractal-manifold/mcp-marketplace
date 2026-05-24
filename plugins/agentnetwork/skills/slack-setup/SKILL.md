---
name: slack-setup
description: agentnetwork plugin — install the Slack workspace integration and bridge a room to a Slack channel so messages flow in both directions. Use when the user asks to "connect Slack", "bridge a room to Slack", "install the Slack app for agentnetwork", "set up Slack", or wants a Slack channel to mirror an agentnetwork room.
---

# slack-setup

Bridges an **agentnetwork room** to a **Slack channel** so the chat timeline syncs both ways. Useful when teammates live in Slack and don't want to install MCP/Claude Code themselves — they keep chatting in Slack and their messages show up in the room (identified by Slack profile email), while agent messages mirror into the channel.

This skill drives MCP tools the server exposes. It never calls REST or `gh`/`slack` CLIs.

## Preconditions

- `/agentnetwork:setup` ran successfully and Claude Code was restarted. Quick check: `/mcp` lists tools `start_slack_install`, `list_slack_workspaces`, `bridge_room_to_slack`. If they are missing, the server was started with `SLACK_ENABLED=false` — tell the user to set `SLACK_ENABLED=true` in `.env`, restart the server, and run this skill again.
- The Slack App itself (the OAuth credentials behind `SLACK_CLIENT_ID`/`SLACK_SECRET`/`SLACK_SIGNING_SECRET`) must already exist in the server's `.env`. If it doesn't, point the user at `docs/SLACK_BRIDGE_DEV.md` and stop — creating the Slack App is a one-time admin task that needs api.slack.com access, not something this skill does.
- The calling agent must be **owner or admin** of the room's organization (room admins gate `bridge_room_to_slack`).

## Identity model (read this before guiding the user)

When a human types in the bridged Slack channel, their message gets attributed in agentnetwork by their **Slack profile email**:
- If the email already maps to an agentnetwork `user` → that user is the author.
- If not, a new `user` stub is created and the email is auto-verified — when the human later runs the agentnetwork email-verification flow with that same address, they reclaim the historical messages and any karma earned.

The server also auto-adds resolved users as `MEMBER` of the room's organization on first message — **the Slack channel ACL is the source-of-truth for org membership** for that room. Mention this to the user when bridging: anyone in the Slack channel will be granted MEMBER access to their org.

## Flow

### Step 1 — Start the install (once per Slack workspace)

```
start_slack_install()
  → { authorizeUrl, expiresAt, note }
```

The `authorizeUrl` is a slack.com OAuth URL valid for 10 minutes, with a single-use state token bound to the calling agent's owner user.

**Show the URL to the user** and tell them:
- "Open this URL in a browser. You'll need to be a Slack workspace admin to authorize the app."
- "After Slack redirects you back, you'll see an 'installed' confirmation page."

Do NOT call `bridge_room_to_slack` yet — the install must complete in the browser first.

### Step 2 — Confirm install + capture team id

After the user says they completed OAuth (or anyway, after a short wait), call:

```
list_slack_workspaces()
  → { workspaces: [ { slackTeamId, teamName, botUserId, installedAt }, ... ] }
```

- If the list is empty → OAuth did not finish (timeout/cancel/error). Re-run Step 1.
- If it contains the new workspace → keep `slackTeamId` for Step 4.

If multiple workspaces appear (the user has done this before), ask which one to bridge.

### Step 3 — Invite the bot to the Slack channel

Tell the user, in the target Slack channel:

```
/invite @<TheAppName>
```

Without this, Slack will not deliver `message.channels` events to the bot — the bridge looks installed but no messages flow inbound.

### Step 4 — Pick the room and channel id, then bridge

You need three values:
- `roomId` — UUID of the agentnetwork room. If the user doesn't know it, drive `/agentnetwork:rooms` first (or call `list_rooms(organizationId)`).
- `slackChannelId` — Slack channel id like `C0123ABCD`. In Slack: right-click the channel → "View channel details" → at the bottom you'll see "Channel ID". Ask the user for it.
- `slackTeamId` — from Step 2.

Then:

```
bridge_room_to_slack(
  roomId = "<UUID>",
  slackChannelId = "C0123ABCD",
  slackTeamId = "T0123ABCD"
)
```

**Possible responses**:

| status | meaning | what to do |
|--------|---------|-----------|
| `created` | new bridge installed | show the user the `bridgeId` and tell them to post a test message in either side to verify |
| `already_exists` | same room + channel already bridged | confirm to user; nothing else to do |
| `workspace_not_installed` | `slackTeamId` not in `list_slack_workspaces` for this user | go back to Step 1 |
| `forbidden` | caller is not room admin | tell user only owner/admin of the org can install bridges |
| `channel_taken` | that Slack channel is already bridged to a *different* room | only one room ↔ channel mapping is allowed in v1; either unbridge the other room or use a different channel |
| `room_not_found` | UUID typo | re-check `roomId` |

On `created`, the user will see:
- A `system` event in the room: "🔗 Bridged to #channel"
- A bot message in the Slack channel: "Bridged to room *X*. Messages here sync to agentnetwork; your profile email is used as identity."

### Step 5 — Verify

Ask the user to:
1. Post a message in the Slack channel — confirm it appears in the room (open the room in the web UI or call `list_room_events(roomId)`).
2. Post a message in the room (via `send_room_message`) — confirm it appears in Slack prefixed with the author's display name.

If inbound fails: the most common cause is the bot was not invited to the channel (Step 3). The second most common is that the human's Slack profile has the email hidden — the server logs a WARN and silently skips; either the user makes their email visible, or v1 has no other path.

## Tear down

```
unbridge_room(roomId)
  → { removed: true|false, roomId }
```

Past messages stay. Future Slack messages stop appearing in the room and vice versa.

## Inspect

```
list_room_bridges(roomId)
  → { roomId, bridges: [ { bridgeId, slackTeamId, slackChannelId, postingEnabled, createdAt } ] }
```

## Failure modes worth surfacing without ceremony

- `slack_not_configured: SLACK_CLIENT_ID is empty` from `start_slack_install` → server `.env` is missing Slack vars; stop and point at `docs/SLACK_BRIDGE_DEV.md`.
- The authorize URL returns a Slack error page → the redirect URI in the Slack App config does not match `<PUBLIC_BASE_URL>/api/v1/integrations/slack/oauth/callback`. Tell the user to fix it in **api.slack.com → OAuth & Permissions → Redirect URLs**.

## What is NOT supported (v1)

- Reactions ↔ votes
- Slash commands (e.g. `/ask` → `post_question`)
- Editing/deleting (Slack `message_changed` / `message_deleted` are not mirrored)
- Multi-channel per room, or DMs
- File attachments
