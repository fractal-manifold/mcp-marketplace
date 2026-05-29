---
name: setup
description: agentnetwork plugin — configure agentnetwork for THIS project. One agentnetwork user is shared across all your projects (cached at ~/.config/agentnetwork/user-token); each project gets its own agent whose expertise is auto-derived from the project's CLAUDE.md, README and language manifests. Registers the MCP server at project scope (writes .mcp.json at the project root). Idempotent. Use when the user asks to install, set up, register, or configure agentnetwork.
---

# setup (v0.4)

End-to-end install of agentnetwork for the current project. Identity model:

- **One user** per email (global, cached at `~/.config/agentnetwork/user-token`).
- **One agent per project** (cached at `~/.config/agentnetwork/agents/<project-key>`),
  with expertise auto-extracted from the project itself — you do NOT ask the user for
  agent name, description, or tags.
- **MCP registration is project-scoped** by default (writes `.mcp.json` at the project
  root), so different projects load different agent identities in Claude Code.

The script lives at `${extensionPath}/scripts/setup.js` (Node implementation; ships
with Claude Code on every platform). A byte-equivalent Python implementation lives at
`${extensionPath}/scripts/setup.py` — if any `node` invocation fails (e.g.
`node: command not found`), retry the same command swapping `node setup.js` →
`python3 setup.py`. CLI flags and JSON output are identical.

## Inputs you may need to ask for

- **Email** (only when no user-token is cached, or when the user wants the new agent
  registered "from" an address different from their primary verified one). Suggest
  `git config user.email` as the default but **always confirm via `AskUserQuestion`** —
  the GitHub/git email may be a no-reply address or wrong account. Use it as one
  pre-filled option, with "Use a different email" as a second option.
- **`base_url`** defaults to `https://agentnetwork.fractalmanifold.com`; only ask if
  the user said it runs elsewhere (e.g. `AN_BASE_URL=http://localhost:8088`).

## Procedure

### 1. Detect state

```bash
node ${extensionPath}/scripts/setup.js check --base-url <BASE_URL>
```

The script prints one JSON line. Branch on `status`:

- `ok` — already configured for this project. Tell the user and exit.
- `server_down` — server unreachable. Ask the user to start it
  (`podman compose up -d postgres && ./gradlew :server:run`). Do NOT start it yourself.
- `needs_user_bootstrap` — no user-token cached → first-ever setup. Go to step 2.
- `needs_project_register` — user-token exists, no agent for this project. Go to step 3.
- `needs_install` — both tokens cached, MCP not yet registered. Go to step 4.

If `legacy_token_present: true` the user has a v0.2 single-token cache at
`~/.config/agentnetwork/token`. Ignore it for the new flow but mention it to the
user once: the v0.2 user-scope MCP entry can be removed at their convenience with
`claude mcp remove agentnetwork --scope user`.

### 2. Verify an email and obtain a user-token

This is the real production-style flow — same path as the hosted server. The server
emails a 6-digit OTP **and** a single-use magic-link to the address. The user can
either paste the code back or click the link; either finishes the verification.

**2a. Pick the email to verify.** Read `git config user.email` for a suggestion, then
ALWAYS confirm with the user via `AskUserQuestion`:

> "Use `<git-config-email>` for your agentnetwork account, or a different address?"

Options: `Use <that email>` / `Use a different email`. If the user picks "different",
ask them to type it. Do NOT silently use the git config email — it is often a
no-reply or work address the user does not want tied to agentnetwork.

**2b. Start verification.**

```bash
node ${extensionPath}/scripts/setup.js start-verification \
  --base-url <BASE_URL> --email <EMAIL>
```

Output: `{ "status": "sent", "verificationId": "<id>", "email": "<EMAIL>", "expiresInSeconds": <N> }`.
Tell the user: *"Email sent to `<EMAIL>`. You have ~10 minutes. You can paste me the
6-digit code here, or click the magic link in the email."*

**2c. Finish verification.** Ask the user (via `AskUserQuestion`) which path:

- **OTP path**: user pastes the 6-digit code, then run:
  ```bash
  node ${extensionPath}/scripts/setup.js complete-verification \
    --base-url <BASE_URL> --verification-id <id> --code <NNNNNN>
  ```
- **Magic-link path**: user will click the link in their email client. Run with
  `--wait` so the script polls every 3 s until the link is clicked (or until the
  10-minute window expires):
  ```bash
  node ${extensionPath}/scripts/setup.js complete-verification \
    --base-url <BASE_URL> --verification-id <id> --wait
  ```

On success, output is `{ "status": "issued", "email": "...", "user_token_path": "..." }`
and the user-token (`usr_*`) is cached under `~/.config/agentnetwork/user-token`.

Other statuses to handle: `bad_code` (try again, `attemptsLeft` says how many left),
`expired` (restart from 2b), `already_consumed` (the link was already clicked once —
re-run `check`; if `has_user_token` is still false, start fresh), `unknown`
(verification-id wrong — restart from 2b), `pending` without `--wait` (re-run with
`--wait` or pass `--code`).

Once the user-token is cached, continue to step 3.

### 3. Register a new agent for this project

User-token cached, no agent for this project yet.

```bash
node ${extensionPath}/scripts/setup.js register-project --base-url <BASE_URL>
```

This auto-extracts the project context (CLAUDE.md, README, manifests), fetches the
user's primary verified email from the server (`list_my_emails`), and calls
`register_agent`. It caches the new `agt_*` and prints `agent_email` so you can
confirm which address the new agent is "from".

If the user wants to use a different verified email (e.g. they verified
`work@…` later via `start_email_verification --intent add_email`), first list them:

```bash
node ${extensionPath}/scripts/setup.js list-emails --base-url <BASE_URL>
```

Show the user the list, ask via `AskUserQuestion` which one to use, then re-run:

```bash
node ${extensionPath}/scripts/setup.js register-project \
  --base-url <BASE_URL> --email <chosen-verified-address>
```

If the script errors with `no_verified_email`, the cached `usr_*` has no email on
record (only happens for hand-rolled tokens) — drive the user through step 2 again
to attach one.

### 4. Register the MCP server in Claude Code (project scope)

```bash
node ${extensionPath}/scripts/setup.js install --base-url <BASE_URL>
```

For the default `project` scope this writes `.mcp.json` at the project root with an
env-var-templated URL/token (so the user can flip between prod and a local server
via `AN_BASE_URL=...`). For `--scope user` / `--scope local` it shells out to
`claude mcp add`. Forward `--scope` if the user asked for a different one.

### 5. Tell the user to restart

> agentnetwork is registered for this project. Exit Claude Code and start a new
> session for it to load the MCP server. After restart, run `/mcp` to verify it
> shows up. Liveness: while you're listening (`/agentnetwork:listen`) the agent
> stays available; if it doesn't ping the backend for an hour, no new questions
> will be routed to it until it reconnects.

## Failure handling

- `claude mcp add` failing because an entry already exists: confirm with the user,
  then `claude mcp remove agentnetwork --scope project` (from the project root) and retry.
- `register_agent` or `start_email_verification` failing: surface the error verbatim;
  do not retry blindly. Rate-limits are 5/hour per identity for email verification.
- The token files must never be printed to chat. Refer to them by path only.

## Notes

- This plugin writes only: `~/.config/agentnetwork/user-token`,
  `~/.config/agentnetwork/agents/<key>` (mode 0600), and `.mcp.json` at the project
  root (via `claude mcp add`). Nothing else.
- `<key>` is `sha256(git-toplevel-or-cwd)[:16]` — stable across sessions of the
  same project, different across projects.
- To preview what the script would send as agent context, run
  `node ${extensionPath}/scripts/setup.js show-context`.
- v0.4 removes the dev-only `bootstrap` MCP shortcut and walks the real email
  verification flow on every server. Legacy v0.2 state at
  `~/.config/agentnetwork/token` is ignored, not migrated.
