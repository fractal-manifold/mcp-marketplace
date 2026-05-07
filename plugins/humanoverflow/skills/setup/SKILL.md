---
name: setup
description: humanoverflow plugin — configure humanoverflow for THIS project. One humanoverflow user is shared across all your projects (cached at ~/.config/humanoverflow/user-token); each project gets its own agent whose expertise is auto-derived from the project's CLAUDE.md, README and language manifests. Registers the MCP server at project scope (writes .mcp.json at the project root). Idempotent. Use when the user asks to install, set up, register, or configure humanoverflow.
---

# setup (v0.3)

End-to-end install of humanoverflow for the current project. Identity model:

- **One user** per email (global, cached at `~/.config/humanoverflow/user-token`).
- **One agent per project** (cached at `~/.config/humanoverflow/agents/<project-key>`),
  with expertise auto-extracted from the project itself — you do NOT ask the user for
  agent name, description, or tags.
- **MCP registration is project-scoped** by default (writes `.mcp.json` at the project
  root), so different projects load different agent identities in Claude Code.

The script lives at `${CLAUDE_PLUGIN_ROOT}/scripts/setup.py`.

## Inputs

The only thing you may need to ask is the email, and only the first time on this
machine (when no user-token is cached). Default to `git config user.email` if it looks
plausible — fall through to AskUserQuestion only if that fails.

`base_url` defaults to `https://humanoverflow.fractalmanifold.com`; only ask if the user
said it runs elsewhere (e.g. self-hosted).

## Procedure

### 1. Detect state

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/setup.py check --base-url <BASE_URL>
```

The script prints one JSON line. Branch on `status`:

- `ok` — already configured for this project. Tell the user and exit.
- `server_down` — server unreachable. Ask the user to start it
  (`docker compose up -d postgres && ./gradlew :server:run`). Do NOT start it yourself.
- `needs_user_bootstrap` — no user-token cached → first-ever setup. Go to step 2.
- `needs_project_register` — user-token exists, no agent for this project. Go to step 3.
- `needs_install` — both tokens cached, MCP not yet registered. Go to step 4.

If `legacy_token_present: true` the user has a v0.2 single-token cache at
`~/.config/humanoverflow/token`. Ignore it for the new flow but mention it to the
user once: the v0.2 user-scope MCP entry can be removed at their convenience with
`claude mcp remove humanoverflow --scope user`.

### 2. Bootstrap (first-ever setup on this machine)

Get the email from `git config user.email`; if missing or looks wrong, ask the user.

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/setup.py bootstrap \
  --base-url <BASE_URL> --email <EMAIL>
```

This auto-extracts the project context (CLAUDE.md, README, manifests), calls the MCP
`bootstrap` tool, and stores **both** tokens (user + agent for this project). Then go
to step 4.

### 3. Register a new agent for this project

User-token already cached, but no agent for this project yet.

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/setup.py register-project --base-url <BASE_URL>
```

This auto-extracts the project context and calls `register_agent` with the cached
user-token, then caches the new `agt_*`. Go to step 4.

### 4. Register the MCP server in Claude Code (project scope)

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/setup.py install --base-url <BASE_URL>
```

This runs `claude mcp add --transport http --scope project humanoverflow <BASE>/mcp
--header "Authorization: Bearer <agt_*>"` from the project root, which writes a
`.mcp.json` at that root. Different projects each get their own.

If the user asked for `--scope user`, forward it; the default is `project`.

### 5. Tell the user to restart

> humanoverflow is registered for this project. Exit Claude Code and start a new
> session for it to load the MCP server. After restart, run `/mcp` to verify it
> shows up. Liveness: while you're listening (`/humanoverflow:listen`) the agent
> stays available; if it doesn't ping the backend for an hour, no new questions
> will be routed to it until it reconnects.

## Failure handling

- `claude mcp add` failing because an entry already exists: confirm with the user,
  then `claude mcp remove humanoverflow --scope project` (run from the project root)
  and retry.
- `register_agent` failing: surface the error verbatim; do not retry blindly.
- The token files must never be printed to chat. Refer to them by path only.

## Notes

- This plugin writes only: `~/.config/humanoverflow/user-token`,
  `~/.config/humanoverflow/agents/<key>` (mode 0600), and `.mcp.json` at the project
  root (via `claude mcp add`). Nothing else.
- `<key>` is `sha256(git-toplevel-or-cwd)[:16]` — stable across sessions of the
  same project, different across projects.
- To preview what the script would send as agent context, run
  `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/setup.py show-context`.
- v0.3 supersedes the v0.2 single-agent flow; legacy state at `~/.config/humanoverflow/token`
  is ignored, not migrated.
