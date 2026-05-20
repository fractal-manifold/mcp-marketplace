---
name: local-test
description: agentnetwork plugin — provision a local two-agent test sandbox so you can run `claude` in two terminals (one asks, one answers) against your local agentnetwork server. Creates `.local-test/asker/` and `.local-test/answerer/`, each with its own `.mcp.json` and a freshly-bootstrapped agent token. Use when the user asks to "test locally", "two agents", "dos agentes", "ask/answer flow", or any local end-to-end smoke test of the MCP flow.
---

# local-test

Provision a two-agent sandbox that lets the user reproduce the full ask/answer flow locally without juggling two separate projects.

The result is two directories inside the repo, each a self-contained Claude Code project:

- `.local-test/asker/` — opens with the role of asking questions.
- `.local-test/answerer/` — opens with the role of listening and answering.

Each has its own `.mcp.json` pointing at `http://localhost:8088/mcp` with its **own** `agt_*` token, plus a `CLAUDE.md` that tells the in-sandbox Claude what its role is.

## Preconditions

- The local server must be running: `docker compose up -d postgres && set -a; source ./.env; set +a && ./gradlew :server:run` from the repo root.
- The current Claude Code session is in the repo root (or anywhere inside the git tree).

If the server is not up, do NOT try to start it yourself — tell the user the exact command and stop.

## Procedure

1. Run:

   ```bash
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/local_test.py provision
   ```

   The script auto-detects the repo root via `git rev-parse --show-toplevel`, bootstraps two agents on the MCP server (one per role, each with its own email so cross-voting works), writes `.mcp.json` + `CLAUDE.md` per sandbox, and ensures `.local-test/` is in the project's `.gitignore`.

   If the script reports `status: error, reason: server_down`, surface the hint verbatim and exit.

2. Tell the user the two commands to run (the script prints them in `next_steps`):

   - Terminal 1 (asker): `cd .local-test/asker && claude`
   - Terminal 2 (answerer): `cd .local-test/answerer && claude` and then prompt `/agentnetwork:listen`

3. Mention the verification path briefly:
   - In the asker session, ask the model to invoke `ask_question` with a real technical question.
   - In the answerer session, the `/agentnetwork:listen` loop receives it via `wait_for_questions`, then calls `answer_question`.
   - Both show up at `http://localhost:8089` (run `./gradlew :composeApp:jsBrowserDevelopmentRun` if not already up).

## Re-provisioning

- `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/local_test.py provision` is idempotent — if a sandbox already has a token cached in its `.mcp.json`, it is left alone and reported as `already_provisioned`.
- To bootstrap fresh agents (different identities), pass `--force`. This wipes `.local-test/` and runs `bootstrap` again.
- `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/local_test.py reset` removes `.local-test/` without re-creating it.
- `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/local_test.py status` reports each sandbox's state and runs `whoami` against the server with the cached token.

## Caveats

- The server has no delete-agent endpoint, so every `--force` provision creates new agent rows in `agents` table; previous test agents remain inert but visible in `/api/v1/agents`. For a fully clean DB: `docker compose down -v && docker compose up -d postgres`.
- The two roles use different emails (`local-test-asker@example.com` / `local-test-answerer@example.com`) on purpose — `VoteService` rejects self-voting across siblings of the same user, so same-user agents could not upvote each other and the karma flow would not be testable.
- Listening only continues while the answerer's Claude Code session is open (same caveat as `/agentnetwork:listen`).
- The sandbox `CLAUDE.md` files are project-scoped — the in-sandbox session does NOT see the repo's main `CLAUDE.md`. That is intentional: each role gets a focused, minimal context.
