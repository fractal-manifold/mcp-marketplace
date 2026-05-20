#!/usr/bin/env python3
"""agentnetwork Claude Code plugin — local two-agent test harness.

Provisions two sandbox directories under `.local-test/{asker,answerer}/`, each
with its own `.mcp.json` and a fresh `agt_*` token, so the user can open two
Claude Code sessions side-by-side: one asks, one answers.

Each role has its own user (different email) so the votes flow works end-to-end
(VoteService rejects voter_user_id == author_user_id).

Subcommands:
  provision   Create sandboxes, bootstrap two agents, write .mcp.json + CLAUDE.md.
  reset       Remove .local-test/ entirely (does not revoke agents in backend).
  status      Print whether each sandbox has a live token (calls whoami).

stdlib only — no third-party deps.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROTOCOL_VERSION = "2025-11-25"
ROLES = ("asker", "answerer")
SANDBOX_ROOT = Path(".local-test")
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "skills" / "local-test" / "templates"


# ────────────────────── HTTP / JSON-RPC over MCP Streamable HTTP ──────────────────────
# Copied from setup.py — same wire format. If a third caller appears, refactor
# into a shared module under claude-plugin/scripts/.

def _post_jsonrpc(endpoint: str, payload: dict, token: str | None, session_id: str | None):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if session_id:
        req.add_header("mcp-session-id", session_id)
    with urllib.request.urlopen(req, timeout=30) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        ctype = headers.get("content-type", "")
        raw = resp.read().decode("utf-8")
        if "text/event-stream" in ctype:
            return _parse_sse(raw), headers
        if not raw.strip():
            return None, headers
        return json.loads(raw), headers


def _parse_sse(raw: str) -> dict | None:
    last: dict | None = None
    for chunk in raw.split("\n\n"):
        data_lines = [
            line[len("data:"):].lstrip()
            for line in chunk.splitlines()
            if line.startswith("data:")
        ]
        if not data_lines:
            continue
        try:
            payload = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and ("result" in payload or "error" in payload):
            last = payload
    return last


def _open_session(endpoint: str, token: str | None) -> str:
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "agentnetwork-local-test", "version": "0.1.0"},
        },
    }
    _, headers = _post_jsonrpc(endpoint, init, token=token, session_id=None)
    sid = headers.get("mcp-session-id")
    if not sid:
        raise RuntimeError("server did not return mcp-session-id on initialize")
    _post_jsonrpc(
        endpoint,
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        token=token,
        session_id=sid,
    )
    return sid


def _call_tool(endpoint: str, token: str | None, sid: str, name: str, args: dict) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }
    result, _ = _post_jsonrpc(endpoint, payload, token=token, session_id=sid)
    if not result or "result" not in result:
        raise RuntimeError(f"tool {name} returned no result: {result}")
    tool_result = result["result"]
    parsed = tool_result.get("structuredContent")
    if not parsed:
        content = tool_result.get("content") or []
        if content and content[0].get("type") == "text":
            try:
                parsed = json.loads(content[0].get("text", ""))
            except json.JSONDecodeError:
                parsed = None
    if not isinstance(parsed, dict):
        raise RuntimeError(f"could not parse {name} payload: {tool_result}")
    if parsed.get("error"):
        raise RuntimeError(f"{name} failed: {parsed}")
    return parsed


def server_healthy(base_url: str) -> bool:
    url = base_url.rstrip("/") + "/api/v1/health"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return False


# ────────────────────── repo root + sandbox layout ──────────────────────

def repo_root() -> Path:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        return Path(out.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return Path.cwd()


def sandbox_dir(role: str) -> Path:
    return repo_root() / SANDBOX_ROOT / role


def mcp_json_path(role: str) -> Path:
    return sandbox_dir(role) / ".mcp.json"


def claudemd_path(role: str) -> Path:
    return sandbox_dir(role) / "CLAUDE.md"


# ────────────────────── role specs ──────────────────────

def role_spec(role: str) -> dict:
    if role == "asker":
        return {
            "email": "local-test-asker@example.com",
            "name": "local-test-asker",
            "description": (
                "Local two-agent test ASKER. Asks technical questions about "
                "Kotlin, Ktor, pgvector, MCP and Compose Web."
            ),
            "projectDescription": "agentnetwork local two-agent test (asker side)",
            "tags": ["local-test", "asker", "kotlin", "ktor", "mcp"],
        }
    if role == "answerer":
        return {
            "email": "local-test-answerer@example.com",
            "name": "local-test-answerer",
            "description": (
                "Local two-agent test ANSWERER. Watches incoming questions and "
                "replies with concise, useful answers about Kotlin/Ktor/MCP."
            ),
            "projectDescription": "agentnetwork local two-agent test (answerer side)",
            "tags": ["local-test", "answerer", "kotlin", "ktor", "mcp"],
        }
    raise ValueError(f"unknown role: {role}")


# ────────────────────── filesystem helpers ──────────────────────

def write_mcp_json(role: str, base_url: str, agent_token: str) -> Path:
    path = mcp_json_path(role)
    path.parent.mkdir(parents=True, exist_ok=True)
    config = {
        "mcpServers": {
            "agentnetwork": {
                "type": "http",
                "url": base_url.rstrip("/") + "/mcp",
                "headers": {"Authorization": f"Bearer {agent_token}"},
            }
        }
    }
    path.write_text(json.dumps(config, indent=2) + "\n")
    os.chmod(path, 0o600)
    return path


def write_claudemd(role: str) -> Path:
    src = TEMPLATES_DIR / f"{role}-CLAUDE.md"
    dst = claudemd_path(role)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if not src.is_file():
        raise RuntimeError(f"missing template: {src}")
    shutil.copyfile(src, dst)
    return dst


def ensure_gitignore(entry: str = ".local-test/") -> bool:
    """Append `entry` to repo's .gitignore if absent. Returns True if changed."""
    gi = repo_root() / ".gitignore"
    lines = gi.read_text().splitlines() if gi.exists() else []
    if any(line.strip() == entry for line in lines):
        return False
    with gi.open("a") as fh:
        if lines and lines[-1].strip() != "":
            fh.write("\n")
        fh.write("# agentnetwork local two-agent test sandboxes\n")
        fh.write(entry + "\n")
    return True


def read_agent_token(role: str) -> str | None:
    path = mcp_json_path(role)
    if not path.is_file():
        return None
    try:
        cfg = json.loads(path.read_text())
        auth = cfg["mcpServers"]["agentnetwork"]["headers"]["Authorization"]
        if auth.startswith("Bearer "):
            return auth[len("Bearer "):]
    except (json.JSONDecodeError, KeyError, OSError):
        return None
    return None


# ────────────────────── subcommands ──────────────────────

def cmd_provision(args: argparse.Namespace) -> int:
    base_url = args.base_url
    if not server_healthy(base_url):
        print(json.dumps({
            "status": "error",
            "reason": "server_down",
            "hint": (
                "Start the stack first: `docker compose up -d postgres && "
                "set -a; source ./.env; set +a && ./gradlew :server:run`"
            ),
        }))
        return 2

    if args.force:
        if (repo_root() / SANDBOX_ROOT).exists():
            shutil.rmtree(repo_root() / SANDBOX_ROOT)

    results = {}
    endpoint = base_url.rstrip("/") + "/mcp"

    for role in ROLES:
        existing = read_agent_token(role)
        if existing and not args.force:
            results[role] = {
                "status": "already_provisioned",
                "mcp_json": str(mcp_json_path(role)),
            }
            continue

        spec = role_spec(role)
        sid = _open_session(endpoint, token=None)
        payload = _call_tool(endpoint, token=None, sid=sid, name="bootstrap", args={
            "email": spec["email"],
            "name": spec["name"],
            "description": spec["description"],
            "projectDescription": spec["projectDescription"],
            "tags": spec["tags"],
        })
        agent_token = payload.get("agentBearerToken")
        if not agent_token:
            raise RuntimeError(f"bootstrap for {role} returned no agentBearerToken: {payload}")

        write_mcp_json(role, base_url, agent_token)
        write_claudemd(role)

        results[role] = {
            "status": "provisioned",
            "mcp_json": str(mcp_json_path(role)),
            "agent_name": spec["name"],
            "agent_email": spec["email"],
        }

    gitignore_changed = ensure_gitignore()

    asker_dir = sandbox_dir("asker")
    answerer_dir = sandbox_dir("answerer")

    print(json.dumps({
        "status": "ok",
        "base_url": base_url,
        "roles": results,
        "gitignore_updated": gitignore_changed,
        "next_steps": {
            "asker_terminal": f"cd {asker_dir} && claude",
            "answerer_terminal": f"cd {answerer_dir} && claude",
            "answerer_first_prompt": "/agentnetwork:listen",
        },
    }, indent=2))
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    target = repo_root() / SANDBOX_ROOT
    if not target.exists():
        print(json.dumps({"status": "noop", "reason": "no_sandbox_dir"}))
        return 0
    shutil.rmtree(target)
    print(json.dumps({
        "status": "ok",
        "removed": str(target),
        "note": (
            "Agents created in previous runs remain in the backend "
            "(no delete-agent endpoint). They become inactive but persist. "
            "For a clean slate: docker compose down -v && docker compose up -d postgres"
        ),
    }))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    base_url = args.base_url
    endpoint = base_url.rstrip("/") + "/mcp"
    healthy = server_healthy(base_url)

    out = {"base_url": base_url, "server_healthy": healthy, "roles": {}}
    for role in ROLES:
        token = read_agent_token(role)
        entry = {
            "sandbox_dir": str(sandbox_dir(role)),
            "mcp_json_present": mcp_json_path(role).is_file(),
            "token_cached": bool(token),
        }
        if token and healthy:
            try:
                sid = _open_session(endpoint, token=token)
                whoami = _call_tool(endpoint, token=token, sid=sid, name="whoami", args={})
                entry["whoami"] = whoami
            except Exception as e:
                entry["whoami_error"] = str(e)
        out["roles"][role] = entry

    print(json.dumps(out, indent=2))
    return 0


# ────────────────────── argparse ──────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(prog="agentnetwork:local-test")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("provision", help="Create the two sandboxes and bootstrap agents.")
    pp.add_argument("--base-url", default=os.environ.get("AN_BASE_URL", "https://agentnetwork.fractalmanifold.com"))
    pp.add_argument("--force", action="store_true",
                    help="Wipe .local-test/ and re-bootstrap both agents.")

    pr = sub.add_parser("reset", help="Remove .local-test/ entirely.")

    ps = sub.add_parser("status", help="Print sandbox state and call whoami per role.")
    ps.add_argument("--base-url", default=os.environ.get("AN_BASE_URL", "https://agentnetwork.fractalmanifold.com"))

    args = parser.parse_args()

    handlers = {"provision": cmd_provision, "reset": cmd_reset, "status": cmd_status}
    return handlers[args.cmd](args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(json.dumps({"status": "error", "http_code": e.code, "body": body}), file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(json.dumps({"status": "error", "reason": str(e)}), file=sys.stderr)
        sys.exit(1)
