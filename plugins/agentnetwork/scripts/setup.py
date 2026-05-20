#!/usr/bin/env python3
"""agentnetwork Claude Code plugin — setup helper (v0.3, project-scoped agents).

Identity model:
  - One agentnetwork user per email (global, cached at ~/.config/agentnetwork/user-token).
  - One agent per *project* (cached at ~/.config/agentnetwork/agents/<project-key>),
    where the agent's expertise is auto-derived from the project's CLAUDE.md, README,
    and language manifests by `project_context.py`.

Subcommands:
  check               Probe server health, project key, cached tokens, MCP registration.
                      Prints a single JSON line for the skill to branch on.
  bootstrap           First-ever setup. Calls MCP `bootstrap` with no auth, captures
                      both `userToken` (usr_*) and `agentBearerToken` (agt_*), caches
                      them. Project context auto-derived from cwd/git toplevel.
  register-project    Have user-token but no agent for this project. Calls MCP
                      `register_agent` with the user-token, stores the new agt_* under
                      the project key. Project context auto-derived.
  install             Run `claude mcp add` with the project's cached agent token
                      (default scope: project, writes to .mcp.json at the project root).

stdlib only — no third-party deps.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

# Cloudflare in front of the public server blocks the default `Python-urllib/3.x`
# UA with HTTP 1010. Identify ourselves with a real-looking UA instead.
_USER_AGENT = "agentnetwork-setup/0.5 (+https://github.com/fractal-manifold/mcp-marketplace)"
from pathlib import Path

# Local helpers — same directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from project_context import extract as extract_project_context

PROTOCOL_VERSION = "2025-11-25"
CONFIG_DIR = Path.home() / ".config" / "agentnetwork"
USER_TOKEN_PATH = CONFIG_DIR / "user-token"
AGENTS_DIR = CONFIG_DIR / "agents"
LEGACY_TOKEN_PATH = CONFIG_DIR / "token"
MCP_NAME = "agentnetwork"


# ────────────────────── HTTP / JSON-RPC over MCP Streamable HTTP ──────────────────────

def _post_jsonrpc(endpoint: str, payload: dict, token: str | None, session_id: str | None):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    req.add_header("User-Agent", _USER_AGENT)
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
            "clientInfo": {"name": "agentnetwork-plugin", "version": "0.3.0"},
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
    payload = tool_result.get("structuredContent")
    if not payload:
        content = tool_result.get("content") or []
        if content and content[0].get("type") == "text":
            try:
                payload = json.loads(content[0].get("text", ""))
            except json.JSONDecodeError:
                payload = None
    if not isinstance(payload, dict):
        raise RuntimeError(f"could not parse {name} payload: {tool_result}")
    if payload.get("error"):
        raise RuntimeError(f"{name} failed: {payload}")
    return payload


def server_healthy(base_url: str) -> bool:
    url = base_url.rstrip("/") + "/api/v1/health"
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", _USER_AGENT)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return False


# ────────────────────── project key + token storage ──────────────────────

def project_root() -> Path:
    """git toplevel if available, else cwd."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        return Path(out.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return Path.cwd()


def project_key(root: Path) -> str:
    return hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]


def _write_secret(path: Path, value: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n")
    os.chmod(path, 0o600)
    return path


def _read_secret(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text().strip() or None


def write_user_token(token: str) -> Path:
    return _write_secret(USER_TOKEN_PATH, token)


def read_user_token() -> str | None:
    return _read_secret(USER_TOKEN_PATH)


def agent_token_path(key: str) -> Path:
    return AGENTS_DIR / key


def write_agent_token(key: str, token: str) -> Path:
    return _write_secret(agent_token_path(key), token)


def read_agent_token(key: str) -> str | None:
    return _read_secret(agent_token_path(key))


# ────────────────────── claude mcp add ──────────────────────

def mcp_already_registered(scope: str, cwd: Path | None = None) -> bool:
    """Check whether `agentnetwork` is registered in the relevant scope.

    `claude mcp list` shows everything; we just look for the name. When scope=project
    we only run it from the project root so user-scope leaks aren't false positives.
    """
    try:
        out = subprocess.run(
            ["claude", "mcp", "list"],
            capture_output=True, text=True, timeout=15,
            cwd=str(cwd) if cwd else None,
        )
    except FileNotFoundError as e:
        raise RuntimeError("`claude` CLI not on PATH") from e
    return MCP_NAME in (out.stdout or "")


def claude_mcp_add(base_url: str, token: str, scope: str, cwd: Path) -> subprocess.CompletedProcess:
    url = base_url.rstrip("/") + "/mcp"
    cmd = [
        "claude", "mcp", "add",
        "--transport", "http",
        "--scope", scope,
        MCP_NAME,
        url,
        "--header", f"Authorization: Bearer {token}",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(cwd))


def write_project_mcp_json(base_url: str, token: str, cwd: Path) -> Path:
    """Write `.mcp.json` at the project root with env-var-templated URL/token.

    `claude mcp add` bakes literal values into the file; we want Claude Code to
    expand `${AN_BASE_URL}` and `${AN_AGENT_TOKEN}` at session start so the
    same `.mcp.json` works against prod and a local server without re-running
    setup. The values from this run become the defaults (`${VAR:-default}`).
    Existing entries for other MCP servers in `.mcp.json` are preserved.
    """
    path = cwd / ".mcp.json"
    data: dict = {}
    if path.exists():
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            data = {}
    servers = data.setdefault("mcpServers", {})
    servers[MCP_NAME] = {
        "type": "http",
        "url": "${AN_BASE_URL:-" + base_url.rstrip("/") + "}/mcp",
        "headers": {
            "Authorization": "Bearer ${AN_AGENT_TOKEN:-" + token + "}",
        },
    }
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path


# ────────────────────── subcommands ──────────────────────

def cmd_check(args: argparse.Namespace) -> int:
    healthy = server_healthy(args.base_url)
    root = project_root()
    key = project_key(root)
    user_token = read_user_token()
    agent_token = read_agent_token(key)
    legacy_token = _read_secret(LEGACY_TOKEN_PATH)
    registered = False
    try:
        registered = mcp_already_registered(args.scope, cwd=root)
    except RuntimeError:
        pass

    if not healthy:
        status = "server_down"
    elif user_token is None:
        status = "needs_user_bootstrap"
    elif agent_token is None:
        status = "needs_project_register"
    elif not registered:
        status = "needs_install"
    else:
        status = "ok"

    print(json.dumps({
        "status": status,
        "healthy": healthy,
        "registered": registered,
        "project_root": str(root),
        "project_key": key,
        "has_user_token": user_token is not None,
        "has_agent_token": agent_token is not None,
        "legacy_token_present": legacy_token is not None,
    }))
    return 0


def cmd_bootstrap(args: argparse.Namespace) -> int:
    """First-ever setup: no tokens at all → create user + first agent for this project."""
    root = project_root()
    key = project_key(root)
    ctx = extract_project_context(root)
    endpoint = args.base_url.rstrip("/") + "/mcp"
    sid = _open_session(endpoint, token=None)
    payload = _call_tool(endpoint, token=None, sid=sid, name="bootstrap", args={
        "email": args.email,
        "name": ctx["name"],
        "description": ctx["description"],
        "projectDescription": ctx["project_description"],
        "tags": ctx["tags"],
    })
    user_token = payload.get("userToken")
    agent_token = payload.get("agentBearerToken")
    if not user_token or not agent_token:
        raise RuntimeError(f"bootstrap response missing tokens: {payload}")
    write_user_token(user_token)
    write_agent_token(key, agent_token)
    print(json.dumps({
        "status": "ok",
        "project_root": str(root),
        "project_key": key,
        "user_token_path": str(USER_TOKEN_PATH),
        "agent_token_path": str(agent_token_path(key)),
        "agent_name": ctx["name"],
        "tags": ctx["tags"],
    }))
    return 0


def cmd_register_project(args: argparse.Namespace) -> int:
    """Have user-token, missing agent for this project → register a new agent."""
    user_token = read_user_token()
    if not user_token:
        print(json.dumps({"status": "error", "reason": "no_user_token"}), file=sys.stderr)
        return 2
    root = project_root()
    key = project_key(root)
    ctx = extract_project_context(root)
    endpoint = args.base_url.rstrip("/") + "/mcp"
    sid = _open_session(endpoint, token=user_token)
    payload = _call_tool(endpoint, token=user_token, sid=sid, name="register_agent", args={
        "name": ctx["name"],
        "description": ctx["description"],
        "projectDescription": ctx["project_description"],
        "tags": ctx["tags"],
    })
    agent_token = payload.get("agentBearerToken")
    if not agent_token:
        raise RuntimeError(f"register_agent response missing token: {payload}")
    write_agent_token(key, agent_token)
    print(json.dumps({
        "status": "ok",
        "project_root": str(root),
        "project_key": key,
        "agent_token_path": str(agent_token_path(key)),
        "agent_name": ctx["name"],
        "tags": ctx["tags"],
    }))
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    """Register the MCP server for the current project.

    For the default `project` scope we write `.mcp.json` directly with an
    env-var-templated URL/token so users can flip between prod and a local
    server (`AN_BASE_URL=http://localhost:8088 claude`) without re-running
    setup. For `user`/`local` scope we fall through to `claude mcp add`, which
    bakes literal values into the relevant settings file.
    """
    root = project_root()
    key = project_key(root)
    token = read_agent_token(key)
    if not token:
        print(json.dumps({"status": "error", "reason": "no_agent_token_for_project"}), file=sys.stderr)
        return 2
    if args.scope == "project":
        path = write_project_mcp_json(args.base_url, token, cwd=root)
        print(json.dumps({
            "status": "ok",
            "scope": args.scope,
            "project_root": str(root),
            "mcp_json": str(path),
            "url_template": "${AN_BASE_URL:-" + args.base_url.rstrip("/") + "}/mcp",
        }))
        return 0
    out = claude_mcp_add(args.base_url, token, args.scope, cwd=root)
    if out.returncode != 0:
        print(json.dumps({
            "status": "error",
            "reason": "claude_mcp_add_failed",
            "stdout": out.stdout,
            "stderr": out.stderr,
        }), file=sys.stderr)
        return out.returncode
    print(json.dumps({
        "status": "ok",
        "scope": args.scope,
        "project_root": str(root),
        "url": args.base_url.rstrip("/") + "/mcp",
    }))
    return 0


def cmd_show_context(args: argparse.Namespace) -> int:
    """Debug: print what would be sent as agent context for this project."""
    root = project_root()
    ctx = extract_project_context(root)
    print(json.dumps({"project_root": str(root), "context": ctx}, indent=2))
    return 0


# ────────────────────── argparse ──────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(prog="agentnetwork:setup")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("check")
    pc.add_argument("--base-url", default=os.environ.get("AN_BASE_URL", "https://agentnetwork.fractalmanifold.com"))
    pc.add_argument("--scope", default="project", choices=["user", "project", "local"])

    pb = sub.add_parser("bootstrap")
    pb.add_argument("--base-url", default=os.environ.get("AN_BASE_URL", "https://agentnetwork.fractalmanifold.com"))
    pb.add_argument("--email", required=True)

    pr = sub.add_parser("register-project")
    pr.add_argument("--base-url", default=os.environ.get("AN_BASE_URL", "https://agentnetwork.fractalmanifold.com"))

    pi = sub.add_parser("install")
    pi.add_argument("--base-url", default=os.environ.get("AN_BASE_URL", "https://agentnetwork.fractalmanifold.com"))
    pi.add_argument("--scope", default="project", choices=["user", "project", "local"])

    sub.add_parser("show-context")

    args = parser.parse_args()
    try:
        if args.cmd == "check":
            return cmd_check(args)
        if args.cmd == "bootstrap":
            return cmd_bootstrap(args)
        if args.cmd == "register-project":
            return cmd_register_project(args)
        if args.cmd == "install":
            return cmd_install(args)
        if args.cmd == "show-context":
            return cmd_show_context(args)
    except Exception as e:
        print(json.dumps({"status": "error", "reason": str(e)}), file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
