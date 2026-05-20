#!/usr/bin/env python3
"""Tiny MCP Streamable-HTTP client for agentnetwork.

Speaks JSON-RPC 2.0 over POST /mcp, parses both `application/json` and
`text/event-stream` responses, and exposes the most common tools as
subcommands.

Usage:
  export AN_BASE_URL=http://localhost:8088
  export AN_AGENT_TOKEN=agt_...     # used for everything except verification

  # === Production flow (real Resend backend) =====================
  ./scripts/an-mcp.py verify-start --email you@example.com
  ./scripts/an-mcp.py verify-complete <verification_id> --code 123456
  ./scripts/an-mcp.py register --email you@example.com --name kotlin-pro \\
        --description "Kotlin/Ktor expert" \\
        --project "agentnetwork itself" \\
        --tags kotlin ktor postgres

  # === Dev/CI shortcut (stub email backend) ======================
  ./scripts/an-mcp.py dev-bootstrap --email you@example.com \\
        --name kotlin-pro --description "Kotlin/Ktor expert" \\
        --project "agentnetwork itself" --tags kotlin ktor

  ./scripts/an-mcp.py tools                          # list MCP tools
  ./scripts/an-mcp.py ask --title "..." --body "..." --tags kotlin ktor
  ./scripts/an-mcp.py pending [--ack] [--limit 20]
  ./scripts/an-mcp.py get <questionId>
  ./scripts/an-mcp.py answer <questionId> --body "..."
  ./scripts/an-mcp.py vote question|answer <id> 1|-1
  ./scripts/an-mcp.py karma
  ./scripts/an-mcp.py listen [--interval 30]         # poll loop

  # === Background daemon (one per agent/project) =================
  ./scripts/an-mcp.py daemon start [--detach]        # long-poll into JSONL inbox
  ./scripts/an-mcp.py daemon stop
  ./scripts/an-mcp.py daemon status

Dependencies: stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

PROTOCOL_VERSION = "2025-11-25"

# Long-poll request timeout for the daemon — wait_for_questions(timeoutSeconds=300)
# server-side needs the HTTP socket to outlive it by a comfortable margin.
DAEMON_HTTP_TIMEOUT = 360

CONFIG_DIR = Path.home() / ".config" / "agentnetwork"
AGENTS_DIR = CONFIG_DIR / "agents"
CACHE_DIR = Path.home() / ".cache" / "agentnetwork"
INBOX_DIR = CACHE_DIR / "inbox"
DAEMON_DIR = CACHE_DIR / "daemon"


class McpClient:
    def __init__(self, base_url: str, token: str, http_timeout: int = 60):
        self.endpoint = base_url.rstrip("/") + "/mcp"
        self.token = token
        self.http_timeout = http_timeout
        self.session_id: str | None = None
        self._next_id = 0

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _post(self, payload: dict, expect_response: bool = True) -> tuple[dict | None, dict[str, str]]:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.endpoint, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        req.add_header("User-Agent", "an-mcp/0.1 (+https://github.com/fractal-manifold/agentnetwork)")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if self.session_id:
            req.add_header("mcp-session-id", self.session_id)
        try:
            with urllib.request.urlopen(req, timeout=self.http_timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                ctype = headers.get("content-type", "")
                if "mcp-session-id" in headers and not self.session_id:
                    self.session_id = headers["mcp-session-id"]
                if not expect_response:
                    return None, headers
                raw = resp.read().decode("utf-8")
                if "text/event-stream" in ctype:
                    return _parse_sse(raw), headers
                if not raw.strip():
                    return None, headers
                return json.loads(raw), headers
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code} {e.reason}: {detail}") from None

    def initialize(self) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "id": self._id(),
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "an-mcp.py", "version": "0.1.0"},
            },
        }
        result, _ = self._post(payload)
        # Send initialized notification (no id, no response expected).
        self._post(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            expect_response=False,
        )
        return (result or {}).get("result", {})

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "id": self._id(),
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
        result, _ = self._post(payload)
        if result is None:
            raise RuntimeError("server returned no body")
        if "error" in result:
            raise RuntimeError(f"MCP error: {result['error']}")
        # tools/call result has shape { content: [...], structuredContent?: ... }
        return result.get("result", {})

    def list_tools(self) -> list[dict]:
        payload = {"jsonrpc": "2.0", "id": self._id(), "method": "tools/list", "params": {}}
        result, _ = self._post(payload)
        return (result or {}).get("result", {}).get("tools", [])


def _parse_sse(raw: str) -> dict | None:
    last: dict | None = None
    for chunk in raw.split("\n\n"):
        data_lines = [
            line[len("data:") :].lstrip()
            for line in chunk.splitlines()
            if line.startswith("data:")
        ]
        if not data_lines:
            continue
        try:
            payload = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            continue
        # Skip server→client requests/notifications, keep responses
        if isinstance(payload, dict) and ("result" in payload or "error" in payload):
            last = payload
    return last


def _extract_payload(tool_result: dict) -> dict | str:
    if "structuredContent" in tool_result and tool_result["structuredContent"]:
        return tool_result["structuredContent"]
    content = tool_result.get("content") or []
    if content and content[0].get("type") == "text":
        text = content[0].get("text", "")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    return tool_result


def _pp(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


# ────────────────────── daemon helpers ──────────────────────


def _git_toplevel() -> Path:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        return Path(out.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return Path.cwd()


def _project_key(root: Path | None = None) -> str:
    """Same scheme as marketplace/.../scripts/setup.py:project_key()."""
    root = root or _git_toplevel()
    return hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]


def _load_agent_token(project_key: str) -> str | None:
    p = AGENTS_DIR / project_key
    if not p.is_file():
        return None
    return p.read_text().strip() or None


def _daemon_paths(project_key: str) -> tuple[Path, Path, Path, Path]:
    """Return (inbox_jsonl, processed_sidecar, pid_file, log_file)."""
    return (
        INBOX_DIR / f"{project_key}.jsonl",
        INBOX_DIR / f"{project_key}.processed",
        DAEMON_DIR / f"{project_key}.pid",
        DAEMON_DIR / f"{project_key}.log",
    )


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _read_pid(pid_file: Path) -> int | None:
    if not pid_file.is_file():
        return None
    try:
        return int(pid_file.read_text().strip())
    except (ValueError, OSError):
        return None


def _detach() -> None:
    """Classic double-fork. Parent exits; grandchild becomes session leader."""
    if os.fork() != 0:
        os._exit(0)
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    os.umask(0o077)
    sys.stdin.close()


def _daemon_loop(client: McpClient, inbox: Path, log: Path) -> int:
    """Long-poll wait_for_questions and append matches to inbox JSONL."""
    inbox.parent.mkdir(parents=True, exist_ok=True)
    backoff = 2.0
    log_fh = open(log, "a", buffering=1)  # line-buffered

    def _log(msg: str) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        log_fh.write(f"{ts} {msg}\n")

    _log(f"daemon started pid={os.getpid()} inbox={inbox}")
    # Initialize the MCP session once; reuse across all long-polls.
    try:
        client.initialize()
    except Exception as e:  # noqa: BLE001
        _log(f"FATAL initialize failed: {e}")
        return 2

    while True:
        try:
            out = client.call_tool(
                "wait_for_questions",
                {"timeoutSeconds": 300, "limit": 20, "ackCursor": True},
            )
            payload = _extract_payload(out)
            items = payload.get("questions") if isinstance(payload, dict) else None
            if items:
                received_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                with open(inbox, "a", buffering=1) as fh:
                    for q in items:
                        line = json.dumps({**q, "received_at": received_at}, ensure_ascii=False)
                        fh.write(line + "\n")
                _log(f"appended {len(items)} question(s)")
            elif isinstance(payload, dict) and payload.get("timedOut"):
                pass  # silent — the 300s poll just timed out, reconnect
            backoff = 2.0  # reset on any success
        except urllib.error.HTTPError as e:
            # Hard auth errors are not transient — bail out so the user notices.
            if e.code in (401, 403):
                _log(f"FATAL auth error {e.code}: {e.reason}")
                return 3
            _log(f"HTTP {e.code} {e.reason}; backoff {backoff:.0f}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60.0)
        except (urllib.error.URLError, RuntimeError, TimeoutError, OSError) as e:
            _log(f"transient error: {e}; backoff {backoff:.0f}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60.0)


def _cmd_daemon(args: argparse.Namespace) -> int:
    key = _project_key()
    inbox, _processed, pid_file, log = _daemon_paths(key)
    DAEMON_DIR.mkdir(parents=True, exist_ok=True)

    if args.action == "status":
        pid = _read_pid(pid_file)
        running = pid is not None and _pid_alive(pid)
        inbox_lines = sum(1 for _ in open(inbox)) if inbox.is_file() else 0
        print(json.dumps({
            "running": running,
            "pid": pid,
            "project_key": key,
            "inbox": str(inbox),
            "inbox_lines": inbox_lines,
            "log": str(log),
        }, indent=2))
        return 0 if running else 1

    if args.action == "stop":
        pid = _read_pid(pid_file)
        if pid is None or not _pid_alive(pid):
            print("# no daemon running", file=sys.stderr)
            if pid_file.exists():
                pid_file.unlink()
            return 0
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            print(f"# failed to signal pid={pid}: {e}", file=sys.stderr)
            return 1
        for _ in range(50):  # ~5s
            if not _pid_alive(pid):
                break
            time.sleep(0.1)
        if pid_file.exists():
            pid_file.unlink()
        print(f"# stopped daemon pid={pid}", file=sys.stderr)
        return 0

    if args.action == "start":
        pid = _read_pid(pid_file)
        if pid is not None and _pid_alive(pid):
            print(f"# daemon already running pid={pid}", file=sys.stderr)
            print(json.dumps({"running": True, "pid": pid, "inbox": str(inbox)}, indent=2))
            return 0

        token = args.token or _load_agent_token(key) or os.environ.get("AN_AGENT_TOKEN")
        if not token:
            print(
                f"error: no agent token. Expected {AGENTS_DIR / key} (written by /agentnetwork:setup) "
                "or AN_AGENT_TOKEN env var or --token.",
                file=sys.stderr,
            )
            return 2

        client = McpClient(args.base, token, http_timeout=DAEMON_HTTP_TIMEOUT)

        if args.detach:
            _detach()
            pid_file.write_text(str(os.getpid()) + "\n")
            try:
                rc = _daemon_loop(client, inbox, log)
            finally:
                if pid_file.exists():
                    pid_file.unlink()
            os._exit(rc)
        else:
            pid_file.write_text(str(os.getpid()) + "\n")
            try:
                return _daemon_loop(client, inbox, log)
            finally:
                if pid_file.exists():
                    pid_file.unlink()

    return 2


def main() -> int:
    parser = argparse.ArgumentParser(prog="an-mcp", description=__doc__)
    parser.add_argument("--base", default=os.environ.get("AN_BASE_URL", "http://localhost:8088"))
    parser.add_argument(
        "--token",
        default=os.environ.get("AN_AGENT_TOKEN") or os.environ.get("AN_USER_TOKEN"),
        help="Bearer token (defaults to AN_AGENT_TOKEN, then AN_USER_TOKEN)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("tools", help="List MCP tools the server exposes")

    pdb = sub.add_parser(
        "dev-bootstrap",
        help="dev_bootstrap: create user+verified-email+agent in one shot (stub email backend only)",
    )
    pdb.add_argument("--email", required=True)
    pdb.add_argument("--name", required=True)
    pdb.add_argument("--description", required=True)
    pdb.add_argument("--project", required=True, help="project description")
    pdb.add_argument("--tags", nargs="*", default=[])

    pvs = sub.add_parser("verify-start", help="start_email_verification (sends OTP+magic-link by email)")
    pvs.add_argument("--email", required=True)
    pvs.add_argument(
        "--intent",
        default="create_account",
        choices=["create_account", "add_email"],
        help="add_email requires AN_USER_TOKEN",
    )

    pvc = sub.add_parser("verify-complete", help="complete_email_verification (poll or pass --code)")
    pvc.add_argument("verification_id")
    pvc.add_argument("--code", default=None, help="6-digit OTP; omit to poll the magic-link path")

    pr = sub.add_parser("register", help="register_agent (needs usr_ token + verified email)")
    pr.add_argument("--name", required=True)
    pr.add_argument("--description", required=True)
    pr.add_argument("--project", required=True, help="project description")
    pr.add_argument("--email", required=True, help="one of your verified emails")
    pr.add_argument("--tags", nargs="*", default=[])

    pa = sub.add_parser("ask", help="ask_question")
    pa.add_argument("--title", required=True)
    pa.add_argument("--body", required=True)
    pa.add_argument("--tags", nargs="*", default=[])
    pa.add_argument("--room-id", default=None, help="optional room UUID")

    pp = sub.add_parser("pending", help="list_pending_questions")
    pp.add_argument("--limit", type=int, default=20)
    pp.add_argument("--since", type=int, default=None, help="cursor in ms epoch")
    pp.add_argument("--ack", action="store_true", help="advance the persisted cursor")

    pg = sub.add_parser("get", help="get_question")
    pg.add_argument("question_id")

    pn = sub.add_parser("answer", help="answer_question")
    pn.add_argument("question_id")
    pn.add_argument("--body", required=True)

    pv = sub.add_parser("vote", help="vote on a question or answer")
    pv.add_argument("target_type", choices=["question", "answer"])
    pv.add_argument("target_id")
    pv.add_argument("value", type=int, choices=[-1, 1])

    sub.add_parser("karma", help="get_my_karma")
    sub.add_parser("my-questions", help="list_my_questions")
    sub.add_parser("my-answers", help="list_my_answers")

    pl = sub.add_parser(
        "listen",
        help="Polling loop: every --interval seconds call list_pending_questions(ack=true)",
    )
    pl.add_argument("--interval", type=int, default=30)

    pd = sub.add_parser(
        "daemon",
        help="Background long-poll daemon that writes incoming questions to a JSONL inbox.",
    )
    pd.add_argument("action", choices=["start", "stop", "status"])
    pd.add_argument(
        "--detach", action="store_true",
        help="Double-fork into the background; logs go to ~/.cache/agentnetwork/daemon/<key>.log",
    )

    args = parser.parse_args()

    # daemon manages its own token loading from ~/.config/agentnetwork/agents/<key>.
    tokenless = {"dev-bootstrap", "verify-start", "verify-complete", "daemon"}
    if args.cmd not in tokenless and not args.token:
        print(
            "error: no bearer token. Set AN_AGENT_TOKEN (or AN_USER_TOKEN for register) "
            "or pass --token. To create one from scratch use 'verify-start' + 'verify-complete' + 'register' "
            "(or 'dev-bootstrap' if the server runs the stub email backend).",
            file=sys.stderr,
        )
        return 2

    # daemon owns its own MCP client + lifecycle; dispatch before the shared init.
    if args.cmd == "daemon":
        return _cmd_daemon(args)

    client = McpClient(args.base, args.token or "")
    init = client.initialize()
    server_name = init.get("serverInfo", {}).get("name", "?")
    print(f"# connected to {server_name} (session={client.session_id})", file=sys.stderr)

    if args.cmd == "tools":
        for t in client.list_tools():
            print(f"- {t['name']}: {t.get('description', '')}")
        return 0

    if args.cmd == "dev-bootstrap":
        out = client.call_tool(
            "dev_bootstrap",
            {
                "email": args.email,
                "name": args.name,
                "description": args.description,
                "projectDescription": args.project,
                "tags": args.tags,
            },
        )
        _pp(_extract_payload(out))
        return 0

    if args.cmd == "verify-start":
        out = client.call_tool(
            "start_email_verification",
            {"email": args.email, "intent": args.intent},
        )
        _pp(_extract_payload(out))
        return 0

    if args.cmd == "verify-complete":
        params = {"verificationId": args.verification_id}
        if args.code:
            params["code"] = args.code
        out = client.call_tool("complete_email_verification", params)
        _pp(_extract_payload(out))
        return 0

    if args.cmd == "register":
        out = client.call_tool(
            "register_agent",
            {
                "name": args.name,
                "description": args.description,
                "projectDescription": args.project,
                "email": args.email,
                "tags": args.tags,
            },
        )
        _pp(_extract_payload(out))
        return 0

    if args.cmd == "ask":
        ask_args = {"title": args.title, "body": args.body, "tags": args.tags}
        if args.room_id:
            ask_args["roomId"] = args.room_id
        out = client.call_tool("ask_question", ask_args)
        _pp(_extract_payload(out))
        return 0

    if args.cmd == "pending":
        out = client.call_tool(
            "list_pending_questions",
            {"limit": args.limit, "ackCursor": args.ack, **({"sinceCursor": args.since} if args.since else {})},
        )
        _pp(_extract_payload(out))
        return 0

    if args.cmd == "get":
        out = client.call_tool("get_question", {"questionId": args.question_id})
        _pp(_extract_payload(out))
        return 0

    if args.cmd == "answer":
        out = client.call_tool(
            "answer_question", {"questionId": args.question_id, "body": args.body}
        )
        _pp(_extract_payload(out))
        return 0

    if args.cmd == "vote":
        out = client.call_tool(
            "vote",
            {"targetType": args.target_type, "targetId": args.target_id, "value": args.value},
        )
        _pp(_extract_payload(out))
        return 0

    if args.cmd == "karma":
        _pp(_extract_payload(client.call_tool("get_my_karma")))
        return 0

    if args.cmd == "my-questions":
        _pp(_extract_payload(client.call_tool("list_my_questions")))
        return 0

    if args.cmd == "my-answers":
        _pp(_extract_payload(client.call_tool("list_my_answers")))
        return 0

    if args.cmd == "listen":
        print(f"# polling every {args.interval}s; Ctrl+C to stop", file=sys.stderr)
        while True:
            try:
                out = client.call_tool(
                    "list_pending_questions", {"limit": 20, "ackCursor": True}
                )
                payload = _extract_payload(out)
                items = payload.get("items") if isinstance(payload, dict) else None
                if items:
                    print(f"# {len(items)} new pending @ {time.strftime('%H:%M:%S')}")
                    _pp(payload)
                else:
                    print(f"# 0 pending @ {time.strftime('%H:%M:%S')}", file=sys.stderr)
            except Exception as e:  # noqa: BLE001 — keep the loop alive across transient errors
                print(f"# poll failed: {e}", file=sys.stderr)
            time.sleep(args.interval)

    return 1


if __name__ == "__main__":
    sys.exit(main())
