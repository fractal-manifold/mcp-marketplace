#!/usr/bin/env python3
"""Read/mark helpers for the humanoverflow daemon inbox.

The daemon (scripts/hof-mcp.py daemon) appends incoming questions to
~/.cache/humanoverflow/inbox/<project-key>.jsonl. This script gives skills
a stable interface to query unprocessed entries and mark them done, without
each skill having to know the on-disk layout.

Subcommands:
  inbox.py list [--limit N]        unprocessed entries as JSON lines
  inbox.py mark <questionId>...    append IDs to the processed sidecar
  inbox.py status                  counts + paths (for status skills)

The processed sidecar is append-only (one questionId per line), so the
daemon's append-only inbox and the skill's append-only sidecar never race.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "humanoverflow"
INBOX_DIR = CACHE_DIR / "inbox"


def git_toplevel() -> Path:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        return Path(out.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return Path.cwd()


def project_key(root: Path | None = None) -> str:
    root = root or git_toplevel()
    return hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]


def paths(key: str) -> tuple[Path, Path]:
    return INBOX_DIR / f"{key}.jsonl", INBOX_DIR / f"{key}.processed"


def load_processed_ids(processed: Path) -> set[str]:
    if not processed.is_file():
        return set()
    return {line.strip() for line in processed.read_text().splitlines() if line.strip()}


def iter_inbox(inbox: Path):
    if not inbox.is_file():
        return
    with open(inbox) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def cmd_list(args: argparse.Namespace) -> int:
    key = project_key()
    inbox, processed = paths(key)
    done = load_processed_ids(processed)
    count = 0
    for q in iter_inbox(inbox):
        qid = q.get("id")
        if qid in done:
            continue
        sys.stdout.write(json.dumps(q, ensure_ascii=False) + "\n")
        count += 1
        if args.limit and count >= args.limit:
            break
    return 0


def cmd_mark(args: argparse.Namespace) -> int:
    key = project_key()
    _inbox, processed = paths(key)
    processed.parent.mkdir(parents=True, exist_ok=True)
    with open(processed, "a") as fh:
        for qid in args.ids:
            fh.write(qid + "\n")
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    key = project_key()
    inbox, processed = paths(key)
    total = sum(1 for _ in iter_inbox(inbox))
    done = load_processed_ids(processed)
    unprocessed = sum(1 for q in iter_inbox(inbox) if q.get("id") not in done)
    print(json.dumps({
        "project_key": key,
        "inbox": str(inbox),
        "processed_sidecar": str(processed),
        "total": total,
        "processed": len(done),
        "unprocessed": unprocessed,
    }, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="inbox.py", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="emit unprocessed inbox entries as JSON lines")
    pl.add_argument("--limit", type=int, default=0, help="max entries to emit (0 = no limit)")

    pm = sub.add_parser("mark", help="append questionId(s) to the processed sidecar")
    pm.add_argument("ids", nargs="+")

    sub.add_parser("status", help="counts + paths")

    args = parser.parse_args()
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "mark":
        return cmd_mark(args)
    if args.cmd == "status":
        return cmd_status(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
