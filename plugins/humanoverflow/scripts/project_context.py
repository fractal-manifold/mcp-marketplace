"""Extract project context (description, tags, slug) from a project directory.

Used by setup.py to auto-derive an agent's expertise without asking the user.
Reads CLAUDE.md, README.md, and language manifests (package.json, Cargo.toml,
pyproject.toml, build.gradle.kts, go.mod, pom.xml, …).

stdlib only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

MAX_DESCRIPTION = 500
MAX_PROJECT_DESCRIPTION = 1500
MAX_TAGS = 10


def extract(root: Path) -> dict:
    """Return {name, description, project_description, tags[]} for a project root."""
    root = root.resolve()
    raw_name = root.name
    name = _slug(raw_name) or "agent"

    project_description = ""
    description_hints: list[str] = []
    tags: set[str] = set()

    # CLAUDE.md — preferred since it's curated for AI consumption
    claude_md = _read(root / "CLAUDE.md")
    if claude_md:
        para = _first_paragraph(claude_md)
        if para:
            project_description = para

    # README.md — fallback or supplementary
    readme = _read(root / "README.md")
    if readme:
        para = _first_paragraph(readme)
        if para and not project_description:
            project_description = para

    # package.json
    pkg_json = _read(root / "package.json")
    if pkg_json:
        tags.add("javascript")
        if (root / "tsconfig.json").is_file():
            tags.add("typescript")
        try:
            data = json.loads(pkg_json)
            if isinstance(data, dict):
                if not project_description and isinstance(data.get("description"), str):
                    project_description = data["description"]
                deps = {}
                deps.update(data.get("dependencies") or {})
                deps.update(data.get("devDependencies") or {})
                for dep in deps:
                    if dep == "react":
                        tags.add("react")
                    elif dep == "next":
                        tags.add("nextjs")
                    elif dep == "vue":
                        tags.add("vue")
                    elif dep.startswith("@angular/"):
                        tags.add("angular")
                    elif dep == "express":
                        tags.add("express")
                    elif dep == "fastify":
                        tags.add("fastify")
        except (json.JSONDecodeError, AttributeError):
            pass

    # Rust
    cargo = _read(root / "Cargo.toml")
    if cargo:
        tags.add("rust")
        m = re.search(r'(?m)^\s*description\s*=\s*"([^"]+)"', cargo)
        if m and not project_description:
            project_description = m.group(1)

    # Python
    pyproject = _read(root / "pyproject.toml")
    if pyproject or (root / "setup.py").is_file() or (root / "requirements.txt").is_file():
        tags.add("python")
        if pyproject:
            m = re.search(r'(?m)^\s*description\s*=\s*"([^"]+)"', pyproject)
            if m and not project_description:
                project_description = m.group(1)

    # Go
    if (root / "go.mod").is_file():
        tags.add("go")

    # JVM / Gradle / Maven
    has_gradle = any((root / f).is_file() for f in (
        "build.gradle.kts", "build.gradle", "settings.gradle.kts", "settings.gradle",
    ))
    if has_gradle:
        tags.add("gradle")
    if (root / "pom.xml").is_file():
        tags.add("maven")
        tags.add("java")

    # Kotlin / Java detection by file extension (top-level + src/)
    exts = _scan_extensions(root, max_files=300)
    if ".kt" in exts or ".kts" in exts:
        tags.add("kotlin")
    elif has_gradle and ".java" in exts:
        tags.add("java")
    if ".swift" in exts:
        tags.add("swift")
    if ".rb" in exts:
        tags.add("ruby")
    if ".py" in exts:
        tags.add("python")
    if ".rs" in exts:
        tags.add("rust")
    if ".go" in exts:
        tags.add("go")

    # Infra
    if (root / "Dockerfile").is_file() or _glob_any(root, ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]):
        tags.add("docker")
    if any(p.suffix == ".tf" for p in root.glob("*.tf")):
        tags.add("terraform")
    if (root / "kubernetes").is_dir() or _glob_any(root, ["k8s", "deployment.yaml"]):
        tags.add("kubernetes")

    # Heuristic feature tags from the description
    blob = (project_description + " " + (claude_md or "") + " " + (readme or "")).lower()
    for kw, tag in (
        ("postgres", "postgres"), ("postgresql", "postgres"),
        ("pgvector", "pgvector"), ("redis", "redis"), ("kafka", "kafka"),
        ("mcp", "mcp"), ("ktor", "ktor"), ("spring boot", "spring-boot"),
        ("graphql", "graphql"), ("grpc", "grpc"),
        ("embedding", "embeddings"), ("llm", "llm"),
    ):
        if kw in blob:
            tags.add(tag)

    if not project_description:
        project_description = f"Working on {raw_name}"

    description = description_hints[0] if description_hints else (
        f"AI agent for the {raw_name} codebase"
    )

    return {
        "name": name,
        "description": description[:MAX_DESCRIPTION],
        "project_description": project_description[:MAX_PROJECT_DESCRIPTION],
        "tags": sorted(tags)[:MAX_TAGS],
    }


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else None
    except OSError:
        return None


def _first_paragraph(md: str) -> str:
    """First 1-2 prose paragraphs of a Markdown doc, skipping headings, code, lists."""
    if md.startswith("---"):
        end = md.find("\n---", 3)
        if end > 0:
            md = md[end + 4:]
    paras: list[str] = []
    buf: list[str] = []
    in_code = False
    for line in md.splitlines():
        s = line.strip()
        if s.startswith("```") or s.startswith("~~~"):
            in_code = not in_code
            continue
        if in_code:
            continue
        if s.startswith("#"):
            if buf:
                paras.append(" ".join(buf).strip())
                buf = []
            if len(paras) >= 2:
                break
            continue
        if s.startswith(("-", "*", ">", "|")) or re.match(r"^\d+\.\s", s):
            continue
        if not s:
            if buf:
                paras.append(" ".join(buf).strip())
                buf = []
            if len(paras) >= 2:
                break
            continue
        buf.append(s)
    if buf:
        paras.append(" ".join(buf).strip())
    return "\n\n".join(p for p in paras[:2] if p)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", s.lower()).strip("-")


def _scan_extensions(root: Path, max_files: int) -> set[str]:
    out: set[str] = set()
    skip = {"node_modules", ".git", "build", "dist", "target", "__pycache__", ".gradle", ".venv", "venv"}
    count = 0
    for p in root.rglob("*"):
        if count >= max_files:
            break
        if p.is_dir():
            if p.name in skip:
                # rglob doesn't honor a skip filter directly; just continue
                continue
        elif p.is_file():
            if any(part in skip for part in p.parts):
                continue
            out.add(p.suffix.lower())
            count += 1
    return out


def _glob_any(root: Path, names: list[str]) -> bool:
    return any((root / n).exists() for n in names)
