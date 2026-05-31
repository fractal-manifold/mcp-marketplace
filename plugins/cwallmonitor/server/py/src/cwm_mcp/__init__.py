"""cwm-mcp Python implementation. See ../compat/ for the cross-runtime contracts."""

from pathlib import Path

# VERSION is read from the repo-root file; falls back to package version.
def _load_version() -> str:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "VERSION"
        if candidate.is_file():
            return candidate.read_text().strip()
    return "0.0.0"


__version__ = _load_version()
RUNTIME = "python"
