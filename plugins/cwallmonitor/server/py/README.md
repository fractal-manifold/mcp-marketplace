# cwm-mcp-py

Python port of `cwm-mcp` with byte-exact parity to the Go reference
impl on every wire and storage contract documented under `../compat/`.

## Install

```sh
pipx install .
# or, in a venv:
pip install -e .
```

## Run

```sh
cwm-mcp-py --probe       # used by the cwm-mcp launcher
cwm-mcp-py --daemon      # standalone broker
cwm-mcp-py --version
cwm-mcp-py               # default: MCP stdio + leader-elected broker
```

Config lives at `~/.config/claude-wall-monitor/cwm.toml`; the schema
matches the Go impl (see `../compat/`).

## Tests

```sh
pip install -e . pytest pytest-asyncio
pytest
```

Tests validate against the shared vectors in `../compat/vectors/` and
the goldens in `../compat/registry/golden/`.
