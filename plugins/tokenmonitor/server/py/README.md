# tokenmonitor-mcp-py

Python port of `tokenmonitor-mcp` with byte-exact parity to the Go reference
impl on every wire and storage contract documented under `../compat/`.

## Install

```sh
pipx install .
# or, in a venv:
pip install -e .
```

## Run

```sh
tokenmonitor-mcp-py --probe       # used by the tokenmonitor-mcp launcher
tokenmonitor-mcp-py --daemon      # standalone broker
tokenmonitor-mcp-py --version
tokenmonitor-mcp-py               # default: MCP stdio + leader-elected broker
```

Config lives at `~/.config/tokenmonitor/tokenmonitor.toml`; the schema
matches the Go impl (see `../compat/`).

## Tests

```sh
pip install -e . pytest pytest-asyncio
pytest
```

Tests validate against the shared vectors in `../compat/vectors/` and
the goldens in `../compat/registry/golden/`.
