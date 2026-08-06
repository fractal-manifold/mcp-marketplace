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
matches the Go impl (see `../compat/`). You don't have to create it — the first
start writes a working default there (0600, random `psk_passphrase`) rather than
exiting, so a fresh install still reaches MCP "ready". A config that exists but
carries no PSK gets a generated fallback key in a `psk` sidecar beside it rather
than an exit. A config that doesn't fully parse doesn't stop the start either:
the broker comes up on the sections that survive, logs the ones it had to drop,
and reports them as a failing `config` check in `tokenmonitor_health` — your
file is never rewritten. An explicit `--config` path is never bootstrapped,
never salvaged, and never gets a sidecar. See `../go/README.md` for the full
rules.

## Tests

```sh
pip install -e . pytest pytest-asyncio
pytest
```

Tests validate against the shared vectors in `../compat/vectors/` and
the goldens in `../compat/registry/golden/`.
