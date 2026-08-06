# tokenmonitor-mcp-js

Node.js port of tokenmonitor-mcp with byte-exact parity to the Go reference
impl on every wire and storage contract documented under `../compat/`.

## Install

```sh
npm install -g .
# or, for local dev:
npm install
```

## Run

```sh
tokenmonitor-mcp-js --probe       # used by the tokenmonitor-mcp launcher
tokenmonitor-mcp-js --daemon
tokenmonitor-mcp-js --version
tokenmonitor-mcp-js               # default: MCP stdio + leader-elected broker
```

Requires Node ≥ 20. Config lives at
`~/.config/tokenmonitor/tokenmonitor.toml`; the schema matches the Go impl. You
don't have to create it — the first start writes a working default there (0600,
random `psk_passphrase`) rather than exiting, so a fresh install still reaches
MCP "ready". A config that exists but carries no PSK gets a generated fallback
key in a `psk` sidecar beside it rather than an exit. A config that doesn't fully
parse doesn't stop the start either: the broker comes up on the sections that
survive, logs the ones it had to drop, and reports them as a failing `config`
check in `tokenmonitor_health` — your file is never rewritten. An explicit
`--config` path is never bootstrapped, never salvaged, and never gets a sidecar.
See `../go/README.md` for the full rules.

## Tests

```sh
npm test
```
