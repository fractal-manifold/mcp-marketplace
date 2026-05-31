# cwm-mcp-js

Node.js port of cwm-mcp with byte-exact parity to the Go reference
impl on every wire and storage contract documented under `../compat/`.

## Install

```sh
npm install -g .
# or, for local dev:
npm install
```

## Run

```sh
cwm-mcp-js --probe       # used by the cwm-mcp launcher
cwm-mcp-js --daemon
cwm-mcp-js --version
cwm-mcp-js               # default: MCP stdio + leader-elected broker
```

Requires Node ≥ 20. Config lives at
`~/.config/claude-wall-monitor/cwm.toml`; the schema matches the Go impl.

## Tests

```sh
npm test
```
