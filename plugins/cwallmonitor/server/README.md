# `server/` — the cwallmonitor MCP server (canonical source)

This directory **is** the source of the cwm-mcp credential broker + MCP server.
Edit it here, in this repo (`mcp-marketplace`) — there is no generation step
and nothing copies into it. The plugin ships its own server so that installing
the plugin is enough: no separate `go install` / `pipx` / `npm`.

Layout:

```
server/
  cwm-mcp                  bundle-mode launcher (POSIX sh); .mcp.json execs this
  install.sh               optional standalone PATH-mode installer
  VERSION                  vendored copy of the monorepo-root VERSION (see below)
  compat/tool-schemas.json vendored copy of the monorepo compat/ (see below)
  js/                      Node.js runtime (src/ + test/)
  py/                      Python runtime (src/ + tests/)
  go/                      Go runtime (cmd/ internal/ go.mod … + *_test.go)
```

## Runtime selection & dependencies

`cwm-mcp` auto-detects "bundle mode" from the sibling `VERSION` + `compat/` +
`js|py|go/` and execs the first available runtime (Node → Python → Go; override
with `runtime=` in `~/.config/claude-wall-monitor/launcher.conf`). Dependencies
— including native ones (serialport, fs-ext, cryptography) — are resolved on
first run into `~/.cache/claude-wall-monitor/<version>/`, not committed here.

## The two vendored files (`VERSION`, `compat/tool-schemas.json`)

`compat/` and `VERSION` are authoritative in the **monorepo root**
(`claude-wall-monitor`), shared with the firmware and host tooling. Because the
published plugin is cloned standalone (without the monorepo around it), the
server needs those two files present to start, so they are vendored here. They
are kept in sync by `tools/cwmtools/plugin/vendor_contract.py` in the monorepo;
`tools/tests/plugin_vendor_sync_test.py` fails if they drift. Do **not** edit
these two files here — change them in the monorepo and re-vendor.

The runtime loaders (`py/src/cwm_mcp/mcp/server.py`, `js/src/mcp/server.js`)
and the version loaders walk *up* for `compat/tool-schemas.json` / `VERSION`
and find these vendored copies first, so dev (inside the monorepo) and the
published plugin behave identically.

## Tests

`js/test/`, `py/tests/`, `go/internal/**/*_test.go` carry the byte-exact
cross-runtime contract tests. Their vector/golden fixtures live in the
monorepo's full `compat/` (not vendored here), which the tests locate by
walking up. They therefore run only inside a **full monorepo checkout**; in a
standalone `mcp-marketplace` clone those fixture-backed tests skip cleanly.

```
cd server/py  && python3 -m pytest tests/ -q
cd server/js  && node --test test/*.test.js
cd server/go  && go test ./...
```
