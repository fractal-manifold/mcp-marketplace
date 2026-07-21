# `server/` — the tokenmonitor MCP server (canonical source)

This directory **is** the source of the tokenmonitor-mcp credential broker + MCP server.
Edit it here, in this repo (`mcp-marketplace`) — there is no generation step
and nothing copies into it. The plugin ships its own server so that installing
the plugin is enough: no separate `go install` / `pipx` / `npm`.

Layout:

```
server/
  tokenmonitor-mcp         bundle-mode launcher (POSIX sh); the plugin mcpServers entry execs this
  install.sh               optional standalone PATH-mode installer
  VERSION                  canonical broker version axis (NOT vendored; see below)
  compat/tool-schemas.json vendored copy of the monorepo compat/ (see below)
  bin/SHA256SUMS           trust root for fetched prebuilt Go binaries (see below)
  js/                      Node.js runtime (src/ + test/)
  py/                      Python runtime (src/ + tests/)
  go/                      Go runtime (cmd/ internal/ go.mod … + *_test.go)
```

## Runtime selection & dependencies

`tokenmonitor-mcp` auto-detects "bundle mode" from the sibling `VERSION` + `compat/` +
`js|py|go/` and execs the first available runtime (Node → Python → Go; override
with `runtime=` in `~/.config/tokenmonitor/launcher.conf`). Dependencies
— including native ones (serialport, fs-ext, cryptography) — are resolved on
first run into `~/.cache/tokenmonitor/<version>/`, not committed here.

**Prebuilt-first Go path.** When the Go runtime is selected the launcher, by
default, **prefers** a prebuilt, statically-linked Go binary for the host
(`linux|darwin|windows` × `amd64|arm64`) from the broker GitHub release
(`broker-v<VERSION>`), verified against `bin/SHA256SUMS` (fail-closed) — this
keeps a from-source *compile* out of the MCP startup critical path (which is
what trips client startup timeouts). The download is bounded (fast connect cap +
total cap) so an unreachable endpoint fails quickly and falls back to a
from-source build when a `go` toolchain is present. Set `go_prefer=source` in
`~/.config/tokenmonitor/launcher.conf` to build from source first (fetch only as
fallback) — for provenance-conscious or air-gapped toolchain hosts, which then
never touch the network. `TMON_PREBUILT_BASE_URL` overrides the base URL. Only
`bin/SHA256SUMS` is committed; the binaries live in the release (see
`docs/releasing.md` Procedure C) and are listed in `go/THIRD_PARTY_NOTICES.md`.

**Prewarm.** `tokenmonitor-mcp --prewarm` resolves/fetches/builds the selected
runtime to a ready state and exits 0 without starting a server. The SessionStart
hook fires it detached so the cache is warm before the client's MCP handshake (a
next-launch optimization). `TMON_NO_PREWARM=1` opts out.

**Native Windows.** The plugin launches the server via `command: "sh"`, absent on
native Windows. Windows works only under **Git-Bash/MSYS** on `PATH` or a client
running **inside WSL**; native `cmd`/PowerShell-only hosts are unsupported.

## Vendored vs. canonical files (`compat/tool-schemas.json`, `VERSION`)

`compat/tool-schemas.json` is a **vendored** copy of the monorepo-root
`compat/` (authoritative in the `tokenmonitor` monorepo, shared with the
firmware and host tooling). Because the published plugin is cloned standalone
(without the monorepo around it), the server needs it present to start, so it
is vendored here and kept in sync by `tools/tmtools/plugin/vendor_contract.py`;
`tools/tests/plugin_vendor_sync_test.py` fails if it drifts. Do **not** edit it
here — change it in the monorepo and re-vendor.

`VERSION` is **not** vendored: it is the canonical broker version axis
(`docs/releasing.md` row #6) and is bumped in place. There is no monorepo-root
`VERSION` file — the broker version lives only here.

The runtime loaders (`py/src/tmon_mcp/mcp/server.py`, `js/src/mcp/server.js`)
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
