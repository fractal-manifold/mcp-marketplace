# Third-party notices — tokenmonitor-mcp (Go)

The prebuilt `tokenmonitor-mcp-go-*` binaries published on the broker GitHub
release (and any locally-built binary) statically link the Go modules below.
Each is redistributed under its own permissive license; the full license text
ships with each module (in the Go module cache and upstream). This file exists
because the prebuilt binaries are redistributed as compiled artefacts — the
attributions travel with them.

Regenerate the version/license facts with `go list -m all` and the upstream
`LICENSE` files after any dependency bump (see `docs/releasing.md` Procedure C).

## Linked dependencies

| Module | Version | License |
| --- | --- | --- |
| github.com/BurntSushi/toml | v1.4.0 | MIT |
| github.com/cenkalti/backoff | v2.2.1+incompatible | MIT |
| github.com/google/jsonschema-go | v0.4.2 | MIT |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause |
| github.com/grandcat/zeroconf | v1.0.0 | MIT |
| github.com/mark3labs/mcp-go | v0.54.0 | MIT |
| github.com/miekg/dns | v1.1.27 | BSD-3-Clause |
| github.com/santhosh-tekuri/jsonschema/v6 | v6.0.2 | Apache-2.0 |
| github.com/spf13/cast | v1.7.1 | MIT |
| github.com/yosida95/uritemplate/v3 | v3.0.2 | BSD-3-Clause |
| golang.org/x/crypto | v0.32.0 | BSD-3-Clause |
| golang.org/x/net | v0.34.0 | BSD-3-Clause |
| golang.org/x/sys | v0.29.0 | BSD-3-Clause |
| golang.org/x/text | v0.21.0 | BSD-3-Clause |

The Go standard library and runtime are covered by the Go project's
BSD-3-Clause license. `santhosh-tekuri/jsonschema` (Apache-2.0) ships a NOTICE
file upstream; no additional attributions are required by it for this use.
