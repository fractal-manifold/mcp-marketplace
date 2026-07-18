#!/bin/sh
# build-prebuilt.sh — cross-compile the Go MCP-server/broker for every shipped
# platform into <server>/bin/, plus a SHA256SUMS over them.
#
# Distribution: the binaries are UPLOADED to the broker GitHub release
# (`gh release upload broker-v<version> bin/tokenmonitor-mcp-go-*`); the
# launcher fetches the one matching a toolchain-free host on first run. Only
# bin/SHA256SUMS is committed to the plugin — it is the trust root the launcher
# verifies each download against (integrity check, NOT a signature; the real
# trust root is the git checkout that ships SHA256SUMS). The binaries under
# bin/ are git-ignored (see server/.gitignore) — they are a build/upload
# staging area, never committed.
#
# Naming:  tokenmonitor-mcp-go-<os>-<arch>   (windows gets a .exe suffix)
#
# Flags MUST match the on-host fallback build (go/Makefile `build` target and
# the launcher's ensure_go): CGO_ENABLED=0 -trimpath -ldflags="-s -w -X
# main.Version=<v>". We additionally pin -buildvcs=false and neutralise
# GOFLAGS/GOEXPERIMENT so the output doesn't drift with the invoking shell.
#
# Atomic: everything is built into a temp dir and swapped into place only once
# the WHOLE matrix succeeds — a failed target never leaves a half-updated bin/.
#
# POSIX sh, no bashisms. Run from the go/ module dir (the Makefile does).
set -eu

VERSION="${1:?usage: build-prebuilt.sh <version> <outdir> <os/arch>...}"
OUTDIR="${2:?missing outdir}"
shift 2
[ "$#" -gt 0 ] || { echo "build-prebuilt.sh: no platforms given" >&2; exit 2; }

LDFLAGS="-s -w -X main.Version=$VERSION"
PKG="./cmd/tokenmonitor-mcp"

# Neutralise environment that would perturb the build; keep it reproducible-ish.
unset GOFLAGS GOEXPERIMENT 2>/dev/null || true
export CGO_ENABLED=0

# sha256 helper: prints "<hash>  <name>" for a file, portable across coreutils
# (sha256sum) and BSD/macOS (shasum -a 256).
sha256_line() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    else
        shasum -a 256 "$1"
    fi
}

tmp="$OUTDIR.tmp.$$"
rm -rf "$tmp"
mkdir -p "$tmp"
# Clean up the temp dir on any failure (success path renames it away first).
trap 'rm -rf "$tmp"' EXIT INT TERM

for plat in "$@"; do
    os=${plat%/*}
    arch=${plat#*/}
    [ "$os" != "$plat" ] && [ "$arch" != "$plat" ] || {
        echo "build-prebuilt.sh: bad platform '$plat' (want os/arch)" >&2
        exit 2
    }
    name="tokenmonitor-mcp-go-$os-$arch"
    [ "$os" = "windows" ] && name="$name.exe"
    echo "  building $name (v$VERSION)" >&2
    GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
        -ldflags="$LDFLAGS" -o "$tmp/$name" "$PKG"
done

# One SHA256SUMS covering exactly the freshly-built set, hashes over basenames
# so the launcher can look them up by name regardless of path.
( cd "$tmp" && rm -f SHA256SUMS
  for f in tokenmonitor-mcp-go-*; do sha256_line "$f"; done > SHA256SUMS )

# Swap the whole bin/ into place, with rollback: move the old bin/ aside, then
# move the new one in; if that second move fails, restore the old bin/ so a
# botched swap never leaves bin/ missing.
had_old=0
if [ -d "$OUTDIR" ]; then
    rm -rf "$OUTDIR.old.$$"
    mv "$OUTDIR" "$OUTDIR.old.$$" && had_old=1
fi
if ! mv "$tmp" "$OUTDIR"; then
    [ "$had_old" -eq 1 ] && mv "$OUTDIR.old.$$" "$OUTDIR"
    echo "build-prebuilt.sh: swap into $OUTDIR failed; restored previous bin/" >&2
    exit 1
fi
rm -rf "$OUTDIR.old.$$" 2>/dev/null || true
trap - EXIT INT TERM

echo "build-prebuilt.sh: wrote $(ls "$OUTDIR" | grep -c '^tokenmonitor-mcp-go-') binaries + SHA256SUMS to $OUTDIR" >&2
