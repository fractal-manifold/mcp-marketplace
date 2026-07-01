#!/bin/sh
# install.sh — copy the tokenmonitor-mcp launcher to ~/.local/bin so Claude Code
# (via the tokenmonitor plugin's .mcp.json that invokes "tokenmonitor-mcp")
# can find it. The launcher then picks the actual impl (Go / Python /
# JS) on each invocation.
#
# Usage:
#   sh install.sh                   # interactive: asks for preferred runtime
#   sh install.sh --runtime=auto    # non-interactive, write runtime=auto
#   sh install.sh --runtime=go      # non-interactive, write runtime=go
#   sh install.sh --no-config       # only install the script, skip launcher.conf
#
# Idempotent.

set -eu

bindir="${HOME}/.local/bin"
src_dir="$(cd "$(dirname "$0")" && pwd)"
src="$src_dir/tokenmonitor-mcp"
dst="$bindir/tokenmonitor-mcp"
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/tokenmonitor"
conf_file="$config_dir/launcher.conf"

runtime=""
write_config="ask"

for arg in "$@"; do
    case "$arg" in
        --runtime=*) runtime="${arg#--runtime=}"; write_config="set" ;;
        --no-config) write_config="skip" ;;
        -h|--help)
            sed -n '2,15p' "$0"
            exit 0
            ;;
        *)
            printf 'install.sh: unknown argument %s\n' "$arg" >&2
            exit 2
            ;;
    esac
done

if [ ! -r "$src" ]; then
    printf 'install.sh: missing launcher at %s\n' "$src" >&2
    exit 1
fi

mkdir -p "$bindir"
install -m 755 "$src" "$dst"
printf 'install.sh: installed launcher at %s\n' "$dst"

# Install the VERSION file next to the launcher so its PATH-mode stale-binary
# check (tokenmonitor-mcp reads $script_dir/VERSION into _want_ver) can warn when a
# standalone tokenmonitor-mcp-{go,py,js} on PATH drifts behind this release.
# Safe: bundle-mode detection additionally requires compat/ + a runtime dir,
# so a lone VERSION next to the launcher stays in PATH mode.
if [ -r "$src_dir/VERSION" ]; then
    install -m 644 "$src_dir/VERSION" "$bindir/VERSION"
    printf 'install.sh: installed VERSION at %s\n' "$bindir/VERSION"
fi

case ":$PATH:" in
    *":$bindir:"*) : ;;
    *)
        printf '\n[!] %s is not on $PATH. Add it to your shell rc:\n' "$bindir" >&2
        printf '    export PATH="%s:$PATH"\n\n' "$bindir" >&2
        ;;
esac

# Configure preferred runtime.
if [ "$write_config" = "ask" ] && [ -t 0 ]; then
    printf '\nPreferred runtime? [auto/go/python/js] (default: auto) '
    read -r runtime
    [ -z "$runtime" ] && runtime="auto"
    write_config="set"
fi

case "$write_config" in
    set)
        case "$runtime" in
            auto|go|python|js) : ;;
            *)
                printf 'install.sh: invalid runtime %s; expected auto|go|python|js\n' "$runtime" >&2
                exit 2
                ;;
        esac
        mkdir -p "$config_dir"
        # Write the file atomically; rewriting in place can race the
        # launcher reading it.
        tmp="$conf_file.tmp.$$"
        printf 'runtime=%s\n' "$runtime" > "$tmp"
        mv "$tmp" "$conf_file"
        printf 'install.sh: wrote %s with runtime=%s\n' "$conf_file" "$runtime"
        ;;
    skip)
        printf 'install.sh: skipped launcher.conf (existing config left as-is)\n'
        ;;
esac

printf '\nNow verify:\n'
printf '    tokenmonitor-mcp --probe   # should print "<runtime> <version>" on stderr\n'
