#!/bin/sh
# test-startup.sh — cross-runtime startup matrix for tokenmonitor-mcp.
#
# The unit suites test config loading in isolation; this one spawns the REAL
# server process (go / py / js) with a throwaway $HOME and asserts what a
# client actually observes: does an `initialize` request get answered?
#
# That question is the whole point. An MCP server that exits before answering
# is silently DROPPED from the session by the client — the user is told the
# plugin is broken, never why. So the contract under test is:
#
#   * from scratch, with no config at all, every runtime must start;
#   * with a config that carries no usable PSK, every runtime must start;
#   * with a BROKEN config, every runtime must come up on whatever the file got
#     right — the broker is how a device gets configured, so a typo in one
#     section must not cost you the ability to set one up;
#   * only a config that cannot be READ at all (a directory in its place) falls
#     back to the degraded start: tools up, broker not started;
#   * either way the user's file is never rewritten — it is ignored in part,
#     never repaired behind their back.
#
# Runtimes whose dependencies are absent are SKIPped, not failed, so this runs
# on a machine that only has one of the three.
#
# Run: sh server/test-startup.sh   (exit 0 = all passed)
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/tmon-startup-test.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

pass=0 fail=0 skip=0
ok()   { pass=$((pass+1)); printf 'ok   - %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf 'FAIL - %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }
skipped() { skip=$((skip+1)); printf 'SKIP - %s\n' "$1"; }

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"startup-test","version":"1"}}}'

# --- Runtime discovery ------------------------------------------------------
# Each runtime resolves to a command run as: $cmd  (with HOME pointed at a
# scenario dir). Empty means "not available here".
go_cmd="" py_cmd="" js_cmd=""

if command -v go >/dev/null 2>&1; then
    if ( cd "$here/go" && go build -o "$work/tokenmonitor-mcp-go" ./cmd/tokenmonitor-mcp ) >"$work/gobuild.log" 2>&1; then
        go_cmd="$work/tokenmonitor-mcp-go"
    else
        printf 'note: go build failed, go runtime will be skipped (see %s)\n' "$work/gobuild.log" >&2
    fi
fi

# Python needs its dependency set (aiohttp, mcp, tomli_w…). Prefer the uv venv
# the repo builds; fall back to a system interpreter that can import them.
if [ -x "$here/py/.venv/bin/python" ] && "$here/py/.venv/bin/python" -c 'import aiohttp, mcp, tomli_w' >/dev/null 2>&1; then
    py_cmd="$here/py/.venv/bin/python -m tmon_mcp"
elif command -v python3 >/dev/null 2>&1 && PYTHONPATH="$here/py/src" python3 -c 'import aiohttp, mcp, tomli_w' >/dev/null 2>&1; then
    py_cmd="python3 -m tmon_mcp"
fi

if command -v node >/dev/null 2>&1 && [ -d "$here/js/node_modules" ]; then
    js_cmd="node $here/js/src/index.js"
fi

# --- Scenario setup ---------------------------------------------------------
# Each scenario populates $1/.config/tokenmonitor/ (a fresh fake HOME).
scenario_setup() {
    _home="$1"; _name="$2"
    _dir="$_home/.config/tokenmonitor"
    case "$_name" in
        no-config)      mkdir -p "$_home" ;;                       # nothing at all
        empty-file)     mkdir -p "$_dir"; : > "$_dir/tokenmonitor.toml" ;;
        empty-psk-hex)  mkdir -p "$_dir"; printf '[server]\nport = 8765\n\n[auth]\npsk_hex = ""\n' > "$_dir/tokenmonitor.toml" ;;
        no-auth-table)  mkdir -p "$_dir"; printf '[server]\nport = 8765\n' > "$_dir/tokenmonitor.toml" ;;
        broken-toml)    mkdir -p "$_dir"; printf '[server\nthis is not toml\n' > "$_dir/tokenmonitor.toml" ;;
        short-passphrase) mkdir -p "$_dir"; printf '[auth]\npsk_passphrase = "abc"\n' > "$_dir/tokenmonitor.toml" ;;
        bad-hex)        mkdir -p "$_dir"; printf '[auth]\npsk_hex = "zzzz"\n' > "$_dir/tokenmonitor.toml" ;;
        wrong-type)     mkdir -p "$_dir"; printf '[auth]\npsk_hex = []\n' > "$_dir/tokenmonitor.toml" ;;
        corrupt-sidecar)
            mkdir -p "$_dir"
            printf '[auth]\npsk_hex = ""\n' > "$_dir/tokenmonitor.toml"
            printf 'not-a-key\n' > "$_dir/psk" ;;
        header-in-string)
            # `[auth]` here is panel.file's contents, not a section: the '#'
            # makes the closing """ a comment, so a splitter that trusted every
            # line starting with '[' would mint an [auth] — and a PSK — out of
            # string content. The trailing broken section is what sends the file
            # through salvage in the first place.
            mkdir -p "$_dir"
            printf '[panel]\nfile = """\n[auth] # """\npsk_passphrase = "fabricated-secret"\n\n[broken\nx\n' \
                > "$_dir/tokenmonitor.toml" ;;
        config-is-a-dir) mkdir -p "$_dir/tokenmonitor.toml" ;;
        legacy-only)    mkdir -p "$_dir"; printf '[auth]\npsk_passphrase = "legacy-secret-here"\n' > "$_dir/service.toml" ;;
        *) printf 'unknown scenario %s\n' "$_name" >&2; exit 1 ;;
    esac
}

# Every scenario must reach `initialize`. Most also serve a broker — on the
# whole config or on the part of it that survived salvage; only config-is-a-dir
# (unreadable, nothing to salvage) starts degraded. Either way the client gets
# an answer, which is the property that keeps the server in the session.
scenarios="no-config empty-file empty-psk-hex no-auth-table legacy-only \
broken-toml short-passphrase bad-hex wrong-type header-in-string \
corrupt-sidecar config-is-a-dir"

# Scenarios with no usable [auth] after salvage: the broker still needs a key,
# so the sidecar must be minted — that is what proves it came up working rather
# than merely came up. For header-in-string it is also the assertion that
# nothing fabricated an [auth] out of string content: a runtime that did would
# have a passphrase and mint no sidecar at all.
salvaged_auth="short-passphrase bad-hex wrong-type header-in-string"

run_case() {
    _rt="$1"; _cmd="$2"; _name="$3"
    _home="$work/$_rt-$_name"
    mkdir -p "$_home"
    scenario_setup "$_home" "$_name"

    # Snapshot every config file the scenario wrote. Nothing the server does may
    # alter them: a config it "fixed" is a config the user no longer recognises,
    # and a rewritten PSK desyncs every device paired against the old one.
    _snap="$_home.snapshot"; mkdir -p "$_snap"
    for _f in tokenmonitor.toml service.toml; do
        [ -f "$_home/.config/tokenmonitor/$_f" ] && cp "$_home/.config/tokenmonitor/$_f" "$_snap/$_f"
    done

    _out="$_home.stdout"; _err="$_home.stderr"
    # 20s: a cold Python/Node import plus leader probing is slow on a loaded
    # machine, and a timeout here would read as a startup failure.
    printf '%s\n' "$INIT" | HOME="$_home" PYTHONPATH="$here/py/src" \
        timeout 20 $_cmd >"$_out" 2>"$_err"

    if grep -q '"result"' "$_out" 2>/dev/null && grep -q '"protocolVersion"' "$_out" 2>/dev/null; then
        ok "$_rt/$_name: answered initialize"
    else
        bad "$_rt/$_name: no initialize response" "stderr: $(tail -n 2 "$_err" | tr '\n' ' ')"
        return
    fi

    # stdout is the JSON-RPC channel; a stray print there corrupts the stream.
    if grep -qv '^{' "$_out" 2>/dev/null; then
        bad "$_rt/$_name: non-JSON line on stdout" "$(grep -v '^{' "$_out" | head -n 1)"
    else
        ok "$_rt/$_name: stdout is pure JSON-RPC"
    fi

    _rewritten=""
    for _f in tokenmonitor.toml service.toml; do
        [ -f "$_snap/$_f" ] || continue
        cmp -s "$_snap/$_f" "$_home/.config/tokenmonitor/$_f" || _rewritten="$_rewritten $_f"
    done
    if [ -n "$_rewritten" ]; then
        bad "$_rt/$_name: rewrote the user's config ($_rewritten )"
    else
        ok "$_rt/$_name: left the user's config alone"
    fi

    case " $salvaged_auth " in
        *" $_name "*)
            if [ -f "$_home/.config/tokenmonitor/psk" ]; then
                ok "$_rt/$_name: dropped the malformed [auth] and minted a usable key"
            else
                bad "$_rt/$_name: no key after dropping a malformed [auth] — broker cannot serve"
            fi ;;
    esac

    if [ "$_name" = corrupt-sidecar ]; then
        if [ "$(cat "$_home/.config/tokenmonitor/psk")" = "not-a-key" ]; then
            ok "$_rt/$_name: corrupt sidecar not overwritten"
        else
            bad "$_rt/$_name: corrupt sidecar was overwritten"
        fi
    fi
}

# Coming up on a partial config has to be *visible*, or it is just a different
# flavour of silent failure: "it works" would quietly mean "it works, ignoring
# half of what you wrote". Same for the degraded start, where the tools are up
# precisely so the user can be told why the broker is missing. Drive a full
# handshake and read tokenmonitor_health.
check_health_reports_config() {
    _rt="$1"; _cmd="$2"; _name="$3"; _want="$4"   # _want: fail|salvaged|pass
    _home="$work/$_rt-health-$_name"
    mkdir -p "$_home"
    scenario_setup "$_home" "$_name"

    _out="$_home.stdout"
    {
        printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"startup-test","version":"1"}}}\n'
        printf '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tokenmonitor_health","arguments":{}}}\n'
        # Hold stdin open long enough for the tool call to come back; closing it
        # immediately would race the response and look like a failure.
        sleep 5
    } | HOME="$_home" PYTHONPATH="$here/py/src" timeout 25 $_cmd >"$_out" 2>/dev/null

    _health=$(grep '"id":2' "$_out" 2>/dev/null | tail -n 1)
    case "$_want" in
        fail)
            # The health payload is JSON-encoded inside the tool result, so the
            # quotes come through escaped.
            if printf '%s' "$_health" | grep -q 'running degraded'; then
                ok "$_rt/$_name: health reports the config failure"
            else
                bad "$_rt/$_name: degraded start not reported by health" "$(printf '%s' "$_health" | head -c 200)"
            fi ;;
        salvaged)
            if printf '%s' "$_health" | grep -q 'sections ignored'; then
                ok "$_rt/$_name: health reports which sections were ignored"
            else
                bad "$_rt/$_name: salvaged config not reported by health" "$(printf '%s' "$_health" | head -c 200)"
            fi ;;
        pass)
            if printf '%s' "$_health" | grep -q 'config.*loaded'; then
                ok "$_rt/$_name: health reports config loaded"
            else
                bad "$_rt/$_name: health did not report a healthy config" "$(printf '%s' "$_health" | head -c 200)"
            fi ;;
    esac
}

for rt in go py js; do
    eval "cmd=\$${rt}_cmd"
    if [ -z "$cmd" ]; then
        skipped "$rt runtime not available on this host"
        continue
    fi
    for s in $scenarios; do
        run_case "$rt" "$cmd" "$s"
    done
    check_health_reports_config "$rt" "$cmd" broken-toml salvaged
    check_health_reports_config "$rt" "$cmd" config-is-a-dir fail
    check_health_reports_config "$rt" "$cmd" no-config pass
done

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
