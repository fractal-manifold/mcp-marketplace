#!/bin/sh
# End-to-end contract for the session-owned broker daemon.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/tmon-session-daemon.XXXXXX")
p1=""; p2=""; f1=""; f2=""; daemon_pid=""
cleanup() {
    [ -n "$f1" ] && kill "$f1" 2>/dev/null || true
    [ -n "$f2" ] && kill "$f2" 2>/dev/null || true
    [ -n "$p1" ] && kill "$p1" 2>/dev/null || true
    [ -n "$p2" ] && kill "$p2" 2>/dev/null || true
    [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

if ! command -v go >/dev/null 2>&1; then
    printf 'SKIP - go toolchain unavailable\n'
    exit 0
fi

bin="$work/tokenmonitor-mcp-go"
(cd "$here/go" && env GOCACHE="$work/go-cache" go build -o "$bin" ./cmd/tokenmonitor-mcp)

# Ask the kernel for an unused loopback port. The listener is immediately
# released; the daemon's singleton lock closes the only relevant startup race.
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
home="$work/home"
runtime="$work/runtime"
mkdir -p "$home/.config/tokenmonitor" "$runtime"
cat > "$home/.config/tokenmonitor/tokenmonitor.toml" <<EOF
[server]
bind = "127.0.0.1"
port = $port

[auth]
psk_passphrase = "session-daemon-test-secret"
EOF

init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"session-daemon-test","version":"1"}}}'
mkfifo "$work/in1" "$work/in2"
printf '%s\n' '[server' >"$work/broken.toml"

{ printf '%s\n' "$init"; exec tail -f /dev/null; } >"$work/in1" &
f1=$!
HOME="$home" TMON_RUNTIME_DIR="$runtime" "$bin" <"$work/in1" >"$work/out1" 2>"$work/err1" &
p1=$!

i=0
while [ "$i" -lt 100 ] && { [ ! -s "$runtime/broker.lock/pid" ] || [ ! -s "$work/out1" ]; }; do
    sleep 0.1; i=$((i + 1))
done
[ -s "$work/out1" ] || { printf 'FAIL - first MCP session did not initialize\n'; exit 1; }
[ -s "$runtime/broker.lock/pid" ] || { printf 'FAIL - daemon did not acquire singleton lock\n'; exit 1; }
[ -s "$runtime/broker-state.json" ] \
  && grep -q '"role":"leader"' "$runtime/broker-state.json" \
  || { printf 'FAIL - daemon did not publish shared state\n'; exit 1; }
daemon_pid=$(cat "$runtime/broker.lock/pid")
kill -0 "$daemon_pid" 2>/dev/null || { printf 'FAIL - daemon pid is not alive\n'; exit 1; }

{ printf '%s\n' "$init"; exec tail -f /dev/null; } >"$work/in2" &
f2=$!
# A degraded adapter cannot safely start a daemon using its invented fallback
# config, but it is still a real CLI/UI session and must hold a lifetime lease
# for the healthy daemon the first adapter started.
HOME="$home" TMON_RUNTIME_DIR="$runtime" "$bin" --config "$work/broken.toml" \
  <"$work/in2" >"$work/out2" 2>"$work/err2" &
p2=$!
i=0
while [ "$i" -lt 100 ] && [ ! -s "$work/out2" ]; do sleep 0.1; i=$((i + 1)); done
[ -s "$work/out2" ] || { printf 'FAIL - second MCP session did not initialize\n'; exit 1; }
[ "$(cat "$runtime/broker.lock/pid")" = "$daemon_pid" ] || {
    printf 'FAIL - second session replaced the daemon instead of sharing it\n'; exit 1; }
[ "$(find "$runtime/sessions" -type f -name 'session-*' | wc -l | tr -d ' ')" = 2 ] || {
    printf 'FAIL - expected two live session leases\n'; exit 1; }

# A session supervisor must restore the invariant after a daemon crash without
# waiting for a third client to open.
old_daemon_pid="$daemon_pid"
kill "$old_daemon_pid"
i=0
while [ "$i" -lt 120 ]; do
    daemon_pid=$(cat "$runtime/broker.lock/pid" 2>/dev/null || true)
    if [ -n "$daemon_pid" ] && [ "$daemon_pid" != "$old_daemon_pid" ] \
       && kill -0 "$daemon_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1; i=$((i + 1))
done
if [ -z "$daemon_pid" ] || [ "$daemon_pid" = "$old_daemon_pid" ] \
   || ! kill -0 "$daemon_pid" 2>/dev/null; then
    printf 'FAIL - live sessions did not restart a stopped daemon\n'
    exit 1
fi

# Closing one stdio peer removes exactly its lease but keeps the shared daemon.
kill "$f1"
wait "$f1" 2>/dev/null || true
f1=""
wait "$p1"
p1=""
sleep 1
kill -0 "$daemon_pid" 2>/dev/null || { printf 'FAIL - daemon died while a session remained\n'; exit 1; }
[ "$(find "$runtime/sessions" -type f -name 'session-*' | wc -l | tr -d ' ')" = 1 ] || {
    printf 'FAIL - first session lease was not removed\n'; exit 1; }

# Closing the final peer triggers the daemon's grace period and clean exit.
kill "$f2"
wait "$f2" 2>/dev/null || true
f2=""
wait "$p2"
p2=""
i=0
while [ "$i" -lt 180 ] && kill -0 "$daemon_pid" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$daemon_pid" 2>/dev/null; then
    printf 'FAIL - daemon remained alive after the last session ended\n'
    exit 1
fi
[ ! -e "$runtime/broker.lock" ] || { printf 'FAIL - daemon lock was not released\n'; exit 1; }

printf 'ok - one shared daemon, crash recovery, degraded-session lease, last-session shutdown\n'
