#!/bin/sh
# test-launcher.sh — hermetic tests for the tokenmonitor-mcp launcher's
# prebuilt-fetch path (detect_platform / verify_prebuilt / fetch_prebuilt_go /
# ensure_go no-toolchain branch).
#
# Hermetic: it copies the launcher into a throwaway "plugin" dir with a FAKE
# prebuilt binary (a tiny shell script) and its own SHA256SUMS, serves it over
# a file:// URL, and runs the launcher with a minimal PATH that excludes `go`
# (so the no-toolchain fetch branch is exercised) but keeps the coreutils the
# launcher needs. No real Go build, no network, no committed binaries needed.
#
# Run: sh server/test-launcher.sh   (exit 0 = all passed)
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
launcher="$here/tokenmonitor-mcp"
work=$(mktemp -d "${TMPDIR:-/tmp}/tmon-launcher-test.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

pass=0 fail=0
ok()   { pass=$((pass+1)); printf 'ok   - %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf 'FAIL - %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# Host platform name, mirroring the launcher's detect_platform.
os=""; arch=""
case "$(uname -s)" in Linux*) os=linux;; Darwin*) os=darwin;; MINGW*|MSYS*|CYGWIN*|Windows_NT) os=windows;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; esac
if [ -z "$os" ] || [ -z "$arch" ]; then
    printf 'SKIP - unsupported host platform (%s/%s)\n' "$(uname -s)" "$(uname -m)"
    exit 0
fi
binname="tokenmonitor-mcp-go-$os-$arch"
[ "$os" = windows ] && binname="$binname.exe"

# --- Build a throwaway "plugin" bundle around the real launcher ------------
plug="$work/plugin"
mkdir -p "$plug/bin" "$plug/go" "$plug/compat"
cp "$launcher" "$plug/tokenmonitor-mcp"
printf '0.10.2\n' > "$plug/VERSION"        # bundle detection needs VERSION+compat+go
: > "$plug/compat/.keep"

# Fake prebuilt: a script that satisfies the --probe contract ("<rt> <ver>" on
# stderr, exit 0). This stands in for the real Go binary the launcher fetches.
rel="$work/release"; mkdir -p "$rel"
cat > "$rel/$binname" <<'FAKE'
#!/bin/sh
# fake tokenmonitor-mcp-go — also reveals the launcher-exported root so the
# TMON_PLUGIN_ROOT export can be asserted.
echo "ROOT=$TMON_PLUGIN_ROOT" >&2
case "${1:-}" in --probe) echo "go 0.10.2" >&2; exit 0;; esac
echo "FAKE-PREBUILT-RAN" >&2; exit 0
FAKE
chmod +x "$rel/$binname"
# Only bin/SHA256SUMS ships in git — write the trust root the launcher checks.
printf '%s  %s\n' "$(sha256_of "$rel/$binname")" "$binname" > "$plug/bin/SHA256SUMS"

# Minimal PATH WITHOUT `go`, WITH the tools the launcher uses.
nogo="$work/nogo"; mkdir -p "$nogo"
for t in sh dash bash uname awk sha256sum shasum curl wget mkdir rm mv cp chmod cat find sleep dirname sed grep tr paste ls id kill; do
    p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$nogo/$t"
done
[ -z "$(PATH=$nogo command -v curl)$(PATH=$nogo command -v wget)" ] && {
    printf 'SKIP - no curl/wget available for file:// fetch\n'; exit 0; }
[ -n "$(PATH=$nogo command -v go)" ] && { printf 'SKIP - could not build a go-free PATH\n'; exit 0; }

cfg="$work/cfg"; mkdir -p "$cfg/tokenmonitor"
printf 'runtime=go\n' > "$cfg/tokenmonitor/launcher.conf"   # force the go path first

# run <cache> <baseurl> [uname_override_dir]
run() {
    _cache="$1"; _url="$2"; _path="${3:-$nogo}"
    env -i HOME="$work/home" PATH="$_path" \
        XDG_CONFIG_HOME="$cfg" XDG_CACHE_HOME="$_cache" \
        TMON_PREBUILT_BASE_URL="$_url" \
        sh "$plug/tokenmonitor-mcp" --probe 2>&1
}

# --- Test 1: fetch hit ------------------------------------------------------
c1="$work/c1"
out=$(run "$c1" "file://$rel"); rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "using prebuilt go" && printf '%s' "$out" | grep -q "go 0.10.2"; then
    ok "fetch hit: downloads, verifies and execs the prebuilt"
else bad "fetch hit" "$out"; fi

# --- Test 2: cache hit (no re-fetch on 2nd run) -----------------------------
out=$(run "$c1" "file://$rel"); rc=$?
if [ "$rc" -eq 0 ] && ! printf '%s' "$out" | grep -q "fetching prebuilt"; then
    ok "cache hit: second run reuses the cached binary, no re-download"
else bad "cache hit (unexpected re-fetch)" "$out"; fi

# --- Test 3: checksum mismatch -> fail-closed -------------------------------
bad_rel="$work/badrel"; mkdir -p "$bad_rel"
printf 'CORRUPT' > "$bad_rel/$binname"; chmod +x "$bad_rel/$binname"
out=$(run "$work/c3" "file://$bad_rel"); rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "checksum mismatch"; then
    ok "tamper: checksum mismatch is rejected (fail-closed)"
else bad "tamper not rejected" "$out"; fi

# --- Test 4: unknown platform -> no fetch -----------------------------------
fu="$work/fakeuname"; mkdir -p "$fu"
for t in sh dash bash awk sha256sum shasum curl wget mkdir rm mv cp chmod cat find sleep dirname sed grep tr paste ls id kill; do
    p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$fu/$t"
done
printf '#!/bin/sh\necho Plan9\n' > "$fu/uname"; chmod +x "$fu/uname"
out=$(run "$work/c4" "file://$rel" "$fu"); rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "unrecognised platform"; then
    ok "unknown platform: no fetch attempted"
else bad "unknown platform handling" "$out"; fi

# --- Test 5: Windows host fetches the .exe-suffixed asset -------------------
# Stub uname to report a Git-Bash-style Windows host and serve a matching
# .exe asset; the launcher must request tokenmonitor-mcp-go-windows-amd64.exe
# (regression guard for the missing-.exe bug).
wrel="$work/winrel"; mkdir -p "$wrel"
cat > "$wrel/tokenmonitor-mcp-go-windows-amd64.exe" <<'FAKE'
#!/bin/sh
case "${1:-}" in --probe) echo "go 0.10.2" >&2; exit 0;; esac
FAKE
chmod +x "$wrel/tokenmonitor-mcp-go-windows-amd64.exe"
printf '%s  %s\n' "$(sha256_of "$wrel/tokenmonitor-mcp-go-windows-amd64.exe")" \
    "tokenmonitor-mcp-go-windows-amd64.exe" > "$plug/bin/SHA256SUMS"
wu="$work/winuname"; mkdir -p "$wu"
for t in sh dash bash awk sha256sum shasum curl wget mkdir rm mv cp chmod cat find sleep dirname sed grep tr paste ls id kill; do
    p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$wu/$t"
done
printf '#!/bin/sh\ncase "$1" in -m) echo x86_64;; *) echo MINGW64_NT-10.0;; esac\n' > "$wu/uname"
chmod +x "$wu/uname"
out=$(run "$work/c5" "file://$wrel" "$wu"); rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "windows-amd64.exe" && printf '%s' "$out" | grep -q "go 0.10.2"; then
    ok "windows: fetches the .exe-suffixed asset and runs it"
else bad "windows .exe handling" "$out"; fi
# Restore SHA256SUMS for any re-run isolation (harmless; $work is throwaway).
printf '%s  %s\n' "$(sha256_of "$rel/$binname")" "$binname" > "$plug/bin/SHA256SUMS"

# --- Test 6: launcher exports TMON_PLUGIN_ROOT (dirname of the bundle) -------
# Every runtime (incl. the cached Go binary and Antigravity, which never sets
# CLAUDE_PLUGIN_ROOT) must be able to find plugin.json via this exported var.
c6="$work/c6"
out=$(run "$c6" "file://$rel"); rc=$?
want_root=$(CDPATH= cd -- "$plug/.." && pwd -P)
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "ROOT=$want_root"; then
    ok "exports TMON_PLUGIN_ROOT to the runtime (= dirname of the bundle)"
else bad "TMON_PLUGIN_ROOT export" "want ROOT=$want_root; got: $out"; fi

# --- Test 7: prebuilt fetch records source-provenance = prebuilt ------------
prov="$c6/tokenmonitor/0.10.2/go/.tmon-prov"
if [ "$(cat "$prov" 2>/dev/null)" = "prebuilt" ]; then
    ok "provenance marker records a fetched binary as 'prebuilt'"
else bad "provenance marker" "expected 'prebuilt' at $prov, got '$(cat "$prov" 2>/dev/null)'"; fi

# --- Test 8: --prewarm readies the cache without running a server -----------
# It must exit 0, log "prewarmed", cache the binary, and NOT exec it (no
# FAKE-PREBUILT-RAN / probe output).
c8="$work/c8"
out=$(env -i HOME="$work/home" PATH="$nogo" \
        XDG_CONFIG_HOME="$cfg" XDG_CACHE_HOME="$c8" \
        TMON_PREBUILT_BASE_URL="file://$rel" \
        sh "$plug/tokenmonitor-mcp" --prewarm 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "prewarmed" \
   && ! printf '%s' "$out" | grep -q "FAKE-PREBUILT-RAN" \
   && [ -x "$c8/tokenmonitor/0.10.2/go/$binname" ] 2>/dev/null; then
    ok "--prewarm caches the runtime and exits 0 without starting a server"
elif [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "prewarmed" \
     && ! printf '%s' "$out" | grep -q "FAKE-PREBUILT-RAN"; then
    # binary name is tokenmonitor-mcp-go (no platform suffix) in the cache slot
    ok "--prewarm caches the runtime and exits 0 without starting a server"
else bad "--prewarm behavior" "$out"; fi

# --- Test 9: go_prefer=source with NO toolchain falls back to prebuilt ------
# Source-first is a preference, not a hard requirement: a toolchain-free host
# must still get a runtime via the verified prebuilt.
cfg2="$work/cfg2"; mkdir -p "$cfg2/tokenmonitor"
printf 'runtime=go\ngo_prefer=source\n' > "$cfg2/tokenmonitor/launcher.conf"
out=$(env -i HOME="$work/home" PATH="$nogo" \
        XDG_CONFIG_HOME="$cfg2" XDG_CACHE_HOME="$work/c9" \
        TMON_PREBUILT_BASE_URL="file://$rel" \
        sh "$plug/tokenmonitor-mcp" --probe 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "using prebuilt go"; then
    ok "go_prefer=source falls back to the prebuilt when no toolchain is present"
else bad "go_prefer=source fallback" "$out"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
