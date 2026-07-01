// Package broker exposes the HTTP /credentials endpoint that the ESP32
// polls. The handler validates the request's HMAC headers, then reads the
// Claude CLI credentials file and returns the bearer token.
//
// Serve(ctx, ln, cfg, st, logger) accepts an already-bound listener so
// the leader-election layer can hand it the socket without races, and a
// *state.State that the handler updates after each request so the MCP
// tools can introspect activity.
package broker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/creds"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/devlog"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/logbuf"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/ota"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/spend"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/state"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/usage"
)

// FirmwareLogSource is the read-side interface the broker needs to serve
// /firmware-logs. The serial tailer owns the *logbuf.Buffer (which already
// satisfies this); tests can plug in a stub. Connected() lets the handler
// flag "device unplugged" vs "no logs yet".
type FirmwareLogSource interface {
	Tail(n int) []string
	Len() int
	Connected() bool
}

// nullFirmwareLogs is the placeholder used when serial tailing is
// disabled in the config. /firmware-logs still answers 200 (with an empty
// list) so callers can distinguish "auth ok, nothing to show" from "broker
// unreachable / signature wrong".
type nullFirmwareLogs struct{}

func (nullFirmwareLogs) Tail(int) []string { return nil }
func (nullFirmwareLogs) Len() int          { return 0 }
func (nullFirmwareLogs) Connected() bool   { return false }

// NewFirmwareLogs builds the FirmwareLogSource the broker handler expects
// from a logbuf and a connectedness probe. Lives here so cmd/main.go can
// pass the result straight into NewMux without leaking adapter types.
func NewFirmwareLogs(buf *logbuf.Buffer, connected func() bool) FirmwareLogSource {
	if buf == nil {
		return nullFirmwareLogs{}
	}
	if connected == nil {
		connected = func() bool { return false }
	}
	return firmwareLogsView{buf: buf, connected: connected}
}

type firmwareLogsView struct {
	buf       *logbuf.Buffer
	connected func() bool
}

func (v firmwareLogsView) Tail(n int) []string { return v.buf.Tail(n) }
func (v firmwareLogsView) Len() int            { return v.buf.Len() }
func (v firmwareLogsView) Connected() bool     { return v.connected() }

// statusRecorder lets us learn the response code chosen by the handler
// so we can record it on the shared *state.State. Every code path in
// this package calls WriteHeader explicitly, so the default of 200 is
// only used in the unlikely "wrote a body without WriteHeader" case.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(s int) {
	r.status = s
	r.ResponseWriter.WriteHeader(s)
}

// Unwrap exposes the wrapped ResponseWriter so http.ResponseController can
// walk through to the underlying connection — without it, per-request
// SetWriteDeadline/Flush calls (e.g. the firmware download's extended write
// deadline) return ErrNotSupported and silently fall back to the tight
// server-wide WriteTimeout.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// NewMux returns the HTTP handler used by both Serve and tests. The
// returned mux records every /credentials hit on `st` (remote addr +
// response code). `fwLogs` may be nil — the handler substitutes a
// null source that answers 200 with an empty list. `reg` may be nil
// — when missing, /credentials falls back to the global PSK in cfg
// (legacy mode) and /device/* answers 404.
func NewMux(cfg *config.Config, cache *auth.NonceCache, st *state.State, logger *log.Logger, fwLogs FirmwareLogSource, reg *registry.Registry, usageCache *usage.Cache, spendCache *spend.Cache) *http.ServeMux {
	if fwLogs == nil {
		fwLogs = nullFirmwareLogs{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleCredentials(cfg, cache, logger, reg, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/credentials/codex", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleCodexCredentials(cfg, cache, logger, reg, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/firmware-logs", func(w http.ResponseWriter, r *http.Request) {
		handleFirmwareLogs(cfg, cache, logger, fwLogs, w, r)
	})
	mux.HandleFunc("/device/", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		// /device/{id}/sync (GET, control plane) vs /device/{id}/logs
		// (POST, diagnostic upload) vs /device/{id}/settings (POST,
		// device-reported display settings). All authenticate the same way.
		if strings.HasSuffix(r.URL.Path, "/logs") {
			handleDeviceLogs(cfg, cache, logger, reg, rec, r)
		} else if strings.HasSuffix(r.URL.Path, "/settings") {
			handleDeviceSettings(cfg, cache, logger, reg, rec, r)
		} else {
			handleDeviceSync(cfg, cache, logger, reg, st, rec, r)
		}
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/usage/", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleUsage(cfg, cache, logger, reg, usageCache, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/spend/", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleSpend(cfg, cache, logger, reg, spendCache, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/firmware/", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		handleFirmware(cfg, cache, logger, reg, rec, r)
		if st != nil {
			st.RecordRequest(r.RemoteAddr, rec.status, time.Now())
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return mux
}

// firmwareSHACache memoises SHA-256 hashes of artifacts in FirmwareDir
// keyed by abs path + mtime + size. Computing SHA on every range request
// would be wasteful (and noticeable for big .bin files), and the device
// expects a stable ETag across resume attempts.
type firmwareSHACacheEntry struct {
	mtime time.Time
	size  int64
	hex   string
}

var (
	firmwareSHACache   = map[string]firmwareSHACacheEntry{}
	firmwareSHACacheMu sync.Mutex
)

func firmwareSHA(path string, fi os.FileInfo) (string, error) {
	firmwareSHACacheMu.Lock()
	if e, ok := firmwareSHACache[path]; ok && e.mtime.Equal(fi.ModTime()) && e.size == fi.Size() {
		firmwareSHACacheMu.Unlock()
		return e.hex, nil
	}
	firmwareSHACacheMu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	firmwareSHACacheMu.Lock()
	firmwareSHACache[path] = firmwareSHACacheEntry{mtime: fi.ModTime(), size: fi.Size(), hex: sum}
	firmwareSHACacheMu.Unlock()
	return sum, nil
}

// handleFirmware serves binaries from config.FirmwarePath() to devices
// that have been armed with an OTA update. Authenticates with the same
// HMAC-v2 scheme as /credentials, accepting either the device's active
// or pending PSK (so a freshly-rotated device can still pull). Supports
// Range: requests via http.ServeContent so resume-on-reconnect works.
//
// Path traversal is the obvious risk; filepath.Clean and the dir-prefix
// check below close it. Unknown device IDs cannot be derived from the
// request (the URL only carries the file name), so we fall back to the
// global PSK in cfg — same fallback /credentials uses for legacy mode.
func handleFirmware(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/firmware/")
	if name == "" || strings.ContainsAny(name, "/\\") {
		writeError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	baseDir := config.FirmwarePath()
	full := filepath.Join(baseDir, name)
	cleanBase, _ := filepath.Abs(baseDir)
	cleanFull, _ := filepath.Abs(full)
	if !strings.HasPrefix(cleanFull, cleanBase+string(os.PathSeparator)) && cleanFull != cleanBase {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	// Auth: same canonical v2 as everything else. We accept either the
	// global PSK or any registered device's active/pending PSK so the
	// HMAC layer doesn't have to know which device asked.
	signedPath := r.URL.Path
	psks := [][]byte{cfg.PSK()}
	if reg != nil {
		// Look up by X-Tmon-Device when present — cheaper than scanning
		// the whole registry on every request, which a chunked Range
		// download can hit many times in a row.
		if devID := r.Header.Get("X-Tmon-Device"); registry.ValidDeviceID(devID) {
			if a, p, err := reg.PSKsFor(devID); err == nil {
				if len(a) == 32 {
					psks = append(psks, a)
				}
				if len(p) == 32 {
					psks = append(psks, p)
				}
			}
		}
	}
	if _, verr := auth.VerifyMulti(
		psks,
		"GET", signedPath,
		r.Header.Get("X-Tmon-Timestamp"),
		r.Header.Get("X-Tmon-Nonce"),
		r.Header.Get("X-Tmon-Signature"),
		r.Header.Get("X-Tmon-Device"),
		r.Header.Get("X-Tmon-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	); verr != nil {
		logger.Printf("auth rejected /firmware/%s from %s: %v", name, r.RemoteAddr, verr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	f, err := os.Open(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "firmware not found")
			return
		}
		logger.Printf("open %s: %v", full, err)
		writeError(w, http.StatusInternalServerError, "io error")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stat failed")
		return
	}
	if sum, err := firmwareSHA(full, fi); err == nil {
		w.Header().Set("ETag", `"`+sum+`"`)
		w.Header().Set("X-Tmon-Firmware-SHA256", sum)
	}
	// A full firmware image takes far longer than the server-wide 10s
	// WriteTimeout to stream — especially when the device reads slowly
	// while rendering the UI over a congested 2.4 GHz link. That 10s cap
	// severed the .bin at ~60% (the device saw ENOTCONN and the OTA
	// attempt failed). Extend the write deadline for this download only;
	// the tight server-wide timeout still guards the small JSON endpoints.
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute)); err != nil {
		logger.Printf("firmware: extend write deadline unsupported: %v", err)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

func handleFirmwareLogs(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, fwLogs FirmwareLogSource, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Sign over the bare path (no query) so the limit param can change
	// without forcing the client to recompute the signature for the same
	// fetch — it's a read-only diagnostic anyway.
	if err := auth.Verify(
		cfg.PSK(),
		"GET", "/firmware-logs",
		r.Header.Get("X-Tmon-Timestamp"),
		r.Header.Get("X-Tmon-Nonce"),
		r.Header.Get("X-Tmon-Signature"),
		r.Header.Get("X-Tmon-Device"),
		r.Header.Get("X-Tmon-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	); err != nil {
		logger.Printf("auth rejected /firmware-logs from %s: %v", r.RemoteAddr, err)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			switch {
			case n < 1:
				limit = 1
			case n > 2000:
				limit = 2000
			default:
				limit = n
			}
		}
	}
	lines := fwLogs.Tail(limit)
	if lines == nil {
		lines = []string{}
	}
	body, _ := json.Marshal(struct {
		Connected bool     `json:"connected"`
		Total     int      `json:"total_available"`
		Lines     []string `json:"lines"`
	}{
		Connected: fwLogs.Connected(),
		Total:     fwLogs.Len(),
		Lines:     lines,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func handleCredentials(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !verifyCredentialRequest(cfg, cache, logger, reg, w, r, "/credentials") {
		return
	}

	c, err := creds.Load(cfg.OAuthPath())
	switch {
	case errors.Is(err, creds.ErrFileMissing):
		writeError(w, http.StatusNotFound, "credentials file missing")
		return
	case err != nil:
		logger.Printf("cannot parse credentials: %v", err)
		writeError(w, http.StatusInternalServerError, "cannot read credentials")
		return
	}
	if c.IsExpired(time.Now()) {
		writeError(w, http.StatusServiceUnavailable, "token expired, refresh on laptop")
		return
	}

	body, _ := json.Marshal(struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
	}{
		AccessToken: c.AccessToken,
		ExpiresAt:   c.ExpiresAtISO(),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func handleCodexCredentials(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !verifyCredentialRequest(cfg, cache, logger, reg, w, r, "/credentials/codex") {
		return
	}
	if !cfg.Codex.Enabled {
		writeError(w, http.StatusNotFound, "codex provider disabled")
		return
	}

	c, err := creds.LoadCodex(cfg.CodexAuthPath())
	switch {
	case errors.Is(err, creds.ErrFileMissing):
		// Missing auth is recoverable: keep the firmware retrying instead
		// of treating Codex as absent for the rest of the boot.
		writeError(w, http.StatusServiceUnavailable, "codex credentials file missing")
		return
	case err != nil:
		logger.Printf("cannot parse codex credentials: %v", err)
		writeError(w, http.StatusInternalServerError, "cannot read codex credentials")
		return
	}
	if c.IsExpired(time.Now()) {
		writeError(w, http.StatusServiceUnavailable, "codex token expired, refresh on laptop")
		return
	}

	body, _ := json.Marshal(struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
		AccountID   string `json:"account_id"`
	}{
		AccessToken: c.AccessToken,
		ExpiresAt:   c.ExpiresAtISO(),
		AccountID:   c.AccountID,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func verifyCredentialRequest(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request, path string) bool {
	// Per-device path: when X-Tmon-Device is present AND we have a
	// registry, look up the device's PSKs and verify with VerifyMulti.
	// A successful pending-PSK signature plus the version it implies
	// triggers MaybePromote so the broker tracks the rotation. When the
	// header is missing or no registry exists, fall back to the legacy
	// global-PSK path so field devices keep working.
	deviceID := r.Header.Get("X-Tmon-Device")
	if reg != nil && deviceID != "" {
		if !registry.ValidDeviceID(deviceID) {
			writeError(w, http.StatusBadRequest, "invalid device_id")
			return false
		}
		active, pending, perr := reg.PSKsFor(deviceID)
		if errors.Is(perr, registry.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown device")
			return false
		} else if perr != nil {
			logger.Printf("registry lookup %s: %v", deviceID, perr)
			writeError(w, http.StatusInternalServerError, "registry error")
			return false
		}
		res, verr := auth.VerifyMulti(
			[][]byte{active, pending},
			"GET", path,
			r.Header.Get("X-Tmon-Timestamp"),
			r.Header.Get("X-Tmon-Nonce"),
			r.Header.Get("X-Tmon-Signature"),
			r.Header.Get("X-Tmon-Device"),
			r.Header.Get("X-Tmon-Config-Version"),
			cache,
			time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
			time.Now(),
		)
		if verr != nil {
			logger.Printf("auth rejected %s device=%s from %s: %v", path, deviceID, r.RemoteAddr, verr)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return false
		}
		obs, _ := parseUint32Header(r.Header.Get("X-Tmon-Config-Version"))
		if _, perr := reg.MaybePromote(deviceID, obs, res.PSKIndex == 1); perr != nil {
			logger.Printf("registry promote %s: %v", deviceID, perr)
		}
		if terr := reg.Touch(deviceID); terr != nil {
			logger.Printf("registry touch %s: %v", deviceID, terr)
		}
		return true
	}

	if err := auth.Verify(
		cfg.PSK(),
		"GET", path,
		r.Header.Get("X-Tmon-Timestamp"),
		r.Header.Get("X-Tmon-Nonce"),
		r.Header.Get("X-Tmon-Signature"),
		r.Header.Get("X-Tmon-Device"),
		r.Header.Get("X-Tmon-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	); err != nil {
		logger.Printf("auth rejected %s from %s: %v", path, r.RemoteAddr, err)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

// handleUsage serves GET /usage/{provider}. Authenticates with the same
// HMAC envelope as /credentials (per-device or legacy global PSK). On
// upstream success returns the cached Snapshot as JSON; on upstream
// failure with a previously-cached value, returns the stale snapshot
// with 200 + an X-Tmon-Stale-Reason header so the firmware can keep
// rendering while logging the drift.
func handleUsage(cfg *config.Config, nonceCache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, usageCache *usage.Cache, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Path is /usage/<provider>; reject anything deeper to avoid
	// silently serving /usage/claude/extra as claude.
	provider := strings.TrimPrefix(r.URL.Path, "/usage/")
	if provider == "" || strings.ContainsRune(provider, '/') {
		writeError(w, http.StatusNotFound, "unknown usage provider")
		return
	}
	if !verifyCredentialRequest(cfg, nonceCache, logger, reg, w, r, "/usage/"+provider) {
		return
	}
	// HMAC was verified against the literal path above; only now fold the
	// deprecated "gemini" wire alias onto the canonical "antigravity" key
	// for cache/fetcher lookup. Old firmware that signs /usage/gemini keeps
	// working; new firmware uses /usage/antigravity directly.
	provider = usage.CanonicalProvider(provider)
	if usageCache == nil {
		writeError(w, http.StatusServiceUnavailable, "usage disabled (no providers configured)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// NOTE: the per-device Antigravity model override was removed (bug 27).
	// FetchWithModels ignored its models arg since the quota went grouped, so
	// the override block was a pure cache bypass — two upstream Google calls
	// per device poll for an identical result. The gemini_models registry→
	// device wire plumbing is unrelated (device-side config) and is kept.
	snap, err := usageCache.Get(ctx, provider)
	if err != nil {
		// Stale-with-error: cache returned the last good snapshot
		// alongside a transient error. Surface the snapshot and a
		// header so the firmware can log the staleness without
		// blanking the UI.
		if snap.FetchedAtUnix > 0 {
			w.Header().Set("X-Tmon-Stale-Reason", err.Error())
			writeJSON(w, http.StatusOK, snap)
			return
		}
		writeUsageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// handleSpend serves GET /spend/{provider}: locally-computed token cost.
// Same HMAC envelope as /usage. See compat/SPEND_WIRE.md.
func handleSpend(cfg *config.Config, nonceCache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, spendCache *spend.Cache, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	provider := strings.TrimPrefix(r.URL.Path, "/spend/")
	if provider == "" || strings.ContainsRune(provider, '/') {
		writeError(w, http.StatusNotFound, "unknown spend provider")
		return
	}
	if !verifyCredentialRequest(cfg, nonceCache, logger, reg, w, r, "/spend/"+provider) {
		return
	}
	// Canonicalize the deprecated "gemini" alias AFTER HMAC verification.
	provider = spend.CanonicalProvider(provider)
	if provider != spend.ProviderClaude && provider != spend.ProviderCodex && provider != spend.ProviderAntigravity {
		writeError(w, http.StatusNotFound, "unknown spend provider")
		return
	}
	if spendCache == nil {
		writeError(w, http.StatusNotImplemented, "spend disabled")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	snap, err := spendCache.Get(ctx, provider)
	if err != nil {
		if snap.FetchedAtUnix > 0 {
			w.Header().Set("X-Tmon-Stale-Reason", err.Error())
			writeJSON(w, http.StatusOK, snap)
			return
		}
		switch {
		case errors.Is(err, spend.ErrNotImpl):
			writeError(w, http.StatusNotImplemented, "provider not enabled")
		case errors.Is(err, spend.ErrUnavailable):
			writeError(w, http.StatusServiceUnavailable, "spend unavailable")
		default:
			logger.Printf("spend handler error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
		}
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeUsageError maps a usage-layer error to an HTTP response. For a 429
// it also mirrors the upstream Retry-After hint (carried on
// *usage.RateLimitedError) into the response header, matching the py/js
// brokers which forward RateLimited.retry_after. The header is only set
// when the hint is a positive whole number of seconds.
func writeUsageError(w http.ResponseWriter, err error) {
	var rl *usage.RateLimitedError
	if errors.As(err, &rl) && rl.RetryAfter > 0 {
		secs := int(rl.RetryAfter.Round(time.Second) / time.Second)
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	status, msg := usageErrorToHTTP(err)
	writeError(w, status, msg)
}

func usageErrorToHTTP(err error) (int, string) {
	switch {
	case errors.Is(err, usage.ErrCredsMissing):
		return http.StatusNotFound, "creds file missing"
	case errors.Is(err, usage.ErrTokenExpired):
		return http.StatusServiceUnavailable, "token expired, refresh on laptop"
	case errors.Is(err, usage.ErrUnauthorized):
		return http.StatusUnauthorized, "upstream rejected token"
	case errors.Is(err, usage.ErrRateLimited):
		return http.StatusTooManyRequests, "rate limited"
	case errors.Is(err, usage.ErrNotImpl), errors.Is(err, usage.ErrDisabled):
		return http.StatusNotImplemented, "provider not enabled"
	case errors.Is(err, usage.ErrTransport):
		return http.StatusBadGateway, "transport error"
	case errors.Is(err, usage.ErrUpstream), errors.Is(err, usage.ErrParseUpstream):
		return http.StatusBadGateway, "upstream error"
	default:
		return http.StatusInternalServerError, "internal error"
	}
}

// pendingBlob is the wire format of an encrypted pending payload.
// payload_b64 is the ciphertext (base64-std); nonce_b64 is the nonce
// (also base64-std). Decryption requires the device's currently-active
// PSK; the new PSK lives *inside* the payload, so a passive attacker
// watching one rotation can't learn the next key unless they already
// broke the active one.
//
// Enc selects the cipher: "gcm" => AES-256-GCM with a 12-byte nonce and
// payload_b64 = ciphertext||16-byte-tag, AAD = ASCII decimal of Version.
// Empty (omitted) => legacy AES-CTR with a 16-byte IV nonce (no auth
// tag; integrity rides the surrounding HTTP-response HMAC). The broker
// emits "gcm" only when the live X-Tmon-Fw-Version header reports a
// version >= PendingGCMMinFwVersion; older / absent / unparseable
// versions still get the CTR blob. Gating on the LIVE header (never on
// registry state) makes canary reverts self-healing: a device that rolls
// back to pre-GCM firmware immediately gets CTR again on its next poll.
type pendingBlob struct {
	Version    uint32 `json:"version"`
	Enc        string `json:"enc,omitempty"`
	NonceB64   string `json:"nonce_b64"`
	PayloadB64 string `json:"payload_b64"`
}

// fwSupportsGCM reports whether a device reporting firmware version `fw`
// (the live X-Tmon-Fw-Version header) understands the AES-256-GCM pending
// envelope. The comparison is on the numeric MAJOR.MINOR.PATCH prefix
// ONLY — any suffix (e.g. a "-dev.<ts>" prerelease) is ignored, because
// a dev build like "0.9.0-dev.202606091938" carries the very same
// decrypt code as the matured 0.9.0 release (same source tree). So
// "0.8.0" -> false, "0.9.0" -> true, "0.10.0" -> true, "0.9.0-dev.x"
// -> true. An absent / unparseable header -> false (legacy CTR).
func fwSupportsGCM(fw string) bool {
	if fw == "" {
		return false
	}
	got, ok := ota.PackSemver(fw) // strips any "-…" suffix, packs maj.min.patch
	if !ok {
		return false
	}
	min, ok := ota.PackSemver(registry.PendingGCMMinFwVersion)
	if !ok {
		return false
	}
	return got >= min
}

type syncResponse struct {
	ActiveVersion uint32       `json:"active_version"`
	Pending       *pendingBlob `json:"pending,omitempty"`
	// BrokerUpdateAvailable is true when the broker's self-version check found
	// a newer plugin/broker release published than the one running. Emitted
	// only once a check has succeeded; absent while the verdict is unknown, so
	// the device never shows a false "update available" banner. BrokerVersion
	// is the running release version (for the device's Settings line);
	// BrokerLatest is the newest published version when known.
	BrokerUpdateAvailable *bool  `json:"broker_update_available,omitempty"`
	BrokerVersion         string `json:"broker_version,omitempty"`
	BrokerLatest          string `json:"broker_latest,omitempty"`
}

// pendingPayloadJSON serialises a registry.ConfigPayload to the canonical
// JSON the firmware decrypts. Kept separate so changes to TOML
// representation in registry don't leak into the wire format.
func pendingPayloadJSON(p registry.ConfigPayload) ([]byte, error) {
	wire := map[string]any{
		"version": p.Version,
	}
	if p.BrokerURL != "" {
		wire["broker_url"] = p.BrokerURL
	}
	if p.PSKHex != "" {
		wire["psk_hex"] = p.PSKHex
	}
	if p.City != "" {
		wire["city"] = p.City
	}
	if p.BrDay != nil && *p.BrDay != 0 {
		wire["br_day"] = *p.BrDay
	}
	if p.BrNight != nil && *p.BrNight != 0 {
		wire["br_night"] = *p.BrNight
	}
	if p.Vol != nil {
		// vol == 0 is "muted", which is a legitimate state the device
		// must be able to receive; only nil means "no change".
		wire["vol"] = *p.Vol
	}
	// Providers: emit the rich provider_modes enum AND a derived legacy
	// providers bool map. New firmware consumes provider_modes; firmware
	// from before the mode split only understands the bool map. Both are
	// derived from the same ProviderModes source so they never disagree.
	if pm := p.ProviderModes; pm != nil {
		// Dual-emit the Antigravity provider under BOTH the new "antigravity"
		// key and the deprecated "gemini" key. Firmware after the rename reads
		// "antigravity"; deployed firmware still reads "gemini". Both derive
		// from the same ProviderModeSet field so they never disagree. Drop the
		// "gemini" key once the fleet has updated.
		wire["provider_modes"] = map[string]string{
			"claude":      string(pm.Claude),
			"codex":       string(pm.Codex),
			"antigravity": string(pm.Gemini),
			"gemini":      string(pm.Gemini),
		}
		wire["providers"] = map[string]bool{
			"claude":      pm.Claude.Enabled(),
			"codex":       pm.Codex.Enabled(),
			"antigravity": pm.Gemini.Enabled(),
			"gemini":      pm.Gemini.Enabled(),
		}
	}
	if p.AutorotateEnabled != nil {
		wire["autorotate_enabled"] = *p.AutorotateEnabled
	}
	if p.AutorotateIntervalS != nil {
		wire["autorotate_interval_s"] = *p.AutorotateIntervalS
	}
	if p.ThemeMode != "" {
		// firmware/config_sync.c reads "theme_mode" from the decrypted
		// blob and writes it to KEY_THEME_MD. Omitting it here would
		// silently no-op /tokenmonitor:theme switches.
		wire["theme_mode"] = p.ThemeMode
	}
	if p.PetEnabled != nil {
		wire["pet_enabled"] = *p.PetEnabled
	}
	if p.PetSpecies != nil {
		wire["pet_species"] = *p.PetSpecies
	}
	if p.PetName != "" {
		wire["pet_name"] = p.PetName
	}
	if len(p.GeminiModels) > 0 {
		// Dual-emit the per-device model override CSV under the new
		// "antigravity_models" key and the deprecated "gemini_models" key.
		// firmware/config_sync.c (post-rename) reads "antigravity_models";
		// deployed firmware reads "gemini_models". The broker also consults
		// the registry override directly; persisting it on device makes the
		// override observable in Settings and survive broker restarts.
		csv := strings.Join(p.GeminiModels, ",")
		wire["antigravity_models"] = csv
		wire["gemini_models"] = csv
	}
	if p.LogEnabled != nil {
		// firmware/config_sync.c reads "log_enabled" and writes NVS key
		// tmon_log_en, gating the device's diagnostic log upload.
		wire["log_enabled"] = *p.LogEnabled
	}
	// OTA staging fields. firmware/components/net/src/config_sync.c
	// requires ALL THREE to be present and well-formed before arming
	// the on-device tmon_ota_* NVS keys, so we send them together or
	// not at all. The SHA-256 is the integrity anchor for the .bin.
	if p.FirmwareURL != "" && p.FirmwareSHA256 != "" && p.FirmwareVersion != "" {
		wire["firmware_url"] = p.FirmwareURL
		wire["firmware_sha256"] = p.FirmwareSHA256
		wire["firmware_version"] = p.FirmwareVersion
	}
	// Signed manifest delivery (schema v2). The firmware verifies the
	// Ed25519 signature over the canonical manifest BEFORE downloading
	// the .bin, so missing either field on a firmware-bearing pending
	// turns the OTA into a no-op (production firmware refuses unsigned
	// manifests unless built with TMON_OTA_UNSIGNED=y). We forward
	// whichever fields are present and let the device-side gate apply
	// the policy.
	if p.FirmwareManifestB64 != "" {
		wire["firmware_manifest_b64"] = p.FirmwareManifestB64
	}
	if p.FirmwareManifestSigB64 != "" {
		wire["firmware_manifest_sig_b64"] = p.FirmwareManifestSigB64
	}
	return json.Marshal(wire)
}

// handleDeviceSync implements GET /device/{id}/sync. Verifies the
// signature with active+pending PSKs (so a device freshly rotated to
// pending PSK can fetch and confirm), promotes if the device has
// adopted pending, and returns the (encrypted) pending blob whenever
// the device's reported config_version lags behind.
func handleDeviceSync(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, st *state.State, w http.ResponseWriter, r *http.Request) {
	if reg == nil {
		writeError(w, http.StatusNotFound, "device registry not configured")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Path is /device/{id}/sync; reject anything else under /device/.
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/device/"), "/")
	if len(parts) != 2 || parts[1] != "sync" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	deviceID := parts[0]
	if !registry.ValidDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid device_id")
		return
	}

	active, pending, perr := reg.PSKsFor(deviceID)
	if errors.Is(perr, registry.ErrNotFound) {
		writeError(w, http.StatusNotFound, "unknown device")
		return
	} else if perr != nil {
		logger.Printf("registry lookup %s: %v", deviceID, perr)
		writeError(w, http.StatusInternalServerError, "registry error")
		return
	}

	// Path used in the signature is the literal URL path so the firmware
	// signs the same string the router parses. Query string is not in
	// scope today; if /sync ever gets one, both ends update together.
	signedPath := r.URL.Path
	res, verr := auth.VerifyMulti(
		[][]byte{active, pending},
		"GET", signedPath,
		r.Header.Get("X-Tmon-Timestamp"),
		r.Header.Get("X-Tmon-Nonce"),
		r.Header.Get("X-Tmon-Signature"),
		r.Header.Get("X-Tmon-Device"),
		r.Header.Get("X-Tmon-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	)
	if verr != nil {
		logger.Printf("auth rejected /device/%s/sync from %s: %v", deviceID, r.RemoteAddr, verr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	observed, _ := parseUint32Header(r.Header.Get("X-Tmon-Config-Version"))

	// Promote opportunistically on every authenticated /sync. For key
	// rotations the device must sign with the pending PSK (PSKIndex==1);
	// for non-rotation updates (theme / city / brightness / providers)
	// the version header on a valid active-PSK signature is enough.
	if _, perr := reg.MaybePromote(deviceID, observed, res.PSKIndex == 1); perr != nil {
		logger.Printf("registry promote %s: %v", deviceID, perr)
	}
	if terr := reg.Touch(deviceID); terr != nil {
		logger.Printf("registry touch %s: %v", deviceID, terr)
	}
	// Schema v2: capture the device's reported factory serial + SKU
	// when present. These headers are NOT bound to the HMAC (see
	// CLAUDE.md "Things NOT to assume" — the X-Tmon-Sku is metadata of
	// routing, not a security control). The Ed25519 manifest on a
	// pending firmware is what actually enforces SKU at install time.
	if serial := r.Header.Get("X-Tmon-Serial"); serial != "" {
		sku := r.Header.Get("X-Tmon-Sku")
		if serr := reg.SetSerial(deviceID, serial, sku); serr != nil {
			logger.Printf("registry set-serial %s: %v", deviceID, serr)
		}
	}
	// Mirror the device's anti-rollback floor. BumpMinSV is monotonic
	// in the registry; a spoofed-high value can only lock the device
	// out of downgrade attacks, not enable one.
	if msv := r.Header.Get("X-Tmon-Min-Sv"); msv != "" {
		if sv, err := strconv.ParseUint(msv, 10, 32); err == nil {
			if berr := reg.BumpMinSV(deviceID, uint32(sv)); berr != nil {
				logger.Printf("registry bump-min-sv %s: %v", deviceID, berr)
			}
		}
	}
	// The device reports its running firmware version on every request
	// (X-Tmon-Fw-Version, unsigned metadata like serial/sku). Persist it to
	// Active.FirmwareVersion so the OTA auto-discovery loop (ota.decide,
	// which keys off Active.FirmwareVersion) sees the version the device is
	// actually running. This is what makes a canary revert stick: without
	// it, a rolled-back device kept reporting the OLD (newer) version only
	// to a process-local map, and auto-discovery happily re-staged the
	// release it had just reverted from. The write happens only when the
	// header changed (SetActiveFirmwareVersion is a no-op otherwise), so
	// the 60s poll doesn't churn the TOML, and it survives broker restarts.
	fwReported := r.Header.Get("X-Tmon-Fw-Version")
	if fwReported != "" {
		if ferr := reg.SetActiveFirmwareVersion(deviceID, fwReported, logger); ferr != nil {
			logger.Printf("registry set-fw-version %s: %v", deviceID, ferr)
		}
	}

	dev, lerr := reg.Load(deviceID)
	if lerr != nil {
		logger.Printf("registry reload %s: %v", deviceID, lerr)
		writeError(w, http.StatusInternalServerError, "registry error")
		return
	}

	// Clear a stale revert tombstone once the device has reached a version
	// STRICTLY NEWER than the blocked one (a fixed release landed), so the
	// tombstone doesn't outlive the bad release and surprise a future
	// re-publish of that same version number. Uses ota.PackSemver so an
	// unparseable header never clears it.
	if dev.BlockedFirmwareVersion != "" && fwReported != "" {
		if got, gok := ota.PackSemver(fwReported); gok {
			if blk, bok := ota.PackSemver(dev.BlockedFirmwareVersion); bok && got > blk {
				if cerr := reg.SetBlockedFirmwareVersion(deviceID, ""); cerr != nil {
					logger.Printf("registry clear-blocked %s: %v", deviceID, cerr)
				} else {
					dev.BlockedFirmwareVersion = ""
				}
			}
		}
	}

	resp := syncResponse{ActiveVersion: dev.Active.Version}
	if st != nil {
		// Advertise the broker self-version-check verdict on every 200 so the
		// device can surface a "broker outdated" banner. Only once known — an
		// unchecked/unreachable verdict stays absent (no false banner).
		if u := st.Update(); u.Known {
			avail := u.Outdated
			resp.BrokerUpdateAvailable = &avail
			resp.BrokerVersion = u.Current
			resp.BrokerLatest = u.Latest
		}
	}
	if dev.Pending != nil && observed < dev.Pending.Version {
		// Encrypt the pending payload with the device's *currently active*
		// PSK. The device decrypts with what it already has, learns the
		// new key from inside, and only the next rotation needs the new
		// key. Bricked-broker captures see ciphertext, not the next PSK.
		if len(active) != 32 {
			logger.Printf("device %s active PSK not 32 bytes (%d) — cannot encrypt pending", deviceID, len(active))
			writeError(w, http.StatusInternalServerError, "broker config invalid")
			return
		}
		pt, perr := pendingPayloadJSON(dev.Pending.ConfigPayload)
		if perr != nil {
			logger.Printf("pending JSON marshal %s: %v", deviceID, perr)
			writeError(w, http.StatusInternalServerError, "pending serialize")
			return
		}
		// Cipher choice is gated on the LIVE reported firmware version,
		// never on registry state, so a canary revert to pre-GCM firmware
		// self-heals: the next poll's header decides the envelope.
		var (
			nonce, ct []byte
			eerr      error
			enc       string
		)
		if fwSupportsGCM(fwReported) {
			enc = "gcm"
			nonce, ct, eerr = registry.EncryptPendingGCM(active, dev.Pending.Version, pt)
		} else {
			nonce, ct, eerr = registry.EncryptPending(active, pt)
		}
		if eerr != nil {
			logger.Printf("pending encrypt %s: %v", deviceID, eerr)
			writeError(w, http.StatusInternalServerError, "pending encrypt")
			return
		}
		resp.Pending = &pendingBlob{
			Version:    dev.Pending.Version,
			Enc:        enc,
			NonceB64:   base64.StdEncoding.EncodeToString(nonce),
			PayloadB64: base64.StdEncoding.EncodeToString(ct),
		}
	}

	body, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleDeviceLogs receives a diagnostic log batch the device POSTs to
// /device/{id}/logs and appends it to the per-device log file. Auth is
// identical to /sync (HMAC over method+path+ts+nonce+device+cfgver). The
// signature does NOT cover the body — that is acceptable: the body is
// scrubbed of secrets on-device and is diagnostic only, so a tamperer who
// is somehow on-path can corrupt debug text but cannot forge a privileged
// action. The body is capped (MaxBodyBytes) to bound abuse.
func handleDeviceLogs(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request) {
	if reg == nil {
		writeError(w, http.StatusNotFound, "device registry not configured")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/device/"), "/")
	if len(parts) != 2 || parts[1] != "logs" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	deviceID := parts[0]
	if !registry.ValidDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid device_id")
		return
	}

	active, pending, perr := reg.PSKsFor(deviceID)
	if errors.Is(perr, registry.ErrNotFound) {
		writeError(w, http.StatusNotFound, "unknown device")
		return
	} else if perr != nil {
		logger.Printf("registry lookup %s: %v", deviceID, perr)
		writeError(w, http.StatusInternalServerError, "registry error")
		return
	}

	signedPath := r.URL.Path
	if _, verr := auth.VerifyMulti(
		[][]byte{active, pending},
		"POST", signedPath,
		r.Header.Get("X-Tmon-Timestamp"),
		r.Header.Get("X-Tmon-Nonce"),
		r.Header.Get("X-Tmon-Signature"),
		r.Header.Get("X-Tmon-Device"),
		r.Header.Get("X-Tmon-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	); verr != nil {
		logger.Printf("auth rejected /device/%s/logs from %s: %v", deviceID, r.RemoteAddr, verr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, devlog.MaxBodyBytes)
	raw, rerr := io.ReadAll(r.Body)
	if rerr != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}

	lines := devlog.StampLines(string(raw), time.Now())
	if aerr := devlog.Append(devlog.DirFor(reg.Dir()), deviceID, lines); aerr != nil {
		logger.Printf("devlog append %s: %v", deviceID, aerr)
		writeError(w, http.StatusInternalServerError, "log store error")
		return
	}

	writeJSON(w, http.StatusAccepted, struct {
		Stored int `json:"stored"`
	}{Stored: len(lines)})
}

// settingsReportBody is the JSON the device POSTs to /device/{id}/settings.
// Numbers are decoded into pointers so an omitted field stays nil ("leave it").
type settingsReportBody struct {
	ThemeMode           *string `json:"theme_mode"`
	BrDay               *uint8  `json:"br_day"`
	BrNight             *uint8  `json:"br_night"`
	Vol                 *uint8  `json:"vol"`
	AutorotateEnabled   *bool   `json:"autorotate_enabled"`
	AutorotateIntervalS *uint16 `json:"autorotate_interval_s"`
	PetEnabled          *bool   `json:"pet_enabled"`
	PetSpecies          *uint8  `json:"pet_species"`
	PetName             *string `json:"pet_name"`
}

// handleDeviceSettings ingests a device-reported display-settings update and
// mirrors it into the registry (compat/SETTINGS_REPORT.md). The device owns
// these fields, so this converges the broker's stored config to the device's
// state instead of pushing a change — no version bump, no reverts.
func handleDeviceSettings(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request) {
	if reg == nil {
		writeError(w, http.StatusNotFound, "device registry not configured")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/device/"), "/")
	if len(parts) != 2 || parts[1] != "settings" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	deviceID := parts[0]
	if !registry.ValidDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid device_id")
		return
	}

	active, pending, perr := reg.PSKsFor(deviceID)
	if errors.Is(perr, registry.ErrNotFound) {
		writeError(w, http.StatusNotFound, "unknown device")
		return
	} else if perr != nil {
		logger.Printf("registry lookup %s: %v", deviceID, perr)
		writeError(w, http.StatusInternalServerError, "registry error")
		return
	}

	signedPath := r.URL.Path
	if _, verr := auth.VerifyMulti(
		[][]byte{active, pending},
		"POST", signedPath,
		r.Header.Get("X-Tmon-Timestamp"),
		r.Header.Get("X-Tmon-Nonce"),
		r.Header.Get("X-Tmon-Signature"),
		r.Header.Get("X-Tmon-Device"),
		r.Header.Get("X-Tmon-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	); verr != nil {
		logger.Printf("auth rejected /device/%s/settings from %s: %v", deviceID, r.RemoteAddr, verr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 512)
	raw, rerr := io.ReadAll(r.Body)
	if rerr != nil { // includes the 512-byte cap being exceeded
		writeError(w, http.StatusBadRequest, "bad settings body")
		return
	}
	// Canonical body handling shared with the Python/JS brokers: an empty
	// (or whitespace-only) body is a no-op; anything present must be a single
	// JSON object with no trailing data; null / arrays / scalars are rejected.
	var body settingsReportBody
	if trimmed := strings.TrimSpace(string(raw)); trimmed != "" {
		if trimmed == "null" {
			writeError(w, http.StatusBadRequest, "bad settings body")
			return
		}
		dec := json.NewDecoder(strings.NewReader(trimmed))
		if derr := dec.Decode(&body); derr != nil {
			writeError(w, http.StatusBadRequest, "bad settings body")
			return
		}
		// Reject any trailing data after the object. dec.More() is unreliable
		// here (it returns false on a stray '}'/']'), so decode a second value
		// and require a clean io.EOF.
		var trailing json.RawMessage
		if terr := dec.Decode(&trailing); terr != io.EOF {
			writeError(w, http.StatusBadRequest, "bad settings body")
			return
		}
	}

	if _, rerr := reg.ReportSettings(deviceID, registry.ReportedSettings{
		ThemeMode:           body.ThemeMode,
		BrDay:               body.BrDay,
		BrNight:             body.BrNight,
		Vol:                 body.Vol,
		AutorotateEnabled:   body.AutorotateEnabled,
		AutorotateIntervalS: body.AutorotateIntervalS,
		PetEnabled:          body.PetEnabled,
		PetSpecies:          body.PetSpecies,
		PetName:             body.PetName,
	}); errors.Is(rerr, registry.ErrNotFound) {
		writeError(w, http.StatusNotFound, "unknown device")
		return
	} else if rerr != nil {
		logger.Printf("report settings %s: %v", deviceID, rerr)
		writeError(w, http.StatusInternalServerError, "registry error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func parseUint32Header(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

func writeError(w http.ResponseWriter, status int, msg string) {
	body, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: msg})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// Serve takes ownership of an already-bound listener and runs the HTTP
// broker until ctx is cancelled. On cancellation it shuts down with a 1s
// drain so the leader-election follower can grab the port quickly.
// `fwLogs` is the read-side of the serial tailer; pass nil to keep
// /firmware-logs answering 200 with an empty list. `reg` may be nil
// to disable the per-device control plane (legacy global-PSK mode).
func Serve(ctx context.Context, ln net.Listener, cfg *config.Config, st *state.State, logger *log.Logger, fwLogs FirmwareLogSource, reg *registry.Registry, usageCache *usage.Cache, spendCache *spend.Cache) error {
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	srv := &http.Server{
		Handler:           NewMux(cfg, cache, st, logger, fwLogs, reg, usageCache, spendCache),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("broker: serving on %s", ln.Addr())
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Printf("broker: shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	}
}
