package broker

// Custom "panel" endpoint: GET /device/{id}/panel returns a self-describing
// JSON document (charts / tables) that a device renders on its extra screen.
// The document is authored by the USER — their own program rewrites a local
// file — and the broker merely serves it verbatim over the same HMAC-signed
// channel as /device/{id}/sync. The feature is purely additive: an old broker
// (no route) or a broker with no [panel] configured answers 404, which the
// firmware treats identically as "no panel to draw".

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

// panelMaxBytes bounds the served document. The device parses into fixed-size
// buffers (see firmware panel_client.c), so a runaway file must be rejected
// here rather than streamed. Keep this in sync with compat/PANEL_WIRE.md.
const panelMaxBytes = 8 * 1024

// panelCache memoises the last read of each panel file keyed by mtime+size,
// mirroring firmwareSHACache / spend's fileRecordCache. The user's program
// rewrites the file in place; an mtime/size change invalidates the entry.
type panelCacheEntry struct {
	mtime time.Time
	size  int64
	body  []byte
}

var (
	panelCache   = map[string]panelCacheEntry{}
	panelCacheMu sync.Mutex
)

// resolvePanelPath picks the file to serve for deviceID. Resolution order,
// most specific first: the explicit [panel.file].<id> entry, then
// <dir>/<id>.json, then <dir>/default.json, then the [panel.file].default
// entry (a.k.a. the legacy bare `file`). Returns "" when the feature is not
// configured.
//
// deviceID has already passed registry.ValidDeviceID (strict charset, no
// slashes) before this is called, so <id>.json is traversal-safe.
func resolvePanelPath(cfg *config.Config, deviceID string) string {
	if p := cfg.PanelFileExplicit(deviceID); p != "" {
		return p
	}
	if dir := cfg.PanelDir(); dir != "" {
		if deviceID != "" {
			p := filepath.Join(dir, deviceID+".json")
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
		p := filepath.Join(dir, "default.json")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	if f := cfg.PanelFileDefault(); f != "" {
		return f
	}
	return ""
}

// readPanelFile returns the raw JSON bytes for path with mtime caching. On
// error it returns the HTTP status the caller should surface: 404 when the
// file is absent, 422 when it is too large or not valid JSON.
func readPanelFile(path string) (body []byte, errStatus int, err error) {
	fi, statErr := os.Stat(path)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil, http.StatusNotFound, errors.New("no panel")
		}
		return nil, http.StatusInternalServerError, statErr
	}
	if fi.IsDir() {
		return nil, http.StatusNotFound, errors.New("no panel")
	}
	if fi.Size() > panelMaxBytes {
		return nil, http.StatusUnprocessableEntity,
			fmt.Errorf("panel too large (%d > %d bytes)", fi.Size(), panelMaxBytes)
	}

	panelCacheMu.Lock()
	if e, ok := panelCache[path]; ok && e.mtime.Equal(fi.ModTime()) && e.size == fi.Size() {
		cached := e.body
		panelCacheMu.Unlock()
		return cached, 0, nil
	}
	panelCacheMu.Unlock()

	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, http.StatusInternalServerError, readErr
	}
	if !json.Valid(raw) {
		return nil, http.StatusUnprocessableEntity, errors.New("panel is not valid JSON")
	}

	panelCacheMu.Lock()
	panelCache[path] = panelCacheEntry{mtime: fi.ModTime(), size: fi.Size(), body: raw}
	panelCacheMu.Unlock()
	return raw, 0, nil
}

// writeJSONBytes serves pre-serialised JSON verbatim (unlike writeJSON, which
// re-marshals a value). Used so the device sees exactly the bytes the user
// wrote — no canonicalisation surprises.
func writeJSONBytes(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// handleDevicePanel authenticates exactly like handleDeviceSync (same HMAC
// over "GET" + the literal path) and then serves the resolved panel file.
func handleDevicePanel(cfg *config.Config, cache *auth.NonceCache, logger *log.Logger, reg *registry.Registry, w http.ResponseWriter, r *http.Request) {
	if reg == nil {
		writeError(w, http.StatusNotFound, "device registry not configured")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/device/"), "/")
	if len(parts) != 2 || parts[1] != "panel" {
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

	if _, verr := auth.VerifyMulti(
		[][]byte{active, pending},
		"GET", r.URL.Path,
		r.Header.Get("X-Tmon-Timestamp"),
		r.Header.Get("X-Tmon-Nonce"),
		r.Header.Get("X-Tmon-Signature"),
		r.Header.Get("X-Tmon-Device"),
		r.Header.Get("X-Tmon-Config-Version"),
		cache,
		time.Duration(cfg.Security.MaxTimestampSkewSeconds)*time.Second,
		time.Now(),
	); verr != nil {
		logger.Printf("auth rejected /device/%s/panel from %s: %v", deviceID, r.RemoteAddr, verr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := resolvePanelPath(cfg, deviceID)
	if path == "" {
		writeError(w, http.StatusNotFound, "panel not configured")
		return
	}
	body, errStatus, err := readPanelFile(path)
	if err != nil {
		if errStatus == http.StatusInternalServerError {
			logger.Printf("panel read %s: %v", path, err)
			writeError(w, errStatus, "panel read error")
		} else {
			writeError(w, errStatus, err.Error())
		}
		return
	}
	writeJSONBytes(w, http.StatusOK, body)
}
