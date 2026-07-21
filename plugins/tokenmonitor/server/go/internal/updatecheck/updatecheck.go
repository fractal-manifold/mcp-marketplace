// Package updatecheck answers one question the broker cannot otherwise see:
// is a newer TokenMonitor broker/plugin release published than the one this
// process is running? The broker does NOT auto-update, so over time it drifts
// behind the firmware it feeds. This package periodically fetches the public
// marketplace catalog, compares the tokenmonitor entry's version against the
// installed release version, and stashes the verdict in *state.State so three
// surfaces can advertise it: the /device/<id>/sync body (→ on-device banner),
// tokenmonitor_health / tokenmonitor_status (→ Claude Code), and a stderr WARN.
//
// It is strictly best-effort: any network/parse failure leaves the cached
// verdict Unknown (never a false "up to date" or "outdated") and never blocks
// or errors the broker.
package updatecheck

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/ota"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/state"
)

const (
	// PluginName is the marketplace entry whose version tracks releases.
	PluginName = "tokenmonitor"
	// DefaultMarketplaceURL is the raw catalog on the marketplace repo's
	// default branch — the single source of truth for "latest published".
	// Overridable via TMON_MARKETPLACE_URL (used by tests); legacy
	// TOKENMONITOR_MARKETPLACE_URL is still honoured as an alias.
	DefaultMarketplaceURL = "https://raw.githubusercontent.com/fractal-manifold/mcp-marketplace/main/.claude-plugin/marketplace.json"

	httpTimeout  = 10 * time.Second
	pollInterval = 6 * time.Hour
	initialDelay = 30 * time.Second
	maxBody      = 1 * 1024 * 1024
)

// marketplaceDoc is the subset of marketplace.json this package reads.
type marketplaceDoc struct {
	Plugins []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"plugins"`
}

// pluginManifest is the subset of .claude-plugin/plugin.json we read.
type pluginManifest struct {
	Version string `json:"version"`
}

// MarketplaceURL returns the catalog URL, honouring the test/CI override.
// TMON_ is the project's env-var convention; TOKENMONITOR_MARKETPLACE_URL is a
// backward-compat alias (TMON_ wins when both are set).
func MarketplaceURL() string {
	if u := os.Getenv("TMON_MARKETPLACE_URL"); u != "" {
		return u
	}
	if u := os.Getenv("TOKENMONITOR_MARKETPLACE_URL"); u != "" {
		return u
	}
	return DefaultMarketplaceURL
}

// InstalledVersion resolves the running release version. It prefers the
// bundle's plugin.json (the release/marketplace axis, apples-to-apples with the
// catalog). The launcher exports TMON_PLUGIN_ROOT (set on every client, incl.
// Antigravity and the cached Go binary); CLAUDE_PLUGIN_ROOT is the host-provided
// fallback (Claude/Codex only). Falls back to the baked-in broker build version
// when the manifest is absent or unreadable.
func InstalledVersion(baked string) string {
	root := os.Getenv("TMON_PLUGIN_ROOT")
	if root == "" {
		root = os.Getenv("CLAUDE_PLUGIN_ROOT")
	}
	if root != "" {
		p := filepath.Join(root, ".claude-plugin", "plugin.json")
		if b, err := os.ReadFile(p); err == nil {
			var m pluginManifest
			if json.Unmarshal(b, &m) == nil && m.Version != "" {
				return m.Version
			}
		}
	}
	return baked
}

// fetchLatest GETs the marketplace catalog and returns the tokenmonitor entry's
// version. An empty string (nil error) means the entry was absent.
func fetchLatest(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, MarketplaceURL(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tokenmonitor-mcp-updatecheck")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &httpError{resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", err
	}
	var doc marketplaceDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", err
	}
	for _, p := range doc.Plugins {
		if p.Name == PluginName {
			return p.Version, nil
		}
	}
	return "", nil
}

type httpError struct{ code int }

func (e *httpError) Error() string { return "marketplace fetch: HTTP " + itoa(e.code) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Check performs one fetch+compare and returns the verdict. On any failure it
// returns a Known:false result (verdict unknown) — callers must treat that as
// "advertise nothing".
func Check(ctx context.Context, client *http.Client, current string) state.UpdateInfo {
	latest, err := fetchLatest(ctx, client)
	if err != nil || latest == "" {
		return state.UpdateInfo{Known: false, Current: current}
	}
	cmp, ok := ota.CompareSemver(latest, current)
	if !ok {
		// Either version is unparseable under the project's semver subset;
		// don't guess.
		return state.UpdateInfo{Known: false, Current: current}
	}
	return state.UpdateInfo{
		Known:     true,
		Outdated:  cmp > 0,
		Current:   current,
		Latest:    latest,
		CheckedAt: time.Now(),
	}
}

// Run polls the marketplace catalog on a slow cadence and publishes each
// verdict into st. It returns when ctx is cancelled. baked is the compiled-in
// broker version, used only as the installed-version fallback.
func Run(ctx context.Context, baked string, st *state.State, logger *log.Logger) {
	if st == nil {
		return
	}
	current := InstalledVersion(baked)
	client := &http.Client{Timeout: httpTimeout}
	timer := time.NewTimer(initialDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		info := Check(ctx, client, current)
		st.SetUpdate(info)
		if logger != nil {
			if info.Known && info.Outdated {
				logger.Printf("updatecheck: WARNING broker %s is behind published %s — update the tokenmonitor plugin", info.Current, info.Latest)
			} else if info.Known {
				logger.Printf("updatecheck: broker %s is up to date", info.Current)
			}
		}
		timer.Reset(pollInterval)
	}
}
