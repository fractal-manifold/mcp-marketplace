package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mockCatalog(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	t.Setenv("TMON_MARKETPLACE_URL", ts.URL)
	return ts
}

func TestMarketplaceURL_Precedence(t *testing.T) {
	// TMON_ is canonical and must win over the legacy alias; the alias alone
	// still works.
	t.Setenv("TMON_MARKETPLACE_URL", "https://canonical.example/catalog.json")
	t.Setenv("TOKENMONITOR_MARKETPLACE_URL", "https://legacy.example/catalog.json")
	if got := MarketplaceURL(); got != "https://canonical.example/catalog.json" {
		t.Fatalf("TMON_ should win, got %q", got)
	}
	t.Setenv("TMON_MARKETPLACE_URL", "")
	if got := MarketplaceURL(); got != "https://legacy.example/catalog.json" {
		t.Fatalf("legacy alias should apply when TMON_ unset, got %q", got)
	}
}

func TestInstalledVersion_RootPrecedence(t *testing.T) {
	// TMON_PLUGIN_ROOT (launcher-exported, all clients) wins over the
	// host-provided CLAUDE_PLUGIN_ROOT; both resolve a manifest version.
	dirTmon := t.TempDir()
	writeManifest(t, dirTmon, "1.2.3")
	dirClaude := t.TempDir()
	writeManifest(t, dirClaude, "4.5.6")

	t.Setenv("TMON_PLUGIN_ROOT", dirTmon)
	t.Setenv("CLAUDE_PLUGIN_ROOT", dirClaude)
	if got := InstalledVersion("0.0.0"); got != "1.2.3" {
		t.Fatalf("TMON_PLUGIN_ROOT should win, got %q", got)
	}
	t.Setenv("TMON_PLUGIN_ROOT", "")
	if got := InstalledVersion("0.0.0"); got != "4.5.6" {
		t.Fatalf("CLAUDE_PLUGIN_ROOT fallback should apply, got %q", got)
	}
	t.Setenv("CLAUDE_PLUGIN_ROOT", "")
	if got := InstalledVersion("0.0.0"); got != "0.0.0" {
		t.Fatalf("baked fallback should apply, got %q", got)
	}
}

func writeManifest(t *testing.T, root, version string) {
	t.Helper()
	dir := filepath.Join(root, ".claude-plugin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"name":"tokenmonitor","version":"` + version + `"}`
	if err := os.WriteFile(filepath.Join(dir, "plugin.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func tmonCatalog(version string) string {
	return `{"plugins":[{"name":"other","version":"1.0.0"},{"name":"tokenmonitor","version":"` + version + `"}]}`
}

func TestCheck_Outdated(t *testing.T) {
	mockCatalog(t, tmonCatalog("0.9.9"), 200)
	got := Check(context.Background(), &http.Client{Timeout: time.Second}, "0.9.4")
	if !got.Known || !got.Outdated {
		t.Fatalf("got %+v, want Known && Outdated", got)
	}
	if got.Current != "0.9.4" || got.Latest != "0.9.9" {
		t.Errorf("versions = %q/%q, want 0.9.4/0.9.9", got.Current, got.Latest)
	}
}

func TestCheck_UpToDate(t *testing.T) {
	mockCatalog(t, tmonCatalog("0.9.4"), 200)
	got := Check(context.Background(), &http.Client{Timeout: time.Second}, "0.9.4")
	if !got.Known || got.Outdated {
		t.Fatalf("got %+v, want Known && !Outdated", got)
	}
}

func TestCheck_InstalledNewer(t *testing.T) {
	// A dev build ahead of the published release must not report "outdated".
	mockCatalog(t, tmonCatalog("0.9.4"), 200)
	got := Check(context.Background(), &http.Client{Timeout: time.Second}, "0.9.5")
	if !got.Known || got.Outdated {
		t.Fatalf("got %+v, want Known && !Outdated", got)
	}
}

func TestCheck_HTTPError_Unknown(t *testing.T) {
	mockCatalog(t, "boom", 500)
	got := Check(context.Background(), &http.Client{Timeout: time.Second}, "0.9.4")
	if got.Known {
		t.Fatalf("got %+v, want Known=false on HTTP 500", got)
	}
}

func TestCheck_MissingEntry_Unknown(t *testing.T) {
	mockCatalog(t, `{"plugins":[{"name":"other","version":"1.0.0"}]}`, 200)
	got := Check(context.Background(), &http.Client{Timeout: time.Second}, "0.9.4")
	if got.Known {
		t.Fatalf("got %+v, want Known=false when tokenmonitor absent", got)
	}
}

func TestCheck_Unparseable_Unknown(t *testing.T) {
	mockCatalog(t, tmonCatalog("not-a-version"), 200)
	got := Check(context.Background(), &http.Client{Timeout: time.Second}, "0.9.4")
	if got.Known {
		t.Fatalf("got %+v, want Known=false on unparseable version", got)
	}
}

func TestCheck_BadJSON_Unknown(t *testing.T) {
	mockCatalog(t, `{"plugins":`, 200)
	got := Check(context.Background(), &http.Client{Timeout: time.Second}, "0.9.4")
	if got.Known {
		t.Fatalf("got %+v, want Known=false on malformed JSON", got)
	}
}
