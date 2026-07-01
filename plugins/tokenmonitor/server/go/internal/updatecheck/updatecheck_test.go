package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	t.Setenv("TOKENMONITOR_MARKETPLACE_URL", ts.URL)
	return ts
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
