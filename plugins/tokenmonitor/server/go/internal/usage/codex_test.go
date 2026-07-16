package usage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// codexSample is the LEGACY two-window shape captured by
// scripts/proto-usage-codex.py on 2026-05-25 from a Plus plan (primary=5h
// Session, secondary=7d Weekly). Kept as a regression case: accounts/plans
// still returning both windows must render Session + Weekly.
const codexSample = `{
  "plan_type": "plus",
  "rate_limit": {
    "primary_window":   {"used_percent": 33, "limit_window_seconds": 18000, "reset_after_seconds": 14007, "reset_at": 1779678515},
    "secondary_window": {"used_percent": 6,  "limit_window_seconds": 604800, "reset_after_seconds": 582744, "reset_at": 1780247253}
  },
  "credits": {"has_credits": false}
}`

// codexSingleWeeklySample is the real shape captured 2026-07-16 after OpenAI
// collapsed Codex to a SINGLE weekly limit: primary_window is now the 7d
// weekly window and secondary_window is null. The device must render a single
// weekly card (session hidden), the same as Antigravity.
const codexSingleWeeklySample = `{
  "plan_type": "plus",
  "rate_limit": {
    "allowed": true,
    "limit_reached": false,
    "primary_window":   {"used_percent": 1, "limit_window_seconds": 604800, "reset_after_seconds": 602722, "reset_at": 1784812589},
    "secondary_window": null
  },
  "rate_limit_reset_credits": {"available_count": 4}
}`

func makeJWT(t *testing.T, exp int64) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{"exp": exp})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func writeCodexAuth(t *testing.T, exp int64) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.json")
	doc := map[string]any{
		"auth_mode": "chatgpt",
		"tokens": map[string]any{
			"access_token": makeJWT(t, exp),
			"account_id":   "acct-test",
		},
	}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCodexFetcher_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("ChatGPT-Account-Id"); got != "acct-test" {
			t.Errorf("account header: %q", got)
		}
		if got := r.Header.Get("Authorization"); got == "" || got[:7] != "Bearer " {
			t.Errorf("auth header: %q", got)
		}
		_, _ = w.Write([]byte(codexSample))
	}))
	defer srv.Close()

	f := &CodexFetcher{
		AuthPath: writeCodexAuth(t, time.Now().Add(time.Hour).Unix()),
		HTTP:     &http.Client{Transport: rewriteHost(srv.URL)},
		Now:      time.Now,
	}
	snap, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if snap.SessionPct != 33 {
		t.Errorf("session_pct: %v", snap.SessionPct)
	}
	if snap.WeeklyPct != 6 {
		t.Errorf("weekly_pct: %v", snap.WeeklyPct)
	}
	if snap.SessionWindowSeconds != 18000 {
		t.Errorf("session_window: %d", snap.SessionWindowSeconds)
	}
	if snap.WeeklyWindowSeconds != 604800 {
		t.Errorf("weekly_window: %d", snap.WeeklyWindowSeconds)
	}
	if snap.SessionResetETASeconds != 14007 {
		t.Errorf("session_reset_eta: %d", snap.SessionResetETASeconds)
	}
	if snap.WeeklyResetETASeconds != 582744 {
		t.Errorf("weekly_reset_eta: %d", snap.WeeklyResetETASeconds)
	}
	if snap.Tier != "plus" {
		t.Errorf("tier: %q", snap.Tier)
	}
	if snap.DesignPresent {
		t.Errorf("design_present: want false for codex")
	}
	// Codex emits exactly Session + Weekly slots (no third bucket).
	wantSlots := []Slot{
		{Label: "Session", Pct: 33, WindowSeconds: 18000, ResetETASeconds: 14007},
		{Label: "Weekly", Pct: 6, WindowSeconds: 604800, ResetETASeconds: 582744},
	}
	if len(snap.Slots) != len(wantSlots) {
		t.Fatalf("slots: want %d, got %d (%+v)", len(wantSlots), len(snap.Slots), snap.Slots)
	}
	for i, w := range wantSlots {
		if snap.Slots[i] != w {
			t.Errorf("slots[%d]: want %+v, got %+v", i, w, snap.Slots[i])
		}
	}
}

func TestCodexFetcher_SingleWeeklyWindow(t *testing.T) {
	// The real 2026-07 shape: primary_window is the 7d weekly window,
	// secondary_window is null. Codex must degrade to a single weekly card
	// (session hidden), like Antigravity.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(codexSingleWeeklySample))
	}))
	defer srv.Close()
	f := &CodexFetcher{
		AuthPath: writeCodexAuth(t, time.Now().Add(time.Hour).Unix()),
		HTTP:     &http.Client{Transport: rewriteHost(srv.URL)},
		Now:      time.Now,
	}
	snap, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	// primary → weekly; session hidden.
	if snap.WeeklyPct != 1 {
		t.Errorf("weekly_pct: want 1, got %v", snap.WeeklyPct)
	}
	if snap.WeeklyWindowSeconds != 604800 {
		t.Errorf("weekly_window: want 604800, got %d", snap.WeeklyWindowSeconds)
	}
	if snap.WeeklyResetETASeconds != 602722 {
		t.Errorf("weekly_reset_eta: want 602722, got %d", snap.WeeklyResetETASeconds)
	}
	if snap.SessionWindowSeconds != 0 {
		t.Errorf("session must be hidden (0), got %d", snap.SessionWindowSeconds)
	}
	if snap.SessionPct != 0 {
		t.Errorf("session_pct: want 0, got %v", snap.SessionPct)
	}
	// Exactly one weekly slot.
	wantSlots := []Slot{{Label: "Weekly", Pct: 1, WindowSeconds: 604800, ResetETASeconds: 602722}}
	if len(snap.Slots) != len(wantSlots) {
		t.Fatalf("slots: want %d, got %d (%+v)", len(wantSlots), len(snap.Slots), snap.Slots)
	}
	for i, want := range wantSlots {
		if snap.Slots[i] != want {
			t.Errorf("slots[%d]: want %+v, got %+v", i, want, snap.Slots[i])
		}
	}
}

func TestCodexFetcher_MissingRateLimit(t *testing.T) {
	// Empty rate_limit (no secondary) → single-weekly path with zero usage:
	// session hidden, weekly at 0% with the 7d fallback window, one slot.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"plan_type":"plus","rate_limit":{}}`))
	}))
	defer srv.Close()
	f := &CodexFetcher{
		AuthPath: writeCodexAuth(t, time.Now().Add(time.Hour).Unix()),
		HTTP:     &http.Client{Transport: rewriteHost(srv.URL)},
		Now:      time.Now,
	}
	snap, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if snap.SessionPct != 0 || snap.WeeklyPct != 0 {
		t.Errorf("expected zeros, got %+v", snap)
	}
	if snap.SessionWindowSeconds != 0 {
		t.Errorf("session must be hidden (0), got %d", snap.SessionWindowSeconds)
	}
	if snap.WeeklyWindowSeconds != codexWeeklyWindowFallback {
		t.Errorf("weekly_window fallback: %d", snap.WeeklyWindowSeconds)
	}
	if len(snap.Slots) != 1 || snap.Slots[0].Label != "Weekly" {
		t.Errorf("want single Weekly slot, got %+v", snap.Slots)
	}
}
