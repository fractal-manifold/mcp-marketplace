package spend

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The Antigravity CLI (agy) has no machine-readable per-turn token source yet:
// the Gemini-CLI chat-log JSONL is gone, and agy's proto+SQLite trajectory
// store has no recoverable counts (spike 2026-06-30). So /spend/antigravity
// must return ErrNotImpl ("--" on the device) and — critically — must NEVER
// surface a stale, Gemini-derived dollar figure under the renamed slot. These
// tests lock that guarantee so a future re-wiring of geminiRecords can't
// silently break it.

func TestAntigravitySpendNotImplemented(t *testing.T) {
	if got := CanonicalProvider("gemini"); got != "antigravity" {
		t.Fatalf("CanonicalProvider(gemini) = %q, want antigravity", got)
	}
	c := NewCache(300*time.Second, map[string]Fetcher{})
	for _, p := range []string{"antigravity", CanonicalProvider("gemini")} {
		if _, err := c.Get(context.Background(), p); !errors.Is(err, ErrNotImpl) {
			t.Fatalf("Get(%q) err = %v, want ErrNotImpl", p, err)
		}
	}
}

func TestBuildCacheOmitsAntigravity(t *testing.T) {
	c := BuildCache(SpendConfig{
		Enabled:         true,
		CacheTTLSeconds: 300,
		ClaudeProjects:  t.TempDir(),
	}, nil)
	if c == nil {
		t.Fatal("BuildCache returned nil for an enabled spend config")
	}
	for _, p := range c.Providers() {
		if p == "antigravity" || p == "gemini" {
			t.Fatalf("spend provider %q must not be registered", p)
		}
	}
}
