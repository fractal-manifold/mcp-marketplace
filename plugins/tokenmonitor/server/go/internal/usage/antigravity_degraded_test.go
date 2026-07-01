package usage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// rtFunc adapts a func to http.RoundTripper.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// newAntigravityFetcher builds a fetcher with a pre-seeded token (so it never
// touches the OS keyring) and an injected transport. quotaStatus controls the
// retrieveUserQuotaSummary reply.
func newAntigravityFetcher(quotaStatus int, quotaBody string) *AntigravityFetcher {
	f := &AntigravityFetcher{
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
		HTTP: &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, "loadCodeAssist") {
				return jsonResp(200, `{"cloudaicompanionProject":"proj-123","currentTier":{"id":"free-tier"}}`), nil
			}
			// retrieveUserQuotaSummary
			return jsonResp(quotaStatus, quotaBody), nil
		})},
	}
	// Pre-seed the token cache so token() returns without a keyring lookup.
	f.cachedTok = geminiAccessToken{Token: "seeded", ExpiresAtMS: f.now().UnixMilli() + 3_600_000}
	return f
}

// TestAntigravity_DegradedOnQuotaError: loadCodeAssist OK but the quota
// sub-RPC 500s → snapshot marked Degraded, and the marker serialises to JSON.
func TestAntigravity_DegradedOnQuotaError(t *testing.T) {
	f := newAntigravityFetcher(500, `{"error":"boom"}`)
	snap, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error, want degraded snapshot: %v", err)
	}
	if !snap.Degraded {
		t.Fatal("snapshot.Degraded = false, want true when quota RPC fails")
	}
	raw, _ := json.Marshal(snap)
	if !strings.Contains(string(raw), `"degraded":true`) {
		t.Fatalf("degraded must serialise as true, got %s", raw)
	}
}

// TestAntigravity_NotDegradedWhenQuotaOK: quota OK → not degraded and the
// key is omitted from JSON (omitempty).
func TestAntigravity_NotDegradedWhenQuotaOK(t *testing.T) {
	body := `{"groups":[{"displayName":"Gemini Models","buckets":[{"bucketId":"gemini-weekly","window":"weekly","resetTime":"2026-07-07T10:55:39Z","remainingFraction":0.5}]}]}`
	f := newAntigravityFetcher(200, body)
	snap, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if snap.Degraded {
		t.Fatal("snapshot.Degraded = true, want false on quota success")
	}
	raw, _ := json.Marshal(snap)
	if strings.Contains(string(raw), "degraded") {
		t.Fatalf("degraded key must be omitted on success, got %s", raw)
	}
}
