package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// Antigravity's grouped weekly quota is served from the `daily-` CANARY
	// host, not prod cloudcode-pa (prod 403s the quota RPC). Verified
	// end-to-end via a mitmproxy capture of agy 1.0.13 (2026-06-30) — see the
	// project memory "agy-antigravity-cli-format" for the full recipe. Mirror
	// of the JS broker's ANTIGRAVITY_HOST / GEMINI_CODE_ASSIST / GEMINI_USER_QUOTA.
	antigravityHost     = "https://daily-cloudcode-pa.googleapis.com/v1internal:"
	geminiCodeAssistURL = antigravityHost + "loadCodeAssist"
	geminiUserQuotaURL  = antigravityHost + "retrieveUserQuotaSummary"

	// antigravityUA is agy's exact client User-Agent. retrieveUserQuotaSummary
	// is a PRIVATE API gated on it: without this header Google returns 403
	// PERMISSION_DENIED; with it, 200. Send it on every call. Verified
	// 2026-06-30 via live capture.
	antigravityUA = "antigravity/cli/1.0.13 (aidev_client; os_type=linux; arch=amd64)"

	// antigravityWeekly is the only window Antigravity exposes — a WEEKLY
	// per-group limit (Gemini Models / Claude+GPT). There is no daily/session
	// window, so the device hides the session card (SessionWindowSeconds=0).
	antigravityWeekly = 604800

	// antigravityKeyringService is the OS keyring service under which agy
	// stores its consumer OAuth token. The token is a JSON value
	// {token:{access_token,refresh_token,expiry},…}; only the access_token is
	// read here (agy keeps it fresh while it runs).
	antigravityKeyringService = "gemini"
)

// AntigravityFetcher fetches Antigravity's (agy, successor to the retired
// Gemini CLI) grouped weekly quota. It reads agy's consumer OAuth token from
// the OS keyring (libsecret) — READ-ONLY, never refreshed, per the
// maintainer's choice; agy keeps it fresh while it runs — then POSTs to the
// canary cloudcode-pa host. The grouped response carries one weekly bucket
// per model group (Gemini Models / Claude+GPT); each becomes a Slot, and the
// Gemini group drives the headline weekly bar. Verified end-to-end against the
// live Google API via a mitmproxy capture of agy 1.0.13 (2026-06-30); mirrors
// the JS broker's AntigravityFetcher for wire parity.
//
// Models / ModelsFor are retained only for call-site compatibility with the
// per-device override path (FetchWithModels). The quota is now GROUPED, not
// per-model, so they no longer affect the result.
type AntigravityFetcher struct {
	KeyringService string
	Models         []string
	ModelsFor      func(ctx context.Context) []string
	HTTP           *http.Client
	Now            func() time.Time

	mu        sync.Mutex
	cachedTok geminiAccessToken
}

func (f *AntigravityFetcher) httpClient() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return http.DefaultClient
}

func (f *AntigravityFetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *AntigravityFetcher) keyringService() string {
	if f.KeyringService != "" {
		return f.KeyringService
	}
	return antigravityKeyringService
}

type geminiAccessToken struct {
	Token       string
	ExpiresAtMS int64
}

// FetchWithModels is like Fetch but kept for call-site compatibility with the
// per-device override path. The quota is now grouped (Gemini Models /
// Claude+GPT), not per-model, so `models` is ignored — the broker can keep
// calling this without instantiating a second fetcher (and duplicating the
// token cache).
func (f *AntigravityFetcher) FetchWithModels(ctx context.Context, _ []string) (Snapshot, error) {
	return f.fetchInternal(ctx)
}

// Fetch reads agy's keyring token and POSTs to the canary cloudcode-pa host.
func (f *AntigravityFetcher) Fetch(ctx context.Context) (Snapshot, error) {
	return f.fetchInternal(ctx)
}

func (f *AntigravityFetcher) fetchInternal(ctx context.Context) (Snapshot, error) {
	tok, err := f.token()
	if err != nil {
		return Snapshot{}, err
	}

	// agy sends exactly this: ideType ANTIGRAVITY, no pluginType, no project.
	// The response carries cloudaicompanionProject, used for the quota call.
	raw, _ := json.Marshal(map[string]any{
		"metadata": map[string]any{"ideType": "ANTIGRAVITY"},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, geminiCodeAssistURL, bytes.NewReader(raw))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", antigravityUA)

	resp, err := f.httpClient().Do(req)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == 401:
		return Snapshot{}, ErrUnauthorized
	case resp.StatusCode == 429:
		return Snapshot{}, &RateLimitedError{RetryAfter: retryAfter(resp)}
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return Snapshot{}, fmt.Errorf("%w: status=%d", ErrUpstream, resp.StatusCode)
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	var doc geminiLoadCodeAssistDoc
	if err := json.Unmarshal(respBody, &doc); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}

	// Weekly-only quota: hide the session/daily card, surface the weekly one.
	snap := Snapshot{
		SessionWindowSeconds: 0,
		WeeklyWindowSeconds:  antigravityWeekly,
		Tier:                 "unknown",
	}
	if doc.PaidTier != nil {
		if doc.PaidTier.ID != "" {
			snap.Tier = doc.PaidTier.ID
		} else {
			snap.Tier = "paid"
		}
	} else if doc.CurrentTier != nil {
		if doc.CurrentTier.ID != "" {
			snap.Tier = doc.CurrentTier.ID // typically "free-tier"
		}
	}

	// retrieveUserQuotaSummary carries the grouped weekly buckets. On any
	// error we fall back to the tier-only snapshot (matches the JS broker,
	// which swallows the quota error and keeps the partial snapshot).
	if q, qerr := f.fetchQuota(ctx, tok, doc.CloudAICompanionProject); qerr == nil && q != nil {
		antigravityApplyQuota(&snap, q, f.now())
	}
	return snap, nil
}

func (f *AntigravityFetcher) fetchQuota(ctx context.Context, tok, project string) (*geminiQuotaDoc, error) {
	// retrieveUserQuotaSummary requires a top-level `project` (empty body →
	// 403) and rejects loadCodeAssist-style metadata fields. Verified
	// 2026-06-30 via live capture.
	body := map[string]any{}
	if project != "" {
		body["project"] = project
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, geminiUserQuotaURL, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", antigravityUA)
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status=%d", ErrUpstream, resp.StatusCode)
	}
	body2, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	var q geminiQuotaDoc
	if err := json.Unmarshal(body2, &q); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	return &q, nil
}

// token returns agy's consumer access token from the OS keyring. READ-ONLY:
// per the maintainer's choice we do NOT refresh it — agy keeps it fresh while
// it runs. A missing token surfaces as ErrCredsMissing, an expired one (within
// 60s of expiry) as ErrTokenExpired; the broker maps these to 404/503 and the
// device renders "--" (graceful, no fake data). Mirror of the JS broker's
// AntigravityFetcher._token().
func (f *AntigravityFetcher) token() (string, error) {
	now := f.now()
	f.mu.Lock()
	cached := f.cachedTok
	f.mu.Unlock()
	if cached.Token != "" && cached.ExpiresAtMS-now.UnixMilli() > 60_000 {
		return cached.Token, nil
	}

	t := readKeyringToken(f.keyringService())
	if t == nil || t.AccessToken == "" {
		return "", fmt.Errorf("%w: antigravity keyring token not found (service=%q; sign in with agy)", ErrCredsMissing, f.keyringService())
	}
	var expMS int64
	if t.Expiry != "" {
		if parsed, perr := time.Parse(time.RFC3339, t.Expiry); perr == nil {
			expMS = parsed.UnixMilli()
		}
	}
	if expMS != 0 && expMS-now.UnixMilli() < 60_000 {
		return "", fmt.Errorf("%w: antigravity keyring token expired (run agy to refresh it)", ErrTokenExpired)
	}
	if expMS == 0 {
		expMS = now.UnixMilli() + 300_000
	}
	f.mu.Lock()
	f.cachedTok = geminiAccessToken{Token: t.AccessToken, ExpiresAtMS: expMS}
	f.mu.Unlock()
	return t.AccessToken, nil
}

// keyringToken is the inner `token` object agy stores in the OS keyring.
type keyringToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expiry       string `json:"expiry"`
}

// readKeyringToken pulls agy's consumer OAuth token from the OS keyring
// (libsecret) via `secret-tool lookup service <name>`. The quota RPC requires
// THIS token — the gemini-cli token in oauth_creds.json authenticates
// loadCodeAssist but is rejected (403) by the quota endpoint. Returns the
// inner token object, or nil on any failure (no secret-tool, locked/empty
// keyring, bad JSON) so the fetcher degrades to ErrCredsMissing rather than
// crashing. Mirror of the JS broker's readKeyringToken().
func readKeyringToken(service string) *keyringToken {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "secret-tool", "lookup", "service", service).Output()
	if err != nil {
		return nil
	}
	var d struct {
		Token *keyringToken `json:"token"`
	}
	if err := json.Unmarshal(out, &d); err != nil {
		return nil
	}
	return d.Token
}

// geminiLoadCodeAssistDoc captures the fields we care about from the
// loadCodeAssist response: the tier and the cloudaicompanionProject required
// by the quota call.
type geminiLoadCodeAssistDoc struct {
	CurrentTier *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"currentTier"`
	PaidTier *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"paidTier"`
	CloudAICompanionProject string `json:"cloudaicompanionProject"`
}

// geminiQuotaDoc mirrors the real v1internal:retrieveUserQuotaSummary
// response, captured live from agy 1.0.13 (2026-06-30):
//
//	{"groups":[
//	  {"displayName":"Gemini Models","buckets":[
//	     {"bucketId":"gemini-weekly","window":"weekly","resetTime":"…","remainingFraction":0}]},
//	  {"displayName":"Claude and GPT models","buckets":[
//	     {"bucketId":"3p-weekly","window":"weekly","resetTime":"…","remainingFraction":0.906058}]}]}
//
// Top-level `groups[]` (NOT quotaSummaryGroups). remainingFraction is
// REMAINING (0 = exhausted; pct_used = (1-remainingFraction)*100).
type geminiQuotaDoc struct {
	Groups []geminiQuotaGroup `json:"groups"`
}

type geminiQuotaGroup struct {
	DisplayName string         `json:"displayName"`
	Description string         `json:"description"`
	Buckets     []geminiBucket `json:"buckets"`
}

type geminiBucket struct {
	BucketID          string  `json:"bucketId"`
	Window            string  `json:"window"`
	ResetTime         string  `json:"resetTime"`
	RemainingFraction float64 `json:"remainingFraction"`
}

// antigravityApplyQuota maps the real retrieveUserQuotaSummary response onto
// the device snapshot. Each group becomes one weekly slot; the "Gemini Models"
// group drives the headline weekly bar (maintainer's choice), falling back to
// the first group if no Gemini group is present. Verified against a live
// capture (agy 1.0.13, 2026-06-30). Mirror of the JS broker's
// antigravityApplyQuota().
func antigravityApplyQuota(snap *Snapshot, q *geminiQuotaDoc, now time.Time) {
	if q == nil {
		return
	}
	headlineSet := false
	for _, g := range q.Groups {
		b := pickWeeklyBucket(g.Buckets)
		if b == nil {
			continue
		}
		pct := geminiUsedPct(b.RemainingFraction)
		eta := geminiResetETA(b.ResetTime, now)
		snap.Slots = append(snap.Slots, Slot{
			Label:           antigravityGroupLabel(g.DisplayName),
			Pct:             pct,
			WindowSeconds:   antigravityWeekly,
			ResetETASeconds: eta,
		})
		isGemini := strings.Contains(strings.ToLower(g.DisplayName), "gemini") ||
			strings.HasPrefix(strings.ToLower(b.BucketID), "gemini")
		if isGemini && !headlineSet {
			snap.WeeklyPct = pct
			snap.WeeklyResetETASeconds = eta
			headlineSet = true
		}
	}
	if !headlineSet && len(snap.Slots) > 0 {
		snap.WeeklyPct = snap.Slots[0].Pct
		snap.WeeklyResetETASeconds = snap.Slots[0].ResetETASeconds
	}
}

// pickWeeklyBucket returns the group's weekly bucket (window=="weekly"),
// falling back to the first bucket when none is tagged weekly.
func pickWeeklyBucket(buckets []geminiBucket) *geminiBucket {
	for i := range buckets {
		if buckets[i].Window == "weekly" {
			return &buckets[i]
		}
	}
	if len(buckets) > 0 {
		return &buckets[0]
	}
	return nil
}

// antigravityGroupLabel turns a group's displayName into the short pill text:
// "Gemini Models" → "Gemini", "Claude and GPT models" → "Claude and GPT".
// Capped to the device's 15-char slot label budget. Mirror of the JS broker's
// antigravityGroupLabel().
func antigravityGroupLabel(displayName string) string {
	s := strings.TrimSpace(displayName)
	low := strings.ToLower(s)
	if strings.HasSuffix(low, " models") {
		s = strings.TrimSpace(s[:len(s)-len(" models")])
	}
	if s == "" {
		return "Quota"
	}
	if len(s) > 15 {
		s = s[:15]
	}
	return s
}

// geminiUsedPct converts a REMAINING fraction into a used-percentage,
// clamping to [0,1] defensively. pct_used = (1 - remainingFraction) * 100.
func geminiUsedPct(remainingFraction float64) float64 {
	if remainingFraction < 0 {
		remainingFraction = 0
	} else if remainingFraction > 1 {
		remainingFraction = 1
	}
	return (1 - remainingFraction) * 100
}

// geminiResetETA returns the seconds until an RFC3339 reset time, clamped to
// 0 for an absent/past timestamp.
func geminiResetETA(resetTime string, now time.Time) uint32 {
	if resetTime == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, resetTime)
	if err != nil {
		return 0
	}
	eta := t.Sub(now).Seconds()
	if eta <= 0 {
		return 0
	}
	return uint32(eta)
}
