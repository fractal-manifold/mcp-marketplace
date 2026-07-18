package usage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/creds"
)

const (
	codexUsageURL = "https://chatgpt.com/backend-api/wham/usage"
	codexUA       = "tokenmonitor-mcp/usage"
	// Codex windows DO come back in the response (limit_window_seconds),
	// so these are only fallbacks when upstream omits them.
	codexSessionWindowFallback = 5 * 3600
	codexWeeklyWindowFallback  = 7 * 86400
	codexMonthlyWindowFallback = 30 * 86400

	// Bucket boundaries, keyed on a window's DURATION rather than its
	// position in the response. OpenAI has already reshuffled which window
	// sits in primary_window vs secondary_window once (2026-07); classifying
	// by limit_window_seconds keeps the Session / Weekly / Monthly labels
	// correct no matter which slot each window arrives in, and lets a future
	// monthly window surface without a code change.
	codexSessionMaxSeconds = 5 * 3600   // ≤ 5h        → Session
	codexWeeklyMaxSeconds  = 14 * 86400 // > 5h, ≤ 2wk → Weekly; above → Monthly
)

// codexBucket is the Session / Weekly / Monthly card a Codex window maps to.
type codexBucket int

const (
	codexBucketNone codexBucket = iota
	codexBucketSession
	codexBucketWeekly
	codexBucketMonthly
)

// codexClassify picks a bucket from a window's duration in seconds:
// ≤ 5h is a session window, up to 2 weeks is weekly, and anything longer is
// treated as a monthly window. A zero/unknown duration returns codexBucketNone
// so the caller can fall back to positional heuristics.
func codexClassify(windowSeconds uint32) codexBucket {
	switch {
	case windowSeconds == 0:
		return codexBucketNone
	case windowSeconds <= codexSessionMaxSeconds:
		return codexBucketSession
	case windowSeconds <= codexWeeklyMaxSeconds:
		return codexBucketWeekly
	default:
		return codexBucketMonthly
	}
}

// CodexFetcher reads ~/.codex/auth.json and hits ChatGPT's wham/usage
// endpoint. Refresh-token handling is intentionally NOT done here: the
// Codex CLI manages auth.json with its own write semantics, and racing
// against it from the broker risks corrupting the file. When the JWT
// expires we return ErrTokenExpired and the user runs `codex login`.
type CodexFetcher struct {
	AuthPath string
	HTTP     *http.Client
	Now      func() time.Time
}

func (f *CodexFetcher) httpClient() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return http.DefaultClient
}

func (f *CodexFetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *CodexFetcher) Fetch(ctx context.Context) (Snapshot, error) {
	c, err := creds.LoadCodex(f.AuthPath)
	if err != nil {
		if errors.Is(err, creds.ErrFileMissing) {
			return Snapshot{}, fmt.Errorf("%w: %v", ErrCredsMissing, err)
		}
		return Snapshot{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	if c.IsExpired(f.now()) {
		return Snapshot{}, ErrTokenExpired
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, codexUsageURL, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	if c.AccountID != "" {
		req.Header.Set("ChatGPT-Account-Id", c.AccountID)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", codexUA)
	req.Header.Set("OpenAI-Beta", "chatgpt-account=enabled")

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	var doc codexUsageDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrParseUpstream, err)
	}
	return codexMap(doc), nil
}

// codexUsageDoc captures the fields we need from
//
//	GET /backend-api/wham/usage
//
// (sampled 2026-05-25 from a Plus plan). Other top-level keys we don't
// use: code_review_rate_limit, additional_rate_limits, spend_control,
// promo, referral_beacon, rate_limit_reset_credits.
type codexUsageDoc struct {
	PlanType  string `json:"plan_type"`
	RateLimit struct {
		PrimaryWindow   *codexWindow `json:"primary_window"`
		SecondaryWindow *codexWindow `json:"secondary_window"`
		// TertiaryWindow is not part of any shape OpenAI has shipped yet; it
		// is parsed defensively so that if they ever return three windows
		// (e.g. session + weekly + monthly) the third is classified and
		// rendered without a code change.
		TertiaryWindow *codexWindow `json:"tertiary_window"`
	} `json:"rate_limit"`
}

type codexWindow struct {
	UsedPercent *float64 `json:"used_percent"`
	// LimitWindowSeconds is a float64 (not uint32) so a fractional value
	// coerces the way the js/py runtimes do rather than hard-failing the whole
	// JSON unmarshal. codexWindowSeconds() floors + range-checks it.
	LimitWindowSeconds *float64 `json:"limit_window_seconds"`
	ResetAfterSeconds  *uint32  `json:"reset_after_seconds"`
	ResetAt            *int64   `json:"reset_at"`
}

// codexWindowSeconds coerces limit_window_seconds to a u32 the same way js
// (Math.floor) and py (int()) do: floor the value, and treat a missing, ≤0, or
// out-of-u32-range value as 0 ("unusable"). Parsing the field as float64 keeps
// a fractional value from rejecting the entire response, so the three runtimes
// stay byte-for-byte identical on the same input.
func codexWindowSeconds(w *codexWindow) uint32 {
	if w.LimitWindowSeconds == nil {
		return 0
	}
	v := math.Floor(*w.LimitWindowSeconds)
	if v < 1 || v > 4294967295 { // 0/negative → unusable; overflow → drop
		return 0
	}
	return uint32(v)
}

// codexBucketData accumulates the one window that claimed a bucket.
type codexBucketData struct {
	pct    float64
	window uint32
	eta    uint32
	set    bool
}

func codexMap(d codexUsageDoc) Snapshot {
	snap := Snapshot{Tier: d.PlanType}
	if snap.Tier == "" {
		snap.Tier = "unknown"
	}

	// Windows in wire order. OpenAI currently ships primary + secondary;
	// tertiary is parsed defensively (see codexUsageDoc).
	windows := []*codexWindow{
		d.RateLimit.PrimaryWindow,
		d.RateLimit.SecondaryWindow,
		d.RateLimit.TertiaryWindow,
	}
	present := make([]*codexWindow, 0, len(windows))
	for _, w := range windows {
		if w != nil {
			present = append(present, w)
		}
	}

	var session, weekly, monthly codexBucketData
	claim := func(b *codexBucketData, w *codexWindow, dur uint32) {
		if b.set { // first window to claim a bucket wins
			return
		}
		b.set = true
		if w.UsedPercent != nil {
			b.pct = *w.UsedPercent
		}
		b.window = dur
		b.eta = codexResetETA(w)
	}
	// Classify each window by its DURATION into Session / Weekly / Monthly.
	// A window that omits limit_window_seconds can't be classified, so it
	// falls back to POSITION: a lone window is the account-level weekly cap;
	// with several, the first is the short (session) window and the rest are
	// weekly — matching the pre-2026-07 two-window layout.
	for i, w := range present {
		dur := codexWindowSeconds(w)
		switch codexClassify(dur) {
		case codexBucketSession:
			claim(&session, w, dur)
		case codexBucketWeekly:
			claim(&weekly, w, dur)
		case codexBucketMonthly:
			claim(&monthly, w, dur)
		default: // no usable duration → positional fallback
			if len(present) == 1 || i > 0 {
				claim(&weekly, w, codexWeeklyWindowFallback)
			} else {
				claim(&session, w, codexSessionWindowFallback)
			}
		}
	}

	// Populate the legacy scalar fields the pre-slots firmware still reads.
	// An absent Session/Weekly bucket leaves *WindowSeconds at 0, which the
	// device treats as "hide this card". Monthly has no legacy scalar, so a
	// window longer than 2 weeks surfaces via slots only.
	if session.set {
		snap.SessionPct = session.pct
		snap.SessionWindowSeconds = session.window
		snap.SessionResetETASeconds = session.eta
	}
	if weekly.set {
		snap.WeeklyPct = weekly.pct
		snap.WeeklyWindowSeconds = weekly.window
		snap.WeeklyResetETASeconds = weekly.eta
	}

	// Slots in fixed card order (Session, Weekly, Monthly) for whichever
	// buckets are present — broker-labelled cards, like Antigravity.
	if session.set {
		snap.Slots = append(snap.Slots, Slot{Label: "Session", Pct: session.pct, WindowSeconds: session.window, ResetETASeconds: session.eta})
	}
	if weekly.set {
		snap.Slots = append(snap.Slots, Slot{Label: "Weekly", Pct: weekly.pct, WindowSeconds: weekly.window, ResetETASeconds: weekly.eta})
	}
	if monthly.set {
		snap.Slots = append(snap.Slots, Slot{Label: "Monthly", Pct: monthly.pct, WindowSeconds: monthly.window, ResetETASeconds: monthly.eta})
	}

	// Nothing usable parsed (empty rate_limit, etc.): keep the historical
	// "single empty Weekly card at 0%" default so the device shows a Codex
	// weekly bar rather than a blank provider.
	if len(snap.Slots) == 0 {
		snap.WeeklyWindowSeconds = codexWeeklyWindowFallback
		snap.Slots = []Slot{{Label: "Weekly", WindowSeconds: codexWeeklyWindowFallback}}
	}
	return snap
}

// codexResetETA prefers the upstream's pre-computed reset_after_seconds
// (no clock skew between broker and CLI) and falls back to reset_at minus
// the broker's local clock.
func codexResetETA(w *codexWindow) uint32 {
	if w.ResetAfterSeconds != nil {
		return *w.ResetAfterSeconds
	}
	if w.ResetAt != nil {
		eta := *w.ResetAt - time.Now().Unix()
		if eta > 0 {
			return uint32(eta)
		}
	}
	return 0
}
