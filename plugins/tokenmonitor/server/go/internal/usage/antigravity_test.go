package usage

import (
	"math"
	"testing"
	"time"
)

func approxEq(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

// TestAntigravityApplyQuota_Groups locks the real grouped
// retrieveUserQuotaSummary mapping captured live from agy 1.0.13 (2026-06-30):
// each group → one weekly slot, the Gemini Models group drives the headline
// weekly bar. remainingFraction is REMAINING, so pct = (1-frac)*100.
func TestAntigravityApplyQuota_Groups(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	q := &geminiQuotaDoc{Groups: []geminiQuotaGroup{
		{
			DisplayName: "Gemini Models",
			Buckets: []geminiBucket{
				{BucketID: "gemini-weekly", Window: "weekly", ResetTime: "2026-07-07T10:55:39Z", RemainingFraction: 0},
			},
		},
		{
			DisplayName: "Claude and GPT models",
			Buckets: []geminiBucket{
				{BucketID: "3p-weekly", Window: "weekly", ResetTime: "2026-07-07T14:15:06Z", RemainingFraction: 0.906058},
			},
		},
	}}
	snap := Snapshot{}
	antigravityApplyQuota(&snap, q, now)

	if len(snap.Slots) != 2 {
		t.Fatalf("slots: got %d entries want 2 (%+v)", len(snap.Slots), snap.Slots)
	}
	// Gemini Models → "Gemini", 0 remaining → 100% used.
	if snap.Slots[0].Label != "Gemini" || snap.Slots[0].Pct != 100 {
		t.Errorf("slot[0]: got %+v want Gemini/100", snap.Slots[0])
	}
	if snap.Slots[0].WindowSeconds != antigravityWeekly {
		t.Errorf("slot window: got %d want %d", snap.Slots[0].WindowSeconds, antigravityWeekly)
	}
	// "Claude and GPT models" → "Claude and GPT", 0.906058 remaining → ~9.39% used.
	if snap.Slots[1].Label != "Claude and GPT" || !approxEq(snap.Slots[1].Pct, (1-0.906058)*100) {
		t.Errorf("slot[1]: got %+v want 'Claude and GPT'/~9.39", snap.Slots[1])
	}
	// Headline weekly comes from the Gemini group.
	if snap.WeeklyPct != 100 {
		t.Errorf("weekly_pct: got %v want 100 (Gemini headline)", snap.WeeklyPct)
	}
	if snap.WeeklyResetETASeconds == 0 {
		t.Errorf("weekly reset eta should be the Gemini bucket's resetTime, got 0")
	}
}

// TestAntigravityApplyQuota_HeadlineByBucketID exercises the bucketId-based
// Gemini match (displayName not containing "gemini" but bucketId starting with
// "gemini").
func TestAntigravityApplyQuota_HeadlineByBucketID(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	q := &geminiQuotaDoc{Groups: []geminiQuotaGroup{
		{
			DisplayName: "Frontier Models",
			Buckets: []geminiBucket{
				{BucketID: "gemini-weekly", Window: "weekly", ResetTime: "2026-07-07T00:00:00Z", RemainingFraction: 0.25},
			},
		},
	}}
	snap := Snapshot{}
	antigravityApplyQuota(&snap, q, now)
	if snap.WeeklyPct != 75 {
		t.Errorf("weekly_pct: got %v want 75 (bucketId gemini headline)", snap.WeeklyPct)
	}
}

// TestAntigravityApplyQuota_HeadlineFallback: when no group looks like Gemini,
// the first group drives the headline.
func TestAntigravityApplyQuota_HeadlineFallback(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	q := &geminiQuotaDoc{Groups: []geminiQuotaGroup{
		{
			DisplayName: "Claude and GPT models",
			Buckets: []geminiBucket{
				{BucketID: "3p-weekly", Window: "weekly", ResetTime: "2026-07-07T00:00:00Z", RemainingFraction: 0.4},
			},
		},
	}}
	snap := Snapshot{}
	antigravityApplyQuota(&snap, q, now)
	if len(snap.Slots) != 1 {
		t.Fatalf("slots: got %d want 1", len(snap.Slots))
	}
	if !approxEq(snap.WeeklyPct, 60) {
		t.Errorf("weekly_pct fallback: got %v want 60 (first group)", snap.WeeklyPct)
	}
}

// TestAntigravityApplyQuota_WeeklyBucketPick: a group with a non-weekly bucket
// first must still resolve the weekly one.
func TestAntigravityApplyQuota_WeeklyBucketPick(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	q := &geminiQuotaDoc{Groups: []geminiQuotaGroup{
		{
			DisplayName: "Gemini Models",
			Buckets: []geminiBucket{
				{BucketID: "gemini-daily", Window: "daily", ResetTime: "2026-07-01T00:00:00Z", RemainingFraction: 0.9},
				{BucketID: "gemini-weekly", Window: "weekly", ResetTime: "2026-07-07T00:00:00Z", RemainingFraction: 0.1},
			},
		},
	}}
	snap := Snapshot{}
	antigravityApplyQuota(&snap, q, now)
	if len(snap.Slots) != 1 {
		t.Fatalf("slots: got %d want 1", len(snap.Slots))
	}
	if !approxEq(snap.Slots[0].Pct, 90) {
		t.Errorf("expected weekly bucket (0.1 remaining → 90 used), got %v", snap.Slots[0].Pct)
	}
}

func TestAntigravityApplyQuota_NoOpOnNil(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	snap := Snapshot{WeeklyPct: 11}
	antigravityApplyQuota(&snap, nil, now)
	if snap.WeeklyPct != 11 {
		t.Errorf("nil quota must leave snap untouched, got %+v", snap)
	}
}

func TestAntigravityGroupLabel(t *testing.T) {
	cases := map[string]string{
		"Gemini Models":           "Gemini",
		"Claude and GPT models":   "Claude and GPT",
		"  Gemini Models  ":       "Gemini",
		"":                        "Quota",
		"A really long group name": "A really long g", // capped to 15 chars
	}
	for in, want := range cases {
		if got := antigravityGroupLabel(in); got != want {
			t.Errorf("antigravityGroupLabel(%q) = %q want %q", in, got, want)
		}
	}
}

func TestGeminiUsedPct(t *testing.T) {
	if got := geminiUsedPct(0); got != 100 {
		t.Errorf("0 remaining → 100 used, got %v", got)
	}
	if got := geminiUsedPct(1); got != 0 {
		t.Errorf("1 remaining → 0 used, got %v", got)
	}
	if got := geminiUsedPct(-0.5); got != 100 {
		t.Errorf("negative clamps to 0 remaining → 100 used, got %v", got)
	}
	if got := geminiUsedPct(1.5); got != 0 {
		t.Errorf(">1 clamps to 1 remaining → 0 used, got %v", got)
	}
}

func TestGeminiResetETA(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	if got := geminiResetETA("2026-06-30T13:00:00Z", now); got != 3600 {
		t.Errorf("eta: got %d want 3600", got)
	}
	if got := geminiResetETA("2020-01-01T00:00:00Z", now); got != 0 {
		t.Errorf("past reset must be 0, got %d", got)
	}
	if got := geminiResetETA("", now); got != 0 {
		t.Errorf("empty reset must be 0, got %d", got)
	}
}
