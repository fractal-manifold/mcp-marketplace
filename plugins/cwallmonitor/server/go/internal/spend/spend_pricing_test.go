package spend

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// spendPricingVectors is the parsed shape of compat/vectors/spend_pricing.json.
type spendPricingVectors struct {
	Prices map[string]Rate `json:"prices"`
	Cases  []struct {
		Note   string `json:"note"`
		Model  string `json:"model"`
		Tokens struct {
			InputTokens         uint64 `json:"input_tokens"`
			OutputTokens        uint64 `json:"output_tokens"`
			CacheReadTokens     uint64 `json:"cache_read_tokens"`
			CacheCreationTokens uint64 `json:"cache_creation_tokens"`
		} `json:"tokens"`
		ExpectedUSD   float64 `json:"expected_usd"`
		ExpectedCents int64   `json:"expected_cents"`
	} `json:"cases"`
}

// findSpendPricing walks up looking for the authoritative monorepo
// compat/vectors/spend_pricing.json (the same probe pattern auth_test.go
// uses). Skips cleanly in a standalone plugin checkout.
func findSpendPricing(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 9; i++ {
		candidate := filepath.Join(dir, "compat", "vectors", "spend_pricing.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("compat/vectors/spend_pricing.json not found upward from %s (standalone checkout)", wd)
	return ""
}

// TestSpendPricingVectors locks the per-model USD + cents output to the other
// runtimes. The half-cent case in the vector also pins round2() to half-up
// (banker's rounding would diverge).
func TestSpendPricingVectors(t *testing.T) {
	path := findSpendPricing(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v spendPricingVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("compat spend cases empty")
	}
	table := &PriceTable{rates: v.Prices, Source: "fallback"}
	for _, c := range v.Cases {
		b := Bundle{
			Input:         c.Tokens.InputTokens,
			Output:        c.Tokens.OutputTokens,
			CacheRead:     c.Tokens.CacheReadTokens,
			CacheCreation: c.Tokens.CacheCreationTokens,
		}
		wireUSD := round2(table.CostFor(c.Model, b))
		cents := int64(math.Floor(wireUSD*100 + 0.5))
		if wireUSD != c.ExpectedUSD {
			t.Errorf("%s (%s): usd = %v, want %v", c.Note, c.Model, wireUSD, c.ExpectedUSD)
		}
		if cents != c.ExpectedCents {
			t.Errorf("%s (%s): cents = %d, want %d", c.Note, c.Model, cents, c.ExpectedCents)
		}
	}
}
