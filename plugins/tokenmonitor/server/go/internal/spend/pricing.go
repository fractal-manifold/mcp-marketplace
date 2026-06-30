// Model price table: turns token counts into USD. Source of truth is
// LiteLLM's machine-readable table (the same data ccusage uses), fetched
// over HTTP and cached on disk, with an embedded fallback for offline /
// first-run. Kept byte-compatible with js/src/pricing.js and
// py/src/tmon_mcp/pricing.py. See compat/SPEND_WIRE.md ("Pricing").
package spend

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Rate is per-token USD pricing for a model.
type Rate struct {
	Input         float64 `json:"input"`
	Output        float64 `json:"output"`
	CacheRead     float64 `json:"cache_read"`
	CacheCreation float64 `json:"cache_creation"`
}

// FallbackPrices mirrors FALLBACK_PRICES in js/src/pricing.js. Best-effort
// values used only when LiteLLM is unreachable and no disk cache exists.
var FallbackPrices = map[string]Rate{
	"claude-opus-4-8":   {5e-6, 25e-6, 0.5e-6, 6.25e-6},
	"claude-opus-4-7":   {5e-6, 25e-6, 0.5e-6, 6.25e-6},
	"claude-opus-4-6":   {5e-6, 25e-6, 0.5e-6, 6.25e-6},
	"claude-opus-4-5":   {5e-6, 25e-6, 0.5e-6, 6.25e-6},
	"claude-opus-4-1":   {15e-6, 75e-6, 1.5e-6, 18.75e-6},
	"claude-sonnet-4-6": {3e-6, 15e-6, 0.3e-6, 3.75e-6},
	"claude-sonnet-4-5": {3e-6, 15e-6, 0.3e-6, 3.75e-6},
	"claude-haiku-4-5":  {1e-6, 5e-6, 0.1e-6, 1.25e-6},
	"gpt-5":             {1.25e-6, 10e-6, 0.125e-6, 0},
	"gpt-5-codex":       {1.25e-6, 10e-6, 0.125e-6, 0},
	"o4-mini":           {1.1e-6, 4.4e-6, 0.275e-6, 0},
	"gemini-2.5-pro":         {1.25e-6, 10e-6, 0.31e-6, 0},
	"gemini-2.5-flash":       {0.3e-6, 2.5e-6, 0.075e-6, 0},
	"gemini-3-flash-preview": {0.3e-6, 2.5e-6, 0.075e-6, 0},
	// Antigravity (agy) Gemini-family models. Effort-suffixed ids
	// (gemini-3.5-flash-low etc.) resolve by prefix in rate_for.
	"gemini-3.5-flash":       {0.3e-6, 2.5e-6, 0.075e-6, 0},
	"gemini-3.1-pro":         {1.25e-6, 10e-6, 0.31e-6, 0},
}

// PriceTable is an immutable snapshot of model rates plus provenance.
type PriceTable struct {
	rates  map[string]Rate
	Source string // "litellm" | "fallback" | "none"
	Stale  bool
}

func basename(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// RateFor resolves a model id to a rate: exact, basename-after-slash, then
// longest prefix match (covers date-suffixed ids and provider-prefixed
// litellm keys). Returns (zero, false) when unpriced.
func (t *PriceTable) RateFor(model string) (Rate, bool) {
	if model == "" {
		return Rate{}, false
	}
	if r, ok := t.rates[model]; ok {
		return r, true
	}
	base := basename(model)
	if r, ok := t.rates[base]; ok {
		return r, true
	}
	// Deterministic across runtimes: longest basename match, ties broken by
	// the lexicographically smallest full key. Go map iteration is randomized,
	// so without an explicit tie-break the chosen rate (and thus the per-model
	// USD) would differ run-to-run and from the JS/Py impls. See
	// compat/SPEND_WIRE.md.
	bestKey := ""
	bestLen := -1
	found := false
	for key := range t.rates {
		k := basename(key)
		if !(strings.HasPrefix(base, k) || strings.HasPrefix(k, base)) {
			continue
		}
		if len(k) > bestLen || (len(k) == bestLen && (!found || key < bestKey)) {
			bestKey, bestLen, found = key, len(k), true
		}
	}
	if found {
		return t.rates[bestKey], true
	}
	return Rate{}, false
}

// CostFor returns USD for a token bundle; 0 when the model is unpriced
// (the caller still surfaces the real token counts).
func (t *PriceTable) CostFor(model string, b Bundle) float64 {
	r, ok := t.RateFor(model)
	if !ok {
		return 0
	}
	return float64(b.Input)*r.Input +
		float64(b.Output)*r.Output +
		float64(b.CacheRead)*r.CacheRead +
		float64(b.CacheCreation)*r.CacheCreation
}

func fallbackTable() *PriceTable {
	m := make(map[string]Rate, len(FallbackPrices))
	for k, v := range FallbackPrices {
		m[k] = v
	}
	return &PriceTable{rates: m, Source: "fallback"}
}

// litellm entry subset we care about.
type litellmEntry struct {
	InputCostPerToken         *float64 `json:"input_cost_per_token"`
	OutputCostPerToken        *float64 `json:"output_cost_per_token"`
	CacheReadInputTokenCost   float64  `json:"cache_read_input_token_cost"`
	CacheCreationInputTokenCost float64 `json:"cache_creation_input_token_cost"`
}

func parseLiteLLM(raw []byte) (map[string]Rate, error) {
	var doc map[string]litellmEntry
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	m := make(map[string]Rate)
	for key, e := range doc {
		if key == "sample_spec" || e.InputCostPerToken == nil || e.OutputCostPerToken == nil {
			continue
		}
		m[key] = Rate{
			Input:         *e.InputCostPerToken,
			Output:        *e.OutputCostPerToken,
			CacheRead:     e.CacheReadInputTokenCost,
			CacheCreation: e.CacheCreationInputTokenCost,
		}
	}
	if len(m) == 0 {
		return nil, errors.New("pricing table empty")
	}
	return m, nil
}

// Pricing loads and caches the price table. Never fatal: pricing problems
// degrade to fallback/stale, they don't blank the spend response.
type Pricing struct {
	url       string
	cachePath string
	ttl       time.Duration
	client    *http.Client
	logger    Logger

	mu       sync.Mutex
	table    *PriceTable
	loadedAt time.Time
}

// Logger is the minimal logging surface (matches *log.Logger.Printf).
type Logger interface{ Printf(format string, v ...any) }

type diskCache struct {
	FetchedAtMs int64           `json:"fetched_at_ms"`
	Prices      map[string]Rate `json:"prices"`
}

func NewPricing(url, cachePath string, ttlHours int, logger Logger) *Pricing {
	if ttlHours < 1 {
		ttlHours = 1
	}
	return &Pricing{
		url:       url,
		cachePath: cachePath,
		ttl:       time.Duration(ttlHours) * time.Hour,
		client:    &http.Client{Timeout: 20 * time.Second},
		logger:    logger,
	}
}

func (p *Pricing) logf(format string, v ...any) {
	if p.logger != nil {
		p.logger.Printf(format, v...)
	}
}

func (p *Pricing) readDisk() (*diskCache, bool) {
	if p.cachePath == "" {
		return nil, false
	}
	raw, err := os.ReadFile(p.cachePath)
	if err != nil {
		return nil, false
	}
	var dc diskCache
	if err := json.Unmarshal(raw, &dc); err != nil || len(dc.Prices) == 0 {
		return nil, false
	}
	return &dc, true
}

func (p *Pricing) writeDisk(m map[string]Rate, nowMs int64) {
	if p.cachePath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p.cachePath), 0o755); err != nil {
		p.logf("pricing: cache mkdir failed: %v", err)
		return
	}
	raw, err := json.Marshal(diskCache{FetchedAtMs: nowMs, Prices: m})
	if err != nil {
		return
	}
	if err := os.WriteFile(p.cachePath, raw, 0o644); err != nil {
		p.logf("pricing: cache write failed: %v", err)
	}
}

func (p *Pricing) fetchLive(ctx context.Context) (map[string]Rate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("pricing fetch non-2xx")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // cap 8 MiB
	if err != nil {
		return nil, err
	}
	return parseLiteLLM(raw)
}

// Table returns a price table, refreshing if the cache is stale. now lets
// tests pin time.
func (p *Pricing) Table(ctx context.Context, now time.Time) *PriceTable {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.table != nil && now.Sub(p.loadedAt) < p.ttl {
		return p.table
	}
	nowMs := now.UnixMilli()
	disk, hasDisk := p.readDisk()
	if hasDisk && now.Sub(time.UnixMilli(disk.FetchedAtMs)) < p.ttl {
		p.table = &PriceTable{rates: disk.Prices, Source: "litellm"}
		p.loadedAt = now
		return p.table
	}

	m, err := p.fetchLive(ctx)
	if err == nil {
		p.writeDisk(m, nowMs)
		p.table = &PriceTable{rates: m, Source: "litellm"}
		p.loadedAt = now
		return p.table
	}
	p.logf("pricing: live fetch failed (%v); using %s", err, ternary(hasDisk, "stale cache", "fallback"))
	if hasDisk {
		p.table = &PriceTable{rates: disk.Prices, Source: "litellm", Stale: true}
	} else {
		p.table = fallbackTable()
	}
	p.loadedAt = now
	return p.table
}

func ternary(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}
