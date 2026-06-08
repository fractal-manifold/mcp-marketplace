// Package spend computes per-provider token cost locally from the CLI
// logs on this host and serves it at /spend/{claude,codex,gemini}. No
// admin key, account-local only. Wire-compatible with js/src/spend.js and
// py/src/cwm_mcp/spend.py. See compat/SPEND_WIRE.md.
package spend

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Provider names served at /spend/{name}.
const (
	ProviderClaude = "claude"
	ProviderCodex  = "codex"
	ProviderGemini = "gemini"
)

// MaxModels mirrors CWM_SPEND_MAX_MODELS in the firmware.
const MaxModels = 8

var (
	ErrNotImpl     = errors.New("spend: provider not implemented")
	ErrUnavailable = errors.New("spend: unavailable")
)

// Snapshot is the cross-provider wire shape. JSON tags are byte-exact with
// SPEND_WIRE.md and the JS/Python impls.
type Snapshot struct {
	Currency        string       `json:"currency"`
	HasSubscription bool         `json:"has_subscription"`
	TodayUSD        float64      `json:"today_usd"`
	WeekUSD         float64      `json:"week_usd"`
	MonthUSD        float64      `json:"month_usd"`
	TodayTokens     uint64       `json:"today_tokens"`
	WeekTokens      uint64       `json:"week_tokens"`
	MonthTokens     uint64       `json:"month_tokens"`
	PricingSource   string       `json:"pricing_source"`
	PricingStale    bool         `json:"pricing_stale"`
	Models          []ModelSpend `json:"models"`
	FetchedAtUnix   int64        `json:"fetched_at_unix"`
	StaleSeconds    uint32       `json:"stale_seconds"`
}

// ModelSpend is one month-to-date per-model row.
type ModelSpend struct {
	Model               string  `json:"model"`
	Label               string  `json:"label"`
	InputTokens         uint64  `json:"input_tokens"`
	OutputTokens        uint64  `json:"output_tokens"`
	CacheReadTokens     uint64  `json:"cache_read_tokens"`
	CacheCreationTokens uint64  `json:"cache_creation_tokens"`
	USD                 float64 `json:"usd"`
}

func emptySnapshot() Snapshot {
	return Snapshot{Currency: "USD", PricingSource: "none", Models: []ModelSpend{}}
}

// Bundle is an accumulating token count (used by pricing.CostFor too).
type Bundle struct {
	Input, Output, CacheRead, CacheCreation uint64
}

func (b *Bundle) add(r record) {
	b.Input += r.input
	b.Output += r.output
	b.CacheRead += r.cacheRead
	b.CacheCreation += r.cacheCreation
}
func (b Bundle) total() uint64 { return b.Input + b.Output + b.CacheRead + b.CacheCreation }

type record struct {
	model                              string
	ts                                 time.Time
	input, output, cacheRead, cacheCreation uint64
}

// -----------------------------------------------------------------------
// Time windows (local)
// -----------------------------------------------------------------------

type windows struct{ today, week, month time.Time }

func windowStarts(now time.Time) windows {
	y, m, d := now.Date()
	loc := now.Location()
	today := time.Date(y, m, d, 0, 0, 0, 0, loc)
	// ISO week: Monday start. Weekday() Sunday=0.
	dow := (int(now.Weekday()) + 6) % 7
	week := today.AddDate(0, 0, -dow)
	month := time.Date(y, m, 1, 0, 0, 0, 0, loc)
	return windows{today, week, month}
}

// -----------------------------------------------------------------------
// Accumulation
// -----------------------------------------------------------------------

type acc struct {
	w                  windows
	today, week, month map[string]*Bundle
}

func newAcc(w windows) *acc {
	return &acc{w, map[string]*Bundle{}, map[string]*Bundle{}, map[string]*Bundle{}}
}
func addTo(m map[string]*Bundle, r record) {
	b := m[r.model]
	if b == nil {
		b = &Bundle{}
		m[r.model] = b
	}
	b.add(r)
}
func (a *acc) add(r record) {
	if r.model == "" || r.ts.IsZero() || r.ts.Before(a.w.month) {
		return
	}
	addTo(a.month, r)
	if !r.ts.Before(a.w.week) {
		addTo(a.week, r)
	}
	if !r.ts.Before(a.w.today) {
		addTo(a.today, r)
	}
}

// -----------------------------------------------------------------------
// Labels
// -----------------------------------------------------------------------

var (
	reClaude = regexp.MustCompile(`^claude-(opus|sonnet|haiku)-(\d+)-(\d+)`)
	reGemini = regexp.MustCompile(`^gemini-[\d.]+-([a-z]+)`)
)

func clip15(s string) string {
	if len(s) > 15 {
		return s[:15]
	}
	return s
}

// LabelFor pretty-names a model id (≤15 chars). Mirrors labelFor in JS.
func LabelFor(model string) string {
	if mm := reClaude.FindStringSubmatch(model); mm != nil {
		fam := strings.ToUpper(mm[1][:1]) + mm[1][1:]
		return clip15(fam + " " + mm[2] + "." + mm[3])
	}
	if strings.HasPrefix(strings.ToLower(model), "gpt-") {
		s := "GPT-" + model[4:]
		s = strings.ReplaceAll(s, "-codex", " Codex")
		s = strings.ReplaceAll(s, "-", " ")
		return clip15(s)
	}
	if mm := reGemini.FindStringSubmatch(model); mm != nil {
		return clip15(strings.ToUpper(mm[1][:1]) + mm[1][1:])
	}
	return clip15(model)
}

// -----------------------------------------------------------------------
// File walking + per-file record cache
// -----------------------------------------------------------------------

type fileInfo struct {
	path  string
	mtime int64
	size  int64
}

func listFiles(root string, match func(string) bool) []fileInfo {
	var out []fileInfo
	_ = filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees
		}
		if de.IsDir() || !match(de.Name()) {
			return nil
		}
		info, err := de.Info()
		if err != nil {
			return nil
		}
		out = append(out, fileInfo{p, info.ModTime().UnixMilli(), info.Size()})
		return nil
	})
	return out
}

type cachedFile struct {
	mtime, size int64
	records     []record
}

type fileRecordCache struct {
	mu      sync.Mutex
	entries map[string]cachedFile
}

func newFileRecordCache() *fileRecordCache {
	return &fileRecordCache{entries: map[string]cachedFile{}}
}
func (c *fileRecordCache) get(f fileInfo, parse func(string) []record) []record {
	c.mu.Lock()
	defer c.mu.Unlock()
	if hit, ok := c.entries[f.path]; ok && hit.mtime == f.mtime && hit.size == f.size {
		return hit.records
	}
	recs := parse(f.path)
	c.entries[f.path] = cachedFile{f.mtime, f.size, recs}
	return recs
}

func scanLines(path string, fn func(line []byte)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	// ReadBytes, not bufio.Scanner: agent transcripts contain individual
	// JSON lines tens of MiB long (a single message can embed a huge file
	// dump). Scanner has a max-token cap and silently stops reading the
	// rest of a file once a line exceeds it; ReadBytes grows unbounded.
	r := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if n := len(line); n > 0 {
			if line[n-1] == '\n' {
				line = line[:n-1]
			}
			fn(line)
		}
		if err != nil {
			break
		}
	}
}

func parseISO(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// try without timezone-strictness
		if t2, err2 := time.Parse(time.RFC3339Nano, s); err2 == nil {
			return t2
		}
		return time.Time{}
	}
	return t
}

// -----------------------------------------------------------------------
// Claude — ~/.claude/projects/**/*.jsonl (per-message)
// -----------------------------------------------------------------------

type claudeUsage struct {
	InputTokens             uint64 `json:"input_tokens"`
	OutputTokens            uint64 `json:"output_tokens"`
	CacheReadInputTokens    uint64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens uint64 `json:"cache_creation_input_tokens"`
}
type claudeLine struct {
	Timestamp string `json:"timestamp"`
	Message   *struct {
		Model string       `json:"model"`
		Usage *claudeUsage `json:"usage"`
	} `json:"message"`
}

func claudeRecords(path string) []record {
	var out []record
	scanLines(path, func(line []byte) {
		if len(line) == 0 {
			return
		}
		var o claudeLine
		if json.Unmarshal(line, &o) != nil || o.Message == nil || o.Message.Usage == nil {
			return
		}
		model := o.Message.Model
		if model == "" || model == "<synthetic>" {
			return
		}
		ts := parseISO(o.Timestamp)
		if ts.IsZero() {
			return
		}
		u := o.Message.Usage
		out = append(out, record{
			model: model, ts: ts,
			input: u.InputTokens, output: u.OutputTokens,
			cacheRead: u.CacheReadInputTokens, cacheCreation: u.CacheCreationInputTokens,
		})
	})
	return out
}

// -----------------------------------------------------------------------
// Codex — ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl (accumulated/session)
// -----------------------------------------------------------------------

var reCodexDate = regexp.MustCompile(`(\d{4})/(\d{2})/(\d{2})`)

func codexRecords(path string) []record {
	var (
		model     string
		sessionTs time.Time
		lastTotal *struct {
			Input     uint64 `json:"input_tokens"`
			Cached    uint64 `json:"cached_input_tokens"`
			Output    uint64 `json:"output_tokens"`
			Reasoning uint64 `json:"reasoning_output_tokens"`
		}
	)
	scanLines(path, func(line []byte) {
		if len(line) == 0 {
			return
		}
		var o struct {
			Type        string          `json:"type"`
			Timestamp   string          `json:"timestamp"`
			SessionMeta json.RawMessage `json:"session_meta"`
			Payload     json.RawMessage `json:"payload"`
		}
		if json.Unmarshal(line, &o) != nil {
			return
		}
		if o.Type == "session_meta" || len(o.SessionMeta) > 0 {
			var meta struct {
				Model      string `json:"model"`
				Originator string `json:"originator"`
				Timestamp  string `json:"timestamp"`
			}
			src := o.SessionMeta
			if len(src) == 0 {
				src = o.Payload
			}
			if len(src) > 0 {
				_ = json.Unmarshal(src, &meta)
			}
			if model == "" {
				if meta.Model != "" {
					model = meta.Model
				} else {
					model = meta.Originator
				}
			}
			if sessionTs.IsZero() {
				sessionTs = parseISO(meta.Timestamp)
				if sessionTs.IsZero() {
					sessionTs = parseISO(o.Timestamp)
				}
			}
		}
		// turn_context is a TOP-LEVEL record type; its payload carries the
		// active model, which overrides the session_meta originator.
		if o.Type == "turn_context" && len(o.Payload) > 0 {
			var tc struct {
				Model string `json:"model"`
			}
			if json.Unmarshal(o.Payload, &tc) == nil && tc.Model != "" {
				model = tc.Model
			}
		}
		if len(o.Payload) > 0 {
			var p struct {
				Type string `json:"type"`
				Info *struct {
					Total json.RawMessage `json:"total_token_usage"`
				} `json:"info"`
			}
			if json.Unmarshal(o.Payload, &p) == nil {
				if p.Type == "token_count" && p.Info != nil && len(p.Info.Total) > 0 {
					var t struct {
						Input     uint64 `json:"input_tokens"`
						Cached    uint64 `json:"cached_input_tokens"`
						Output    uint64 `json:"output_tokens"`
						Reasoning uint64 `json:"reasoning_output_tokens"`
					}
					if json.Unmarshal(p.Info.Total, &t) == nil {
						tt := t
						lastTotal = (*struct {
							Input     uint64 `json:"input_tokens"`
							Cached    uint64 `json:"cached_input_tokens"`
							Output    uint64 `json:"output_tokens"`
							Reasoning uint64 `json:"reasoning_output_tokens"`
						})(&tt)
					}
				}
			}
		}
	})
	if lastTotal == nil {
		return nil
	}
	if sessionTs.IsZero() {
		if m := reCodexDate.FindStringSubmatch(filepath.ToSlash(path)); m != nil {
			y := atoi(m[1])
			mo := atoi(m[2])
			d := atoi(m[3])
			sessionTs = time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.Local)
		}
	}
	input := uint64(0)
	if lastTotal.Input > lastTotal.Cached {
		input = lastTotal.Input - lastTotal.Cached
	}
	if model == "" {
		model = "gpt-5-codex"
	}
	return []record{{
		model: model, ts: sessionTs,
		input: input, output: lastTotal.Output + lastTotal.Reasoning,
		cacheRead: lastTotal.Cached, cacheCreation: 0,
	}}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// -----------------------------------------------------------------------
// Gemini — ~/.gemini/tmp/<project>/chats/session-*.jsonl (per-message)
// -----------------------------------------------------------------------

func geminiRecords(path string) []record {
	var out []record
	scanLines(path, func(line []byte) {
		if len(line) == 0 {
			return
		}
		var o struct {
			Type      string `json:"type"`
			Model     string `json:"model"`
			Timestamp string `json:"timestamp"`
			Tokens    *struct {
				Input    uint64 `json:"input"`
				Output   uint64 `json:"output"`
				Cached   uint64 `json:"cached"`
				Thoughts uint64 `json:"thoughts"`
			} `json:"tokens"`
		}
		if json.Unmarshal(line, &o) != nil || o.Type != "gemini" || o.Tokens == nil {
			return
		}
		ts := parseISO(o.Timestamp)
		if ts.IsZero() {
			return
		}
		model := o.Model
		if model == "" {
			model = "gemini-2.5-pro"
		}
		out = append(out, record{
			model: model, ts: ts,
			input: o.Tokens.Input, output: o.Tokens.Output + o.Tokens.Thoughts,
			cacheRead: o.Tokens.Cached, cacheCreation: 0,
		})
	})
	return out
}

// -----------------------------------------------------------------------
// Subscription detection (on-disk)
// -----------------------------------------------------------------------

func claudeHasSubscription(credsPath string) bool {
	raw, err := os.ReadFile(credsPath)
	if err != nil {
		return false
	}
	var doc struct {
		OAuth *struct {
			SubscriptionType string `json:"subscriptionType"`
			RateLimitTier    string `json:"rateLimitTier"`
		} `json:"claudeAiOauth"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.OAuth == nil {
		return false
	}
	sub := strings.ToLower(doc.OAuth.SubscriptionType)
	if sub != "" && sub != "free" {
		return true
	}
	tier := strings.ToLower(doc.OAuth.RateLimitTier)
	return tier != "" && tier != "free"
}

func codexHasSubscription(authPath string) bool {
	raw, err := os.ReadFile(authPath)
	if err != nil {
		return false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	// has_subscription = "quota-based view (%)" vs "pay-as-you-go ($)", NOT
	// "paid plan". A ChatGPT OAuth login consumes against the ChatGPT plan's
	// quota (free or paid alike) → keep showing %. A bare API key is billed
	// per token → show $. We do not distinguish free vs paid ChatGPT: that
	// needs a remote plan_type call, which this local-only endpoint never
	// makes. See compat/SPEND_WIRE.md → Subscription detection.
	for _, k := range []string{"tokens", "access_token", "OPENAI_ACCESS_TOKEN"} {
		if _, ok := doc[k]; ok {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------
// Provider fetcher
// -----------------------------------------------------------------------

// Fetcher computes one provider's spend snapshot.
type Fetcher interface {
	Fetch(ctx context.Context, now time.Time) (Snapshot, error)
}

// priceProvider is the pricing surface providerSpend needs (Pricing
// implements it; tests inject a fixed table).
type priceProvider interface {
	Table(ctx context.Context, now time.Time) *PriceTable
}

type providerSpend struct {
	root      string
	match     func(string) bool
	parse     func(string) []record
	hasSub    func() bool
	pricing   priceProvider
	fileCache *fileRecordCache
}

func (p *providerSpend) Fetch(ctx context.Context, now time.Time) (Snapshot, error) {
	w := windowStarts(now)
	cutoff := w.month.AddDate(0, 0, -1).UnixMilli() // 1-day slack
	files := listFiles(p.root, p.match)

	a := newAcc(w)
	for _, f := range files {
		if f.mtime < cutoff {
			continue
		}
		for _, r := range p.fileCache.get(f, p.parse) {
			a.add(r)
		}
	}

	table := p.pricing.Table(ctx, now)
	snap := emptySnapshot()
	snap.HasSubscription = p.hasSub()
	snap.PricingSource = table.Source
	snap.PricingStale = table.Stale

	// Sum in sorted-key order so the float accumulation order matches the
	// JS/Py impls. Go map iteration is randomized, and float addition is not
	// associative, so an unordered sum could round to a different cent both
	// run-to-run and across runtimes. See compat/SPEND_WIRE.md.
	priceMap := func(m map[string]*Bundle) (usd float64, tokens uint64) {
		keys := make([]string, 0, len(m))
		for model := range m {
			keys = append(keys, model)
		}
		sort.Strings(keys)
		for _, model := range keys {
			b := m[model]
			usd += table.CostFor(model, *b)
			tokens += b.total()
		}
		return
	}
	tu, tt := priceMap(a.today)
	wu, wtk := priceMap(a.week)
	mu, mt := priceMap(a.month)
	snap.TodayUSD, snap.TodayTokens = round2(tu), tt
	snap.WeekUSD, snap.WeekTokens = round2(wu), wtk
	snap.MonthUSD, snap.MonthTokens = round2(mu), mt

	rows := make([]ModelSpend, 0, len(a.month))
	for model, b := range a.month {
		rows = append(rows, ModelSpend{
			Model: model, Label: LabelFor(model),
			InputTokens: b.Input, OutputTokens: b.Output,
			CacheReadTokens: b.CacheRead, CacheCreationTokens: b.CacheCreation,
			USD: round2(table.CostFor(model, *b)),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].USD != rows[j].USD {
			return rows[i].USD > rows[j].USD
		}
		ti := rows[i].InputTokens + rows[i].OutputTokens + rows[i].CacheReadTokens + rows[i].CacheCreationTokens
		tj := rows[j].InputTokens + rows[j].OutputTokens + rows[j].CacheReadTokens + rows[j].CacheCreationTokens
		if ti != tj {
			return ti > tj
		}
		return rows[i].Model < rows[j].Model
	})
	snap.Models = foldModels(rows)
	return snap, nil
}

func foldModels(rows []ModelSpend) []ModelSpend {
	if len(rows) <= MaxModels {
		return rows
	}
	head := append([]ModelSpend{}, rows[:MaxModels-1]...)
	other := ModelSpend{Model: "other", Label: "Other"}
	for _, r := range rows[MaxModels-1:] {
		other.InputTokens += r.InputTokens
		other.OutputTokens += r.OutputTokens
		other.CacheReadTokens += r.CacheReadTokens
		other.CacheCreationTokens += r.CacheCreationTokens
		other.USD += r.USD
	}
	other.USD = round2(other.USD)
	return append(head, other)
}

func round2(x float64) float64 { return math.Round(x*100) / 100 }

// -----------------------------------------------------------------------
// Cache (TTL + stale-with-error, mirrors usage.Cache)
// -----------------------------------------------------------------------

type Cache struct {
	ttl       time.Duration
	now       func() time.Time
	fetchers  map[string]Fetcher
	mu        sync.Mutex
	entries   map[string]cacheEntry
	inFlights map[string]chan cacheResult
	// results holds the outcome of the most recent in-flight fetch per
	// provider, published just before its channel is closed. Closing a
	// channel wakes ALL waiters (a buffered send only reaches one), so the
	// waiters read the shared result from here instead of off the channel.
	results map[string]cacheResult
}

type cacheEntry struct {
	snap     Snapshot
	fetched  time.Time
	hasValue bool
}
type cacheResult struct {
	snap Snapshot
	err  error
}

func NewCache(ttl time.Duration, fetchers map[string]Fetcher) *Cache {
	return &Cache{
		ttl: ttl, now: time.Now, fetchers: fetchers,
		entries: map[string]cacheEntry{}, inFlights: map[string]chan cacheResult{},
		results: map[string]cacheResult{},
	}
}

// Get returns a provider snapshot, refreshing past the TTL. On error,
// returns the last good value (if any) with bumped StaleSeconds AND the
// error so the broker can serve stale-200.
func (c *Cache) Get(ctx context.Context, provider string) (Snapshot, error) {
	f, ok := c.fetchers[provider]
	if !ok {
		return Snapshot{}, ErrNotImpl
	}
	c.mu.Lock()
	e := c.entries[provider]
	if e.hasValue && c.now().Sub(e.fetched) < c.ttl {
		snap := e.snap
		snap.StaleSeconds = uint32(c.now().Sub(e.fetched) / time.Second)
		c.mu.Unlock()
		return snap, nil
	}
	if ch, busy := c.inFlights[provider]; busy {
		c.mu.Unlock()
		select {
		case <-ch: // closed by the leader once results[provider] is published
			c.mu.Lock()
			res := c.results[provider]
			c.mu.Unlock()
			return res.snap, res.err
		case <-ctx.Done():
			return Snapshot{}, ctx.Err()
		}
	}
	ch := make(chan cacheResult) // used only as a broadcast signal via close
	c.inFlights[provider] = ch
	c.mu.Unlock()

	snap, err := f.Fetch(ctx, c.now())
	now := c.now()
	c.mu.Lock()
	delete(c.inFlights, provider)
	var res cacheResult
	if err == nil {
		snap.FetchedAtUnix = now.Unix()
		snap.StaleSeconds = 0
		c.entries[provider] = cacheEntry{snap: snap, fetched: now, hasValue: true}
		res = cacheResult{snap, nil}
	} else if e.hasValue {
		stale := e.snap
		stale.StaleSeconds = uint32(now.Sub(e.fetched) / time.Second)
		res = cacheResult{stale, err}
	} else {
		res = cacheResult{snap, err}
	}
	c.results[provider] = res
	c.mu.Unlock()
	close(ch) // wake every waiter; they read c.results under the lock
	return res.snap, res.err
}

func (c *Cache) Providers() []string {
	out := make([]string, 0, len(c.fetchers))
	for k := range c.fetchers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// -----------------------------------------------------------------------
// Factory
// -----------------------------------------------------------------------

// SpendConfig is the subset of *config.Config that BuildCache needs. The
// broker passes a small adapter so this package doesn't import config.
type SpendConfig struct {
	Enabled            bool
	CacheTTLSeconds    int
	ClaudeProjects     string
	CodexSessions      string
	GeminiTmp          string
	ClaudeCredsPath    string
	CodexAuthPath      string
	CodexEnabled       bool
	GeminiEnabled      bool
	PricingURL         string
	PricingCachePath   string
	PricingTTLHours    int
}

// BuildCache wires the per-provider fetchers. Returns nil when spend is
// disabled.
func BuildCache(c SpendConfig, logger Logger) *Cache {
	if !c.Enabled {
		return nil
	}
	pricing := NewPricing(c.PricingURL, c.PricingCachePath, c.PricingTTLHours, logger)
	fetchers := map[string]Fetcher{
		ProviderClaude: &providerSpend{
			root:      c.ClaudeProjects,
			match:     func(n string) bool { return strings.HasSuffix(n, ".jsonl") },
			parse:     claudeRecords,
			hasSub:    func() bool { return claudeHasSubscription(c.ClaudeCredsPath) },
			pricing:   pricing,
			fileCache: newFileRecordCache(),
		},
	}
	if c.CodexEnabled {
		fetchers[ProviderCodex] = &providerSpend{
			root:      c.CodexSessions,
			match:     func(n string) bool { return strings.HasPrefix(n, "rollout-") && strings.HasSuffix(n, ".jsonl") },
			parse:     codexRecords,
			hasSub:    func() bool { return codexHasSubscription(c.CodexAuthPath) },
			pricing:   pricing,
			fileCache: newFileRecordCache(),
		}
	}
	if c.GeminiEnabled {
		fetchers[ProviderGemini] = &providerSpend{
			root:      c.GeminiTmp,
			match:     func(n string) bool { return strings.HasPrefix(n, "session-") && strings.HasSuffix(n, ".jsonl") },
			parse:     geminiRecords,
			// Always $ for Gemini: free Code-Assist and a paid tier both write
			// the same local oauth_creds.json, so they can't be told apart
			// without a remote call. Default to computed $ rather than guess.
			hasSub: func() bool { return false },
			pricing:   pricing,
			fileCache: newFileRecordCache(),
		}
	}
	ttl := time.Duration(c.CacheTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 300 * time.Second
	}
	if logger != nil {
		ps := make([]string, 0, len(fetchers))
		for k := range fetchers {
			ps = append(ps, k)
		}
		sort.Strings(ps)
		logger.Printf("spend: providers=%v cache_ttl=%s", ps, ttl)
	}
	return NewCache(ttl, fetchers)
}
