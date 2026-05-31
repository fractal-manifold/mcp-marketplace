// Package ota implements the broker-driven OTA update channel: a periodic
// check of a public GitHub releases repo that auto-stages a pending
// firmware update for matching registered devices.
//
// Flow per check:
//
//  1. Collect the distinct hardware SKUs of all registered devices.
//  2. For each SKU, GET <repo>/releases/latest/download/update-<SKU>.json.
//     GitHub 302-redirects this to the newest non-prerelease release's
//     asset; the stdlib http.Client follows the redirect chain.
//  3. Decode the index's manifest_b64 + signature_b64 and verify the
//     Ed25519 signature against the configured keyring. This is defense
//     in depth — the device verifies the same signature again before it
//     installs — but it stops a misconfigured release from ever reaching
//     a device.
//  4. For every device of that SKU whose installed version (mirrored in
//     Active.MinSecureVersion as packed 8.8.16) is older than the
//     release, stage a pending carrying the firmware fields. The device
//     picks it up on its next /device/<id>/sync.
//
// The broker never holds a signing key — only public verification keys.
// A compromised or misconfigured broker cannot forge a manifest, and the
// on-device gate_manifest remains the ultimate authority.
package ota

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fractal-manifold/cwm-mcp/internal/config"
	"github.com/fractal-manifold/cwm-mcp/internal/registry"
)

const (
	// defaultPollInterval is used when [ota].poll_interval_minutes is unset
	// or non-positive. minPollInterval is a floor so a misconfigured tiny
	// value can't hammer GitHub.
	defaultPollMinutes = 60
	minPollMinutes     = 5
	// initialDelay lets the broker settle (and any clock/SNTP on the host
	// is already fine) before the first check after leadership is acquired.
	initialDelay = 30 * time.Second
	httpTimeout  = 10 * time.Second
	maxIndexBody = 64 * 1024 // an update-<SKU>.json is well under 1 KiB
)

// Index is the per-SKU update descriptor published as the release asset
// <repo>/releases/latest/download/update-<SKU>.json.
type Index struct {
	Version      string `json:"version"`
	ManifestB64  string `json:"manifest_b64"`
	SignatureB64 string `json:"signature_b64"`
	BinURL       string `json:"bin_url"`
}

// manifestFields is the subset of the canonical OTA manifest the broker
// inspects for the staging decision. The manifest bytes are
// signature-verified as-is; this struct only reads fields, never
// re-encodes (re-encoding could diverge from the signed canonical form).
type manifestFields struct {
	KeyID            string `json:"key_id"`
	MinSecureVersion uint32 `json:"min_secure_version"`
	SHA256           string `json:"sha256"`
	SKU              string `json:"sku"`
	Version          string `json:"version"`
}

// PackSemver packs MAJOR.MINOR.PATCH into the 8.8.16 u32 layout the
// firmware uses for cwm_min_sv (major<<24 | minor<<16 | patch). Returns
// (0, false) on any malformed or out-of-range input. Mirrors
// packed_semver() in tools/cwmtools/lib/manifest.py and
// pack_semver_strict() in firmware/components/ota/src/cwm_ota.c.
func PackSemver(v string) (uint32, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, false
	}
	nums := [3]int{}
	for i, p := range parts {
		if p == "" || !allDigits(p) {
			return 0, false
		}
		// Reject leading zeros (except the literal "0") to match the
		// firmware's strict semver gate.
		if len(p) > 1 && p[0] == '0' {
			return 0, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0, false
		}
		nums[i] = n
	}
	maj, min, pat := nums[0], nums[1], nums[2]
	if maj > 0xff || min > 0xff || pat > 0xffff {
		return 0, false
	}
	return uint32(maj)<<24 | uint32(min)<<16 | uint32(pat), true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// VerifyManifest reports whether sig is a valid Ed25519 signature over
// manifest bytes under pubkey (32-byte raw public key, 64-byte sig).
func VerifyManifest(pubkey, manifest, sig []byte) bool {
	if len(pubkey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubkey), manifest, sig)
}

// Checker performs one or more OTA checks against the configured repo and
// keyring, staging pendings into the registry.
type Checker struct {
	cfg    *config.Config
	reg    *registry.Registry
	client *http.Client
	logger *log.Logger
}

// NewChecker builds a Checker. logger may be nil (used by the on-demand
// MCP tool, which has no logger to share).
func NewChecker(cfg *config.Config, reg *registry.Registry, logger *log.Logger) *Checker {
	return &Checker{
		cfg:    cfg,
		reg:    reg,
		client: &http.Client{Timeout: httpTimeout},
		logger: logger,
	}
}

func (c *Checker) logf(format string, args ...any) {
	if c.logger != nil {
		c.logger.Printf("ota: "+format, args...)
	}
}

// SKUResult reports the outcome of resolving one SKU's latest release.
type SKUResult struct {
	SKU           string `json:"sku"`
	LatestVersion string `json:"latest_version,omitempty"`
	Verified      bool   `json:"verified"`
	Error         string `json:"error,omitempty"`
}

// DeviceResult reports what the check decided for one device.
type DeviceResult struct {
	DeviceID string `json:"device_id"`
	SKU      string `json:"sku"`
	Action   string `json:"action"` // staged | would_stage | up_to_date | skipped:<reason> | error:<reason>
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
}

// Report is the structured result of a Check, returned to the MCP tool
// and logged by the background loop.
type Report struct {
	Repo      string         `json:"repo"`
	Enabled   bool           `json:"enabled"`
	Configured bool          `json:"configured"`
	DryRun    bool           `json:"dry_run"`
	CheckedAt time.Time      `json:"checked_at"`
	PerSKU    []SKUResult    `json:"per_sku"`
	Devices   []DeviceResult `json:"devices"`
	Note      string         `json:"note,omitempty"`
	Staged    int            `json:"staged"`
}

// resolved bundles a verified index + parsed manifest for a SKU.
type resolved struct {
	idx Index
	mf  manifestFields
}

// Check runs one pass. dryRun=true reports without writing. skuFilter (if
// non-empty) restricts to one SKU; deviceFilter (if non-empty) restricts
// staging to one device id.
func (c *Checker) Check(ctx context.Context, dryRun bool, skuFilter, deviceFilter string) (Report, error) {
	o := c.cfg.OTA
	rep := Report{
		Repo:       o.ReleasesRepo,
		Enabled:    o.Enabled,
		Configured: o.Configured(),
		DryRun:     dryRun,
		CheckedAt:  time.Now().UTC(),
		PerSKU:     []SKUResult{},
		Devices:    []DeviceResult{},
	}
	if !o.Configured() {
		rep.Note = "ota auto-staging is not active: set [ota].enabled, releases_repo and at least one [[ota.keys]] in cwm.toml"
		return rep, nil
	}
	if c.reg == nil {
		rep.Note = "device registry unavailable"
		return rep, nil
	}

	devices, err := c.reg.List()
	if err != nil {
		return rep, fmt.Errorf("list devices: %w", err)
	}

	// Filter devices and collect the SKUs we need to resolve.
	skuFilter = strings.ToUpper(strings.TrimSpace(skuFilter))
	deviceFilter = strings.ToLower(strings.TrimSpace(deviceFilter))
	var wanted []*registry.Device
	skuSet := map[string]bool{}
	for _, dev := range devices {
		if dev.HWSku == "" {
			continue
		}
		if deviceFilter != "" && dev.DeviceID != deviceFilter {
			continue
		}
		if skuFilter != "" && dev.HWSku != skuFilter {
			continue
		}
		wanted = append(wanted, dev)
		skuSet[dev.HWSku] = true
	}

	// Resolve each SKU's latest signed release once.
	resolvedBySKU := map[string]*resolved{}
	for sku := range skuSet {
		r, sres := c.resolveSKU(ctx, sku)
		rep.PerSKU = append(rep.PerSKU, sres)
		if r != nil {
			resolvedBySKU[sku] = r
		}
	}

	// Decide + (optionally) stage per device.
	for _, dev := range wanted {
		r := resolvedBySKU[dev.HWSku]
		if r == nil {
			rep.Devices = append(rep.Devices, DeviceResult{
				DeviceID: dev.DeviceID, SKU: dev.HWSku, Action: "skipped:no-release",
			})
			continue
		}
		res := c.decide(dev, r, dryRun)
		if res.Action == "staged" {
			rep.Staged++
		}
		rep.Devices = append(rep.Devices, res)
	}
	return rep, nil
}

// resolveSKU fetches, verifies and parses the latest release index for a
// SKU. Returns (nil, SKUResult{Error}) on any failure.
func (c *Checker) resolveSKU(ctx context.Context, sku string) (*resolved, SKUResult) {
	sres := SKUResult{SKU: sku}
	idx, err := c.fetchIndex(ctx, sku)
	if err != nil {
		sres.Error = err.Error()
		return nil, sres
	}
	sres.LatestVersion = idx.Version

	man, err := base64.StdEncoding.DecodeString(strings.TrimSpace(idx.ManifestB64))
	if err != nil || len(man) == 0 {
		sres.Error = "manifest_b64 decode failed"
		return nil, sres
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(idx.SignatureB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		sres.Error = "signature_b64 decode failed or wrong length"
		return nil, sres
	}
	var mf manifestFields
	if err := json.Unmarshal(man, &mf); err != nil {
		sres.Error = "manifest is not valid JSON"
		return nil, sres
	}
	pub, ok := c.cfg.OTA.Pubkey(mf.KeyID)
	if !ok {
		sres.Error = "no pubkey configured for key_id " + mf.KeyID
		return nil, sres
	}
	if !VerifyManifest(pub, man, sig) {
		sres.Error = "Ed25519 signature verify failed"
		return nil, sres
	}
	// Sanity: the manifest's SKU must match the index we asked for, and
	// the index version must match the manifest version (the index is
	// untrusted metadata; the manifest is the signed authority).
	if mf.SKU != sku {
		sres.Error = fmt.Sprintf("manifest sku %q != requested %q", mf.SKU, sku)
		return nil, sres
	}
	if idx.Version != mf.Version {
		sres.Error = fmt.Sprintf("index version %q != manifest version %q", idx.Version, mf.Version)
		return nil, sres
	}
	if !strings.HasPrefix(idx.BinURL, "https://") {
		sres.Error = "bin_url must be HTTPS"
		return nil, sres
	}
	if _, ok := PackSemver(mf.Version); !ok {
		sres.Error = "manifest version is not MAJOR.MINOR.PATCH"
		return nil, sres
	}
	sres.Verified = true
	return &resolved{idx: idx, mf: mf}, sres
}

// decide computes the action for one device against a resolved release,
// staging a pending when appropriate (unless dryRun).
func (c *Checker) decide(dev *registry.Device, r *resolved, dryRun bool) DeviceResult {
	out := DeviceResult{DeviceID: dev.DeviceID, SKU: dev.HWSku, To: r.mf.Version}
	releasePacked, ok := PackSemver(r.mf.Version)
	if !ok {
		out.Action = "skipped:bad-version"
		return out
	}
	out.From = dev.Active.FirmwareVersion
	// Compare against the device's reported anti-rollback floor, which the
	// firmware bumps to packed(running) after a successful boot. A release
	// at or below the floor is already installed (or would be refused
	// on-device anyway).
	if releasePacked <= dev.Active.MinSecureVersion {
		out.Action = "up_to_date"
		return out
	}
	// Avoid churning the config version: if a pending already carries this
	// exact firmware version, leave it.
	if dev.Pending != nil && dev.Pending.FirmwareVersion == r.mf.Version {
		out.Action = "skipped:already-pending"
		return out
	}
	if dryRun {
		out.Action = "would_stage"
		return out
	}
	update := registry.ConfigPayload{
		FirmwareURL:            r.idx.BinURL,
		FirmwareSHA256:         r.mf.SHA256,
		FirmwareVersion:        r.mf.Version,
		FirmwareManifestB64:    r.idx.ManifestB64,
		FirmwareManifestSigB64: r.idx.SignatureB64,
	}
	if _, err := c.reg.SetPending(dev.DeviceID, update); err != nil {
		out.Action = "error:" + err.Error()
		return out
	}
	c.logf("staged %s -> %s for device %s (sku=%s)", out.From, r.mf.Version, dev.DeviceID, dev.HWSku)
	out.Action = "staged"
	return out
}

// fetchIndex GETs the update-<SKU>.json release asset. The stdlib client
// follows GitHub's cross-host redirect chain (github.com →
// objects.githubusercontent.com) automatically.
func (c *Checker) fetchIndex(ctx context.Context, sku string) (Index, error) {
	url := strings.TrimRight(c.cfg.OTA.ReleasesRepo, "/") +
		"/releases/latest/download/update-" + sku + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Index{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cwm-mcp-ota")
	resp, err := c.client.Do(req)
	if err != nil {
		return Index{}, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Index{}, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexBody))
	if err != nil {
		return Index{}, fmt.Errorf("read %s: %w", url, err)
	}
	var idx Index
	if err := json.Unmarshal(body, &idx); err != nil {
		return Index{}, fmt.Errorf("decode %s: %w", url, err)
	}
	if idx.Version == "" || idx.ManifestB64 == "" || idx.SignatureB64 == "" || idx.BinURL == "" {
		return Index{}, fmt.Errorf("%s missing required fields", url)
	}
	return idx, nil
}

// Run is the background poll loop. It returns immediately (logging once)
// when OTA is not configured, and otherwise ticks every poll interval
// until ctx is cancelled (e.g. the leader loses the bind). Intended to be
// launched with `go ota.Run(...)` inside the leader's lifecycle.
func Run(ctx context.Context, cfg *config.Config, reg *registry.Registry, logger *log.Logger) {
	if cfg == nil || !cfg.OTA.Configured() {
		if logger != nil {
			logger.Printf("ota: auto-staging inactive (enabled=%t repo=%q keys=%d)",
				cfg != nil && cfg.OTA.Enabled,
				ifaceRepo(cfg), ifaceKeys(cfg))
		}
		return
	}
	if reg == nil {
		logger.Printf("ota: registry unavailable, auto-staging disabled")
		return
	}
	interval := time.Duration(cfg.OTA.PollIntervalMinutes) * time.Minute
	if cfg.OTA.PollIntervalMinutes <= 0 {
		interval = defaultPollMinutes * time.Minute
	}
	if interval < minPollMinutes*time.Minute {
		interval = minPollMinutes * time.Minute
	}
	logger.Printf("ota: auto-staging active, repo=%s interval=%s", cfg.OTA.ReleasesRepo, interval)

	checker := NewChecker(cfg, reg, logger)
	timer := time.NewTimer(initialDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		rep, err := checker.Check(ctx, false, "", "")
		if err != nil {
			logger.Printf("ota: check failed: %v", err)
		} else {
			logger.Printf("ota: check done, staged=%d skus=%d devices=%d",
				rep.Staged, len(rep.PerSKU), len(rep.Devices))
		}
		timer.Reset(interval)
	}
}

func ifaceRepo(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return cfg.OTA.ReleasesRepo
}

func ifaceKeys(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	return len(cfg.OTA.Keys)
}
