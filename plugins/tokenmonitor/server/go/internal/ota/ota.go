// Package ota implements the broker-driven OTA update channel: a periodic
// check of a public GitHub releases repo that auto-stages a pending
// firmware update for matching registered devices.
//
// Flow per check:
//
//  1. Collect the distinct hardware SKUs of all registered devices.
//  2. For each SKU on the STABLE track, GET
//     <repo>/releases/latest/download/update-<SKU>.json. GitHub
//     302-redirects this to the newest non-prerelease release's asset; the
//     stdlib http.Client follows the redirect chain (zero API, no rate
//     limit). For the DEV track there is no "latest prerelease" redirect, so
//     the broker lists releases via the GitHub API once per check and picks
//     the newest immutable vX.Y.Z-dev.<ts> prerelease carrying that SKU.
//  3. Decode the index's manifest_b64 + signature_b64 and verify the
//     Ed25519 signature against the configured keyring. This is defense
//     in depth — the device verifies the same signature again before it
//     installs — but it stops a misconfigured release from ever reaching
//     a device.
//  4. For every device of that SKU whose installed version
//     (Active.FirmwareVersion, packed 8.8.16) is strictly older than the
//     release — and that also clears the anti-rollback floor
//     (Active.MinSecureVersion) — stage a pending carrying the firmware
//     fields. The device picks it up on its next /device/<id>/sync. A
//     release equal to or older than what the device already runs is never
//     announced, so a re-published "latest" can't churn the device.
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
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
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
	// maxReleasesBody caps the GitHub releases-list JSON read to resolve the
	// newest dev prerelease. 100 releases × a few small assets each is well
	// under this; it's a guard, not a tuning knob.
	maxReleasesBody = 4 * 1024 * 1024
	// devReleasesPerPage requests the newest N releases in one page. GitHub
	// returns releases newest-first by created_at, so the newest dev
	// prerelease is always on the first page; we never paginate. Bound caveat:
	// a SKU whose newest dev build is >N releases back (i.e. N other releases
	// were cut without it) would be missed — irrelevant in practice, since a
	// dev publish ships every SKU together at an hourly cadence.
	devReleasesPerPage = 100
)

// Index is the per-SKU update descriptor published as the release asset
// <repo>/releases/latest/download/update-<SKU>.json.
type Index struct {
	Version      string `json:"version"`
	ManifestB64  string `json:"manifest_b64"`
	SignatureB64 string `json:"signature_b64"`
	BinURL       string `json:"bin_url"`
}

// ghAsset / ghRelease are the subset of the GitHub Releases API
// (GET /repos/<owner>/<repo>/releases) the broker reads to locate the
// newest dev prerelease. Dev builds publish IMMUTABLE per-version
// prerelease tags (vX.Y.Z-dev.<ts>) — GitHub has no "latest prerelease"
// redirect, so the broker lists releases and picks the newest by SemVer.
// Stable still rides the zero-API latest/download redirect.
type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName    string    `json:"tag_name"`
	Prerelease bool      `json:"prerelease"`
	Draft      bool      `json:"draft"`
	Assets     []ghAsset `json:"assets"`
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
	// Channel: a manifest carries channel:"dev" for the dev track; stable
	// manifests OMIT it (absent == stable).
	Channel string `json:"channel"`
}

// PackSemver packs the MAJOR.MINOR.PATCH base into the 8.8.16 u32 layout the
// firmware uses for tmon_min_sv (major<<24 | minor<<16 | patch). An optional
// "-dev.<ts>" development prerelease suffix is ignored (the anti-rollback
// floor is base-level). Returns (0, false) on any malformed or out-of-range
// input. Mirrors packed_semver() in tools/tmtools/lib/manifest.py and
// pack_semver_strict() in firmware/components/ota/src/tmon_ota.c.
func PackSemver(v string) (uint32, bool) {
	base := strings.SplitN(v, "-", 2)[0]
	parts := strings.Split(base, ".")
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

// devPrerelease extracts the numeric timestamp from a "-dev.<12 digits>"
// development prerelease suffix (a YYYYMMDDhhmm value). Returns (ts, true) when
// present and well-formed, (0, false) when the string carries no such suffix
// OR the suffix is malformed (wrong marker, not exactly 12 digits, trailing
// junk). The fixed 12-digit width keeps the value well within uint64 / JS
// Number / Python int so ordering is identical across runtimes.
func devPrerelease(v string) (uint64, bool) {
	const marker = "-dev."
	i := strings.Index(v, marker)
	if i < 0 {
		return 0, false
	}
	ts := v[i+len(marker):]
	if len(ts) != 12 || !allDigits(ts) {
		return 0, false
	}
	n, err := strconv.ParseUint(ts, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ValidVersion reports whether v is a well-formed firmware version under the
// project's grammar: MAJOR.MINOR.PATCH (packable into 8.8.16) with an OPTIONAL
// "-dev.<12 digits>" development prerelease suffix and NOTHING else. The broker
// gates signed manifests on this so it never stages a version the firmware's
// stricter semver_ok() would refuse (which would churn stage -> on-device
// reject -> re-stage). Lock-step with semver_ok() in tmon_manifest.c.
func ValidVersion(v string) bool {
	if _, ok := PackSemver(v); !ok {
		return false
	}
	i := strings.Index(v, "-")
	if i < 0 {
		return true // plain MAJOR.MINOR.PATCH
	}
	_, ok := devPrerelease(v[i:])
	return ok
}

// CompareSemver orders two version strings under the project's SemVer subset:
// the MAJOR.MINOR.PATCH base plus an optional "-dev.<ts>" development
// prerelease. Returns (sign, true) where sign is -1/0/1 (a<b / a==b / a>b), or
// (0, false) if either string isn't a parseable version. Ordering: a differing
// base wins; with equal bases a final build (no suffix) is NEWER than a
// prerelease, and two prereleases compare by their numeric <ts> (larger =
// newer). This is the SemVer rule (X.Y.Z-pre < X.Y.Z). Wire-identical to the
// JS/Python brokers; the firmware never needs it (only the broker orders dev
// builds — the device clears its pending by string equality + the base floor).
func CompareSemver(a, b string) (int, bool) {
	pa, oka := PackSemver(a)
	pb, okb := PackSemver(b)
	if !oka || !okb {
		return 0, false
	}
	if pa != pb {
		if pa < pb {
			return -1, true
		}
		return 1, true
	}
	ta, hasA := devPrerelease(a)
	tb, hasB := devPrerelease(b)
	switch {
	case !hasA && !hasB:
		return 0, true
	case !hasA: // a is final, b is prerelease -> a is newer
		return 1, true
	case !hasB: // b is final, a is prerelease -> a is older
		return -1, true
	case ta < tb:
		return -1, true
	case ta > tb:
		return 1, true
	default:
		return 0, true
	}
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

// SKUResult reports the outcome of resolving one (SKU, channel) release.
type SKUResult struct {
	SKU           string `json:"sku"`
	Channel       string `json:"channel"`
	LatestVersion string `json:"latest_version,omitempty"`
	Verified      bool   `json:"verified"`
	Error         string `json:"error,omitempty"`
}

// DeviceResult reports what the check decided for one device.
type DeviceResult struct {
	DeviceID string `json:"device_id"`
	SKU      string `json:"sku"`
	Channel  string `json:"channel"`
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
		rep.Note = "ota auto-staging is not active: set [ota].enabled, releases_repo and at least one [[ota.keys]] in tokenmonitor.toml"
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

	// Filter devices and collect the (SKU, channel) pairs we need to
	// resolve. One release lookup per distinct (SKU, channel): a dev S1
	// device and a stable S1 device pull different assets, so the SKU
	// alone is not the key.
	skuFilter = strings.ToUpper(strings.TrimSpace(skuFilter))
	deviceFilter = strings.ToLower(strings.TrimSpace(deviceFilter))
	var wanted []*registry.Device
	type target struct{ sku, channel string }
	targets := map[string]target{}
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
		// A dev unit consumes BOTH stable and dev (CandidateChannels), so it
		// can contribute two targets; the newest-wins choice is made per
		// device below.
		for _, ch := range registry.CandidateChannels(dev) {
			targets[dev.HWSku+"/"+ch] = target{sku: dev.HWSku, channel: ch}
		}
	}

	// Dev resolution needs the GitHub releases listing (no "latest
	// prerelease" redirect exists). Fetch it ONCE per check, and only if a
	// dev target is actually in scope — a stable-only fleet makes zero API
	// calls. A listing failure is recorded and surfaced per dev SKU below.
	var devRels []ghRelease
	var devErr error
	for _, t := range targets {
		if t.channel != "" && t.channel != "stable" {
			devRels, devErr = c.listDevReleases(ctx)
			break
		}
	}

	// Resolve each (SKU, channel) signed release once, iterating in a
	// stable sorted key order so the report is deterministic.
	resolvedByKey := map[string]*resolved{}
	keys := make([]string, 0, len(targets))
	for k := range targets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t := targets[k]
		r, sres := c.resolveSKU(ctx, t.sku, t.channel, devRels, devErr)
		rep.PerSKU = append(rep.PerSKU, sres)
		if r != nil {
			resolvedByKey[k] = r
		}
	}

	// Decide + (optionally) stage per device.
	for _, dev := range wanted {
		// Across the device's candidate channels, pick the resolved release
		// with the NEWEST version by SemVer: a final X.Y.Z beats a same-base
		// X.Y.Z-dev.<ts> prerelease, and a newer dev timestamp beats an older
		// one. A dev unit thus rides whichever of stable/dev is ahead (so a
		// freshly cut stable graduates it off an older dev tip); a production
		// unit only ever resolves stable. Ties prefer stable (first in
		// CandidateChannels).
		var best *resolved
		bestChannel := registry.EffectiveChannel(dev)
		for _, ch := range registry.CandidateChannels(dev) {
			r := resolvedByKey[dev.HWSku+"/"+ch]
			if r == nil {
				continue
			}
			if best == nil {
				best = r
				bestChannel = ch
				continue
			}
			if cmp, ok := CompareSemver(r.mf.Version, best.mf.Version); ok && cmp > 0 {
				best = r
				bestChannel = ch
			}
		}
		if best == nil {
			rep.Devices = append(rep.Devices, DeviceResult{
				DeviceID: dev.DeviceID, SKU: dev.HWSku, Channel: registry.EffectiveChannel(dev), Action: "skipped:no-release",
			})
			continue
		}
		res := c.decide(dev, best, dryRun)
		res.Channel = bestChannel
		if res.Action == "staged" {
			rep.Staged++
		}
		rep.Devices = append(rep.Devices, res)
	}
	return rep, nil
}

// resolveSKU fetches, verifies and parses the release index for a (SKU,
// channel). Returns (nil, SKUResult{Error}) on any failure. `channel` is
// the device's effective channel ("stable" or "dev"); want collapses ""
// to "stable" defensively.
func (c *Checker) resolveSKU(ctx context.Context, sku, channel string, devRels []ghRelease, devErr error) (*resolved, SKUResult) {
	want := channel
	if want == "" {
		want = "stable"
	}
	sres := SKUResult{SKU: sku, Channel: want}
	if want == "dev" && devErr != nil {
		sres.Error = devErr.Error()
		return nil, sres
	}
	idx, err := c.fetchIndex(ctx, sku, channel, devRels)
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
	// Channel must match what we asked for. Stable manifests OMIT the
	// field (absent == stable); dev manifests carry channel:"dev". This is
	// a sanity check on the signed authority — the device re-checks it too,
	// and refuses a dev manifest outright on a production unit.
	manChan := mf.Channel
	if manChan == "" {
		manChan = "stable"
	}
	if manChan != want {
		sres.Error = fmt.Sprintf("manifest channel %q != requested %q", manChan, want)
		return nil, sres
	}
	if !strings.HasPrefix(idx.BinURL, "https://") {
		sres.Error = "bin_url must be HTTPS"
		return nil, sres
	}
	if !ValidVersion(mf.Version) {
		sres.Error = "manifest version is not MAJOR.MINOR.PATCH[-dev.<12 digits>]"
		return nil, sres
	}
	sres.Verified = true
	return &resolved{idx: idx, mf: mf}, sres
}

// decide computes the action for one device against a resolved release,
// staging a pending when appropriate (unless dryRun).
func (c *Checker) decide(dev *registry.Device, r *resolved, dryRun bool) DeviceResult {
	out := DeviceResult{DeviceID: dev.DeviceID, SKU: dev.HWSku, Channel: registry.EffectiveChannel(dev), To: r.mf.Version}
	releasePacked, ok := PackSemver(r.mf.Version)
	if !ok {
		out.Action = "skipped:bad-version"
		return out
	}
	// Revert tombstone: never AUTO-stage the exact version the operator just
	// reverted the device away from (tokenmonitor_revert records it in
	// BlockedFirmwareVersion). A NEWER release (a fixed 0.9.2 over a blocked
	// 0.9.1) still stages — we match on version equality only. Manual
	// set_device_pending / publish bypass this path entirely. The tombstone is
	// cleared on /sync once the device reports a newer version.
	if dev.BlockedFirmwareVersion != "" && r.mf.Version == dev.BlockedFirmwareVersion {
		out.Action = "skipped:blocked-version"
		return out
	}
	out.From = dev.Active.FirmwareVersion
	// Primary guard: never announce a release that isn't STRICTLY newer than
	// the version the device is actually running. Active.FirmwareVersion is
	// the last version we saw the device promote, i.e. what's installed.
	// MinSecureVersion is only the anti-rollback FLOOR, which a manifest can
	// (and usually does) set BELOW its own version to leave room for limited
	// rollback — so comparing the release to the floor alone re-stages a
	// version the device already runs, and the device just re-downloads and
	// rejects it as same-version every cycle. That churn is exactly what this
	// check prevents. Skipped only when we don't yet have a parseable running
	// version (fresh device), in which case the floor guard below decides.
	// Uses CompareSemver (not raw packed base) so dev iteration works: two
	// "0.6.8-dev.<ts>" builds share a base, and the newer timestamp must still
	// stage over the older — base-only packing would wrongly call them equal.
	if cmp, ok := CompareSemver(r.mf.Version, dev.Active.FirmwareVersion); ok && cmp <= 0 {
		out.Action = "up_to_date"
		return out
	}
	// Secondary guard (defense in depth): respect the reported anti-rollback
	// floor. The device refuses only packed(version) STRICTLY BELOW the floor
	// (tmon_ota.c: `mf_packed < floor`), so mirror that with `<` — NOT `<=`.
	// A release packing EQUAL to the floor is installable on-device; with `<=`
	// the broker would wrongly skip a newer same-base dev canary (X.Y.Z-dev.<ts2>
	// packs to the same base as a matured X.Y.Z floor) that the device accepts.
	if releasePacked < dev.Active.MinSecureVersion {
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

// apiReleasesURL maps the public releases repo URL to the GitHub Releases
// API listing endpoint. For a github.com repo it rewrites
// https://github.com/<owner>/<repo> → https://api.github.com/repos/<owner>/
// <repo>/releases; for any other host (self-hosted mirror / test server) it
// appends /releases, so a test can intercept the same path shape.
// githubToken returns an optional API token from the environment to lift
// the unauthenticated rate limit; empty (unauthenticated) is fine for a
// public repo at the broker's hourly cadence.
func githubToken() string {
	if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
		return t
	}
	return strings.TrimSpace(os.Getenv("GH_TOKEN"))
}

func isGitHubRepo(repo string) bool {
	return strings.HasPrefix(strings.TrimRight(repo, "/"), "https://github.com/")
}

func apiReleasesURL(repo string) string {
	base := strings.TrimRight(repo, "/")
	const gh = "https://github.com/"
	q := fmt.Sprintf("?per_page=%d", devReleasesPerPage)
	if rest, ok := strings.CutPrefix(base, gh); ok {
		return "https://api.github.com/repos/" + rest + "/releases" + q
	}
	return base + "/releases" + q
}

// listDevReleases fetches the newest page of releases and returns them
// newest-first (as GitHub orders them). Used only when a dev device is in
// scope; stable resolution never calls it (no API, no rate limit). An
// optional GITHUB_TOKEN / GH_TOKEN in the environment raises the
// unauthenticated 60/h rate limit, but is not required for a public repo.
func (c *Checker) listDevReleases(ctx context.Context) ([]ghRelease, error) {
	url := apiReleasesURL(c.cfg.OTA.ReleasesRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "tokenmonitor-mcp-ota")
	// Only ever send a GitHub credential to GitHub itself — never leak it to a
	// self-hosted mirror configured as releases_repo.
	if isGitHubRepo(c.cfg.OTA.ReleasesRepo) {
		if tok := githubToken(); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list releases %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list releases %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReleasesBody))
	if err != nil {
		return nil, fmt.Errorf("read releases %s: %w", url, err)
	}
	var rels []ghRelease
	if err := json.Unmarshal(body, &rels); err != nil {
		return nil, fmt.Errorf("decode releases %s: %w", url, err)
	}
	return rels, nil
}

// pickDevAsset selects, among the dev prereleases, the NEWEST one (by
// CompareSemver on the tag's version) that actually carries an
// update-<SKU>.json asset, and returns that version + the release tag. A
// release qualifies only if it is flagged prerelease (and NOT draft) and its
// tag is a valid X.Y.Z-dev.<ts> version — a stray non-dev, non-prerelease or
// draft release is ignored. Picking per-SKU (not "the newest dev release") is
// deliberate: a dev publish that ships only S1 must not hide an older S2 dev
// build. We return the tag (not the listing's browser_download_url) so the
// caller builds the asset URL from the TRUSTED repo base — the listing is
// untrusted metadata and must never steer the broker to an arbitrary host.
func pickDevAsset(rels []ghRelease, sku string) (version, tag string, ok bool) {
	want := "update-" + sku + ".json"
	for _, r := range rels {
		if !r.Prerelease || r.Draft {
			continue
		}
		ver := strings.TrimPrefix(r.TagName, "v")
		dash := strings.Index(ver, "-")
		if dash < 0 {
			continue // a final X.Y.Z is never a dev build
		}
		if _, isDev := devPrerelease(ver[dash:]); !isDev || !ValidVersion(ver) {
			continue
		}
		has := false
		for _, a := range r.Assets {
			if a.Name == want {
				has = true
				break
			}
		}
		if !has {
			continue
		}
		if !ok {
			version, tag, ok = ver, r.TagName, true
			continue
		}
		if cmp, cok := CompareSemver(ver, version); cok && cmp > 0 {
			version, tag = ver, r.TagName
		}
	}
	return version, tag, ok
}

// fetchIndex GETs the update-<SKU>.json release asset for one (SKU,
// channel). Stable rides GitHub's latest/download redirect (newest
// non-prerelease, zero API). Dev resolves the newest immutable
// vX.Y.Z-dev.<ts> prerelease carrying this SKU from the pre-fetched
// `devRels` listing, then GETs that release's asset — so a dev device never
// sees a stable build and a stable device never sees a prerelease. The
// stdlib client follows GitHub's cross-host redirect chain
// (github.com → objects.githubusercontent.com) automatically.
func (c *Checker) fetchIndex(ctx context.Context, sku, channel string, devRels []ghRelease) (Index, error) {
	base := strings.TrimRight(c.cfg.OTA.ReleasesRepo, "/")
	var url string
	if channel != "" && channel != "stable" {
		_, tag, found := pickDevAsset(devRels, sku)
		if !found {
			return Index{}, fmt.Errorf("no dev prerelease carrying update-%s.json among %d release(s)", sku, len(devRels))
		}
		// Build the asset URL from the TRUSTED repo base + tag (same shape as
		// the stable latest/download path and the publisher's bin_url), not
		// from the listing's browser_download_url — never let untrusted
		// listing metadata point the fetch at an arbitrary host.
		url = base + "/releases/download/" + tag + "/update-" + sku + ".json"
	} else {
		url = base + "/releases/latest/download/update-" + sku + ".json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Index{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tokenmonitor-mcp-ota")
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
