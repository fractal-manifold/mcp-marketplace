package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/cwm-mcp/internal/config"
	"github.com/fractal-manifold/cwm-mcp/internal/registry"
)

// deviceSummary is the trimmed view exposed by wall_monitor_list_devices.
// Anything secret (PSK bytes/hex) stays out — callers see whether a
// rotation is queued without learning the keys themselves.
type deviceSummary struct {
	DeviceID         string    `json:"device_id"`
	SerialNumber     string    `json:"serial_number,omitempty"`
	HWSku            string    `json:"hw_sku,omitempty"`
	Channel          string    `json:"channel"`
	ActiveVersion    uint32    `json:"active_version"`
	ActiveBrokerURL  string    `json:"active_broker_url,omitempty"`
	ActiveCity       string    `json:"active_city,omitempty"`
	ActiveProviders  []string  `json:"active_providers,omitempty"`
	MinSecureVersion uint32    `json:"min_secure_version,omitempty"`
	LastSeen         time.Time `json:"last_seen,omitempty"`
	HasPending       bool      `json:"has_pending"`
	PendingVersion   uint32    `json:"pending_version,omitempty"`
	PendingChanges   []string  `json:"pending_changes,omitempty"`
	PendingCreatedAt time.Time `json:"pending_created_at,omitempty"`
}

// providerNames flattens a ProviderModeSet into the slice of enabled
// (non-disabled) provider names so the JSON stays compact and human-readable.
func providerNames(p *registry.ProviderModeSet) []string {
	if p == nil {
		return nil
	}
	var out []string
	if p.Claude.Enabled() {
		out = append(out, "claude")
	}
	if p.Codex.Enabled() {
		out = append(out, "codex")
	}
	if p.Gemini.Enabled() {
		out = append(out, "gemini")
	}
	return out
}

// pendingChanges enumerates which fields the pending payload would alter
// relative to active. Useful so the operator sees "rotating PSK + city"
// instead of having to diff two opaque blobs in their head.
func pendingChanges(active, pending registry.ConfigPayload) []string {
	var diffs []string
	if pending.BrokerURL != "" && pending.BrokerURL != active.BrokerURL {
		diffs = append(diffs, "broker_url")
	}
	if pending.PSKHex != "" && pending.PSKHex != active.PSKHex {
		diffs = append(diffs, "psk_hex (key rotation)")
	}
	if pending.City != "" && pending.City != active.City {
		diffs = append(diffs, "city")
	}
	if pending.BrDay != nil && (active.BrDay == nil || *pending.BrDay != *active.BrDay) {
		diffs = append(diffs, "br_day")
	}
	if pending.BrNight != nil && (active.BrNight == nil || *pending.BrNight != *active.BrNight) {
		diffs = append(diffs, "br_night")
	}
	if pending.Vol != nil && (active.Vol == nil || *pending.Vol != *active.Vol) {
		diffs = append(diffs, "vol")
	}
	if pending.ProviderModes != nil &&
		(active.ProviderModes == nil || *pending.ProviderModes != *active.ProviderModes) {
		diffs = append(diffs, "providers")
	}
	if pending.AutorotateEnabled != nil {
		if active.AutorotateEnabled == nil || *active.AutorotateEnabled != *pending.AutorotateEnabled {
			diffs = append(diffs, "autorotate_enabled")
		}
	}
	if pending.AutorotateIntervalS != nil {
		if active.AutorotateIntervalS == nil || *active.AutorotateIntervalS != *pending.AutorotateIntervalS {
			diffs = append(diffs, "autorotate_interval_s")
		}
	}
	if pending.ThemeMode != "" && pending.ThemeMode != active.ThemeMode {
		diffs = append(diffs, "theme_mode")
	}
	if pending.GeminiModels != nil && !stringSliceEqual(active.GeminiModels, pending.GeminiModels) {
		diffs = append(diffs, "gemini_models")
	}
	if pending.LogEnabled != nil {
		if active.LogEnabled == nil || *active.LogEnabled != *pending.LogEnabled {
			diffs = append(diffs, "log_enabled")
		}
	}
	if pending.FirmwareVersion != "" && pending.FirmwareVersion != active.FirmwareVersion {
		diffs = append(diffs, "firmware: "+pending.FirmwareVersion)
	}
	return diffs
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func summarise(dev *registry.Device) deviceSummary {
	s := deviceSummary{
		DeviceID:         dev.DeviceID,
		SerialNumber:     dev.SerialNumber,
		HWSku:            dev.HWSku,
		Channel:          registry.EffectiveChannel(dev),
		ActiveVersion:    dev.Active.Version,
		ActiveBrokerURL:  dev.Active.BrokerURL,
		ActiveCity:       dev.Active.City,
		ActiveProviders:  providerNames(dev.Active.ProviderModes),
		MinSecureVersion: dev.Active.MinSecureVersion,
		LastSeen:         dev.Active.LastSeen,
	}
	if dev.Pending != nil {
		s.HasPending = true
		s.PendingVersion = dev.Pending.Version
		s.PendingChanges = pendingChanges(dev.Active.ConfigPayload, dev.Pending.ConfigPayload)
		s.PendingCreatedAt = dev.Pending.CreatedAt
	}
	return s
}

func registryUnavailable() *mcp.CallToolResult {
	return mcp.NewToolResultErrorFromErr(
		"registry disabled",
		errors.New("device registry is not configured on this cwm-mcp install; configure ~/.config/claude-wall-monitor/devices/ and retry"),
	)
}

func handleListDevices(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Registry == nil {
			return registryUnavailable(), nil
		}
		devs, err := d.Registry.List()
		if err != nil {
			return mcp.NewToolResultErrorFromErr("list", err), nil
		}
		out := make([]deviceSummary, 0, len(devs))
		for _, dev := range devs {
			out = append(out, summarise(dev))
		}
		return mcp.NewToolResultJSON(struct {
			Count   int             `json:"count"`
			Devices []deviceSummary `json:"devices"`
		}{Count: len(out), Devices: out})
	}
}

func handleRegisterDevice(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Registry == nil {
			return registryUnavailable(), nil
		}
		deviceID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))
		brokerURL := strings.TrimSpace(req.GetString("broker_url", ""))
		pskHex := strings.ToLower(strings.TrimSpace(req.GetString("psk_hex", "")))

		if !registry.ValidDeviceID(deviceID) {
			return mcp.NewToolResultError("device_id must be 8 lowercase hex chars"), nil
		}
		if brokerURL == "" {
			return mcp.NewToolResultError("broker_url required"), nil
		}
		if len(pskHex) != 64 {
			return mcp.NewToolResultError("psk_hex must be exactly 64 hex chars"), nil
		}
		if _, err := hex.DecodeString(pskHex); err != nil {
			return mcp.NewToolResultError("psk_hex is not valid hex"), nil
		}

		// Release channel is a device-level attribute, NOT part of the
		// config payload. "" = auto-derive the track from the serial;
		// "stable" / "dev" pin it.
		channel := ""
		if raw := strings.TrimSpace(req.GetString("channel", "")); raw != "" {
			ch, ok := validChannelArg(raw)
			if !ok {
				return mcp.NewToolResultError("channel must be 'stable' or 'dev'"), nil
			}
			channel = ch
		}

		payload := registry.ConfigPayload{
			BrokerURL: brokerURL,
			PSKHex:    pskHex,
		}
		payload.City = strings.TrimSpace(req.GetString("city", ""))
		if v := req.GetFloat("br_day", 0); v > 0 {
			u8 := clamp8(uint8(v), 10, 100)
			payload.BrDay = &u8
		}
		if v := req.GetFloat("br_night", 0); v > 0 {
			u8 := clamp8(uint8(v), 5, 100)
			payload.BrNight = &u8
		}
		if v := req.GetFloat("vol", -1); v >= 0 {
			u8 := clamp8(uint8(v), 0, 100)
			payload.Vol = &u8
		}

		dev, err := d.Registry.Register(deviceID, payload, channel)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("register", err), nil
		}
		return mcp.NewToolResultJSON(struct {
			OK     bool          `json:"ok"`
			Device deviceSummary `json:"device"`
		}{OK: true, Device: summarise(dev)})
	}
}

func handleSetDevicePending(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Registry == nil {
			return registryUnavailable(), nil
		}
		deviceID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))
		if !registry.ValidDeviceID(deviceID) {
			return mcp.NewToolResultError("device_id must be 8 lowercase hex chars"), nil
		}

		// Release channel is a device-level attribute (steers which GitHub
		// asset the OTA loop fetches), NOT part of the config pending.
		// Apply it immediately, before any pending merge.
		if raw := strings.TrimSpace(req.GetString("channel", "")); raw != "" {
			ch, ok := validChannelArg(raw)
			if !ok {
				return mcp.NewToolResultError("channel must be 'stable' or 'dev'"), nil
			}
			if err := d.Registry.SetChannel(deviceID, ch); err != nil {
				if errors.Is(err, registry.ErrNotFound) {
					return mcp.NewToolResultError(fmt.Sprintf("device %s not registered — call wall_monitor_register_device first", deviceID)), nil
				}
				return mcp.NewToolResultErrorFromErr("set_channel", err), nil
			}
		}

		var update registry.ConfigPayload
		if v := strings.TrimSpace(req.GetString("broker_url", "")); v != "" {
			update.BrokerURL = v
		}
		if v := strings.ToLower(strings.TrimSpace(req.GetString("psk_hex", ""))); v != "" {
			if len(v) != 64 {
				return mcp.NewToolResultError("psk_hex must be exactly 64 hex chars"), nil
			}
			if _, err := hex.DecodeString(v); err != nil {
				return mcp.NewToolResultError("psk_hex is not valid hex"), nil
			}
			update.PSKHex = v
		}
		if v := strings.TrimSpace(req.GetString("city", "")); v != "" {
			update.City = v
		}
		if v := req.GetFloat("br_day", 0); v > 0 {
			u8 := clamp8(uint8(v), 10, 100)
			update.BrDay = &u8
		}
		if v := req.GetFloat("br_night", 0); v > 0 {
			u8 := clamp8(uint8(v), 5, 100)
			update.BrNight = &u8
		}
		if v := req.GetFloat("vol", -1); v >= 0 {
			u8 := clamp8(uint8(v), 0, 100)
			update.Vol = &u8
		}

		// Providers: build the mode triple if any per-provider arg was
		// supplied — either the rich provider_mode_<p> string enum
		// (auto/disabled/subscription/api_key) or the legacy provider_<p>
		// bool (true→auto, false→disabled). We need *all three* in NVS to
		// be deterministic, so we read the device's current view (pending,
		// else active) and override only what changed. The string arg wins
		// over the bool arg when both are present for a provider.
		anyProv := req.GetArguments()
		base := registry.ProviderModeSet{
			Claude: registry.ProviderModeAuto,
			Codex:  registry.ProviderModeDisabled,
			Gemini: registry.ProviderModeDisabled,
		}
		anySupplied := false
		for _, k := range []string{
			"provider_claude", "provider_codex", "provider_gemini",
			"provider_mode_claude", "provider_mode_codex", "provider_mode_gemini",
		} {
			if _, ok := anyProv[k]; ok {
				anySupplied = true
				break
			}
		}
		if anySupplied {
			cur, err := d.Registry.Load(deviceID)
			if err != nil {
				return mcp.NewToolResultErrorFromErr("load", err), nil
			}
			if cur.Pending != nil && cur.Pending.ProviderModes != nil {
				base = *cur.Pending.ProviderModes
			} else if cur.Active.ProviderModes != nil {
				base = *cur.Active.ProviderModes
			}
			apply := func(field *registry.ProviderMode, boolKey, modeKey string) error {
				if _, ok := anyProv[modeKey]; ok {
					s := req.GetString(modeKey, string(*field))
					if !registry.ValidProviderMode(s) {
						return fmt.Errorf("%s: invalid mode %q (want auto/disabled/subscription/api_key)", modeKey, s)
					}
					*field = registry.ProviderMode(s)
				} else if _, ok := anyProv[boolKey]; ok {
					*field = registry.ProviderModeFromBool(req.GetBool(boolKey, field.Enabled()))
				}
				return nil
			}
			if err := apply(&base.Claude, "provider_claude", "provider_mode_claude"); err != nil {
				return mcp.NewToolResultErrorFromErr("providers", err), nil
			}
			if err := apply(&base.Codex, "provider_codex", "provider_mode_codex"); err != nil {
				return mcp.NewToolResultErrorFromErr("providers", err), nil
			}
			if err := apply(&base.Gemini, "provider_gemini", "provider_mode_gemini"); err != nil {
				return mcp.NewToolResultErrorFromErr("providers", err), nil
			}
			update.ProviderModes = &base
		}

		if _, ok := anyProv["autorotate_enabled"]; ok {
			v := req.GetBool("autorotate_enabled", false)
			update.AutorotateEnabled = &v
		}
		if _, ok := anyProv["autorotate_interval_s"]; ok {
			v := uint16(req.GetFloat("autorotate_interval_s", 30))
			if v < 1 {
				v = 1
			}
			if v > 300 {
				v = 300
			}
			update.AutorotateIntervalS = &v
		}

		if v := strings.TrimSpace(req.GetString("theme_mode", "")); v != "" {
			tm := strings.ToLower(v)
			if tm != "day" && tm != "night" && tm != "auto" {
				return mcp.NewToolResultError("theme_mode must be one of: day, night, auto"), nil
			}
			update.ThemeMode = tm
		}

		// gemini_models: comma-separated list. Empty string clears the
		// override (signalled by an empty-but-non-nil slice; mergePayload
		// then replaces the stored list).
		if raw, ok := req.GetArguments()["gemini_models"]; ok {
			models := parseGeminiModels(fmt.Sprint(raw))
			if len(models) > 3 {
				return mcp.NewToolResultError("gemini_models must list at most 3 entries"), nil
			}
			if models == nil {
				models = []string{}
			}
			update.GeminiModels = models
		}

		if _, ok := anyProv["log_enabled"]; ok {
			v := req.GetBool("log_enabled", false)
			update.LogEnabled = &v
		}

		// Firmware fields ride the same pending blob. All-or-nothing on
		// the device side, so reject partial specifications upfront with
		// a clear message rather than silently dropping them.
		fu := strings.TrimSpace(req.GetString("firmware_url", ""))
		fs := strings.ToLower(strings.TrimSpace(req.GetString("firmware_sha256", "")))
		fv := strings.TrimSpace(req.GetString("firmware_version", ""))
		if fu != "" || fs != "" || fv != "" {
			if fu == "" || fs == "" || fv == "" {
				return mcp.NewToolResultError("firmware_url, firmware_sha256 and firmware_version must be supplied together"), nil
			}
			if !strings.HasPrefix(fu, "https://") {
				return mcp.NewToolResultError("firmware_url must be HTTPS"), nil
			}
			if len(fs) != 64 {
				return mcp.NewToolResultError("firmware_sha256 must be 64 lowercase hex chars"), nil
			}
			if _, err := hex.DecodeString(fs); err != nil {
				return mcp.NewToolResultError("firmware_sha256 is not valid hex"), nil
			}
			if len(fv) > 31 {
				return mcp.NewToolResultError("firmware_version must be ≤31 chars"), nil
			}
			update.FirmwareURL = fu
			update.FirmwareSHA256 = fs
			update.FirmwareVersion = fv
		}

		// Schema v2: signed manifest envelope. Optional in this call so
		// CI can stage unsigned firmware against dev units, but a
		// production device built without CWM_OTA_UNSIGNED will refuse
		// to install an OTA whose pending lacks these fields. We do
		// NOT parse the manifest here for sku/min_sv (the operator may
		// be staging a manifest the broker doesn't have a pubkey for);
		// the device-side gate is authoritative.
		if mb := strings.TrimSpace(req.GetString("firmware_manifest_b64", "")); mb != "" {
			if len(mb) > 4096 {
				return mcp.NewToolResultError("firmware_manifest_b64 exceeds 4 KiB"), nil
			}
			update.FirmwareManifestB64 = mb
		}
		if sb := strings.TrimSpace(req.GetString("firmware_manifest_sig_b64", "")); sb != "" {
			if len(sb) > 128 {
				return mcp.NewToolResultError("firmware_manifest_sig_b64 looks wrong (Ed25519 sig is 64 B → ~88 base64 chars)"), nil
			}
			update.FirmwareManifestSigB64 = sb
		}
		// Pair check: if either manifest field is present, BOTH must be.
		if (update.FirmwareManifestB64 == "") != (update.FirmwareManifestSigB64 == "") {
			return mcp.NewToolResultError("firmware_manifest_b64 and firmware_manifest_sig_b64 must be supplied together"), nil
		}

		dev, err := d.Registry.SetPending(deviceID, update)
		if err != nil {
			if errors.Is(err, registry.ErrNotFound) {
				return mcp.NewToolResultError(fmt.Sprintf("device %s not registered — call wall_monitor_register_device first", deviceID)), nil
			}
			return mcp.NewToolResultErrorFromErr("set_pending", err), nil
		}
		return mcp.NewToolResultJSON(struct {
			OK     bool          `json:"ok"`
			Device deviceSummary `json:"device"`
		}{OK: true, Device: summarise(dev)})
	}
}

// parseGeminiModels splits a comma-separated list of model IDs and
// trims whitespace. Returns an empty slice (not nil) when the input is
// empty after trimming, so callers can distinguish "clear the override"
// (empty slice) from "field not provided" (nil).
func parseGeminiModels(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return []string{}
	}
	parts := strings.Split(trimmed, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// validChannelArg accepts "stable"/"dev" (and, defensively, any 1..7
// lowercase letters for a future channel). Returns the canonical string
// and ok=false if invalid. "" / "stable" both map to "stable". Mirror of
// JS validChannelArg.
var channelArgRe = regexp.MustCompile(`^[a-z]{1,7}$`)

func validChannelArg(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || s == "stable" {
		return "stable", true
	}
	if channelArgRe.MatchString(s) {
		return s, true
	}
	return "", false
}

func clamp8(v, lo, hi uint8) uint8 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// handleRevertFirmware stages a pending whose firmware fields point at
// a previous version. Anti-rollback: the broker rejects the call
// upfront if the target's min_secure_version is below the device's
// active min_secure_version (the device would refuse anyway, this
// just spares a round trip and surfaces the constraint to the
// operator).
//
// The operator supplies the target's firmware_url / firmware_sha256 /
// firmware_version + the signed manifest blobs. The broker doesn't
// keep history of past manifests yet (planned: service.toml
// [ota.history]); for now the operator pastes them in.
func handleRevertFirmware(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Registry == nil {
			return registryUnavailable(), nil
		}
		deviceID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))
		if !registry.ValidDeviceID(deviceID) {
			return mcp.NewToolResultError("device_id must be 8 lowercase hex chars"), nil
		}
		fu := strings.TrimSpace(req.GetString("firmware_url", ""))
		fs := strings.ToLower(strings.TrimSpace(req.GetString("firmware_sha256", "")))
		fv := strings.TrimSpace(req.GetString("firmware_version", ""))
		mb := strings.TrimSpace(req.GetString("firmware_manifest_b64", ""))
		sb := strings.TrimSpace(req.GetString("firmware_manifest_sig_b64", ""))
		targetSV := uint32(req.GetFloat("target_min_secure_version", 0))

		if fu == "" || fs == "" || fv == "" || mb == "" || sb == "" {
			return mcp.NewToolResultError("revert requires firmware_url, firmware_sha256, firmware_version, firmware_manifest_b64 and firmware_manifest_sig_b64"), nil
		}
		if !strings.HasPrefix(fu, "https://") {
			return mcp.NewToolResultError("firmware_url must be HTTPS"), nil
		}
		if len(fs) != 64 {
			return mcp.NewToolResultError("firmware_sha256 must be 64 lowercase hex chars"), nil
		}
		if _, err := hex.DecodeString(fs); err != nil {
			return mcp.NewToolResultError("firmware_sha256 is not valid hex"), nil
		}

		dev, err := d.Registry.Load(deviceID)
		if err != nil {
			if errors.Is(err, registry.ErrNotFound) {
				return mcp.NewToolResultError(fmt.Sprintf("device %s not registered", deviceID)), nil
			}
			return mcp.NewToolResultErrorFromErr("load", err), nil
		}
		if targetSV > 0 && targetSV < dev.Active.MinSecureVersion {
			return mcp.NewToolResultError(fmt.Sprintf(
				"revert blocked by anti-rollback: target min_secure_version=%d < device floor=%d. "+
					"To downgrade, issue a new firmware with min_secure_version below %d, signed by the KSK.",
				targetSV, dev.Active.MinSecureVersion, dev.Active.MinSecureVersion)), nil
		}

		update := registry.ConfigPayload{
			FirmwareURL:            fu,
			FirmwareSHA256:         fs,
			FirmwareVersion:        fv,
			FirmwareManifestB64:    mb,
			FirmwareManifestSigB64: sb,
		}
		dev2, err := d.Registry.SetPending(deviceID, update)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("set_pending", err), nil
		}
		return mcp.NewToolResultJSON(struct {
			OK      bool          `json:"ok"`
			Reverts string        `json:"reverts_to"`
			Device  deviceSummary `json:"device"`
		}{OK: true, Reverts: fv, Device: summarise(dev2)})
	}
}

// handlePublishFirmware copies a freshly-built .bin into the broker's
// firmware directory, computes its SHA-256 and stages a pending update
// pointing the device at it via /firmware/<file>. Two modes:
//
//  1. external_url: caller hosts the binary themselves (S3, GitHub
//     Releases). bin_path is ignored, sha256_hex is required, URL is
//     used verbatim.
//  2. local hosting (default): bin_path is required and must exist;
//     the file is copied to <firmware_dir>/cwm-<version>.bin, SHA is
//     computed, and firmware_url is built from the device's active
//     broker_url + /firmware/cwm-<version>.bin.
//
// Both paths end in registry.SetPending so the next /sync sees the
// pending blob and the firmware/components/ota task on-device takes
// over.
func handlePublishFirmware(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Registry == nil {
			return registryUnavailable(), nil
		}
		deviceID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))
		if !registry.ValidDeviceID(deviceID) {
			return mcp.NewToolResultError("device_id must be 8 lowercase hex chars"), nil
		}
		version := strings.TrimSpace(req.GetString("firmware_version", ""))
		if version == "" {
			return mcp.NewToolResultError("firmware_version is required"), nil
		}
		if len(version) > 31 {
			return mcp.NewToolResultError("firmware_version must be ≤31 chars"), nil
		}
		if strings.ContainsAny(version, "/\\ \t") {
			return mcp.NewToolResultError("firmware_version must not contain whitespace or path separators"), nil
		}

		dev, err := d.Registry.Load(deviceID)
		if err != nil {
			if errors.Is(err, registry.ErrNotFound) {
				return mcp.NewToolResultError(fmt.Sprintf("device %s not registered — call wall_monitor_register_device first", deviceID)), nil
			}
			return mcp.NewToolResultErrorFromErr("load", err), nil
		}

		var firmwareURL, shaHex string
		external := strings.TrimSpace(req.GetString("external_url", ""))

		if external != "" {
			if !strings.HasPrefix(external, "https://") {
				return mcp.NewToolResultError("external_url must be HTTPS"), nil
			}
			shaHex = strings.ToLower(strings.TrimSpace(req.GetString("sha256_hex", "")))
			if len(shaHex) != 64 {
				return mcp.NewToolResultError("sha256_hex required (64 hex chars) when external_url is set"), nil
			}
			if _, err := hex.DecodeString(shaHex); err != nil {
				return mcp.NewToolResultError("sha256_hex is not valid hex"), nil
			}
			firmwareURL = external
		} else {
			binPath := strings.TrimSpace(req.GetString("bin_path", ""))
			if binPath == "" {
				return mcp.NewToolResultError("bin_path required when external_url is not set"), nil
			}
			src, err := os.Open(binPath)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("cannot open bin_path: %v", err)), nil
			}
			defer src.Close()

			firmwareDir := config.FirmwarePath()
			if err := os.MkdirAll(firmwareDir, 0o755); err != nil {
				return mcp.NewToolResultErrorFromErr("mkdir firmware dir", err), nil
			}
			fileName := "cwm-" + version + ".bin"
			dstPath := filepath.Join(firmwareDir, fileName)
			tmpPath := dstPath + ".tmp"
			dst, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return mcp.NewToolResultErrorFromErr("open dst", err), nil
			}
			h := sha256.New()
			mw := io.MultiWriter(dst, h)
			if _, err := io.Copy(mw, src); err != nil {
				dst.Close()
				os.Remove(tmpPath)
				return mcp.NewToolResultErrorFromErr("copy", err), nil
			}
			if err := dst.Sync(); err != nil {
				dst.Close()
				os.Remove(tmpPath)
				return mcp.NewToolResultErrorFromErr("fsync", err), nil
			}
			if err := dst.Close(); err != nil {
				os.Remove(tmpPath)
				return mcp.NewToolResultErrorFromErr("close", err), nil
			}
			if err := os.Rename(tmpPath, dstPath); err != nil {
				os.Remove(tmpPath)
				return mcp.NewToolResultErrorFromErr("rename", err), nil
			}
			shaHex = hex.EncodeToString(h.Sum(nil))

			base := strings.TrimRight(dev.Active.BrokerURL, "/")
			if base == "" {
				return mcp.NewToolResultError("device has no active broker_url; cannot build firmware_url. Re-register the device first."), nil
			}
			firmwareURL = base + "/firmware/" + fileName
		}

		update := registry.ConfigPayload{
			FirmwareURL:     firmwareURL,
			FirmwareSHA256:  shaHex,
			FirmwareVersion: version,
		}
		dev2, err := d.Registry.SetPending(deviceID, update)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("set_pending", err), nil
		}
		return mcp.NewToolResultJSON(struct {
			OK             bool          `json:"ok"`
			FirmwareURL    string        `json:"firmware_url"`
			FirmwareSHA256 string        `json:"firmware_sha256"`
			Version        string        `json:"firmware_version"`
			Device         deviceSummary `json:"device"`
		}{OK: true, FirmwareURL: firmwareURL, FirmwareSHA256: shaHex, Version: version, Device: summarise(dev2)})
	}
}
