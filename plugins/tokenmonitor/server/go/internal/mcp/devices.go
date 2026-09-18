package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/ota"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/textutil"
)

// deviceSummary is the trimmed view exposed by tokenmonitor_list_devices.
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
		out = append(out, "antigravity")
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
	if pending.PetEnabled != nil {
		if active.PetEnabled == nil || *active.PetEnabled != *pending.PetEnabled {
			diffs = append(diffs, "pet_enabled")
		}
	}
	if pending.PanelEnabled != nil {
		if active.PanelEnabled == nil || *active.PanelEnabled != *pending.PanelEnabled {
			diffs = append(diffs, "panel_enabled")
		}
	}
	if pending.PetSpecies != nil {
		if active.PetSpecies == nil || *active.PetSpecies != *pending.PetSpecies {
			diffs = append(diffs, "pet_species")
		}
	}
	if pending.PetName != "" && pending.PetName != active.PetName {
		diffs = append(diffs, "pet_name")
	}
	if pending.GeminiModels != nil && !stringSliceEqual(active.GeminiModels, pending.GeminiModels) {
		diffs = append(diffs, "antigravity_models")
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
		errors.New("device registry is not configured on this tokenmonitor-mcp install; configure ~/.config/tokenmonitor/devices/ and retry"),
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
					return mcp.NewToolResultError(fmt.Sprintf("device %s not registered — call tokenmonitor_register_device first", deviceID)), nil
				}
				return mcp.NewToolResultErrorFromErr("set_channel", err), nil
			}
		}

		// No broker_url here: the device's broker address is not something the
		// control plane sets any more. It is discovered by mDNS on the device's
		// own subnet and adopted only after the response signature proves the
		// pairing, so a staged address would be overwritten within a poll
		// cycle — after costing a reboot. The provisioning tools still accept
		// one as a cache seed for a device that has never resolved.
		var update registry.ConfigPayload
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
			"provider_claude", "provider_codex",

			"provider_antigravity", "provider_gemini",

			"provider_mode_claude", "provider_mode_codex",

			"provider_mode_antigravity", "provider_mode_gemini",
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
			// Antigravity (formerly Gemini): prefer the new arg names, fall back
			// to the deprecated gemini-named args for older automation.
			agBool, agMode := "provider_antigravity", "provider_mode_antigravity"
			if _, ok := anyProv[agBool]; !ok {
				if _, ok2 := anyProv["provider_gemini"]; ok2 {
					agBool = "provider_gemini"
				}
			}
			if _, ok := anyProv[agMode]; !ok {
				if _, ok2 := anyProv["provider_mode_gemini"]; ok2 {
					agMode = "provider_mode_gemini"
				}
			}
			if err := apply(&base.Gemini, agBool, agMode); err != nil {
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

		// Virtual pet — device-owned display settings, same handling shape
		// as theme/brightness/autorotate above.
		if _, ok := anyProv["pet_enabled"]; ok {
			v := req.GetBool("pet_enabled", true)
			update.PetEnabled = &v
		}
		if _, ok := anyProv["panel_enabled"]; ok {
			v := req.GetBool("panel_enabled", false)
			update.PanelEnabled = &v
		}
		if _, ok := anyProv["pet_species"]; ok {
			sp := clamp8(uint8(req.GetFloat("pet_species", 0)), 0, 9)
			update.PetSpecies = &sp
		}
		if v := req.GetString("pet_name", ""); v != "" {
			update.PetName = textutil.ClipRunes(v, 15)
		}

		// gemini_models: comma-separated list. Empty string clears the
		// override (signalled by an empty-but-non-nil slice; mergePayload
		// then replaces the stored list).
		modelsKey := "antigravity_models"
		if _, ok := req.GetArguments()[modelsKey]; !ok {
			modelsKey = "gemini_models" // deprecated alias
		}
		if raw, ok := req.GetArguments()[modelsKey]; ok {
			models := parseGeminiModels(fmt.Sprint(raw))
			if len(models) > 3 {
				return mcp.NewToolResultError(modelsKey + " must list at most 3 entries"), nil
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
		// production device built without TMON_OTA_UNSIGNED will refuse
		// to install an OTA whose pending lacks these fields. The broker
		// holds no private key and cannot verify the signature — but it
		// can READ the fields, which needs none, and that is enough to
		// tell the operator what the device would silently refuse (see
		// gateStagedFirmware).
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

		// Predict the device-side gate before writing anything. A refusal here
		// is a typo the operator can fix in seconds; the same mistake staged is
		// a reboot the device spends telling nobody.
		if update.FirmwareManifestB64 != "" || update.FirmwareURL != "" {
			cur, err := d.Registry.Load(deviceID)
			if err != nil {
				if errors.Is(err, registry.ErrNotFound) {
					return mcp.NewToolResultError(fmt.Sprintf("device %s not registered — call tokenmonitor_register_device first", deviceID)), nil
				}
				return mcp.NewToolResultErrorFromErr("load", err), nil
			}
			if bad := gateStagedFirmware(cur, update.FirmwareManifestB64,
				update.FirmwareSHA256, update.FirmwareVersion, update.FirmwareURL); bad != nil {
				return bad, nil
			}
		}

		dev, err := d.Registry.SetPending(deviceID, update)
		if err != nil {
			if errors.Is(err, registry.ErrNotFound) {
				return mcp.NewToolResultError(fmt.Sprintf("device %s not registered — call tokenmonitor_register_device first", deviceID)), nil
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
		// The real authority is the manifest this call was handed, not the
		// number the operator typed: the device gates on the signed
		// min_secure_version AND on packed(version), and once its floor has
		// risen past the target no manifest can lower it — a revert simply is
		// not possible over OTA any more (USB is the way back). Predicting
		// both here turns a silent on-device refusal, which costs a reboot and
		// reports nothing, into an answer at the call site.
		//
		// target_min_secure_version stays accepted as a cross-check: if the
		// operator states a floor, it must be the one the manifest actually
		// declares, or one of the two is the wrong artifact.
		if bad := gateStagedFirmware(dev, mb, fs, fv, fu); bad != nil {
			return bad, nil
		}
		if targetSV > 0 {
			if raw, err := base64.StdEncoding.DecodeString(mb); err == nil {
				var tmf ota.ManifestFields
				if json.Unmarshal(raw, &tmf) == nil && tmf.MinSecureVersion != targetSV {
					return mcp.NewToolResultError(fmt.Sprintf(
						"target_min_secure_version=%d but the supplied manifest for %s declares %d; "+
							"one of the two is from a different build",
						targetSV, tmf.Version, tmf.MinSecureVersion)), nil
				}
			}
		}

		update := registry.ConfigPayload{
			FirmwareURL:            fu,
			FirmwareSHA256:         fs,
			FirmwareVersion:        fv,
			FirmwareManifestB64:    mb,
			FirmwareManifestSigB64: sb,
		}
		// Tombstone the version we're reverting FROM (the bad release the
		// device is currently running) so the OTA auto-discovery loop doesn't
		// immediately re-stage it once the device reports the older version.
		// Empty active version (fresh device) → nothing to block.
		if bad := dev.Active.FirmwareVersion; bad != "" && bad != fv {
			if err := d.Registry.SetBlockedFirmwareVersion(deviceID, bad); err != nil {
				return mcp.NewToolResultErrorFromErr("set_blocked", err), nil
			}
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
//     the file is copied to <firmware_dir>/tokenmonitor-<version>.bin, SHA is
//     computed, and firmware_url is built from the device's active
//     broker_url + /firmware/tokenmonitor-<version>.bin.
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

		// Loaded to confirm the device is registered (SetPending below needs
		// it, and the error here names the fix). The record's broker_url is
		// NOT used to build the URL any more; its observed last_ip is, only to
		// rank this host's own addresses — see localFirmwareBase.
		dev, err := d.Registry.Load(deviceID)
		if err != nil {
			if errors.Is(err, registry.ErrNotFound) {
				return mcp.NewToolResultError(fmt.Sprintf("device %s not registered — call tokenmonitor_register_device first", deviceID)), nil
			}
			return mcp.NewToolResultErrorFromErr("load", err), nil
		}

		var firmwareURL, shaHex, originSource string
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
			fileName := "tokenmonitor-" + version + ".bin"
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

			// Build the URL from the address the device itself reached us on,
			// not from the registry's recorded broker_url. The device locates
			// the broker by mDNS and its address changes with DHCP, so the
			// stored value goes stale silently — and a stale firmware_url is
			// worse than unreachable: tmon_ota.c withholds the HMAC headers
			// whenever the firmware origin differs from the svc_url the device
			// is actually using, so the download would also be
			// unauthenticated.
			base, herr := firmwareBase(d, dev)
			if herr != nil {
				return mcp.NewToolResultError(herr.Error()), nil
			}
			originSource = base.how
			firmwareURL = base.url + "/firmware/" + fileName
		}

		// Cleartext transport is fine on a modern build — the manifest and the
		// SHA are what establish trust, not TLS — but CONFIG_TMON_OTA_ALLOW_HTTP
		// first appears in sdkconfig.secureboot at v0.10.2. Below that a
		// production unit refuses any http:// firmware_url in config_sync.c and
		// reports nothing, so the whole publish would land as silence.
		if strings.HasPrefix(firmwareURL, "http://") {
			if cur, ok := ota.PackSemver(dev.Active.FirmwareVersion); ok && cur < httpOTAFloor {
				return mcp.NewToolResultError(fmt.Sprintf(
					"device %s runs %s, and plain-http OTA only exists from 0.10.2 "+
						"(CONFIG_TMON_OTA_ALLOW_HTTP); it would drop this pending without "+
						"a word. Publish with external_url over https, or use the GitHub "+
						"release path, to get it past 0.10.2 first.",
					deviceID, dev.Active.FirmwareVersion)), nil
			}
		}

		update := registry.ConfigPayload{
			FirmwareURL:     firmwareURL,
			FirmwareSHA256:  shaHex,
			FirmwareVersion: version,
		}

		// Optional signed-manifest envelope. Same validation as
		// set_device_pending: an SBv2/production build (TMON_OTA_UNSIGNED=n)
		// refuses to install an OTA whose pending lacks these, so the local
		// LAN-hosting path must be able to carry them too. Host-side signer
		// (tools/tmtools/lib/manifest.py) produces the pair; the broker never
		// signs — but it does read the fields and predict the device gate
		// below, so a manifest this unit cannot install is refused here rather
		// than silently on-device.
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
		if (update.FirmwareManifestB64 == "") != (update.FirmwareManifestSigB64 == "") {
			return mcp.NewToolResultError("firmware_manifest_b64 and firmware_manifest_sig_b64 must be supplied together"), nil
		}

		if bad := gateStagedFirmware(dev, update.FirmwareManifestB64,
			update.FirmwareSHA256, update.FirmwareVersion, update.FirmwareURL); bad != nil {
			return bad, nil
		}

		dev2, err := d.Registry.SetPending(deviceID, update)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("set_pending", err), nil
		}
		return mcp.NewToolResultJSON(struct {
			OK             bool          `json:"ok"`
			FirmwareURL    string        `json:"firmware_url"`
			OriginSource   string        `json:"firmware_url_origin,omitempty"`
			FirmwareSHA256 string        `json:"firmware_sha256"`
			Version        string        `json:"firmware_version"`
			Signed         bool          `json:"signed"`
			Device         deviceSummary `json:"device"`
		}{OK: true, FirmwareURL: firmwareURL, OriginSource: originSource, FirmwareSHA256: shaHex, Version: version, Signed: update.FirmwareManifestB64 != "", Device: summarise(dev2)})
	}
}

// httpOTAFloor is packed(0.10.2), the first firmware whose production sdkconfig
// carries CONFIG_TMON_OTA_ALLOW_HTTP. Older units accept https only, and refuse
// anything else in silence.
const httpOTAFloor uint32 = 0<<24 | 10<<16 | 2

// originChoice is a firmware base URL plus how it was arrived at. The "how"
// goes into the tool result because the three sources differ in how much they
// prove: only the first is the address the device demonstrably reached us on.
type originChoice struct {
	url string
	how string
}

// firmwareBase returns "http://<ip>:<port>" for the origin this device will
// accept a firmware download from, in descending order of proof:
//
//  1. the socket-local address of the device's last authenticated request —
//     literally what it dialled, so it is what its NVS svc_url holds. The
//     firmware compares the firmware_url origin against svc_url with strcmp
//     and attaches the HMAC headers only on an exact match (tmon_ota.c), so
//     any other address of ours yields a 401 on /firmware/ — and that path,
//     unlike the manifest gate, poisons the version on-device after 3 tries;
//  2. the address of ours whose subnet contains the device's last source IP.
//     A laptop on WiFi and Ethernet at once has several usable addresses and
//     only one is on the device's network;
//  3. the first usable address, as before.
//
// (2) and (3) use the same interface filter as tokenmonitor_provision_hint
// (docker/VPN/virtual interfaces excluded — a device configured with a Docker
// bridge IP was a real bug).
func firmwareBase(d Deps, dev *registry.Device) (originChoice, error) {
	if a := dev.Active.LastLocalAddr; a != "" {
		return originChoice{
			url: "http://" + a,
			how: "the address the device dialled on its last authenticated request — " +
				"the one origin its OTA download will carry HMAC headers for",
		}, nil
	}
	nets, err := localIPv4Nets()
	if err != nil {
		return originChoice{}, fmt.Errorf("listing interfaces: %w", err)
	}
	if len(nets) == 0 {
		return originChoice{}, errors.New("this host has no reachable LAN address; cannot build firmware_url. Connect to the network the device is on, or publish with external_url.")
	}
	ip := pickLocalIP(nets, dev.Active.LastIP)
	how := "this host's first LAN address; the device has not been seen from a " +
		"matching subnet, so if its broker origin differs the download will 401 " +
		"— have it poll /sync once and republish"
	if dev.Active.LastIP != "" && ip != nets[0].IP.String() {
		how = "this host's address on the device's own subnet (guessed from its " +
			"last source IP, not proven)"
	}
	return originChoice{
		url: "http://" + net.JoinHostPort(ip, strconv.Itoa(d.Cfg.Server.Port)),
		how: how,
	}, nil
}

// pickLocalIP is localFirmwareBase's choice, split out because it is the only
// part that can be tested without the host's real interfaces. nets must be
// non-empty.
func pickLocalIP(nets []*net.IPNet, deviceIP string) string {
	if ip := net.ParseIP(deviceIP); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			for _, n := range nets {
				if n.Contains(v4) {
					return n.IP.String()
				}
			}
		}
	}
	return nets[0].IP.String()
}

// gateStagedFirmware answers, before anything is written to the registry,
// whether the device will actually install what the operator is about to stage.
//
// It exists because a device that refuses a manifest says NOTHING: tmon_ota.c
// clears the pending, records no poison and sends no X-Tmon-Ota-Fail, so the
// operator sees a device that simply keeps running the old version while every
// refused arm costs it a reboot. The published 1.0.0 index was exactly that
// shape — a signed, verifying manifest whose declared floor locked out every
// unit at or past 0.11.4.
//
// Reading the fields needs no key, so the old stance here ("we do not parse the
// manifest; the device-side gate is authoritative") cost the operator the one
// signal the device never gives. The device-side gate stays authoritative — we
// only decline to stage what it has already told us it will reject.
//
// Returns nil when the device would accept it. shaHex/version may be empty
// (nothing to cross-check); manifestB64 empty means an unsigned stage, which
// only a TMON_OTA_UNSIGNED build accepts and which this function cannot judge.
func gateStagedFirmware(dev *registry.Device, manifestB64, shaHex, version, firmwareURL string) *mcp.CallToolResult {
	// The firmware's own hard limits (config_sync.c): a pending that trips one
	// of these is dropped before the gate ever runs.
	if len(firmwareURL) >= 256 {
		return mcp.NewToolResultError(fmt.Sprintf(
			"firmware_url is %d chars; the device refuses any pending whose URL is ≥256",
			len(firmwareURL)))
	}
	if manifestB64 == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return mcp.NewToolResultError("firmware_manifest_b64 is not valid base64")
	}
	if len(raw) > 512 {
		return mcp.NewToolResultError(fmt.Sprintf(
			"the manifest decodes to %d bytes; the device's buffer is 512 and it "+
				"drops the whole pending above that", len(raw)))
	}
	var mf ota.ManifestFields
	if err := json.Unmarshal(raw, &mf); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf(
			"firmware_manifest_b64 does not decode to a JSON manifest: %v", err))
	}
	if verdict, why := ota.PredictPendingCrossCheck(mf, shaHex, version); verdict != ota.GateOK {
		return mcp.NewToolResultError(fmt.Sprintf(
			"the device would refuse this update (%s): %s", verdict, why))
	}
	if verdict, why := ota.PredictDeviceGate(mf, ota.GateDeviceOf(dev)); verdict != ota.GateOK {
		return mcp.NewToolResultError(fmt.Sprintf(
			"the device would refuse this update (%s): %s", verdict, why))
	}
	return nil
}
