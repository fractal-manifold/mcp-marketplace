package mcp

// MCP tools for the Phase-2 discovery flow:
//
//   tokenmonitor_discover_devices  — scan the LAN for `_tmon._tcp.local.`
//                                    advertisements and report devices in
//                                    BOOT_NEEDS_CONFIG.
//   tokenmonitor_provision         — POST /provision against a discovered
//                                    device with the pairing code the user
//                                    just read off its screen.
//
// Both tools live on the laptop, alongside the broker, and need no signed
// HMAC: discovery is multicast and /provision is gated by a 6-digit code
// printed on the device's display (physical-presence proof). The PSK is
// generated server-side: if the caller does not pass psk_hex, we draw 32
// random bytes with crypto/rand and use that. The result is pushed over
// plain HTTP on the LAN once (within the brief pairing window) and stored
// in the registry; the device then reboots into BOOT_READY and signs
// every subsequent request with it. The user never sees the key.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

const (
	mdnsService = "_tmon._tcp"
	mdnsDomain  = "local."
)

// discoveredDevice is the public shape returned by the discover tool. We
// expose every TXT key we know about plus the parsed IPs so the caller
// can both display the device and point /provision straight at it.
type discoveredDevice struct {
	DeviceID     string   `json:"device_id"`
	State        string   `json:"state,omitempty"`
	FW           string   `json:"fw,omitempty"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	IPv4         []string `json:"ipv4,omitempty"`
	ProvisionURL string   `json:"provision_url"`
	InfoURL      string   `json:"info_url"`
}

func registerDiscoveryTools(s *server.MCPServer, d Deps) {
	s.AddTool(
		mcp.NewTool("tokenmonitor_discover_devices",
			mcp.WithDescription("Scan the local network via mDNS for TokenMonitor devices that have just connected to WiFi and are waiting for an initial config (`_tmon._tcp.local.`). Returns one entry per device with its device_id, firmware version, hostname, IPv4 address(es) and the URL to POST a /provision payload to. The pairing code is NOT returned — the user must read it from the device's screen. Default scan window is 4 seconds."),
			mcp.WithNumber("timeout_seconds",
				mcp.Description("Browse window in seconds (1..15). Defaults to 4."),
			),
		),
		handleDiscoverDevices(d),
	)

	s.AddTool(
		mcp.NewTool("tokenmonitor_provision",
			mcp.WithDescription("Pair a device that is waiting for its initial config (BOOT_NEEDS_CONFIG, or pairing mode) with this broker. Requires the 6-digit pairing code the user reads off the device's screen. ENROLMENT: a device this registry already knows is re-sent its own PSK. A device it does not know is paired — given a PSK (psk_hex if supplied, else a freshly generated one) and recorded in the local tokenmonitor-mcp registry so its control-plane polls (/device/<id>/sync) are recognised — only when the call says so: enroll=true, psk_hex or broker_url. For a first pairing pass enroll=true. Without one of those the call is refused before anything is sent, because the new PSK would replace whatever the device holds and nothing on the LAN says whether it is paired with another broker. enroll=false changes settings only. Whenever a PSK is pushed and broker_url was omitted, this host's address on the route to the device is sent with it and reported as broker_url_seeded: firmware 1.0.0 or newer finds the broker by mDNS and keeps it as a cache seed, older firmware cannot pair without it. On success the device persists the config to NVS and reboots. The result's `enrolled` says whether the registry now holds the device with the PSK that was pushed; if a PSK was generated but could not be recorded, the result carries psk_hex and a note so the device can be recovered with tokenmonitor_register_device."),
			mcp.WithString("device_id", mcp.Required(),
				mcp.Description("8 lowercase hex chars from the device screen or tokenmonitor_discover_devices output.")),
			mcp.WithString("provision_url", mcp.Required(),
				mcp.Description("The full http://HOST:80/provision URL from tokenmonitor_discover_devices.")),
			mcp.WithString("pairing_code", mcp.Required(),
				mcp.Description("6-digit code shown on the device's screen.")),
			mcp.WithString("broker_url",
				mcp.Description("Optional: HTTP(S) URL of this broker, stored on the device as the first address to try and in the registry as the last-known address. Not needed to pair on firmware 1.0.0 or newer — the device resolves the broker by mDNS and re-resolves whenever the address changes. Required by older firmware, which cannot leave setup without one — so it is auto-seeded when omitted: whenever a PSK is pushed, this host's address on the route to the device is sent and reported as broker_url_seeded. If you pass one, take it from tokenmonitor_provision_hint; do not assume a specific IP. Passing one also counts as asking to pair a device this registry does not know.")),
			mcp.WithString("psk_hex",
				mcp.Description("64-hex PSK the device should sign requests with. Optional: when omitted, the PSK this registry already holds for the device is reused, else a fresh one is generated if the call pairs the device (see enroll).")),
			mcp.WithBoolean("enroll", mcp.Description("Whether to pair the device with this broker: push a PSK and record the device in the local registry. Omit it to let the tool decide from what it knows (see the tool description): a device this registry already knows is re-sent its own PSK, and a device it does not know is paired only when that is clearly meant — otherwise the call is refused before anything is written. true pairs the device here regardless, replacing any PSK it holds: use it for a first pairing, or to move a device over from another broker. false changes settings only, leaving the device's PSK and the registry untouched: use it for a WiFi-only or settings-only change on a device paired with a DIFFERENT broker. false cannot be combined with psk_hex.")),
			mcp.WithString("city", mcp.Description("Optional city for ambient weather.")),
			mcp.WithNumber("br_day", mcp.Description("Daytime brightness 10..100.")),
			mcp.WithNumber("br_night", mcp.Description("Nighttime brightness 5..100.")),
			mcp.WithNumber("vol", mcp.Description("Alert volume 0..100.")),
			mcp.WithString("theme_mode",
				mcp.Description("Display theme applied on the device: 'day' (light palette), 'night' (dark palette) or 'auto' (follows sunrise/sunset). Default on the device is auto. Same setting and wire convention as tokenmonitor_set_device_pending's theme_mode."),
				mcp.Enum("day", "night", "auto"),
			),
			mcp.WithBoolean("pet_enabled", mcp.Description("Show the on-device virtual pet (default true). Device-owned like the display settings; pass false to hide it. Same setting as tokenmonitor_set_device_pending's pet_enabled.")),
			mcp.WithBoolean("panel_enabled", mcp.Description("Show the on-device custom-panel screen (broker-fed charts/tables via GET /device/<id>/panel; default false, opt-in). Device-owned like the display settings; the user can also toggle it on the device.")),
			mcp.WithBoolean("provider_claude", mcp.Description("Enable Claude provider.")),
			mcp.WithBoolean("provider_codex", mcp.Description("Enable Codex provider.")),
			mcp.WithBoolean("provider_antigravity", mcp.Description("Enable Antigravity provider (tracks the `agy` CLI, successor to Gemini).")),
			mcp.WithBoolean("provider_gemini", mcp.Description("Deprecated alias of provider_antigravity, accepted for backward compatibility.")),
		),
		handleProvision(d),
	)
}

// parseTXT lifts the txt key/value pairs into a map. zeroconf returns them
// as a []string of "key=value" entries.
func parseTXT(txt []string) map[string]string {
	out := make(map[string]string, len(txt))
	for _, kv := range txt {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			out[strings.ToLower(kv[:i])] = kv[i+1:]
		}
	}
	return out
}

func handleDiscoverDevices(_ Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		timeout := 4 * time.Second
		if v := req.GetFloat("timeout_seconds", 0); v > 0 {
			if v < 1 {
				v = 1
			}
			if v > 15 {
				v = 15
			}
			timeout = time.Duration(v * float64(time.Second))
		}

		resolver, err := zeroconf.NewResolver(nil)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("zeroconf resolver", err), nil
		}

		entries := make(chan *zeroconf.ServiceEntry, 16)
		browseCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := resolver.Browse(browseCtx, mdnsService, mdnsDomain, entries); err != nil {
			return mcp.NewToolResultErrorFromErr("zeroconf browse", err), nil
		}

		// Collect entries until the browse context expires. zeroconf will
		// close the channel for us.
		var devices []discoveredDevice
		seen := map[string]bool{}
		for e := range entries {
			txt := parseTXT(e.Text)
			id := strings.ToLower(strings.TrimSpace(txt["device_id"]))
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true

			var ips []string
			for _, ip := range e.AddrIPv4 {
				ips = append(ips, ip.String())
			}
			// Prefer the first IPv4 for the URLs — most users want one
			// clickable address, not a hostname that may not resolve via
			// .local outside macOS.
			host := e.HostName
			if len(ips) > 0 {
				host = ips[0]
			}
			port := e.Port
			if port == 0 {
				port = 80
			}
			base := fmt.Sprintf("http://%s:%d", host, port)
			devices = append(devices, discoveredDevice{
				DeviceID:     id,
				State:        txt["state"],
				FW:           txt["fw"],
				Host:         e.HostName,
				Port:         port,
				IPv4:         ips,
				ProvisionURL: base + "/provision",
				InfoURL:      base + "/info",
			})
		}

		return mcp.NewToolResultJSON(struct {
			Count   int                `json:"count"`
			Devices []discoveredDevice `json:"devices"`
		}{Count: len(devices), Devices: devices})
	}
}

// provisionPayload is the JSON envelope POSTed to /provision. Pointer
// fields stay nil when unset so the device's persist_provision treats
// them as "no change".
type provisionPayload struct {
	PairingCode  string          `json:"pairing_code"`
	BrokerURL    string          `json:"broker_url,omitempty"`
	PSKHex       string          `json:"psk_hex,omitempty"`
	City         string          `json:"city,omitempty"`
	BrDay        *uint8          `json:"br_day,omitempty"`
	BrNight      *uint8          `json:"br_night,omitempty"`
	Vol          *uint8          `json:"vol,omitempty"`
	ThemeMode    string          `json:"theme_mode,omitempty"`
	PetEnabled   *bool           `json:"pet_enabled,omitempty"`
	PanelEnabled *bool           `json:"panel_enabled,omitempty"`
	Providers    map[string]bool `json:"providers,omitempty"`
}

func handleProvision(d Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		deviceID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))
		provisionURL := strings.TrimSpace(req.GetString("provision_url", ""))
		code := strings.TrimSpace(req.GetString("pairing_code", ""))

		if !registry.ValidDeviceID(deviceID) {
			return mcp.NewToolResultError("device_id must be 8 lowercase hex chars"), nil
		}
		if provisionURL == "" || !strings.HasSuffix(provisionURL, "/provision") {
			return mcp.NewToolResultError("provision_url must end in /provision (use tokenmonitor_discover_devices to get it)"), nil
		}
		if len(code) != 6 {
			return mcp.NewToolResultError("pairing_code must be 6 digits"), nil
		}

		brokerURL := strings.TrimSpace(req.GetString("broker_url", ""))
		callerURL := brokerURL != ""
		if _, errRes := explicitPSK(req); errRes != nil {
			return errRes, nil
		}
		// /info and the mDNS TXT carry no has_psk, so the LAN never knows
		// whether the device already holds a key: nil, "unknown".
		pskHex, pskGenerated, pskReused, errText := resolveEnrolPSK(d, req, deviceID, nil)
		if errText != "" {
			return mcp.NewToolResultError(errText), nil
		}
		// A PSK with no address strands firmware older than 1.0.0 on "Waiting
		// for setup": it cannot find the broker by itself. So an enrolment
		// with no broker_url is given the one address the device can
		// demonstrably reach — ours, on the route to it. On 1.0.0+ that is
		// just a cache seed.
		seeded := ""
		if pskHex != "" && brokerURL == "" {
			if u, err := url.Parse(provisionURL); err == nil && u.Hostname() != "" {
				port := u.Port()
				if port == "" {
					port = "80"
				}
				seeded = seedURLTowards(d, net.JoinHostPort(u.Hostname(), port))
			}
			if seeded == "" {
				return mcp.NewToolResultError(errNoSeedLAN), nil
			}
			brokerURL = seeded
		}

		payload := provisionPayload{
			PairingCode: code,
			BrokerURL:   brokerURL,
			PSKHex:      pskHex,
			City:        strings.TrimSpace(req.GetString("city", "")),
		}
		if v := req.GetFloat("br_day", 0); v > 0 {
			b := clamp8(uint8(v), 10, 100)
			payload.BrDay = &b
		}
		if v := req.GetFloat("br_night", 0); v > 0 {
			b := clamp8(uint8(v), 5, 100)
			payload.BrNight = &b
		}
		if v := req.GetFloat("vol", -1); v >= 0 {
			b := clamp8(uint8(v), 0, 100)
			payload.Vol = &b
		}
		if v := strings.TrimSpace(req.GetString("theme_mode", "")); v != "" {
			tm := strings.ToLower(v)
			if tm != "day" && tm != "night" && tm != "auto" {
				return mcp.NewToolResultError("theme_mode must be one of: day, night, auto"), nil
			}
			payload.ThemeMode = tm
		}

		args := req.GetArguments()
		if _, ok := args["pet_enabled"]; ok {
			pe := req.GetBool("pet_enabled", true)
			payload.PetEnabled = &pe
		}
		if _, ok := args["panel_enabled"]; ok {
			pe := req.GetBool("panel_enabled", false)
			payload.PanelEnabled = &pe
		}
		_, hasClaude := args["provider_claude"]
		_, hasCodex := args["provider_codex"]
		_, hasAnti := args["provider_antigravity"]
		_, hasGemini := args["provider_gemini"]
		if hasClaude || hasCodex || hasAnti || hasGemini {
			// A provision that names ANY provider is authoritative over the
			// WHOLE set: fill the ones the caller left out as disabled. The
			// device's provision handler only overwrites a provider whose key
			// is present in the payload, so if we forwarded only the named
			// providers a re-configure that drops one (3→2) would leave the
			// dropped provider enabled on the device. Sending all three also
			// matches the registry lift below, which already reads an absent
			// provider as disabled — keeping device and registry in sync.
			p := map[string]bool{
				"claude": req.GetBool("provider_claude", false),
				"codex":  req.GetBool("provider_codex", false),
			}
			// Antigravity: prefer the new arg, fall back to the deprecated
			// provider_gemini. The internal registry key stays "gemini".
			if hasAnti {
				p["gemini"] = req.GetBool("provider_antigravity", false)
			} else {
				p["gemini"] = req.GetBool("provider_gemini", false)
			}
			payload.Providers = p
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("encode", err), nil
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", provisionURL, bytes.NewReader(body))
		if err != nil {
			return mcp.NewToolResultErrorFromErr("request", err), nil
		}
		httpReq.Header.Set("Content-Type", "application/json")

		client := &http.Client{
			Timeout: 6 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			},
		}
		// postFailed reports a POST that did not complete — refused, timed out,
		// or cut off part-way through the answer.
		postFailed := func(err error) (*mcp.CallToolResult, error) {
			if pskGenerated {
				// The request may have reached the device before the
				// connection died (it reboots right after applying), so the
				// minted PSK may be live with no copy anywhere on this host.
				// Hand it back rather than lose it with the error.
				return mcp.NewToolResultJSON(struct {
					OK             bool   `json:"ok"`
					Error          string `json:"error"`
					OutcomeUnknown bool   `json:"outcome_unknown"`
					PSKHex         string `json:"psk_hex"`
					Note           string `json:"note"`
				}{Error: "POST /provision: " + err.Error(), OutcomeUnknown: true, PSKHex: pskHex, Note: notePSKUnknown})
			}
			return mcp.NewToolResultErrorFromErr("POST /provision", err), nil
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			return postFailed(err)
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return postFailed(err)
		}

		if resp.StatusCode != http.StatusOK {
			rejected := struct {
				OK         bool   `json:"ok"`
				HTTPStatus int    `json:"http_status"`
				Body       string `json:"body"`
				PSKHex     string `json:"psk_hex,omitempty"`
				Note       string `json:"note,omitempty"`
			}{OK: false, HTTPStatus: resp.StatusCode, Body: string(respBody)}
			// A 4xx is a refusal before anything was stored. A 5xx is a failed
			// write, and those can leave a partial config behind
			// (PROVISION_WIRE §3) — the minted PSK may be part of it.
			if pskGenerated && resp.StatusCode >= 500 {
				rejected.PSKHex = pskHex
				rejected.Note = notePSKMaybeLive
			}
			return mcp.NewToolResultJSON(rejected)
		}

		// Mirror the enrolment into the local registry so /device/<id>/sync
		// recognises the device on first poll. This keys on the PSK that was
		// pushed, NOT on broker_url: the device finds the broker by mDNS, so
		// an enrolment with no address is the normal case, not a partial one.
		var registered, reregistered, enrolled bool
		note := noRegistryNote(d, req, pskHex)
		if d.Registry != nil && pskHex != "" {
			reg := registry.ConfigPayload{
				BrokerURL: brokerURL,
				PSKHex:    pskHex,
				City:      payload.City,
			}
			if payload.BrDay != nil {
				v := *payload.BrDay
				reg.BrDay = &v
			}
			if payload.BrNight != nil {
				v := *payload.BrNight
				reg.BrNight = &v
			}
			if payload.Vol != nil {
				v := *payload.Vol
				reg.Vol = &v
			}
			reg.ThemeMode = payload.ThemeMode
			if payload.PetEnabled != nil {
				v := *payload.PetEnabled
				reg.PetEnabled = &v
			}
			if payload.PanelEnabled != nil {
				v := *payload.PanelEnabled
				reg.PanelEnabled = &v
			}
			if payload.Providers != nil {
				// Provisioning carries the coarse bool set; lift it into
				// the canonical mode triple (true→auto, false→disabled).
				reg.ProviderModes = &registry.ProviderModeSet{
					Claude: registry.ProviderModeFromBool(payload.Providers["claude"]),
					Codex:  registry.ProviderModeFromBool(payload.Providers["codex"]),
					Gemini: registry.ProviderModeFromBool(payload.Providers["gemini"]),
				}
			}
			registered, reregistered, enrolled, note = mirrorToRegistry(d, deviceID, reg, callerURL)
		}

		out := struct {
			OK           bool   `json:"ok"`
			DeviceID     string `json:"device_id"`
			Registered   bool   `json:"registered"`
			Reregistered bool   `json:"reregistered,omitempty"`
			Enrolled     bool   `json:"enrolled"`
			PSKGenerated bool   `json:"psk_generated,omitempty"`
			PSKReused    bool   `json:"psk_reused,omitempty"`
			PSKHex       string `json:"psk_hex,omitempty"`
			Seeded       string `json:"broker_url_seeded,omitempty"`
			Note         string `json:"note,omitempty"`
			DeviceResp   any    `json:"device_response,omitempty"`
		}{
			Seeded:       seeded,
			OK:           true,
			DeviceID:     deviceID,
			Registered:   registered,
			Reregistered: reregistered,
			Enrolled:     enrolled,
			PSKGenerated: pskGenerated,
			PSKReused:    pskReused,
			Note:         note,
		}
		if pskGenerated && !enrolled {
			// The device now signs with a key that exists nowhere on this
			// host. Hand it back, or the only way out is a factory reset.
			out.PSKHex = pskHex
			out.Note = joinNotes(note, notePSKUnrecorded)
		}
		var parsed map[string]any
		if json.Unmarshal(respBody, &parsed) == nil {
			out.DeviceResp = parsed
		} else {
			out.DeviceResp = string(respBody)
		}
		return mcp.NewToolResultJSON(out)
	}
}
