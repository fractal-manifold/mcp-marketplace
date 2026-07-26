package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/usbprov"
)

// registerUSBTools registers the two USB-cable provisioning tools. USB is the
// developer / rescue / reconfiguration path (the consumer path stays SoftAP +
// LAN); the tool descriptions are the cross-runtime contract and must stay
// byte-identical to compat/tool-schemas.json (TestToolSchemas_MatchGolden).
func registerUSBTools(s *server.MCPServer, d Deps) {
	s.AddTool(
		mcp.NewTool("tokenmonitor_usb_scan",
			mcp.WithDescription("Enumerate TokenMonitor devices reachable over a USB cable and classify each by identity tier. Returns one entry per serial port with its vid/pid, iSerial, tier (registry-match | probe | shared) and - for enrolled or probed units - device_id/sku/fw/state. A `probe`-tier Espressif port (shared by every ESP32-S3/C3/C6) receives ONE bounded HELLO only during this user-initiated scan; `shared` generic-bridge ports are listed but never written to. Never auto-selects a `probe` or `shared` port. USB is the developer / rescue / reconfiguration path; the consumer path stays SoftAP + LAN (WSL2 without usbipd-win cannot see the device)."),
			mcp.WithNumber("timeout_seconds",
				mcp.Min(1), mcp.Max(10), mcp.DefaultNumber(3),
				mcp.Description("Per-port HELLO probe window in seconds (1..10, default 3). Kept well under the MCP tool budget (30s in Claude, 10s in Codex)."),
			),
		),
		handleUSBScan(d),
	)

	s.AddTool(
		mcp.NewTool("tokenmonitor_usb_provision",
			mcp.WithDescription("Configure or reconfigure a device over a USB cable, independent of the network. No pairing code is needed: the cable is the physical-presence proof, so pairing_code is optional and the device ignores it on this transport. Runs the SLIP+CRC32 serial session (HELLO -> SESSION_BEGIN -> PROVISION -> BYE) behind a leader-mediated port lease so it never collides with the broker's serial log tailer. Carries the config fields the provisioning core applies (broker_url, psk_hex, city, brightness, volume, theme, pet, providers) plus the optional WiFi pair wifi_ssid + wifi_pass, so partial payloads are allowed: sending only city preserves the broker URL and PSK, and the headline flow sends only wifi_ssid + wifi_pass to point the device at the same WiFi the computer is on (prefill wifi_ssid from the host's current network; ask the user for the password). WiFi credentials go into the device's multi-network remembered-networks store, so a USB-configured device roams like any other. On success the device persists to NVS and reboots. If broker_url + psk_hex are supplied, also registers/updates the device in the local registry. See compat/PROVISION_WIRE.md."),
			mcp.WithString("port",
				mcp.Description("Serial port path from tokenmonitor_usb_scan (e.g. /dev/ttyACM0, /dev/cu.usbmodemXXXX, COM3). Optional ONLY when exactly one registry-match device is present; otherwise required, because a probe/shared port is never auto-selected.")),
			mcp.WithString("device_id",
				mcp.Pattern("^[0-9a-f]{8}$"),
				mcp.Description("8 lowercase hex chars, to disambiguate when several devices are attached. Verified against the device's HELLO_RESP before any configuration write.")),
			mcp.WithString("pairing_code",
				mcp.Pattern("^[0-9]{6}$"),
				mcp.Description("6-digit code shown on the device's screen. OPTIONAL over USB: plugging the cable in is itself the physical-presence proof, so the device does not require a code on the serial transport and ignores one sent anyway. Supply it only if you have it. The LAN transport (tokenmonitor_provision) still requires it. Never logged.")),
			mcp.WithString("broker_url",
				mcp.Description("HTTP(S) URL of the tokenmonitor-mcp broker the device should poll. Run tokenmonitor_provision_hint to learn the laptop's reachable URL on this LAN; do not assume a specific IP. If omitted, only the optional fields below are pushed.")),
			mcp.WithString("psk_hex",
				mcp.Pattern("^[0-9a-f]{64}$"),
				mcp.Description("64-hex PSK the device should sign requests with.")),
			mcp.WithString("city", mcp.Description("Optional city for ambient weather.")),
			mcp.WithNumber("br_day", mcp.Min(10), mcp.Max(100), mcp.Description("Daytime brightness 10..100.")),
			mcp.WithNumber("br_night", mcp.Min(5), mcp.Max(100), mcp.Description("Nighttime brightness 5..100.")),
			mcp.WithNumber("vol", mcp.Min(0), mcp.Max(100), mcp.Description("Alert volume 0..100.")),
			mcp.WithString("theme_mode",
				mcp.Enum("day", "night", "auto"),
				mcp.Description("Display theme applied on the device: 'day' (light palette), 'night' (dark palette) or 'auto' (follows sunrise/sunset). Default on the device is auto. Same setting and wire convention as tokenmonitor_set_device_pending's theme_mode.")),
			mcp.WithBoolean("pet_enabled", mcp.Description("Show the on-device virtual pet (default true). Device-owned like the display settings; pass false to hide it. Same setting as tokenmonitor_set_device_pending's pet_enabled.")),
			mcp.WithBoolean("provider_claude", mcp.Description("Enable Claude provider.")),
			mcp.WithBoolean("provider_codex", mcp.Description("Enable Codex provider.")),
			mcp.WithBoolean("provider_antigravity", mcp.Description("Enable Antigravity provider (tracks the `agy` CLI, successor to Gemini).")),
			mcp.WithBoolean("provider_gemini", mcp.Description("Deprecated alias of provider_antigravity, accepted for backward compatibility.")),
			mcp.WithString("wifi_ssid",
				mcp.MinLength(1), mcp.MaxLength(32),
				mcp.Description("WiFi SSID to store on the device (1-32 bytes). Prefill from the computer's current network for the point-at-my-WiFi flow. MUST be sent together with wifi_pass; a bare wifi_ssid is rejected. Stored in the device's multi-network remembered store (enters unverified), so the device roams.")),
			mcp.WithString("wifi_pass",
				mcp.MaxLength(64),
				mcp.Description("WiFi passphrase for wifi_ssid (0-64 bytes). MUST be sent together with wifi_ssid. An explicit empty string means a deliberately open network (the cable is the authority); omitting the key entirely while sending wifi_ssid is an error, not an open network.")),
		),
		handleUSBProvision(d),
	)
}

// registeredSKUs builds the device_id→SKU map Resolve uses for registry-match.
// A nil registry (legacy global-PSK mode) yields an empty map — every port then
// classifies purely by VID/PID, so nothing auto-selects.
func registeredSKUs(d Deps) map[string]string {
	out := map[string]string{}
	if d.Registry == nil {
		return out
	}
	devs, err := d.Registry.List()
	if err != nil {
		return out
	}
	for _, dev := range devs {
		out[dev.DeviceID] = dev.HWSku
	}
	return out
}

// brokerBaseURL is the loopback URL of this host's broker, for the lease client.
// The lease endpoints are loopback-only (serial_lease.go rejects any non-loopback
// peer REGARDLESS of the broker's bind), so the follower must ALWAYS dial
// 127.0.0.1 — never the configured LAN bind, whose self-connection would present
// a non-loopback source and be rejected 403. A broker bound to 0.0.0.0 also
// listens on loopback; one bound only to a specific LAN IP is simply unreachable
// here, and OpenLeased then falls back to a direct exclusive open.
func brokerBaseURL(d Deps) string {
	return "http://127.0.0.1:" + strconv.Itoa(d.Cfg.Server.Port)
}

// scanPortOut is one entry in the usb_scan result.
type scanPortOut struct {
	Path       string `json:"path"`
	VID        string `json:"vid"`
	PID        string `json:"pid"`
	Serial     string `json:"serial,omitempty"`
	Tier       string `json:"tier"`
	Label      string `json:"label,omitempty"`
	DeviceID   string `json:"device_id,omitempty"`
	Registered bool   `json:"registered"`
	SKU        string `json:"sku,omitempty"`
	FW         string `json:"fw,omitempty"`
	State      string `json:"state,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
}

func handleUSBScan(d Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		timeout := 3 * time.Second
		if v := req.GetFloat("timeout_seconds", 0); v > 0 {
			if v < 1 {
				v = 1
			}
			if v > 10 {
				v = 10
			}
			timeout = time.Duration(v * float64(time.Second))
		}

		ports, err := usbprov.Enumerate()
		if err != nil {
			if errors.Is(err, usbprov.ErrEnumerateUnsupported) {
				return mcp.NewToolResultError("USB scan is not supported on this OS yet (Linux is the reference path; macOS/Windows enumeration is deferred). Use SoftAP + LAN provisioning instead."), nil
			}
			return mcp.NewToolResultErrorFromErr("usb enumerate", err), nil
		}

		results := usbprov.Resolve(ports, registeredSKUs(d))
		out := make([]scanPortOut, 0, len(results))
		for _, r := range results {
			e := scanPortOut{
				Path:       r.Path,
				VID:        fmt.Sprintf("0x%04x", r.VID),
				PID:        fmt.Sprintf("0x%04x", r.PID),
				Serial:     r.Serial,
				Tier:       string(r.Tier),
				Label:      r.Label,
				DeviceID:   r.DeviceID,
				Registered: r.Registered,
				SKU:        r.SKU,
			}
			// Only `probe`-tier ports get the one bounded HELLO: a registry-match
			// is already identified without a write, and a `shared` bridge must
			// never receive a byte (it could be someone's 3D printer).
			if r.Tier == usbprov.TierProbe {
				dev, perr := probePort(ctx, d, r.Path, timeout)
				if perr != nil {
					e.ProbeError = perr.Error()
				} else {
					e.DeviceID = dev.DeviceID
					e.FW = dev.FW
					e.State = dev.State
					if dev.SKU != "" {
						e.SKU = dev.SKU
					}
				}
			}
			out = append(out, e)
		}

		return mcp.NewToolResultJSON(struct {
			Ports []scanPortOut `json:"ports"`
		}{Ports: out})
	}
}

// probePort leases the port from the leader (so it doesn't collide with the log
// tailer), opens it exclusively, and sends ONE HELLO handshake. It writes
// nothing but the identification HELLO.
func probePort(ctx context.Context, d Deps, port string, timeout time.Duration) (usbprov.DeviceInfo, error) {
	lp, err := leaseAndOpen(ctx, d, port)
	if err != nil {
		return usbprov.DeviceInfo{}, err
	}
	defer lp.Close()

	sessCtx, cancel := sessionContext(ctx, lp)
	defer cancel()

	to := usbprov.DefaultTimeouts()
	to.HelloResp = timeout
	// A scan sends exactly ONE bounded HELLO (PROVISION_WIRE §5). The default 5
	// tries would cost 5×timeout per silent port — a single non-TokenMonitor
	// ESP32-S3/C3/C6 devkit on the desk would then blow the 10s Codex tool budget.
	to.HelloTries = 1
	// Identify CONSUMES the port fd (closes it); the lease + lock stay with lp.
	return usbprov.Identify(sessCtx, lp.Handle.Conn, to)
}

// leaseAndOpen acquires the port for exclusive use via the leader lease (falling
// back to a direct exclusive open when no leader is tailing it).
func leaseAndOpen(ctx context.Context, d Deps, port string) (*usbprov.LeasedPort, error) {
	client := &usbprov.LeaseClient{BaseURL: brokerBaseURL(d), PSK: d.Cfg.PSK()}
	return client.OpenLeased(ctx, port)
}

// sessionContext derives a context that is cancelled if the lease is lost
// mid-session (the leader reaped it / the broker went away). A session running
// on a port the tailer may reclaim MUST abort rather than corrupt the stream.
func sessionContext(parent context.Context, lp *usbprov.LeasedPort) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-lp.Lost:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func handleUSBProvision(d Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// The cable is the physical-presence proof, so the device's serial
		// transport never demands a code. Accept an absent one; still reject a
		// malformed one, because a caller that bothered to pass a code has the
		// device's screen in front of them and a typo should be surfaced, not
		// silently dropped into a payload the device ignores.
		code := strings.TrimSpace(req.GetString("pairing_code", ""))
		if code != "" && (len(code) != 6 || !isDigits(code)) {
			return mcp.NewToolResultError("pairing_code must be 6 digits"), nil
		}

		expectID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))
		if expectID != "" && !registry.ValidDeviceID(expectID) {
			return mcp.NewToolResultError("device_id must be 8 lowercase hex chars"), nil
		}

		// Resolve the port: explicit wins; else auto-select ONLY when exactly one
		// registry-match exists (a probe/shared port is never auto-picked).
		port := strings.TrimSpace(req.GetString("port", ""))
		if port == "" {
			ports, err := usbprov.Enumerate()
			if err != nil {
				return mcp.NewToolResultErrorFromErr("usb enumerate", err), nil
			}
			matches := usbprov.RegistryMatches(usbprov.Resolve(ports, registeredSKUs(d)))
			switch len(matches) {
			case 1:
				port = matches[0].Path
				if expectID == "" {
					expectID = matches[0].DeviceID
				}
			case 0:
				return mcp.NewToolResultError("no registry-match device found; pass an explicit port from tokenmonitor_usb_scan (a probe/shared port is never auto-selected)"), nil
			default:
				return mcp.NewToolResultError("several registry-match devices attached; pass an explicit port from tokenmonitor_usb_scan"), nil
			}
		}

		// Build the PROVISION payload — the SAME JSON POST /provision accepts, so
		// the device shares all validation with the HTTP path. Pointer/omitempty
		// fields stay absent when unset (the device treats absent as "no change").
		payload, pskHex, pskGenerated, pskReused, errRes := buildUSBPayload(d, req, code, expectID)
		if errRes != nil {
			return errRes, nil
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("encode", err), nil
		}
		// Validate the encoded size HERE, before leasing or opening anything. An
		// over-cap payload fails inside the PROVISION send, which wraps the error
		// as ErrOutcomeUnknown — but zero bytes have left the host, so it is a pure
		// client-side error. Reporting it as outcome-unknown would wrongly tell the
		// caller the device might have applied it and to not retry.
		if len(body) > usbprov.PayloadMax {
			return mcp.NewToolResultError(fmt.Sprintf("provisioning payload is %d bytes, over the %d-byte device limit; shorten fields such as city", len(body), usbprov.PayloadMax)), nil
		}

		// Lease + open + run the serial session.
		lp, err := leaseAndOpen(ctx, d, port)
		if err != nil {
			if errors.Is(err, usbprov.ErrLeaseBusy) {
				return mcp.NewToolResultError("the serial port is leased by another provisioning session; retry shortly"), nil
			}
			if errors.Is(err, usbprov.ErrPortBusy) {
				return mcp.NewToolResultError("the serial port is held by another process; close other serial monitors and retry"), nil
			}
			return mcp.NewToolResultErrorFromErr("open serial port", err), nil
		}
		defer lp.Close()

		sessCtx, cancel := sessionContext(ctx, lp)
		defer cancel()

		res, runErr := usbprov.RunProvision(sessCtx, lp.Handle.Conn, usbprov.ProvisionOpts{
			ProvisionJSON:  body,
			ExpectDeviceID: expectID,
		})
		if runErr != nil {
			return mcp.NewToolResultJSON(usbProvisionErrorReport(runErr, pskHex, pskGenerated))
		}

		// The device applied and returned a RESULT. Its device_id is authoritative
		// (echoed in HELLO_RESP) — use it for the registry mirror below.
		deviceID := res.Device.DeviceID
		var deviceResp map[string]any
		_ = json.Unmarshal(res.ResultJSON, &deviceResp)

		out := struct {
			OK           bool           `json:"ok"`
			DeviceID     string         `json:"device_id"`
			SKU          string         `json:"sku,omitempty"`
			FW           string         `json:"fw,omitempty"`
			Registered   bool           `json:"registered"`
			Reregistered bool           `json:"reregistered,omitempty"`
			PSKGenerated bool           `json:"psk_generated,omitempty"`
			PSKReused    bool           `json:"psk_reused,omitempty"`
			Note         string         `json:"note,omitempty"`
			DeviceResp   map[string]any `json:"device_response,omitempty"`
		}{
			OK:           true,
			DeviceID:     deviceID,
			SKU:          res.Device.SKU,
			FW:           res.Device.FW,
			PSKGenerated: pskGenerated,
			PSKReused:    pskReused,
			DeviceResp:   deviceResp,
		}

		// Mirror into the registry only when broker_url + psk were pushed and the
		// device_id is well-formed (a partial provision — e.g. only WiFi — targets
		// an already-enrolled device and leaves the registry untouched).
		if d.Registry != nil && payload.BrokerURL != "" && pskHex != "" && registry.ValidDeviceID(deviceID) {
			registered, reregistered, note := mirrorToRegistry(d, deviceID, payload, pskHex)
			out.Registered = registered
			out.Reregistered = reregistered
			out.Note = note
		}

		return mcp.NewToolResultJSON(out)
	}
}

// buildUSBPayload assembles the PROVISION JSON from the tool args, including the
// WiFi pair. It mirrors handleProvision's field handling plus PSK reuse/gen, and
// enforces the wifi_ssid⇄wifi_pass togetherness rule (a bare wifi_ssid is an
// error, and an OMITTED wifi_pass while wifi_ssid is present is NOT an open
// network — only an explicit empty string is).
func buildUSBPayload(d Deps, req mcp.CallToolRequest, code, expectID string) (usbProvisionPayload, string, bool, bool, *mcp.CallToolResult) {
	args := req.GetArguments()
	brokerURL := strings.TrimSpace(req.GetString("broker_url", ""))
	pskHex := strings.ToLower(strings.TrimSpace(req.GetString("psk_hex", "")))
	pskGenerated, pskReused := false, false
	if pskHex != "" {
		if len(pskHex) != 64 {
			return usbProvisionPayload{}, "", false, false, mcp.NewToolResultError("psk_hex must be 64 hex chars")
		}
		if _, err := hex.DecodeString(pskHex); err != nil {
			return usbProvisionPayload{}, "", false, false, mcp.NewToolResultError("psk_hex is not valid hex")
		}
	} else if brokerURL != "" && expectID != "" {
		// No PSK supplied but a broker is being (re)set: reuse the device's
		// existing registry PSK so the two never drift, else mint a fresh one.
		existing := ""
		if d.Registry != nil {
			if dev, err := d.Registry.Load(expectID); err == nil && dev != nil {
				existing = dev.Active.PSKHex
			}
		}
		if existing != "" {
			pskHex, pskReused = existing, true
		} else {
			// Registry-less (legacy global-PSK) mode cannot persist a minted
			// per-device PSK — it would be lost the instant this call returns and
			// orphan the device (it signs with a key nobody has). Require an
			// explicit psk_hex there instead of silently generating one.
			if d.Registry == nil {
				return usbProvisionPayload{}, "", false, false, mcp.NewToolResultError("setting broker_url over USB without a device registry needs an explicit psk_hex (a generated PSK cannot be persisted here and would orphan the device)")
			}
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return usbProvisionPayload{}, "", false, false, mcp.NewToolResultErrorFromErr("psk gen", err)
			}
			pskHex, pskGenerated = hex.EncodeToString(b), true
		}
	}
	// A broker_url with no PSK to sign with is a dead config: it can only be
	// resolved (reuse/mint) when we know which device this is. With an explicit
	// port and no device_id we don't, so require one rather than push a broker
	// URL the device could never authenticate against.
	if brokerURL != "" && pskHex == "" {
		return usbProvisionPayload{}, "", false, false, mcp.NewToolResultError("setting broker_url over USB needs device_id (so the device's PSK can be reused/derived) or an explicit psk_hex")
	}

	payload := usbProvisionPayload{
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
			return usbProvisionPayload{}, "", false, false, mcp.NewToolResultError("theme_mode must be one of: day, night, auto")
		}
		payload.ThemeMode = tm
	}
	if _, ok := args["pet_enabled"]; ok {
		pe := req.GetBool("pet_enabled", true)
		payload.PetEnabled = &pe
	}
	_, hasClaude := args["provider_claude"]
	_, hasCodex := args["provider_codex"]
	_, hasAnti := args["provider_antigravity"]
	_, hasGemini := args["provider_gemini"]
	if hasClaude || hasCodex || hasAnti || hasGemini {
		p := map[string]bool{
			"claude": req.GetBool("provider_claude", false),
			"codex":  req.GetBool("provider_codex", false),
		}
		// Emit the current "antigravity" wire key (PROVISION_WIRE §3). Firmware
		// also accepts the legacy "gemini" name (provision_session.c), but py/js
		// are written against the doc, so ALL runtimes must emit "antigravity" to
		// stay byte-identical on the wire.
		if hasAnti {
			p["antigravity"] = req.GetBool("provider_antigravity", false)
		} else {
			p["antigravity"] = req.GetBool("provider_gemini", false)
		}
		payload.Providers = p
	}

	// WiFi pair: enforce togetherness. wifi_pass present without wifi_ssid, or
	// wifi_ssid present without wifi_pass, is an error — never a silent open net.
	_, hasSSID := args["wifi_ssid"]
	_, hasPass := args["wifi_pass"]
	if hasSSID != hasPass {
		return usbProvisionPayload{}, "", false, false, mcp.NewToolResultError("wifi_ssid and wifi_pass must be sent together (an open network needs wifi_pass set to an explicit empty string)")
	}
	if hasSSID {
		ssid := req.GetString("wifi_ssid", "")
		pass := req.GetString("wifi_pass", "")
		// Length is in UTF-8 BYTES, not code points (PROVISION_WIRE §7): the JSON
		// Schema maxLength counts characters, so a 32-CHARACTER SSID of multibyte
		// glyphs passes the schema and is then rejected by firmware as
		// BODY_BAD_WIFI after a whole lease + serial session was spent. Go's len()
		// on a string is the byte count, which is exactly the firmware's bound.
		if ssid == "" || len(ssid) > 32 {
			return usbProvisionPayload{}, "", false, false, mcp.NewToolResultError("wifi_ssid must be 1..32 bytes (UTF-8 bytes, not characters)")
		}
		if len(pass) > 64 {
			return usbProvisionPayload{}, "", false, false, mcp.NewToolResultError("wifi_pass must be at most 64 bytes (UTF-8 bytes, not characters)")
		}
		payload.WiFiSSID = &ssid
		payload.WiFiPass = &pass
	}

	return payload, pskHex, pskGenerated, pskReused, nil
}

// mirrorToRegistry converges the local registry to the just-applied config,
// matching handleProvision's Register→ReplaceActive fallback.
func mirrorToRegistry(d Deps, deviceID string, payload usbProvisionPayload, pskHex string) (registered, reregistered bool, note string) {
	reg := registry.ConfigPayload{
		BrokerURL: payload.BrokerURL,
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
	if payload.Providers != nil {
		reg.ProviderModes = &registry.ProviderModeSet{
			Claude: registry.ProviderModeFromBool(payload.Providers["claude"]),
			Codex:  registry.ProviderModeFromBool(payload.Providers["codex"]),
			Gemini: registry.ProviderModeFromBool(payload.Providers["gemini"]),
		}
	}
	_, err := d.Registry.Register(deviceID, reg)
	switch {
	case err == nil:
		return true, false, ""
	case strings.Contains(err.Error(), "already exists"):
		if _, perr := d.Registry.ReplaceActive(deviceID, reg); perr != nil {
			return false, false, "device provisioned but registry re-register failed: " + perr.Error()
		}
		return false, true, ""
	default:
		return false, false, "device provisioned but registry write failed: " + err.Error()
	}
}

// usbProvisionErrorReport maps a session error to a structured tool result. The
// outcome-unknown case is called out explicitly so the model does NOT blindly
// re-run (which would risk a double-apply / a burned pairing attempt).
//
// pskHex/pskGenerated surface a freshly-minted PSK on the outcome-unknown path:
// the device MAY have committed it, but the registry was NOT updated (we don't
// know it applied), so without this the device could end up signing with a key
// nobody on the host has. A reused/existing PSK is already persisted, so it is
// not echoed.
func usbProvisionErrorReport(err error, pskHex string, pskGenerated bool) any {
	rep := struct {
		OK             bool   `json:"ok"`
		Error          string `json:"error"`
		OutcomeUnknown bool   `json:"outcome_unknown,omitempty"`
		DeviceMismatch bool   `json:"device_mismatch,omitempty"`
		PSKHex         string `json:"psk_hex,omitempty"`
		Note           string `json:"note,omitempty"`
	}{OK: false, Error: err.Error()}
	switch {
	case errors.Is(err, usbprov.ErrOutcomeUnknown):
		rep.OutcomeUnknown = true
		if pskGenerated {
			rep.PSKHex = pskHex
			rep.Note = "a fresh PSK was generated and may already be live on the device; record it — the registry was NOT updated because the outcome is unknown. Do not blindly re-run."
		}
	case errors.Is(err, usbprov.ErrDeviceMismatch):
		rep.DeviceMismatch = true
	}
	return rep
}

// usbProvisionPayload is provisionPayload plus the WiFi pair. WiFi fields are
// pointers so an absent pair stays out of the JSON entirely (no change), while
// an explicit empty wifi_pass (open network) is still emitted.
type usbProvisionPayload struct {
	PairingCode string          `json:"pairing_code,omitempty"`
	BrokerURL   string          `json:"broker_url,omitempty"`
	PSKHex      string          `json:"psk_hex,omitempty"`
	City        string          `json:"city,omitempty"`
	BrDay       *uint8          `json:"br_day,omitempty"`
	BrNight     *uint8          `json:"br_night,omitempty"`
	Vol         *uint8          `json:"vol,omitempty"`
	ThemeMode   string          `json:"theme_mode,omitempty"`
	PetEnabled  *bool           `json:"pet_enabled,omitempty"`
	Providers   map[string]bool `json:"providers,omitempty"`
	WiFiSSID    *string         `json:"wifi_ssid,omitempty"`
	WiFiPass    *string         `json:"wifi_pass,omitempty"`
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}
