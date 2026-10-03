package mcp

import (
	"context"
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
			mcp.WithDescription("Enumerate TokenMonitor devices reachable over a USB cable and classify each by identity tier. Returns one entry per serial port with its vid/pid, iSerial, tier (registry-match | probe | shared) and - for enrolled or probed units - device_id/sku/fw/state. A probed unit also reports has_psk when its firmware sends it: true means the device already holds a PSK (it is paired with some broker), false that it holds none, and an absent has_psk means unknown, never false. A `probe`-tier Espressif port (shared by every ESP32-S3/C3/C6) receives ONE bounded HELLO only during this user-initiated scan; `shared` generic-bridge ports are listed but never written to. Never auto-selects a `probe` or `shared` port. USB is the developer / rescue / reconfiguration path; the consumer path stays SoftAP + LAN (WSL2 without usbipd-win cannot see the device)."),
			mcp.WithNumber("timeout_seconds",
				mcp.Min(1), mcp.Max(10), mcp.DefaultNumber(3),
				mcp.Description("Per-port HELLO probe window in seconds (1..10, default 3). Kept well under the MCP tool budget (30s in Claude, 10s in Codex)."),
			),
		),
		handleUSBScan(d),
	)

	s.AddTool(
		mcp.NewTool("tokenmonitor_usb_provision",
			mcp.WithDescription("Configure or reconfigure a device over a USB cable, independent of the network. No pairing code is needed: the cable is the physical-presence proof, so pairing_code is optional and the device ignores it on this transport. Runs the SLIP+CRC32 serial session (HELLO -> SESSION_BEGIN -> PROVISION -> BYE) behind a leader-mediated port lease so it never collides with the broker's serial log tailer. Carries the config fields the provisioning core applies (broker_url, psk_hex, city, brightness, volume, theme, pet, providers) plus the optional WiFi pair wifi_ssid + wifi_pass; every field is optional and an omitted one is left unchanged on the device. The headline flow sends only wifi_ssid + wifi_pass to point the device at the same WiFi the computer is on (prefill wifi_ssid from the host's current network; ask the user for the password). WiFi credentials go into the device's multi-network remembered-networks store, so a USB-configured device roams like any other.\n\nENROLMENT: the device identifies itself in the serial handshake, and what is pushed is decided from that before anything is written. A device this registry already knows is re-sent its own PSK, which changes nothing. A device it does not know is paired with this broker — given a PSK (psk_hex if supplied, else a freshly generated one) and recorded in the local registry — when it reports that it holds no PSK (has_psk=false, so a first pairing needs no extra argument), or when the call says so with enroll=true or psk_hex, or, on firmware too old to report has_psk, with broker_url. Otherwise the call is refused with nothing written: a device holding a PSK this registry has never seen is paired with another broker, and a new key would break that. enroll=false changes settings only — the WiFi-only call for a device paired elsewhere. Firmware older than 1.0.0 cannot find the broker without an address: when a PSK is pushed to it and broker_url was omitted, the one address tokenmonitor_provision_hint lists is sent with it and reported as broker_url_seeded, and the call is refused if the hint has several or none.\n\nOn success the device persists to NVS and reboots. Top-level ok mirrors the device's own answer, and a device-side error writes nothing to the registry. See compat/PROVISION_WIRE.md."),
			mcp.WithString("port",
				mcp.Description("Serial port path from tokenmonitor_usb_scan (e.g. /dev/ttyACM0, /dev/cu.usbmodemXXXX, COM3). Optional ONLY when exactly one registry-match device is present; otherwise required, because a probe/shared port is never auto-selected.")),
			mcp.WithString("device_id",
				mcp.Pattern("^[0-9a-f]{8}$"),
				mcp.Description("8 lowercase hex chars, to disambiguate when several devices are attached. Verified against the device's HELLO_RESP before any configuration write.")),
			mcp.WithString("pairing_code",
				mcp.Pattern("^[0-9]{6}$"),
				mcp.Description("6-digit code shown on the device's screen. OPTIONAL over USB: plugging the cable in is itself the physical-presence proof, so the device does not require a code on the serial transport and ignores one sent anyway. Supply it only if you have it. The LAN transport (tokenmonitor_provision) still requires it. Never logged.")),
			mcp.WithString("broker_url",
				mcp.Description("Optional: HTTP(S) URL of this broker, stored on the device as the first address to try and in the registry as the last-known address. Not needed to pair on firmware 1.0.0 or newer — the device resolves the broker by mDNS and re-resolves whenever the address changes. Required by older firmware, which cannot leave setup without one — so it is auto-seeded when omitted: when a PSK is pushed to firmware older than 1.0.0, the one address tokenmonitor_provision_hint lists is sent and reported as broker_url_seeded, and the call is refused before anything is written if the hint has several or none. If you pass one, take it from tokenmonitor_provision_hint; do not assume a specific IP. On firmware that does not report has_psk, passing one also counts as asking to pair a device this registry does not know.")),
			mcp.WithString("psk_hex",
				mcp.Pattern("^[0-9a-f]{64}$"),
				mcp.Description("64-hex PSK the device should sign requests with. Optional: when omitted, the PSK this registry already holds for the device is reused, else a fresh one is generated if the call pairs the device (see enroll).")),
			mcp.WithBoolean("enroll", mcp.Description("Whether to pair the device with this broker: push a PSK and record the device in the local registry. Omit it to let the tool decide from what it knows (see the tool description): a device this registry already knows is re-sent its own PSK, and a device it does not know is paired only when that is clearly meant — otherwise the call is refused before anything is written. true pairs the device here regardless, replacing any PSK it holds: use it for a first pairing, or to move a device over from another broker. false changes settings only, leaving the device's PSK and the registry untouched: use it for a WiFi-only or settings-only change on a device paired with a DIFFERENT broker. false cannot be combined with psk_hex.")),
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
	HasPSK     *bool  `json:"has_psk,omitempty"`
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
				return mcp.NewToolResultError("USB scan is not supported on this OS yet (Linux and macOS are supported; Windows enumeration is deferred). Use SoftAP + LAN provisioning instead."), nil
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
					e.HasPSK = dev.HasPSK
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
		// This is everything the arguments alone decide; the PSK and a seeded
		// broker_url are added once the device has said who it is (below).
		base, errRes := buildUSBPayload(req, code)
		if errRes != nil {
			return errRes, nil
		}
		// Validate the encoded size HERE, before leasing or opening anything. An
		// over-cap payload fails inside the PROVISION send, which wraps the error
		// as ErrOutcomeUnknown — but zero bytes have left the host, so it is a pure
		// client-side error. Reporting it as outcome-unknown would wrongly tell the
		// caller the device might have applied it and to not retry.
		if body, err := json.Marshal(base); err != nil {
			return mcp.NewToolResultErrorFromErr("encode", err), nil
		} else if len(body) > usbprov.PayloadMax {
			return mcp.NewToolResultError(payloadTooBig(len(body))), nil
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

		// What may be sent depends on the HELLO_RESP — which device this is,
		// whether it already holds a PSK, whether its firmware can find the
		// broker without an address — so the payload is finished inside the
		// session, after the handshake and before any PROVISION write.
		candidates := hintURLs(d)
		var fin usbFinal
		res, runErr := usbprov.RunProvision(sessCtx, lp.Handle.Conn, usbprov.ProvisionOpts{
			ExpectDeviceID: expectID,
			Finalize: func(dev usbprov.DeviceInfo) ([]byte, error) {
				// A re-handshake (pre-PROVISION reset recovery) must resend the
				// same bytes — in particular the same minted PSK.
				if fin.body != nil && fin.deviceID == dev.DeviceID {
					return fin.body, nil
				}
				f, errText := finalizeUSBPayload(d, req, base, dev, candidates)
				if errText != "" {
					return nil, usbRefusal(errText)
				}
				fin = f
				return f.body, nil
			},
		})
		if runErr != nil {
			var refused usbRefusal
			if errors.As(runErr, &refused) {
				return mcp.NewToolResultError(string(refused)), nil
			}
			return mcp.NewToolResultJSON(usbProvisionErrorReport(runErr, fin.pskHex, fin.pskGenerated))
		}

		return mcp.NewToolResultJSON(usbProvisionReport(d, res, fin, noRegistryNote(d, req, fin.pskHex)))
	}
}

// usbRefusal is a decision NOT to provision, taken after the handshake and
// before any PROVISION write. It surfaces as a plain tool error.
type usbRefusal string

func (r usbRefusal) Error() string { return string(r) }

func payloadTooBig(n int) string {
	return fmt.Sprintf("provisioning payload is %d bytes, over the %d-byte device limit; shorten fields such as city", n, usbprov.PayloadMax)
}

// usbFinal is the payload as it actually goes on the wire, with what was
// decided on the way.
type usbFinal struct {
	deviceID     string
	payload      usbProvisionPayload
	body         []byte
	pskHex       string
	pskGenerated bool
	pskReused    bool
	callerURL    bool   // the caller supplied broker_url
	seeded       string // the broker_url this host added, if any
}

// finalizeUSBPayload completes the payload for the device that answered the
// HELLO: the PSK (resolveEnrolPSK, with the device's own has_psk as evidence)
// and, for firmware that cannot find the broker by itself, a broker_url.
// candidates are the provision hint's URLs. A non-empty errText is a refusal:
// nothing has been written and nothing will be.
func finalizeUSBPayload(d Deps, req mcp.CallToolRequest, base usbProvisionPayload, dev usbprov.DeviceInfo, candidates []string) (usbFinal, string) {
	f := usbFinal{deviceID: dev.DeviceID, payload: base, callerURL: base.BrokerURL != ""}
	var errText string
	f.pskHex, f.pskGenerated, f.pskReused, errText = resolveEnrolPSK(d, req, dev.DeviceID, dev.HasPSK)
	if errText != "" {
		return usbFinal{}, errText
	}
	f.payload.PSKHex = f.pskHex
	// A PSK with no address strands firmware older than 1.0.0 on "Waiting for
	// setup". Over the cable there is no route to read an address off, so the
	// provision hint is used — but only when it names exactly one.
	if f.pskHex != "" && !f.callerURL && !fwFindsBrokerAlone(dev.FW) {
		if f.seeded, errText = seedURLFromHint(dev.FW, candidates); errText != "" {
			return usbFinal{}, errText
		}
		f.payload.BrokerURL = f.seeded
	}
	body, err := json.Marshal(f.payload)
	if err != nil {
		return usbFinal{}, "encode: " + err.Error()
	}
	if len(body) > usbprov.PayloadMax {
		return usbFinal{}, payloadTooBig(len(body))
	}
	f.body = body
	return f, ""
}

// usbProvisionOut is the usb_provision result once a RESULT frame came back.
type usbProvisionOut struct {
	OK           bool           `json:"ok"`
	Error        string         `json:"error,omitempty"`
	DeviceID     string         `json:"device_id"`
	SKU          string         `json:"sku,omitempty"`
	FW           string         `json:"fw,omitempty"`
	Registered   bool           `json:"registered"`
	Reregistered bool           `json:"reregistered,omitempty"`
	Enrolled     bool           `json:"enrolled"`
	PSKGenerated bool           `json:"psk_generated,omitempty"`
	PSKReused    bool           `json:"psk_reused,omitempty"`
	PSKHex       string         `json:"psk_hex,omitempty"`
	Seeded       string         `json:"broker_url_seeded,omitempty"`
	Note         string         `json:"note,omitempty"`
	DeviceResp   map[string]any `json:"device_response,omitempty"`
}

// usbProvisionReport turns a received RESULT into the tool result. A RESULT is
// only the device ANSWERING — success and error alike arrive as one
// (PROVISION_WIRE §3) — so top-level ok is the device's own `ok`, and the
// registry is mirrored only when the device says it applied the payload.
func usbProvisionReport(d Deps, res *usbprov.ProvisionResult, fin usbFinal, note string) usbProvisionOut {
	// The device_id echoed in HELLO_RESP is authoritative — use it for the
	// registry mirror below.
	deviceID := res.Device.DeviceID
	var deviceResp map[string]any
	_ = json.Unmarshal(res.ResultJSON, &deviceResp)
	applied, _ := deviceResp["ok"].(bool)

	out := usbProvisionOut{
		OK:           applied,
		DeviceID:     deviceID,
		SKU:          res.Device.SKU,
		FW:           res.Device.FW,
		PSKGenerated: fin.pskGenerated,
		PSKReused:    fin.pskReused,
		Seeded:       fin.seeded,
		DeviceResp:   deviceResp,
	}
	if !applied {
		out.Error = "device rejected the provisioning payload"
		if msg, _ := deviceResp["error"].(string); msg != "" {
			out.Error = msg
		}
		if fin.pskGenerated {
			out.PSKHex = fin.pskHex
			out.Note = notePSKMaybeLive
		}
		return out
	}

	// Mirror the enrolment into the registry whenever a PSK was pushed and the
	// device_id is well-formed — with or without a broker_url. enroll=false
	// pushed none and leaves the registry untouched.
	out.Note = note
	if d.Registry != nil && fin.pskHex != "" && registry.ValidDeviceID(deviceID) {
		out.Registered, out.Reregistered, out.Enrolled, out.Note =
			mirrorToRegistry(d, deviceID, usbRegistryPayload(fin.payload, fin.pskHex), fin.callerURL)
	}
	if fin.pskGenerated && !out.Enrolled {
		out.PSKHex = fin.pskHex
		out.Note = joinNotes(out.Note, notePSKUnrecorded)
	}
	return out
}

// buildUSBPayload assembles the part of the PROVISION JSON the tool args alone
// decide, including the WiFi pair. It mirrors handleProvision's field handling
// and enforces the wifi_ssid⇄wifi_pass togetherness rule (a bare wifi_ssid is
// an error, and an OMITTED wifi_pass while wifi_ssid is present is NOT an open
// network — only an explicit empty string is). An explicit psk_hex is
// validated here; which PSK is finally sent is finalizeUSBPayload's call.
func buildUSBPayload(req mcp.CallToolRequest, code string) (usbProvisionPayload, *mcp.CallToolResult) {
	args := req.GetArguments()
	brokerURL := strings.TrimSpace(req.GetString("broker_url", ""))
	pskHex, errRes := explicitPSK(req)
	if errRes != nil {
		return usbProvisionPayload{}, errRes
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
			return usbProvisionPayload{}, mcp.NewToolResultError("theme_mode must be one of: day, night, auto")
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
		return usbProvisionPayload{}, mcp.NewToolResultError("wifi_ssid and wifi_pass must be sent together (an open network needs wifi_pass set to an explicit empty string)")
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
			return usbProvisionPayload{}, mcp.NewToolResultError("wifi_ssid must be 1..32 bytes (UTF-8 bytes, not characters)")
		}
		if len(pass) > 64 {
			return usbProvisionPayload{}, mcp.NewToolResultError("wifi_pass must be at most 64 bytes (UTF-8 bytes, not characters)")
		}
		payload.WiFiSSID = &ssid
		payload.WiFiPass = &pass
	}

	return payload, nil
}

// usbRegistryPayload lifts the just-applied USB payload into the registry's
// config shape, matching handleProvision's lift.
func usbRegistryPayload(payload usbProvisionPayload, pskHex string) registry.ConfigPayload {
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
		// The USB payload carries the "antigravity" wire key; the registry's
		// internal name for that provider is still Gemini.
		reg.ProviderModes = &registry.ProviderModeSet{
			Claude: registry.ProviderModeFromBool(payload.Providers["claude"]),
			Codex:  registry.ProviderModeFromBool(payload.Providers["codex"]),
			Gemini: registry.ProviderModeFromBool(payload.Providers["antigravity"]),
		}
	}
	return reg
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
			rep.Note = notePSKUnknown
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
