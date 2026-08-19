package mcp

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

const wifiTestID = "02c46d94"

func wifiTestRegistry(t *testing.T, known []registry.KnownNetwork) *registry.Registry {
	t.Helper()
	r, err := registry.New(t.TempDir())
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if _, err := r.Register(wifiTestID, registry.ConfigPayload{
		BrokerURL: "http://h:8765",
		PSKHex:    strings.Repeat("ab", 32),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if known != nil {
		if _, err := r.ReportSettings(wifiTestID, registry.ReportedSettings{
			WiFiKnown: known,
		}); err != nil {
			t.Fatalf("ReportSettings: %v", err)
		}
	}
	return r
}

func callSetWiFi(t *testing.T, r *registry.Registry, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name = "tokenmonitor_set_wifi"
	req.Params.Arguments = args
	res, err := handleSetWiFi(Deps{Registry: r})(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return res
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// The headline case, and the reason this is a tool and not two more fields on
// set_device_pending: a network the device already remembers needs no
// password, because the device is holding it.
func TestSetWiFi_KnownNetworkNeedsNoPassword(t *testing.T) {
	r := wifiTestRegistry(t, []registry.KnownNetwork{
		{SSID: "Office", Verified: true},
		{SSID: "HomeNet", Verified: true},
	})
	res := callSetWiFi(t, r, map[string]any{"device_id": wifiTestID, "ssid": "Office"})
	if res.IsError {
		t.Fatalf("a remembered network must not need a password: %s", resultText(t, res))
	}

	dev, err := r.Load(wifiTestID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if dev.Pending == nil {
		t.Fatal("a pending must be staged")
	}
	if dev.Pending.WiFiSSID != "Office" {
		t.Errorf("wifi_ssid = %q, want Office", dev.Pending.WiFiSSID)
	}
	if dev.Pending.WiFiPass != "" {
		t.Errorf("no password was supplied or needed, but one was staged: %q", dev.Pending.WiFiPass)
	}
}

// The other half: an unknown network must ASK, and the message has to be
// actionable — the caller needs to know a password is what is missing, and
// what the device does know.
func TestSetWiFi_UnknownNetworkAsksForPassword(t *testing.T) {
	r := wifiTestRegistry(t, []registry.KnownNetwork{{SSID: "HomeNet", Verified: true}})
	res := callSetWiFi(t, r, map[string]any{"device_id": wifiTestID, "ssid": "j2ap"})
	if !res.IsError {
		t.Fatal("an unknown network must not be staged silently")
	}
	msg := resultText(t, res)
	if !strings.Contains(msg, "needs_password=true") {
		t.Errorf("message must say a password is needed, got: %s", msg)
	}
	if !strings.Contains(msg, "HomeNet") {
		t.Errorf("message must list what the device does remember, got: %s", msg)
	}

	dev, _ := r.Load(wifiTestID)
	if dev.Pending != nil {
		t.Error("nothing may be staged when the request could not be satisfied")
	}
}

func TestSetWiFi_UnknownNetworkWithPasswordIsStaged(t *testing.T) {
	r := wifiTestRegistry(t, []registry.KnownNetwork{{SSID: "HomeNet", Verified: true}})
	res := callSetWiFi(t, r, map[string]any{
		"device_id": wifiTestID, "ssid": "j2ap", "pass": "j2apj2ap",
	})
	if res.IsError {
		t.Fatalf("a supplied password must be accepted: %s", resultText(t, res))
	}
	dev, _ := r.Load(wifiTestID)
	if dev.Pending == nil || dev.Pending.WiFiSSID != "j2ap" || dev.Pending.WiFiPass != "j2apj2ap" {
		t.Fatalf("credentials not staged: %+v", dev.Pending)
	}
}

// An open network is remembered but can never be auto-joined, so offering a
// password-free switch to one would stage a change that silently does nothing
// on the device.
func TestSetWiFi_RememberedOpenNetworkIsRefused(t *testing.T) {
	r := wifiTestRegistry(t, []registry.KnownNetwork{{SSID: "CafeWiFi", Open: true}})
	res := callSetWiFi(t, r, map[string]any{"device_id": wifiTestID, "ssid": "CafeWiFi"})
	if !res.IsError {
		t.Fatal("an open network must be refused, not staged")
	}
	if msg := resultText(t, res); !strings.Contains(msg, "OPEN") {
		t.Errorf("the refusal must explain why, got: %s", msg)
	}
}

// Old firmware reports no list at all. That is NOT the same as "it does not
// know the network", and telling the user to supply a password they may not
// need would be guessing — so it says what it actually knows.
func TestSetWiFi_NoReportedListIsDistinctFromUnknown(t *testing.T) {
	r := wifiTestRegistry(t, nil)
	res := callSetWiFi(t, r, map[string]any{"device_id": wifiTestID, "ssid": "Office"})
	if !res.IsError {
		t.Fatal("without a reported list the tool cannot claim the network is known")
	}
	msg := resultText(t, res)
	if strings.Contains(msg, "needs_password=true") {
		t.Errorf("must not claim the device lacks the network when it never reported: %s", msg)
	}
	if !strings.Contains(msg, "has not reported") {
		t.Errorf("must name the real problem, got: %s", msg)
	}
}

// A WiFi password has one job. Once the device has applied the config it holds
// the credential itself, so the registry must not keep accumulating every
// network password the fleet was ever handed.
func TestSetWiFi_PasswordIsDroppedOnPromote(t *testing.T) {
	r := wifiTestRegistry(t, []registry.KnownNetwork{{SSID: "HomeNet", Verified: true}})
	callSetWiFi(t, r, map[string]any{
		"device_id": wifiTestID, "ssid": "j2ap", "pass": "j2apj2ap",
	})
	dev, _ := r.Load(wifiTestID)
	ver := dev.Pending.Version

	promoted, err := r.MaybePromote(wifiTestID, ver, false)
	if err != nil {
		t.Fatalf("MaybePromote: %v", err)
	}
	if !promoted {
		t.Fatal("a wifi-only pending has no PSK rotation, so it must promote")
	}
	dev, _ = r.Load(wifiTestID)
	if dev.Active.WiFiPass != "" {
		t.Errorf("the password must not survive into Active, got %q", dev.Active.WiFiPass)
	}
	if dev.Active.WiFiSSID != "j2ap" {
		t.Errorf("the SSID is not a secret and must survive, got %q", dev.Active.WiFiSSID)
	}
	// Observed state must not be collateral damage of a config promote.
	if dev.Active.WiFiKnown == nil || len(*dev.Active.WiFiKnown) != 1 ||
		(*dev.Active.WiFiKnown)[0].SSID != "HomeNet" {
		t.Errorf("the remembered-networks list must survive a promote, got %+v", dev.Active.WiFiKnown)
	}
}

// SSIDs may legally contain leading/trailing spaces, and trimming would target
// a different network than the caller named.
func TestSetWiFi_SSIDIsNotTrimmed(t *testing.T) {
	r := wifiTestRegistry(t, []registry.KnownNetwork{{SSID: " Padded ", Verified: true}})
	res := callSetWiFi(t, r, map[string]any{"device_id": wifiTestID, "ssid": " Padded "})
	if res.IsError {
		t.Fatalf("an SSID with significant spaces must match exactly: %s", resultText(t, res))
	}
	dev, _ := r.Load(wifiTestID)
	if dev.Pending == nil || dev.Pending.WiFiSSID != " Padded " {
		t.Fatalf("SSID was altered: %+v", dev.Pending)
	}
}

func TestSetWiFi_RejectsOversizeFields(t *testing.T) {
	r := wifiTestRegistry(t, nil)
	res := callSetWiFi(t, r, map[string]any{
		"device_id": wifiTestID, "ssid": strings.Repeat("S", 33), "pass": "x",
	})
	if !res.IsError {
		t.Error("a 33-byte SSID exceeds the 802.11 limit and must be refused")
	}
	res = callSetWiFi(t, r, map[string]any{
		"device_id": wifiTestID, "ssid": "ok", "pass": strings.Repeat("P", 64),
	})
	if !res.IsError {
		t.Error("a 64-byte passphrase exceeds the WPA2 limit and must be refused")
	}
}

// The distinction between "reported none" and "never reported" only earns its
// keep if it survives the disk: every Load re-reads the TOML, so a collapse
// there would make the empty case unreachable in practice.
func TestSetWiFi_EmptyReportedListSurvivesReload(t *testing.T) {
	r := wifiTestRegistry(t, []registry.KnownNetwork{})
	dev, err := r.Load(wifiTestID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if dev.Active.WiFiKnown == nil {
		t.Fatal("an empty reported list must not read back as \"never reported\"")
	}
	if len(*dev.Active.WiFiKnown) != 0 {
		t.Fatalf("list should be empty, got %+v", *dev.Active.WiFiKnown)
	}
	res := callSetWiFi(t, r, map[string]any{"device_id": wifiTestID, "ssid": "Office"})
	msg := resultText(t, res)
	if !strings.Contains(msg, "needs_password=true") {
		t.Errorf("a device that remembers nothing needs the password, got: %s", msg)
	}
}

// The SSID is interpolated into these messages as a JSON string literal, not
// via %q. compat/mcp-errors.md publishes the strings as byte-for-byte identical
// across go/py/js, and the other two quote with json.dumps / JSON.stringify.
// Go's %q escapes differently for exactly the bytes an adversarial SSID would
// carry: BEL prints as a Go \a escape but as \u0007 in JSON, and vertical tab
// as \v vs \u000b. So a %q here silently breaks the contract for the only
// inputs that make it observable. The literal below is what all three runtimes
// must produce.
func TestSetWiFi_SSIDIsQuotedAsJSONNotGo(t *testing.T) {
	// non-ASCII, BEL, VT, an embedded quote and a backslash
	const nasty = "caf\u00e9\a\v\"x\\y"
	const want = "\"caf\u00e9\\u0007\\u000b\\\"x\\\\y\""

	if got := jsonQ(nasty); got != want {
		t.Fatalf("jsonQ = %s, want %s", got, want)
	}
	if goQ := fmt.Sprintf("%q", nasty); goQ == want {
		t.Fatal("Go quoting and JSON quoting agree on this input — pick a " +
			"nastier one, the test no longer proves anything")
	}

	// And it must actually reach the user-visible message.
	r := wifiTestRegistry(t, []registry.KnownNetwork{{SSID: "HomeNet", Verified: true}})
	res := callSetWiFi(t, r, map[string]any{"device_id": wifiTestID, "ssid": nasty})
	if !res.IsError {
		t.Fatal("an unknown network must not be staged silently")
	}
	if msg := resultText(t, res); !strings.Contains(msg, want) {
		t.Errorf("message must carry the JSON-quoted SSID %s, got: %s", want, msg)
	}
}
