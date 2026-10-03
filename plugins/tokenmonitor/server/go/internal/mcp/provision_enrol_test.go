package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

const (
	lanTestID  = "ab12cd34"
	lanTestPSK = "00000000000000000000000000000000000000000000000000000000000000cd"
	// The mock device listens on loopback, so the address of this broker on
	// the route to it — what an enrolment with no broker_url is seeded with —
	// is loopback too.
	lanSeedURL = "http://127.0.0.1:8765"
)

// lanDeps is a broker with a registry and a configured port (the port is what
// a seeded broker_url is built from).
func lanDeps(r *registry.Registry) Deps {
	cfg := &config.Config{}
	cfg.Server.Port = 8765
	return Deps{Registry: r, Cfg: cfg}
}

// refusedProvision drives handleProvision expecting a refusal: it returns the
// tool error text and whether anything reached the device.
func refusedProvision(t *testing.T, d Deps, args map[string]any) (string, bool) {
	t.Helper()
	posted := false
	dev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posted = true
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer dev.Close()
	full := map[string]any{"device_id": lanTestID, "provision_url": dev.URL + "/provision", "pairing_code": "071718"}
	for k, v := range args {
		full[k] = v
	}
	var req mcp.CallToolRequest
	req.Params.Arguments = full
	res, err := handleProvision(d)(context.Background(), req)
	if err != nil || !res.IsError {
		t.Fatalf("expected a refusal: err=%v res=%s", err, errText(t, res))
	}
	return errText(t, res), posted
}

// runProvision drives handleProvision against a mock device /provision endpoint
// and returns the body the device received plus the decoded tool result.
func runProvision(t *testing.T, d Deps, args map[string]any) (wire, out map[string]any) {
	t.Helper()
	dev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &wire)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"next":"rebooting"}`))
	}))
	defer dev.Close()

	full := map[string]any{
		"device_id":     lanTestID,
		"provision_url": dev.URL + "/provision",
		"pairing_code":  "071718",
	}
	for k, v := range args {
		full[k] = v
	}
	var req mcp.CallToolRequest
	req.Params.Arguments = full
	res, err := handleProvision(d)(context.Background(), req)
	if err != nil {
		t.Fatalf("handleProvision: %v", err)
	}
	if res.IsError {
		t.Fatalf("handleProvision returned a tool error: %s", errText(t, res))
	}
	tc, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type %T", res.Content[0])
	}
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return wire, out
}

func lanRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	r, err := registry.New(t.TempDir())
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	return r
}

// The defect this file exists for: enrolment hung off broker_url, so a provision
// with no address pushed no PSK and wrote no registry record, leaving the
// device in BOOT_NEEDS_CONFIG. The device finds the broker by mDNS; the PSK is
// the whole of the pairing.
func TestProvision_EnrolsWithoutBrokerURL(t *testing.T) {
	r := lanRegistry(t)
	wire, out := runProvision(t, lanDeps(r), map[string]any{"city": "Madrid", "enroll": true})

	psk, _ := wire["psk_hex"].(string)
	if len(psk) != 64 {
		t.Fatalf("a PSK must be pushed without a broker_url, wire=%v", wire)
	}
	// Firmware older than 1.0.0 cannot leave BOOT_NEEDS_CONFIG on a PSK alone,
	// and the LAN transport cannot tell which firmware it is talking to, so
	// the address of this broker on the route to the device is always sent.
	if wire["broker_url"] != lanSeedURL || out["broker_url_seeded"] != lanSeedURL {
		t.Errorf("the broker address must be seeded: wire=%v out=%v", wire, out)
	}
	if out["registered"] != true || out["enrolled"] != true || out["psk_generated"] != true {
		t.Errorf("new device must be registered: %v", out)
	}
	if _, leaked := out["psk_hex"]; leaked {
		t.Errorf("a recorded PSK must not be echoed: %v", out)
	}
	dev, err := r.Load(lanTestID)
	if err != nil {
		t.Fatalf("device not in registry: %v", err)
	}
	if dev.Active.PSKHex != psk || dev.Active.City != "Madrid" || dev.Active.BrokerURL != lanSeedURL {
		t.Errorf("registry record wrong: %+v", dev.Active.ConfigPayload)
	}
}

// A device this registry has never seen may be paired with another broker, and
// the LAN gives no way to ask. Minting a key for it needs the caller to say so.
func TestProvision_UnknownDeviceNeedsEnrolmentIntent(t *testing.T) {
	r := lanRegistry(t)
	msg, posted := refusedProvision(t, lanDeps(r), map[string]any{"city": "Madrid"})
	if !contains(msg, "this device is not in the registry and nothing says whether it is already paired with another broker") || posted {
		t.Fatalf("an unknown device with no enrolment intent must be refused before the POST: posted=%v msg=%s", posted, msg)
	}
	if _, err := r.Load(lanTestID); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("a refusal must not write the registry (err=%v)", err)
	}

	// A broker_url is intent (it is how a pairing was always asked for), and a
	// caller-supplied address is used as given — nothing is seeded.
	wire, out := runProvision(t, lanDeps(r), map[string]any{"broker_url": "http://10.0.0.5:8787"})
	if psk, _ := wire["psk_hex"].(string); len(psk) != 64 || wire["broker_url"] != "http://10.0.0.5:8787" {
		t.Fatalf("broker_url must be enough to pair: wire=%v", wire)
	}
	if out["broker_url_seeded"] != nil || out["registered"] != true {
		t.Errorf("a caller-supplied address is not a seed: %v", out)
	}
}

// With no way to name an address the device can reach, an enrolment is refused
// rather than stranding old firmware on "Waiting for setup".
func TestProvision_RefusesWhenNoAddressCanBeSeeded(t *testing.T) {
	r := lanRegistry(t)
	msg, posted := refusedProvision(t, Deps{Registry: r}, map[string]any{"enroll": true})
	if !contains(msg, "could not work out an address of this broker that the device can reach") || posted {
		t.Fatalf("no seed must refuse before the POST: posted=%v msg=%s", posted, msg)
	}
}

func TestProvision_PSKPrecedence(t *testing.T) {
	r := lanRegistry(t)
	if _, err := r.Register(lanTestID, registry.ConfigPayload{PSKHex: lanTestPSK, City: "Madrid"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// No psk_hex → the registry's PSK is reused, and with no broker_url the
	// record is left exactly as it was.
	wire, out := runProvision(t, lanDeps(r), map[string]any{})
	if wire["psk_hex"] != lanTestPSK || out["psk_reused"] != true {
		t.Fatalf("the registry PSK must be reused: wire=%v out=%v", wire, out)
	}
	// The seeded address travels with the key, but it is not a request to
	// converge the record: that stays as it was.
	if wire["broker_url"] != lanSeedURL || out["broker_url_seeded"] != lanSeedURL {
		t.Errorf("a reused PSK is still sent with a seeded address: wire=%v out=%v", wire, out)
	}
	if dev, _ := r.Load(lanTestID); dev.Active.BrokerURL != "" {
		t.Errorf("a seeded address must not rewrite the record: %+v", dev.Active.ConfigPayload)
	}
	if out["enrolled"] != true || out["registered"] != false || out["reregistered"] != nil {
		t.Errorf("reuse must report enrolled without a registry write: %v", out)
	}
	if dev, _ := r.Load(lanTestID); dev.Active.City != "Madrid" {
		t.Errorf("the registry record must be untouched: %+v", dev.Active.ConfigPayload)
	}

	// Passing the SAME key explicitly is no different: it is the key the
	// registry holds, so the record stays as it is rather than being replaced
	// (which would reset its config version and drop the queued pending).
	if _, err := r.SetPending(lanTestID, registry.ConfigPayload{City: "Sevilla"}); err != nil {
		t.Fatalf("set pending: %v", err)
	}
	_, out = runProvision(t, lanDeps(r), map[string]any{"psk_hex": lanTestPSK})
	if out["enrolled"] != true || out["registered"] != false || out["reregistered"] != nil {
		t.Errorf("an explicit PSK equal to the registry's must not rewrite the record: %v", out)
	}
	if dev, _ := r.Load(lanTestID); dev.Active.City != "Madrid" || dev.Pending == nil {
		t.Errorf("the registry record must be untouched: active=%+v pending=%v", dev.Active.ConfigPayload, dev.Pending)
	}

	// An explicit psk_hex wins over the registry and converges the record.
	other := "11111111111111111111111111111111111111111111111111111111111111ef"
	wire, out = runProvision(t, lanDeps(r), map[string]any{"psk_hex": other})
	if wire["psk_hex"] != other || out["reregistered"] != true || out["enrolled"] != true {
		t.Fatalf("explicit psk_hex must win and re-register: wire=%v out=%v", wire, out)
	}
	if dev, _ := r.Load(lanTestID); dev.Active.PSKHex != other {
		t.Errorf("registry must hold the explicit PSK, got %q", dev.Active.PSKHex)
	}
}

func TestProvision_EnrollFalsePushesNoPSK(t *testing.T) {
	r := lanRegistry(t)
	wire, out := runProvision(t, lanDeps(r), map[string]any{"city": "Madrid", "enroll": false})
	if _, present := wire["psk_hex"]; present {
		t.Errorf("enroll=false must push no PSK: %v", wire)
	}
	if out["ok"] != true || out["enrolled"] != false || out["registered"] != false {
		t.Errorf("enroll=false must succeed without enrolling: %v", out)
	}
	if _, err := r.Load(lanTestID); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("enroll=false must not write the registry (err=%v)", err)
	}
}

// When the device took the config but the registry could not be written, the
// minted PSK exists only on the device. It used to be dropped, leaving a
// factory reset as the only way out.
func TestProvision_ReturnsMintedPSKWhenRegistryWriteFails(t *testing.T) {
	dir := t.TempDir()
	r, err := registry.New(dir)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	// A directory squatting on the save's temp file makes the write fail while
	// the load beforehand still reports a clean "not found".
	if err := os.MkdirAll(filepath.Join(dir, lanTestID+".toml.tmp", "x"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	wire, out := runProvision(t, lanDeps(r), map[string]any{"enroll": true})
	if out["ok"] != true || out["registered"] != false || out["enrolled"] != false {
		t.Fatalf("expected an applied-but-unregistered result: %v", out)
	}
	if out["psk_hex"] == nil || out["psk_hex"] != wire["psk_hex"] {
		t.Errorf("the minted PSK must be returned: out=%v wire=%v", out, wire)
	}
	note, _ := out["note"].(string)
	if !contains(note, "device provisioned but registry") || !contains(note, notePSKUnrecorded) {
		t.Errorf("note must say what failed and how to recover, got %q", note)
	}
}

func TestProvision_NoRegistryPushesNoPSK(t *testing.T) {
	wire, out := runProvision(t, Deps{}, map[string]any{"broker_url": "http://10.0.0.5:8787"})
	if _, present := wire["psk_hex"]; present {
		t.Errorf("no PSK may be minted without a registry to keep it in: %v", wire)
	}
	if out["enrolled"] != false || out["note"] != noteNoRegistry {
		t.Errorf("the result must explain the missing enrolment: %v", out)
	}
}

// broker_url used to be required to register a device. It is only a last-known
// address now, so a PSK alone must be enough.
func TestRegisterDevice_BrokerURLOptional(t *testing.T) {
	r := lanRegistry(t)
	var req mcp.CallToolRequest
	req.Params.Arguments = map[string]any{"device_id": lanTestID, "psk_hex": lanTestPSK}
	res, err := handleRegisterDevice(lanDeps(r))(context.Background(), req)
	if err != nil || res.IsError {
		t.Fatalf("register without broker_url must succeed: err=%v res=%s", err, errText(t, res))
	}
	dev, err := r.Load(lanTestID)
	if err != nil || dev.Active.PSKHex != lanTestPSK || dev.Active.BrokerURL != "" {
		t.Fatalf("registry record wrong: dev=%+v err=%v", dev, err)
	}

	// A supplied one is still stored, as the last-known address.
	req.Params.Arguments = map[string]any{"device_id": "ab12cd35", "psk_hex": lanTestPSK, "broker_url": "http://10.0.0.5:8787"}
	if res, _ := handleRegisterDevice(lanDeps(r))(context.Background(), req); res.IsError {
		t.Fatalf("register with broker_url: %s", errText(t, res))
	}
	if dev, _ := r.Load("ab12cd35"); dev.Active.BrokerURL != "http://10.0.0.5:8787" {
		t.Errorf("broker_url not recorded: %q", dev.Active.BrokerURL)
	}
}

// A registry record that exists but cannot be read is not a new device. Minting
// there would re-key a paired device over a transient read failure, so the
// call must stop before anything is sent.
func TestProvision_UnreadableRegistryRecordAborts(t *testing.T) {
	dir := t.TempDir()
	r, err := registry.New(dir)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, lanTestID+".toml"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	posted := false
	dev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posted = true
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer dev.Close()
	var req mcp.CallToolRequest
	req.Params.Arguments = map[string]any{"device_id": lanTestID, "provision_url": dev.URL + "/provision", "pairing_code": "071718"}
	res, err := handleProvision(lanDeps(r))(context.Background(), req)
	if err != nil || !res.IsError || !contains(errText(t, res), "registry load") {
		t.Fatalf("an unreadable record must abort with a registry error: err=%v res=%s", err, errText(t, res))
	}
	if posted {
		t.Error("nothing may be sent to the device when the registry record is unreadable")
	}
}

// failingProvision drives handleProvision against a device that answers with
// `status` (0 = drop the connection without answering, -1 = cut the answer off
// mid-body) and returns the result.
func failingProvision(t *testing.T, d Deps, status int) map[string]any {
	t.Helper()
	dev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		if status <= 0 {
			conn, bufrw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			if status < 0 {
				// Headers promising a body that never arrives.
				_, _ = bufrw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{\"ok\":")
				_ = bufrw.Flush()
			}
			conn.Close()
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"nope"}`))
	}))
	defer dev.Close()
	var req mcp.CallToolRequest
	req.Params.Arguments = map[string]any{"device_id": lanTestID, "provision_url": dev.URL + "/provision", "pairing_code": "071718", "enroll": true}
	res, err := handleProvision(d)(context.Background(), req)
	if err != nil {
		t.Fatalf("handleProvision: %v", err)
	}
	if res.IsError {
		return map[string]any{"tool_error": errText(t, res)}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].(mcp.TextContent).Text), &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return out
}

// The device reboots right after applying, so a connection that dies after the
// request was sent may well have delivered a freshly minted PSK. Losing it with
// the error would orphan the device.
func TestProvision_FailureAfterSendReturnsMintedPSK(t *testing.T) {
	r := lanRegistry(t)
	out := failingProvision(t, lanDeps(r), 0)
	psk, _ := out["psk_hex"].(string)
	if out["ok"] != false || out["outcome_unknown"] != true || len(psk) != 64 || out["note"] != notePSKUnknown {
		t.Fatalf("a dropped connection must hand back the minted PSK: %v", out)
	}
	if _, err := r.Load(lanTestID); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("an unknown outcome must not write the registry (err=%v)", err)
	}

	// An answer cut off mid-body is the same unknown, in every runtime.
	out = failingProvision(t, lanDeps(r), -1)
	if psk, _ := out["psk_hex"].(string); out["outcome_unknown"] != true || len(psk) != 64 {
		t.Errorf("a truncated answer must hand back the minted PSK: %v", out)
	}

	// A 5xx is a failed write, which can leave a partial config behind.
	out = failingProvision(t, lanDeps(r), http.StatusInternalServerError)
	if psk, _ := out["psk_hex"].(string); len(psk) != 64 || out["note"] != notePSKMaybeLive {
		t.Errorf("a 500 must hand back the minted PSK: %v", out)
	}
	// A 4xx is a refusal before anything was stored: nothing to recover.
	out = failingProvision(t, lanDeps(r), http.StatusUnauthorized)
	if out["psk_hex"] != nil || out["http_status"] != float64(401) {
		t.Errorf("a 401 stored nothing and must not echo a PSK: %v", out)
	}

	// A PSK the registry already holds is not at risk and is never echoed —
	// the plain tool error is kept.
	if _, err := r.Register(lanTestID, registry.ConfigPayload{PSKHex: lanTestPSK}); err != nil {
		t.Fatalf("register: %v", err)
	}
	out = failingProvision(t, lanDeps(r), 0)
	if out["tool_error"] == nil {
		t.Errorf("a reused PSK must keep the plain POST error: %v", out)
	}
}
