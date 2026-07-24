package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// capturedProvision runs handleProvision against a mock device /provision
// endpoint and returns the JSON body the broker POSTed to the device.
func capturedProvision(t *testing.T, args map[string]any) map[string]any {
	t.Helper()

	var body map[string]any
	dev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("device got non-JSON body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"next":"rebooting"}`))
	}))
	defer dev.Close()

	full := map[string]any{
		"device_id":     "ab12cd34",
		"provision_url": dev.URL + "/provision",
		"pairing_code":  "071718",
		// Explicit psk_hex keeps the handler off the registry-reuse path so
		// a nil Registry is fine — we only care about the wire body here.
		"broker_url": "http://10.0.0.5:8787",
		"psk_hex":    "0000000000000000000000000000000000000000000000000000000000000000",
	}
	for k, v := range args {
		full[k] = v
	}

	var req mcp.CallToolRequest
	req.Params.Arguments = full
	if _, err := handleProvision(Deps{})(context.Background(), req); err != nil {
		t.Fatalf("handleProvision: %v", err)
	}
	return body
}

// TestProvision_DropsUncheckedProvider is the regression guard for the
// 3→2 re-configure bug: when a provision names ANY provider, the broker must
// forward the WHOLE triple so an unchecked provider reaches the device as an
// explicit false. Forwarding only the named ones left the device's NVS for the
// omitted provider untouched (the firmware only overwrites keys present in the
// payload), so a device dropped from 3 to 2 providers kept the third enabled.
func TestProvision_DropsUncheckedProvider(t *testing.T) {
	body := capturedProvision(t, map[string]any{
		"provider_claude": true,
		"provider_codex":  true,
		// provider_antigravity intentionally omitted (user unchecked it).
	})

	provs, ok := body["providers"].(map[string]any)
	if !ok {
		t.Fatalf("providers missing or wrong type in POST body: %#v", body["providers"])
	}
	want := map[string]bool{"claude": true, "codex": true, "gemini": false}
	for k, w := range want {
		got, present := provs[k].(bool)
		if !present {
			t.Errorf("providers[%q] absent from wire body — the device would keep its old value", k)
			continue
		}
		if got != w {
			t.Errorf("providers[%q] = %v, want %v", k, got, w)
		}
	}
}

// TestProvision_AntigravityAliasAndAbsent covers the deprecated alias path and
// confirms unnamed providers still default to disabled.
func TestProvision_AntigravityAliasAndAbsent(t *testing.T) {
	body := capturedProvision(t, map[string]any{
		"provider_gemini": true, // legacy alias for antigravity
		// claude and codex omitted → must arrive as explicit false.
	})
	provs, _ := body["providers"].(map[string]any)
	want := map[string]bool{"claude": false, "codex": false, "gemini": true}
	for k, w := range want {
		if got, _ := provs[k].(bool); got != w {
			t.Errorf("providers[%q] = %v, want %v", k, got, w)
		}
	}
}

// TestProvision_AntigravityWinsOverGeminiAlias pins the precedence when a
// caller sends BOTH the new arg and the deprecated alias: provider_antigravity
// wins, provider_gemini is ignored. All three runtimes must agree.
func TestProvision_AntigravityWinsOverGeminiAlias(t *testing.T) {
	body := capturedProvision(t, map[string]any{
		"provider_antigravity": false,
		"provider_gemini":      true, // must be ignored in favour of the new arg
	})
	provs, _ := body["providers"].(map[string]any)
	if got, _ := provs["gemini"].(bool); got != false {
		t.Errorf("providers[gemini] = %v, want false (provider_antigravity must win)", got)
	}
}

// TestProvision_NoProviderKeysOmitsField confirms a partial provision that
// names no provider at all leaves the providers field out entirely, so a
// city-only re-provision does not reset the device's provider selection.
func TestProvision_NoProviderKeysOmitsField(t *testing.T) {
	body := capturedProvision(t, map[string]any{
		"city": "Madrid",
	})
	if _, present := body["providers"]; present {
		t.Errorf("providers should be absent when no provider key is sent, got %#v", body["providers"])
	}
}
