package broker

import (
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/auth"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/state"
)

const panelTestID = "ab12cd34"

func newPanelServer(t *testing.T, mutate func(*config.Config)) (*httptest.Server, *registry.Registry) {
	t.Helper()
	cfg := newTestConfig(t, writeCredsFile(t, time.Now().Add(time.Hour).UnixMilli()))
	if mutate != nil {
		mutate(cfg)
	}
	cache := auth.NewNonceCache(time.Duration(cfg.Security.NonceCacheTTLSeconds) * time.Second)
	logger := log.New(io.Discard, "", 0)
	reg, err := registry.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(NewMux(cfg, cache, state.New(), logger, nil, reg, nil, nil, nil))
	t.Cleanup(ts.Close)
	return ts, reg
}

func registerPanelDevice(t *testing.T, reg *registry.Registry) []byte {
	t.Helper()
	activePSK := mustHex(t, 32)
	if _, err := reg.Register(panelTestID, registry.ConfigPayload{
		PSKHex: activePSK, BrokerURL: "http://x",
	}); err != nil {
		t.Fatal(err)
	}
	psk, _ := hex.DecodeString(activePSK)
	return psk
}

func signedPanelRequest(t *testing.T, ts *httptest.Server, psk []byte, deviceID string, tamper bool) *http.Response {
	t.Helper()
	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := mustHex(t, 16)
	path := "/device/" + deviceID + "/panel"
	versionStr := "1"
	sig := auth.ComputeSignature(psk, "GET", path, now, nonce, deviceID, versionStr)
	if tamper {
		sig = strings.Repeat("0", len(sig))
	}
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("X-Tmon-Timestamp", now)
	req.Header.Set("X-Tmon-Nonce", nonce)
	req.Header.Set("X-Tmon-Signature", sig)
	req.Header.Set("X-Tmon-Device", deviceID)
	req.Header.Set("X-Tmon-Config-Version", versionStr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestPanel_ConfiguredFile_ServesVerbatim is the happy path: a configured
// global file is returned byte-for-byte with a 200.
func TestPanel_ConfiguredFile_ServesVerbatim(t *testing.T) {
	body := `{"version":1,"tiles":[{"type":"text","text":"hi"}]}`
	dir := t.TempDir()
	file := filepath.Join(dir, "panel.json")
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	ts, reg := newPanelServer(t, func(c *config.Config) { c.Panel.File = config.PanelPaths{"default": file} })
	psk := registerPanelDevice(t, reg)

	resp := signedPanelRequest(t, ts, psk, panelTestID, false)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Fatalf("body mismatch:\n got %q\nwant %q", got, body)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

// TestPanel_NotConfigured_404 — both keys empty ⇒ feature off ⇒ 404, the same
// code path as an old broker with no route.
func TestPanel_NotConfigured_404(t *testing.T) {
	ts, reg := newPanelServer(t, nil)
	psk := registerPanelDevice(t, reg)
	resp := signedPanelRequest(t, ts, psk, panelTestID, false)
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// TestPanel_UnknownDevice_404 — rejected before auth (PSKsFor ErrNotFound).
func TestPanel_UnknownDevice_404(t *testing.T) {
	file := filepath.Join(t.TempDir(), "panel.json")
	_ = os.WriteFile(file, []byte(`{"version":1}`), 0600)
	ts, _ := newPanelServer(t, func(c *config.Config) { c.Panel.File = config.PanelPaths{"default": file} })
	resp := signedPanelRequest(t, ts, []byte("irrelevant"), panelTestID, false)
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// TestPanel_Oversize_422 — a file past panelMaxBytes is rejected, never streamed.
func TestPanel_Oversize_422(t *testing.T) {
	file := filepath.Join(t.TempDir(), "panel.json")
	big := `{"x":"` + strings.Repeat("a", panelMaxBytes) + `"}`
	if err := os.WriteFile(file, []byte(big), 0600); err != nil {
		t.Fatal(err)
	}
	ts, reg := newPanelServer(t, func(c *config.Config) { c.Panel.File = config.PanelPaths{"default": file} })
	psk := registerPanelDevice(t, reg)
	resp := signedPanelRequest(t, ts, psk, panelTestID, false)
	defer resp.Body.Close()
	if resp.StatusCode != 422 {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
}

// TestPanel_BadJSON_422 — a present but non-JSON file is a config error, 422.
func TestPanel_BadJSON_422(t *testing.T) {
	file := filepath.Join(t.TempDir(), "panel.json")
	if err := os.WriteFile(file, []byte("not json at all"), 0600); err != nil {
		t.Fatal(err)
	}
	ts, reg := newPanelServer(t, func(c *config.Config) { c.Panel.File = config.PanelPaths{"default": file} })
	psk := registerPanelDevice(t, reg)
	resp := signedPanelRequest(t, ts, psk, panelTestID, false)
	defer resp.Body.Close()
	if resp.StatusCode != 422 {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
}

// TestPanel_BadSignature_401.
func TestPanel_BadSignature_401(t *testing.T) {
	file := filepath.Join(t.TempDir(), "panel.json")
	_ = os.WriteFile(file, []byte(`{"version":1}`), 0600)
	ts, reg := newPanelServer(t, func(c *config.Config) { c.Panel.File = config.PanelPaths{"default": file} })
	psk := registerPanelDevice(t, reg)
	resp := signedPanelRequest(t, ts, psk, panelTestID, true /*tamper*/)
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestPanel_PerDeviceDirWins — <dir>/<id>.json takes precedence over the
// global file and over <dir>/default.json.
func TestPanel_PerDeviceDirWins(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "global.json")
	_ = os.WriteFile(global, []byte(`{"src":"global"}`), 0600)
	_ = os.WriteFile(filepath.Join(dir, "default.json"), []byte(`{"src":"default"}`), 0600)
	perDev := `{"src":"perdevice"}`
	_ = os.WriteFile(filepath.Join(dir, panelTestID+".json"), []byte(perDev), 0600)

	ts, reg := newPanelServer(t, func(c *config.Config) {
		c.Panel.Dir = dir
		c.Panel.File = config.PanelPaths{"default": global}
	})
	psk := registerPanelDevice(t, reg)
	resp := signedPanelRequest(t, ts, psk, panelTestID, false)
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != perDev {
		t.Fatalf("expected per-device file, got %q", got)
	}
}

// TestPanel_ExplicitPerDeviceFileWins — an explicit [panel.file].<id> entry
// takes precedence over both the dir convention and the default file.
func TestPanel_ExplicitPerDeviceFileWins(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "def.json")
	_ = os.WriteFile(def, []byte(`{"src":"default"}`), 0600)
	// A dir/<id>.json exists too — the explicit entry must still win.
	_ = os.WriteFile(filepath.Join(dir, panelTestID+".json"), []byte(`{"src":"dir"}`), 0600)
	explicit := filepath.Join(dir, "explicit.json")
	want := `{"src":"explicit"}`
	_ = os.WriteFile(explicit, []byte(want), 0600)

	ts, reg := newPanelServer(t, func(c *config.Config) {
		c.Panel.Dir = dir
		c.Panel.File = config.PanelPaths{"default": def, panelTestID: explicit}
	})
	psk := registerPanelDevice(t, reg)
	resp := signedPanelRequest(t, ts, psk, panelTestID, false)
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != want {
		t.Fatalf("expected explicit per-device file, got %q", got)
	}
}

// TestPanel_ServesCompatGolden round-trips a shared contract golden byte-exact
// (skips in a standalone marketplace checkout where compat/ is absent).
func TestPanel_ServesCompatGolden(t *testing.T) {
	golden := findCompatPanelGolden(t, "session_line.json")
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	ts, reg := newPanelServer(t, func(c *config.Config) { c.Panel.File = config.PanelPaths{"default": golden} })
	psk := registerPanelDevice(t, reg)
	resp := signedPanelRequest(t, ts, psk, panelTestID, false)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != string(want) {
		t.Fatalf("golden byte mismatch")
	}
}

func findCompatPanelGolden(t *testing.T, name string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 9; i++ {
		candidate := filepath.Join(dir, "compat", "panel", "golden", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("compat/panel/golden/%s not found upward from %s (standalone checkout)", name, wd)
	return ""
}
