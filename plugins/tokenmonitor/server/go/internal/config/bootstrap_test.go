package config

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// defaultConfigPath is where Load("") writes on a machine whose HOME the test
// has redirected.
func defaultConfigPath(home string) string {
	return filepath.Join(home, ".config", "tokenmonitor", "tokenmonitor.toml")
}

// TestLoad_BootstrapsMissingDefault is the regression guard for a fresh
// install: before this, Load() returned "no such file" and main() exited 2,
// so the MCP client never saw the server reach ready and dropped it.
func TestLoad_BootstrapsMissingDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load on a machine with no config: %v", err)
	}

	path := defaultConfigPath(home)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat bootstrapped config: %v", err)
	}
	// The file holds a shared secret; it must not be world- or group-readable.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config perm = %04o, want 0600", perm)
	}

	if cfg.Auth.Passphrase == "" || strings.Contains(cfg.Auth.Passphrase, bootstrapPassphrasePlaceholder) {
		t.Fatalf("passphrase not substituted: %q", cfg.Auth.Passphrase)
	}
	if len(cfg.Auth.Passphrase) != 32 {
		t.Errorf("passphrase length = %d, want 32", len(cfg.Auth.Passphrase))
	}
	want := sha256.Sum256([]byte(cfg.Auth.Passphrase))
	if !bytes.Equal(cfg.PSK(), want[:]) {
		t.Error("PSK is not the SHA-256 of the generated passphrase")
	}
	// Defaults the device depends on must survive the short template.
	if cfg.Server.Bind != "0.0.0.0" || cfg.Server.Port != 8765 {
		t.Errorf("server = %s:%d, want 0.0.0.0:8765", cfg.Server.Bind, cfg.Server.Port)
	}
}

// TestLoad_BootstrapIsIdempotent: the second start must adopt the first run's
// passphrase, not mint a new one — rotating it would silently break every
// device already paired against the previous key.
func TestLoad_BootstrapIsIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	first, err := Load("")
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	second, err := Load("")
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if first.Auth.Passphrase != second.Auth.Passphrase {
		t.Errorf("passphrase changed across runs: %q → %q", first.Auth.Passphrase, second.Auth.Passphrase)
	}
}

// TestLoad_ExplicitPathDoesNotBootstrap: --config names a file the user
// believes exists. Creating it silently would hide their typo behind a broker
// that starts with the wrong settings.
func TestLoad_ExplicitPathDoesNotBootstrap(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	missing := filepath.Join(home, "typo.toml")
	if _, err := Load(missing); err == nil {
		t.Fatal("Load with an explicit missing path succeeded, want error")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Error("explicit missing path was created")
	}
}

// TestLoad_PrefersLegacyOverBootstrap: an existing service.toml install must
// keep being honoured rather than shadowed by a freshly generated config.
func TestLoad_PrefersLegacyOverBootstrap(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	legacy := filepath.Join(home, ".config", "tokenmonitor", "service.toml")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("[auth]\npsk_passphrase = \"legacy-secret\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with a legacy config: %v", err)
	}
	if cfg.Auth.Passphrase != "legacy-secret" {
		t.Errorf("passphrase = %q, want the legacy one", cfg.Auth.Passphrase)
	}
	if _, err := os.Stat(defaultConfigPath(home)); !os.IsNotExist(err) {
		t.Error("bootstrapped a config even though the legacy one loaded")
	}
}

// TestLoad_UnreadableLegacyIsNotShadowed: a service.toml that exists but
// cannot be read (root-owned after a sudo run, say) must fail loudly.
// Bootstrapping over it would start the broker on a brand-new passphrase and
// silently break every device paired against the old one.
func TestLoad_UnreadableLegacyIsNotShadowed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	legacy := filepath.Join(home, ".config", "tokenmonitor", "service.toml")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("[auth]\npsk_passphrase = \"legacy-secret\"\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(""); err == nil {
		t.Fatal("Load succeeded with an unreadable legacy config, want error")
	}
	if _, err := os.Stat(defaultConfigPath(home)); !os.IsNotExist(err) {
		t.Error("bootstrapped a fresh passphrase over an unreadable legacy config")
	}
}

// TestBootstrap_LoserOfTheRaceAdoptsTheWinner: several tokenmonitor-mcp
// processes can start simultaneously (leader election happens later, on the
// port). The second writer must return the first one's bytes, not overwrite
// them with a different passphrase.
func TestBootstrap_LoserOfTheRaceAdoptsTheWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokenmonitor.toml")

	first, err := Bootstrap(path)
	if err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}
	second, err := Bootstrap(path)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("second Bootstrap did not adopt the first one's file")
	}
}
