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

// writeDefaultConfig drops a config with the given [auth] body at the
// canonical path under home.
func writeDefaultConfig(t *testing.T, home, authBody string) string {
	t.Helper()
	path := defaultConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "[server]\nbind = \"0.0.0.0\"\nport = 8765\n\n[auth]\n" + authBody
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoad_EmptyPSKFallsBackToSidecar is the second half of the fresh-install
// story: a config that EXISTS but carries no usable PSK used to exit 2 before
// answering `initialize`, so the MCP client dropped the server exactly as it
// did with no config at all. A hand-written `psk_hex = ""` is the real case.
func TestLoad_EmptyPSKFallsBackToSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeDefaultConfig(t, home, "psk_hex = \"\"\n")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with an empty psk_hex: %v", err)
	}
	if len(cfg.PSK()) != 32 {
		t.Fatalf("PSK length = %d, want 32", len(cfg.PSK()))
	}

	sidecar := filepath.Join(filepath.Dir(path), FallbackPSKName)
	info, err := os.Stat(sidecar)
	if err != nil {
		t.Fatalf("stat sidecar: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("sidecar perm = %04o, want 0600", perm)
	}
	// The config itself must be left exactly as the user wrote it.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "psk_hex = \"\"") {
		t.Error("the user's config was rewritten")
	}
}

// TestLoad_MissingAuthSectionFallsBackToSidecar: no [auth] table at all is the
// same "unset" case as an empty value.
func TestLoad_MissingAuthSectionFallsBackToSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := defaultConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[server]\nport = 8765\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with no [auth] section: %v", err)
	}
	if len(cfg.PSK()) != 32 {
		t.Errorf("PSK length = %d, want 32", len(cfg.PSK()))
	}
}

// TestLoad_FallbackPSKIsStable: the sidecar must survive restarts. A key that
// changed on every start would break any device holding the global PSK.
func TestLoad_FallbackPSKIsStable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDefaultConfig(t, home, "psk_hex = \"\"\n")

	first, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PSK(), second.PSK()) {
		t.Error("fallback PSK changed between starts")
	}
}

// TestLoad_MalformedPSKIsDroppedNotFatal: a malformed value costs you that
// section, not the broker. Refusing to start would be self-defeating — the
// broker is how a device gets configured in the first place, so a typo must
// not cost you the ability to set one up.
//
// Overwriting a key a device might know would normally be the danger here, but
// a malformed value was never accepted by any broker version, so no working
// device can be using it. The drop is reported via Salvaged() and the file
// itself is left untouched, so the user can still see what they meant.
func TestLoad_MalformedPSKIsDroppedNotFatal(t *testing.T) {
	cases := []struct{ name, auth string }{
		{"short passphrase", "psk_passphrase = \"abc\"\n"},
		{"short hex", "psk_hex = \"abcd\"\n"},
		{"non-hex", "psk_hex = \"" + strings.Repeat("z", 64) + "\"\n"},
		{"wrong type", "psk_hex = []\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			path := writeDefaultConfig(t, home, tc.auth)

			cfg, err := Load("")
			if err != nil {
				t.Fatalf("Load on a malformed PSK: %v", err)
			}
			// The bad [auth] is gone, so the sidecar supplies the key.
			if len(cfg.PSK()) != 32 {
				t.Errorf("PSK length = %d, want 32", len(cfg.PSK()))
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), FallbackPSKName)); err != nil {
				t.Errorf("no fallback key minted after dropping [auth]: %v", err)
			}
			// The salvage has to be visible, or it is just a silent rewrite of
			// the user's intent.
			if len(cfg.Salvaged()) == 0 {
				t.Error("dropped a section without reporting it")
			}
			// The user's file is never edited — only ignored in part.
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), strings.TrimSpace(tc.auth)) {
				t.Error("the user's config was rewritten")
			}
		})
	}
}

// TestLoad_SalvageKeepsTheGoodSections is the property the whole salvage
// exists for: one broken section must not cost you the rest of the file, and
// what survives has to be the values the user actually wrote.
func TestLoad_SalvageKeepsTheGoodSections(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := defaultConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "[server]\nbind = \"0.0.0.0\"\nport = 9999\n\n" +
		"[auth]\npsk_passphrase = \"a-good-long-passphrase\"\n\n" +
		"[logging]\nlevel = \"DEBUG\"\n\n" +
		"[panel\nthis section is broken\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with one broken section: %v", err)
	}
	if cfg.Server.Port != 9999 {
		t.Errorf("port = %d, want the configured 9999", cfg.Server.Port)
	}
	if cfg.Server.Bind != "0.0.0.0" {
		t.Errorf("bind = %q, want the configured 0.0.0.0", cfg.Server.Bind)
	}
	if cfg.Auth.Passphrase != "a-good-long-passphrase" {
		t.Errorf("passphrase = %q, want the configured one", cfg.Auth.Passphrase)
	}
	want := sha256.Sum256([]byte("a-good-long-passphrase"))
	if !bytes.Equal(cfg.PSK(), want[:]) {
		t.Error("PSK is not derived from the surviving passphrase")
	}
	if cfg.Logging.Level != "DEBUG" {
		t.Errorf("level = %q, want DEBUG", cfg.Logging.Level)
	}
	if len(cfg.Salvaged()) == 0 {
		t.Error("dropped a section without reporting it")
	}
}

// TestLoad_SalvageNeverFabricatesASection is the soundness property: a line
// starting with '[' inside a multi-line string is not a header, and a splitter
// that trusted it would hand the salvage a chunk of *string content* that
// parses as a perfectly good [auth] — with a PSK the user never set. Losing
// data is acceptable; inventing it is not.
func TestLoad_SalvageNeverFabricatesASection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := defaultConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// [auth] here is the contents of panel.file, not a section: the `#` makes
	// the closing """ a comment, so a naive split sees a header.
	body := "[panel]\nfile = \"\"\"\n[auth] # \"\"\"\npsk_passphrase = \"fabricated-secret\"\n\n[broken\nx\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.Passphrase != "" {
		t.Errorf("invented an [auth] section out of string content: %q", cfg.Auth.Passphrase)
	}
	want := sha256.Sum256([]byte("fabricated-secret"))
	if bytes.Equal(cfg.PSK(), want[:]) {
		t.Error("PSK came from text inside a string literal")
	}
	if len(cfg.PSK()) != 32 {
		t.Errorf("PSK length = %d, want a usable fallback key", len(cfg.PSK()))
	}
}

// TestLoad_SalvageKeepsAValidPassphraseUnderAStaleHex: Load resolves the
// passphrase first and never reads psk_hex when one is set, so a leftover
// malformed hex must not condemn the section. Dropping [auth] here would swap
// a working key for the sidecar and desync every paired device.
func TestLoad_SalvageKeepsAValidPassphraseUnderAStaleHex(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDefaultConfig(t, home, "psk_passphrase = \"the-current-valid-secret\"\npsk_hex = \"bad\"\n")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := sha256.Sum256([]byte("the-current-valid-secret"))
	if !bytes.Equal(cfg.PSK(), want[:]) {
		t.Error("PSK is not derived from the configured passphrase")
	}
	if len(cfg.Salvaged()) != 0 {
		t.Errorf("dropped a section that resolves fine: %v", cfg.Salvaged())
	}
}

// TestLoad_SalvageDoesNotWidenAnUnreadableBind: the 0.0.0.0 rescue exists so a
// device can still reach the broker, but a bind we failed to parse is still
// the user saying something about their network boundary. Widening it on their
// behalf is not a rescue.
func TestLoad_SalvageDoesNotWidenAnUnreadableBind(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := defaultConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "[server]\nbind = \"127.0.0.1\"\nport == 8765\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Bind == "0.0.0.0" {
		t.Error("widened a bind the user had restricted but we could not parse")
	}
	if len(cfg.Salvaged()) == 0 {
		t.Error("dropped [server] without reporting it")
	}
}

// TestLoad_SalvageReportsARepeatedHeader: [[ota.keys]] is one entry per signing
// key, so the same header appears several times. A dropped second entry must
// still be named — matching kept-vs-dropped by presence would let it hide
// behind the first entry that survived, and losing a signing key silently is
// exactly what the report exists to prevent.
func TestLoad_SalvageReportsARepeatedHeader(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := defaultConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "[auth]\npsk_passphrase = \"a-good-long-passphrase\"\n\n" +
		"[[ota.keys]]\nkey_id = \"k1\"\npubkey_b64 = \"AAAA\"\n\n" +
		// A syntax error, not a type error: Go's typed unmarshal rejects a
		// wrong-typed value that py/js would coerce, and this test is about the
		// reporting, so it has to fail identically in all three parsers.
		"[[ota.keys]]\nkey_id = \"k2\"\npubkey_b64 == \"AAAA\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with a bad second ota key: %v", err)
	}
	if len(cfg.OTA.Keys) != 1 || cfg.OTA.Keys[0].KeyID != "k1" {
		t.Errorf("OTA keys = %+v, want only the good k1", cfg.OTA.Keys)
	}
	var named bool
	for _, s := range cfg.Salvaged() {
		if strings.Contains(s, "ota.keys") {
			named = true
		}
	}
	if !named {
		t.Errorf("dropped an [[ota.keys]] entry without naming it: %v", cfg.Salvaged())
	}
}

// TestLoad_SalvageBindsForTheDevice: when the rescue loses [server], the code
// default (loopback) would leave the device unable to reach the broker — and
// the broker is how a device gets configured. Fall back to the bind a fresh
// bootstrap would have written instead.
func TestLoad_SalvageBindsForTheDevice(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := defaultConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[server\nbroken header\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with a broken [server]: %v", err)
	}
	if cfg.Server.Bind != "0.0.0.0" {
		t.Errorf("bind = %q, want 0.0.0.0 so the device can reach the broker", cfg.Server.Bind)
	}
	if cfg.Server.Port != 8765 {
		t.Errorf("port = %d, want 8765", cfg.Server.Port)
	}
	if len(cfg.PSK()) != 32 {
		t.Errorf("PSK length = %d, want a usable fallback key", len(cfg.PSK()))
	}
}

// TestLoad_ExplicitPathIsStrict: --config is the operator's file. Quietly
// running on half of it would hide the mistake behind a broker that works but
// isn't doing what they wrote.
func TestLoad_ExplicitPathIsStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "explicit.toml")
	if err := os.WriteFile(path, []byte("[server]\nport = 9999\n\n[panel\nbroken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load salvaged an explicit --config, want error")
	}
}

// TestLoad_ExplicitPathDoesNotMintFallback: an operator-supplied --config may
// be managed from elsewhere; we don't quietly add a key beside it.
func TestLoad_ExplicitPathDoesNotMintFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "explicit.toml")
	if err := os.WriteFile(path, []byte("[auth]\npsk_hex = \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("Load with an explicit PSK-less config succeeded, want error")
	}
	if _, err := os.Stat(filepath.Join(dir, FallbackPSKName)); !os.IsNotExist(err) {
		t.Error("minted a fallback key next to an explicit --config")
	}
}

// TestLoad_CorruptSidecarFails: a sidecar that exists but isn't a 32-byte key
// is never overwritten — the user may have put a specific key there.
func TestLoad_CorruptSidecarFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeDefaultConfig(t, home, "psk_hex = \"\"\n")
	sidecar := filepath.Join(filepath.Dir(path), FallbackPSKName)
	if err := os.WriteFile(sidecar, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(""); err == nil {
		t.Fatal("Load succeeded with a corrupt sidecar, want error")
	}
	raw, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "not-a-key" {
		t.Error("corrupt sidecar was overwritten")
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
