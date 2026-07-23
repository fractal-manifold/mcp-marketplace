package creds

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestReadRaw_FileWinsOverKeychain: a present file is authoritative and the
// Keychain must not be consulted (honours explicit oauth_path / Linux).
func TestReadRaw_FileWinsOverKeychain(t *testing.T) {
	orig := keychainReader
	t.Cleanup(func() { keychainReader = orig })
	keychainReader = func(string) ([]byte, error) {
		t.Fatal("keychain must not be consulted when the file exists")
		return nil, nil
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(p,
		[]byte(`{"claudeAiOauth":{"accessToken":"f","expiresAt":1700000000000}}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c.AccessToken != "f" {
		t.Fatalf("c=%+v err=%v", c, err)
	}
}

// TestReadRaw_KeychainFallbackDarwin: on macOS a missing DEFAULT file falls
// back to the login Keychain, which serves the same JSON blob.
func TestReadRaw_KeychainFallbackDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain fallback is darwin-only")
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	origKC, origDef := keychainReader, defaultOAuthPath
	t.Cleanup(func() { keychainReader, defaultOAuthPath = origKC, origDef })
	defaultOAuthPath = func() string { return missing } // treat the temp path as the default
	keychainReader = func(service string) ([]byte, error) {
		if service != KeychainService {
			t.Fatalf("service = %q, want %q", service, KeychainService)
		}
		return []byte(`{"claudeAiOauth":{"accessToken":"kc","expiresAt":1700000000000}}`), nil
	}
	c, err := Load(missing)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessToken != "kc" {
		t.Errorf("token = %q, want kc", c.AccessToken)
	}
}

// TestReadRaw_ExplicitOverrideNoKeychain: a missing NON-default oauth_path
// must NOT fall back to the Keychain — it errors so we never serve the login
// account's token in place of the configured one.
func TestReadRaw_ExplicitOverrideNoKeychain(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain fallback is darwin-only")
	}
	origKC, origDef := keychainReader, defaultOAuthPath
	t.Cleanup(func() { keychainReader, defaultOAuthPath = origKC, origDef })
	defaultOAuthPath = func() string { return "/the/default/.credentials.json" }
	keychainReader = func(string) ([]byte, error) {
		t.Fatal("keychain must not be consulted for an explicit override path")
		return nil, nil
	}
	if _, err := Load(filepath.Join(t.TempDir(), "custom-missing.json")); !errors.Is(err, ErrFileMissing) {
		t.Fatalf("expected ErrFileMissing, got %v", err)
	}
}

// TestReadRaw_KeychainMissDarwin: a Keychain miss still surfaces
// ErrFileMissing so callers degrade exactly as on Linux.
func TestReadRaw_KeychainMissDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain fallback is darwin-only")
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	origKC, origDef := keychainReader, defaultOAuthPath
	t.Cleanup(func() { keychainReader, defaultOAuthPath = origKC, origDef })
	defaultOAuthPath = func() string { return missing }
	keychainReader = func(string) ([]byte, error) { return nil, errors.New("not found") }
	if _, err := Load(missing); !errors.Is(err, ErrFileMissing) {
		t.Fatalf("expected ErrFileMissing, got %v", err)
	}
}

func TestLoad_Happy(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(p,
		[]byte(`{"claudeAiOauth":{"accessToken":"tok","expiresAt":1700000000000}}`),
		0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessToken != "tok" {
		t.Errorf("token: %q", c.AccessToken)
	}
	if c.ExpiresAtUnixMS != 1700000000000 {
		t.Errorf("expires_at: %d", c.ExpiresAtUnixMS)
	}
}

func TestLoad_Missing(t *testing.T) {
	_, err := Load("/nonexistent/path/credentials.json")
	if !errors.Is(err, ErrFileMissing) {
		t.Fatalf("expected ErrFileMissing, got %v", err)
	}
}

func TestLoad_BadJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	os.WriteFile(p, []byte("not json"), 0600)
	_, err := Load(p)
	if !errors.Is(err, ErrParse) {
		t.Fatalf("expected ErrParse, got %v", err)
	}
}

func TestLoad_MissingFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	os.WriteFile(p, []byte(`{"claudeAiOauth":{}}`), 0600)
	_, err := Load(p)
	if !errors.Is(err, ErrParse) {
		t.Fatalf("expected ErrParse, got %v", err)
	}
}

func TestStored_IsExpired(t *testing.T) {
	c := Stored{ExpiresAtUnixMS: 1000}
	if !c.IsExpired(time.UnixMilli(2000)) {
		t.Error("expected expired at 2000ms")
	}
	if c.IsExpired(time.UnixMilli(500)) {
		t.Error("not yet expired at 500ms")
	}
}

func TestLoadCodex_HappyNested(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(p,
		[]byte(`{"tokens":{"access_token":"tok","account_id":"acct"},"expires_at":"2026-01-02T03:04:05Z"}`),
		0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessToken != "tok" || c.AccountID != "acct" {
		t.Fatalf("codex creds = %+v", c)
	}
	if c.ExpiresAtISO() != "2026-01-02T03:04:05.000Z" {
		t.Fatalf("expires = %s", c.ExpiresAtISO())
	}
}

func TestLoadCodex_HappyFlatEpochSeconds(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(p,
		[]byte(`{"access_token":"tok","account_id":"acct","expires_at":1700000000}`),
		0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ExpiresAtUnixMS != 1700000000000 {
		t.Fatalf("expires ms = %d", c.ExpiresAtUnixMS)
	}
}

func TestLoadCodex_ExpiresFromJWT(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.json")
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1700000000}`))
	jwt := header + "." + payload + ".sig"
	body := `{"tokens":{"access_token":"` + jwt + `","account_id":"acct"}}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ExpiresAtUnixMS != 1700000000000 {
		t.Fatalf("expires ms = %d", c.ExpiresAtUnixMS)
	}
}

func TestLoadCodex_MissingAccount(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.json")
	os.WriteFile(p, []byte(`{"access_token":"tok","expires_at":1700000000}`), 0600)
	_, err := LoadCodex(p)
	if !errors.Is(err, ErrParse) || !errors.Is(err, ErrCodexNoAccount) {
		t.Fatalf("expected ErrParse wrapping ErrCodexNoAccount, got %v", err)
	}
}
