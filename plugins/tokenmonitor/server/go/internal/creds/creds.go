// Package creds reads the OAuth credentials written by the Claude CLI and
// exposes the bits the broker needs to hand to the device.
//
// Source of truth differs by platform: on Linux the Claude CLI writes a
// plaintext file (`~/.claude/.credentials.json` by default); on macOS it
// stores the same JSON blob in the login Keychain as a generic-password item
// under the service name KeychainService. ReadRaw hides that difference —
// file first (honours an explicit oauth_path override or a Linux install),
// then the Keychain on darwin when the file is absent.
package creds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	ErrFileMissing = errors.New("credentials file missing")
	ErrParse       = errors.New("credentials parse error")
)

// KeychainService is the macOS login-Keychain generic-password service name
// the Claude CLI stores its OAuth blob under. The stored secret is the exact
// same {"claudeAiOauth":{...}} JSON document as the on-disk file.
const KeychainService = "Claude Code-credentials"

// keychainReader shells out to /usr/bin/security to print the secret to
// stdout. It is a package var so tests can inject a fake without a real
// Keychain. The first read may raise a GUI authorization prompt; once the
// user picks "Always Allow" it succeeds silently. A short timeout keeps a
// never-answered prompt from wedging the broker's poll loop.
var keychainReader = func(service string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/bin/security",
		"find-generic-password", "-s", service, "-w").Output()
}

// defaultOAuthPath is the platform-default Claude credentials file. The
// Keychain fallback only applies to this path — a var so tests can point it
// at a temp file. Empty if the home dir can't be resolved.
var defaultOAuthPath = func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", ".credentials.json")
}

// ReadRaw returns the raw Claude credentials JSON blob, Keychain-aware on
// macOS. The file wins when present. Only a genuinely-absent DEFAULT file
// falls back to the Keychain (and only on darwin): an explicit oauth_path
// override that's missing must error, not silently serve the login account's
// token. Any other file error surfaces as ErrParse; a missing file or a
// Keychain miss surfaces as ErrFileMissing, so callers behave as before.
func ReadRaw(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return raw, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	if runtime.GOOS == "darwin" && path == defaultOAuthPath() {
		if kc, kerr := keychainReader(KeychainService); kerr == nil && len(strings.TrimSpace(string(kc))) > 0 {
			return kc, nil
		}
		return nil, fmt.Errorf("%w: %s (macOS Keychain %q also unavailable)", ErrFileMissing, path, KeychainService)
	}
	return nil, fmt.Errorf("%w: %s", ErrFileMissing, path)
}

// Stored is the subset of the on-disk credentials we hand to the device.
type Stored struct {
	AccessToken     string
	ExpiresAtUnixMS int64
}

func (s Stored) ExpiresAtISO() string {
	t := time.UnixMilli(s.ExpiresAtUnixMS).UTC()
	return t.Format("2006-01-02T15:04:05.000Z")
}

func (s Stored) IsExpired(now time.Time) bool {
	return now.UnixMilli() >= s.ExpiresAtUnixMS
}

// Load parses the on-disk JSON written by the Claude CLI:
//
//	{"claudeAiOauth": {"accessToken": "...", "expiresAt": <ms>, ...}}
func Load(path string) (*Stored, error) {
	raw, err := ReadRaw(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		ClaudeAIOauth struct {
			AccessToken string `json:"accessToken"`
			ExpiresAt   int64  `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	if doc.ClaudeAIOauth.AccessToken == "" {
		return nil, fmt.Errorf("%w: missing or invalid 'accessToken'", ErrParse)
	}
	if doc.ClaudeAIOauth.ExpiresAt == 0 {
		return nil, fmt.Errorf("%w: missing or invalid 'expiresAt'", ErrParse)
	}
	return &Stored{
		AccessToken:     doc.ClaudeAIOauth.AccessToken,
		ExpiresAtUnixMS: doc.ClaudeAIOauth.ExpiresAt,
	}, nil
}
