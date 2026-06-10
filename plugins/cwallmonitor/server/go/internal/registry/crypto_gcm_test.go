package registry

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// findGCMVectors walks up to the authoritative monorepo
// compat/vectors/aes_gcm.json. Mirrors auth_test.findCompatVectors: it
// probes the *specific* file so the partial server/compat/ slice (which
// ships tool-schemas.json but no vectors/) is skipped, and skips entirely
// on a standalone plugin checkout that has no compat/ at all.
func findGCMVectors(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 9; i++ {
		candidate := filepath.Join(dir, "compat", "vectors", "aes_gcm.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("compat/vectors/aes_gcm.json not found upward from %s (standalone checkout)", wd)
	return ""
}

type gcmVectorDoc struct {
	MinFwVersion string `json:"min_fw_version"`
	Vectors      []struct {
		Name          string `json:"name"`
		KeyHex        string `json:"key_hex"`
		NonceHex      string `json:"nonce_hex"`
		Version       uint32 `json:"version"`
		PlaintextHex  string `json:"plaintext_hex"`
		CiphertextHex string `json:"ciphertext_hex"`
	} `json:"vectors"`
	NegativeVectors []struct {
		Name          string `json:"name"`
		MustError     bool   `json:"must_error"`
		KeyHex        string `json:"key_hex"`
		NonceHex      string `json:"nonce_hex"`
		Version       uint32 `json:"version"`
		CiphertextHex string `json:"ciphertext_hex"`
	} `json:"negative_vectors"`
}

func loadGCMVectors(t *testing.T) gcmVectorDoc {
	t.Helper()
	raw, err := os.ReadFile(findGCMVectors(t))
	if err != nil {
		t.Fatalf("read aes_gcm.json: %v", err)
	}
	var doc gcmVectorDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse aes_gcm.json: %v", err)
	}
	return doc
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// TestGCMVectors_PositiveByteExact reproduces every positive compat vector
// byte-for-byte with the injected nonce, then round-trips it back through
// DecryptPendingGCM. This is the cross-runtime contract py/js also pin.
func TestGCMVectors_PositiveByteExact(t *testing.T) {
	doc := loadGCMVectors(t)
	if len(doc.Vectors) == 0 {
		t.Fatal("compat gcm vectors empty")
	}
	for _, v := range doc.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			key := mustHexDecode(t, v.KeyHex)
			nonce := mustHexDecode(t, v.NonceHex)
			pt := mustHexDecode(t, v.PlaintextHex)
			ct, err := encryptPendingGCMNonce(key, v.Version, nonce, pt)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if got := hex.EncodeToString(ct); got != v.CiphertextHex {
				t.Fatalf("ciphertext mismatch:\n  got  %s\n  want %s", got, v.CiphertextHex)
			}
			// Round-trips with the matching AAD (= version).
			out, err := DecryptPendingGCM(key, v.Version, nonce, ct)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(out, pt) {
				t.Fatalf("round-trip mismatch:\n  got  %x\n  want %x", out, pt)
			}
		})
	}
}

// TestGCMVectors_NegativeMustError asserts every negative vector (flipped
// tag, wrong nonce length, short key, wrong AAD/version) fails to decrypt.
func TestGCMVectors_NegativeMustError(t *testing.T) {
	doc := loadGCMVectors(t)
	if len(doc.NegativeVectors) == 0 {
		t.Fatal("compat gcm negative vectors empty")
	}
	for _, v := range doc.NegativeVectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			if !v.MustError {
				t.Fatalf("negative vector %q has must_error=false", v.Name)
			}
			key := mustHexDecode(t, v.KeyHex)
			nonce := mustHexDecode(t, v.NonceHex)
			ct := mustHexDecode(t, v.CiphertextHex)
			if _, err := DecryptPendingGCM(key, v.Version, nonce, ct); err == nil {
				t.Fatalf("negative vector %q decrypted without error", v.Name)
			}
		})
	}
}

// TestGCMMinFwVersion_MatchesVectorFile pins the constant to the golden.
func TestGCMMinFwVersion_MatchesVectorFile(t *testing.T) {
	doc := loadGCMVectors(t)
	if PendingGCMMinFwVersion != doc.MinFwVersion {
		t.Fatalf("PendingGCMMinFwVersion = %q, want %q (from aes_gcm.json)",
			PendingGCMMinFwVersion, doc.MinFwVersion)
	}
}

// TestEncryptPendingGCM_FreshNonceEachCall confirms the production entry
// point draws a fresh 12-byte nonce per call so identical plaintext does
// not produce identical ciphertext (a reused GCM nonce is catastrophic).
func TestEncryptPendingGCM_FreshNonceEachCall(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pt := []byte("hello pending payload")
	n1, c1, err := EncryptPendingGCM(key, 3, pt)
	if err != nil {
		t.Fatalf("encrypt 1: %v", err)
	}
	n2, c2, err := EncryptPendingGCM(key, 3, pt)
	if err != nil {
		t.Fatalf("encrypt 2: %v", err)
	}
	if len(n1) != PendingGCMNonceLen {
		t.Errorf("nonce length = %d, want %d", len(n1), PendingGCMNonceLen)
	}
	if bytes.Equal(n1, n2) {
		t.Error("nonce reused across calls")
	}
	if bytes.Equal(c1, c2) {
		t.Error("identical plaintext produced identical ciphertext")
	}
	out, err := DecryptPendingGCM(key, 3, n1, c1)
	if err != nil || !bytes.Equal(out, pt) {
		t.Fatalf("round-trip: out=%q err=%v", out, err)
	}
}

// TestGCM_KeyAndNonceLengthEnforced rejects the wrong key / nonce sizes
// on both the encrypt and decrypt paths (AES-256 + 96-bit nonce only).
func TestGCM_KeyAndNonceLengthEnforced(t *testing.T) {
	if _, _, err := EncryptPendingGCM([]byte("short"), 1, []byte("x")); err == nil {
		t.Error("encrypt accepted a short key")
	}
	if _, err := encryptPendingGCMNonce(make([]byte, 32), 1, make([]byte, 16), []byte("x")); err == nil {
		t.Error("encrypt accepted a 16-byte nonce")
	}
	if _, err := DecryptPendingGCM([]byte("short"), 1, make([]byte, 12), []byte("x")); err == nil {
		t.Error("decrypt accepted a short key")
	}
	if _, err := DecryptPendingGCM(make([]byte, 32), 1, make([]byte, 16), []byte("x")); err == nil {
		t.Error("decrypt accepted a 16-byte nonce")
	}
	if _, err := DecryptPendingGCM(make([]byte, 32), 1, make([]byte, 12), nil); err == nil {
		t.Error("decrypt accepted empty ciphertext")
	}
}

// TestGCM_WrongAADVersionFails confirms the AAD binds the ciphertext to
// pending.version: decrypting with a different version must fail.
func TestGCM_WrongAADVersionFails(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	nonce, ct, err := EncryptPendingGCM(key, 7, []byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptPendingGCM(key, 8, nonce, ct); err == nil {
		t.Fatal("decrypt with wrong version (AAD) succeeded")
	}
	if _, err := DecryptPendingGCM(key, 7, nonce, ct); err != nil {
		t.Fatalf("decrypt with right version failed: %v", err)
	}
}
