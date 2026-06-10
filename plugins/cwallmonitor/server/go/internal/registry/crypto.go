package registry

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
)

// PendingNonceLen is the size of the random nonce that prefixes every
// encrypted pending payload. AES-CTR needs an IV the size of the block
// (16 bytes); a fresh one per encryption call guarantees that
// re-encrypting the same payload after a registry edit produces a
// different ciphertext, eliminating the catastrophic AES-CTR
// nonce-reuse failure mode.
const PendingNonceLen = aes.BlockSize

// PendingGCMNonceLen is the nonce size for the AES-256-GCM pending
// envelope (the wire enc="gcm" format). GCM's standard 96-bit nonce;
// distinct from the 16-byte CTR IV on purpose so a downgrade-strip
// attack can't reuse one nonce as the other cipher's IV.
const PendingGCMNonceLen = 12

// PendingGCMMinFwVersion is the lowest running firmware version (numeric
// maj.min.patch) that understands the AES-256-GCM pending envelope.
// Devices reporting an X-Cwm-Fw-Version below this still receive the
// legacy AES-CTR blob. Mirrors compat/vectors/aes_gcm.json min_fw_version.
const PendingGCMMinFwVersion = "0.8.1"

// EncryptPending encrypts `plaintext` with AES-CTR using `key` (must be
// 32 bytes — the device's active PSK). Returns the random nonce and the
// ciphertext separately so the broker can serialise them as distinct
// JSON fields. The plaintext is never logged; callers should treat it
// as secret.
func EncryptPending(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("registry/crypto: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("registry/crypto: aes.NewCipher: %w", err)
	}
	nonce = make([]byte, PendingNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("registry/crypto: rand: %w", err)
	}
	ciphertext = make([]byte, len(plaintext))
	cipher.NewCTR(block, nonce).XORKeyStream(ciphertext, plaintext)
	return nonce, ciphertext, nil
}

// DecryptPending reverses EncryptPending. AES-CTR is malleable on its
// own (no auth tag); callers MUST rely on the HMAC of the surrounding
// HTTP response — not on this function — to detect tampering.
func DecryptPending(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("registry/crypto: key must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != PendingNonceLen {
		return nil, fmt.Errorf("registry/crypto: nonce must be %d bytes, got %d", PendingNonceLen, len(nonce))
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("registry/crypto: empty ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("registry/crypto: aes.NewCipher: %w", err)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCTR(block, nonce).XORKeyStream(out, ciphertext)
	return out, nil
}

// gcmAAD is the additional-authenticated-data for the GCM pending
// envelope: the ASCII decimal representation of pending.version (e.g.
// version 7 => "7"), NOT the raw 4-byte integer. It binds the ciphertext
// to a specific config version so an attacker can't lift a payload onto a
// different version number. See compat/vectors/aes_gcm.json.
func gcmAAD(version uint32) []byte {
	return []byte(strconv.FormatUint(uint64(version), 10))
}

// EncryptPendingGCM encrypts `plaintext` with AES-256-GCM using `key`
// (must be 32 bytes — the device's active PSK). A fresh 12-byte random
// nonce is generated per call. The returned ciphertext is ct||tag (the
// 16-byte GCM tag appended, native crypto/cipher AEAD.Seal byte order).
// `version` becomes the AAD (see gcmAAD). The plaintext is never logged;
// callers should treat it as secret.
//
// The wire envelope sets "enc":"gcm"; absent that field the device
// decrypts the legacy CTR blob instead.
func EncryptPendingGCM(key []byte, version uint32, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, PendingGCMNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("registry/crypto: rand: %w", err)
	}
	ciphertext, err = encryptPendingGCMNonce(key, version, nonce, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return nonce, ciphertext, nil
}

// encryptPendingGCMNonce is the deterministic core of EncryptPendingGCM
// with the nonce injected, so the compat-vector tests can reproduce the
// exact ciphertext_hex. Production code MUST go through EncryptPendingGCM
// (random nonce per call) — reusing a nonce under GCM is catastrophic.
func encryptPendingGCMNonce(key []byte, version uint32, nonce, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("registry/crypto: key must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != PendingGCMNonceLen {
		return nil, fmt.Errorf("registry/crypto: gcm nonce must be %d bytes, got %d", PendingGCMNonceLen, len(nonce))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("registry/crypto: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("registry/crypto: cipher.NewGCM: %w", err)
	}
	// Seal appends the 16-byte tag to the ciphertext: ct||tag.
	return aead.Seal(nil, nonce, plaintext, gcmAAD(version)), nil
}

// DecryptPendingGCM reverses EncryptPendingGCM. `ciphertext` is ct||tag.
// Unlike CTR, GCM authenticates: a flipped tag, wrong key, wrong nonce
// length or wrong AAD (i.e. wrong version) all surface as an error and
// never yield plaintext.
func DecryptPendingGCM(key []byte, version uint32, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("registry/crypto: key must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != PendingGCMNonceLen {
		return nil, fmt.Errorf("registry/crypto: gcm nonce must be %d bytes, got %d", PendingGCMNonceLen, len(nonce))
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("registry/crypto: empty ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("registry/crypto: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("registry/crypto: cipher.NewGCM: %w", err)
	}
	out, err := aead.Open(nil, nonce, ciphertext, gcmAAD(version))
	if err != nil {
		return nil, fmt.Errorf("registry/crypto: gcm open: %w", err)
	}
	return out, nil
}
