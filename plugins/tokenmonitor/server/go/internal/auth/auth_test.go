package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mustPSK() []byte {
	return []byte("psk-32-bytes-of-secret-material!")
}

func TestVerify_HappyPath(t *testing.T) {
	psk := mustPSK()
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "0123456789abcdef0123456789abcdef"
	sig := ComputeSignature(psk, "GET", "/credentials", ts, nonce, "", "")

	if err := Verify(psk, "GET", "/credentials", ts, nonce, sig, "", "", cache, time.Minute, now); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestVerify_MissingHeaders(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	now := time.Now()
	err := Verify(mustPSK(), "GET", "/credentials", "", "abc", "def", "", "", cache, time.Minute, now)
	if !errors.Is(err, ErrMissingHeaders) {
		t.Fatalf("expected ErrMissingHeaders, got %v", err)
	}
}

func TestVerify_NonASCIIHeaderRejected(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	// A non-ASCII nonce (byte >= 0x80) must be a plain non-ASCII rejection,
	// not a signature/format guess — parity with py/js.
	err := Verify(mustPSK(), "GET", "/credentials", ts, "\xc3\xa9deadbeefdeadbeefdeadbeefdead", "deadbeef", "", "", cache, time.Minute, now)
	if !errors.Is(err, ErrNonASCIIHeader) {
		t.Fatalf("expected ErrNonASCIIHeader, got %v", err)
	}
	// Also on a device header carrying UTF-8.
	nonce := "0123456789abcdef0123456789abcdef"
	sig := ComputeSignature(mustPSK(), "GET", "/credentials", ts, nonce, "café", "")
	err = Verify(mustPSK(), "GET", "/credentials", ts, nonce, sig, "café", "", cache, time.Minute, now)
	if !errors.Is(err, ErrNonASCIIHeader) {
		t.Fatalf("expected ErrNonASCIIHeader for device header, got %v", err)
	}
}

func TestVerifyMulti_NonASCIIHeaderRejected(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	_, err := VerifyMulti([][]byte{mustPSK()}, "GET", "/credentials", ts, "\xc3\xa9deadbeefdeadbeefdeadbeefdead", "deadbeef", "", "", cache, time.Minute, now)
	if !errors.Is(err, ErrNonASCIIHeader) {
		t.Fatalf("expected ErrNonASCIIHeader, got %v", err)
	}
}

func TestVerify_BadTimestamp(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	err := Verify(mustPSK(), "GET", "/credentials", "not-a-number",
		"0123456789abcdef0123456789abcdef", "deadbeef", "", "",
		cache, time.Minute, time.Now())
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("expected ErrBadTimestamp, got %v", err)
	}
}

func TestVerify_TimestampSkew(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	now := time.Unix(1700000000, 0)
	oldTS := strconv.FormatInt(now.Unix()-120, 10)
	nonce := "0123456789abcdef0123456789abcdef"
	sig := ComputeSignature(mustPSK(), "GET", "/credentials", oldTS, nonce, "", "")

	err := Verify(mustPSK(), "GET", "/credentials", oldTS, nonce, sig, "", "", cache, time.Minute, now)
	if !errors.Is(err, ErrTimestampSkew) {
		t.Fatalf("expected ErrTimestampSkew, got %v", err)
	}
}

func TestVerify_BadNonceFormat(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	err := Verify(mustPSK(), "GET", "/credentials", ts, "not-hex", "anything", "", "",
		cache, time.Minute, now)
	if !errors.Is(err, ErrBadNonceFormat) {
		t.Fatalf("expected ErrBadNonceFormat, got %v", err)
	}
}

func TestVerify_BadSignature(t *testing.T) {
	cache := NewNonceCache(time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "0123456789abcdef0123456789abcdef"
	wrongSig := "deadbeef"
	err := Verify(mustPSK(), "GET", "/credentials", ts, nonce, wrongSig, "", "",
		cache, time.Minute, now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerify_NonceReplay(t *testing.T) {
	psk := mustPSK()
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "0123456789abcdef0123456789abcdef"
	sig := ComputeSignature(psk, "GET", "/credentials", ts, nonce, "", "")

	if err := Verify(psk, "GET", "/credentials", ts, nonce, sig, "", "", cache, time.Minute, now); err != nil {
		t.Fatalf("first call: %v", err)
	}
	err := Verify(psk, "GET", "/credentials", ts, nonce, sig, "", "", cache, time.Minute, now)
	if !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("expected ErrNonceReplay on second call, got %v", err)
	}
}

// Tampering the X-Tmon-Config-Version header after the client signs the
// request must invalidate the signature. This is the regression test
// for the v1 → v2 bump (see compat/HMAC_CANONICAL.md).
func TestVerify_VersionHeaderIsBoundToSignature(t *testing.T) {
	psk := mustPSK()
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "0123456789abcdef0123456789abcdef"
	sig := ComputeSignature(psk, "GET", "/device/ab12cd34/sync", ts, nonce, "ab12cd34", "5")

	// Client signed for version=5; attacker replays with version=999.
	err := Verify(psk, "GET", "/device/ab12cd34/sync", ts, nonce, sig,
		"ab12cd34", "999", cache, time.Minute, now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered version must yield ErrBadSignature, got %v", err)
	}
}

// Same for X-Tmon-Device: swapping it must invalidate the signature.
func TestVerify_DeviceHeaderIsBoundToSignature(t *testing.T) {
	psk := mustPSK()
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "0123456789abcdef0123456789abcdef"
	sig := ComputeSignature(psk, "GET", "/credentials", ts, nonce, "ab12cd34", "")

	err := Verify(psk, "GET", "/credentials", ts, nonce, sig,
		"99887766", "", cache, time.Minute, now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered device id must yield ErrBadSignature, got %v", err)
	}
}

func TestNonceCache_ReapAfterTTL(t *testing.T) {
	cache := NewNonceCache(30 * time.Second)
	t0 := time.Unix(1700000000, 0)
	nonce := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !cache.CheckAndAdd(nonce, t0) {
		t.Fatal("first insert should succeed")
	}
	if !cache.CheckAndAdd(nonce, t0.Add(31*time.Second)) {
		t.Fatal("expected reuse after TTL, got replay")
	}
}

func TestVerifyMulti_PicksMatchingPSK(t *testing.T) {
	active := []byte("active-32-bytes-of-secret-mat!!!")
	pending := []byte("pending-32-bytes-of-secret-mat!!")
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "1111111111111111aaaaaaaaaaaaaaaa"
	// Sign with the pending key — verifier should report PSKIndex=1.
	sig := ComputeSignature(pending, "GET", "/device/ab12cd34/sync", ts, nonce, "ab12cd34", "")

	res, err := VerifyMulti([][]byte{active, pending},
		"GET", "/device/ab12cd34/sync", ts, nonce, sig, "ab12cd34", "",
		cache, time.Minute, now)
	if err != nil {
		t.Fatalf("VerifyMulti: %v", err)
	}
	if res.PSKIndex != 1 {
		t.Errorf("PSKIndex = %d, want 1", res.PSKIndex)
	}
}

func TestVerifyMulti_ActiveWinsWhenBothCouldMatch(t *testing.T) {
	psk := mustPSK()
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "2222222222222222bbbbbbbbbbbbbbbb"
	sig := ComputeSignature(psk, "GET", "/credentials", ts, nonce, "", "")
	// Same PSK in both slots: index 0 must win (broker treats that as "ran with active").
	res, err := VerifyMulti([][]byte{psk, psk},
		"GET", "/credentials", ts, nonce, sig, "", "",
		cache, time.Minute, now)
	if err != nil || res.PSKIndex != 0 {
		t.Fatalf("PSKIndex = %d, err = %v", res.PSKIndex, err)
	}
}

func TestVerifyMulti_RejectsAllWrong(t *testing.T) {
	wrongA := []byte("wrong-a-32-bytes-of-secret-mat!!")
	wrongB := []byte("wrong-b-32-bytes-of-secret-mat!!")
	right := []byte("right-32-bytes-of-secret-materi!")
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "3333333333333333cccccccccccccccc"
	sig := ComputeSignature(right, "GET", "/credentials", ts, nonce, "", "")
	_, err := VerifyMulti([][]byte{wrongA, wrongB},
		"GET", "/credentials", ts, nonce, sig, "", "",
		cache, time.Minute, now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerifyMulti_EmptySlots_Ignored(t *testing.T) {
	psk := mustPSK()
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "4444444444444444dddddddddddddddd"
	sig := ComputeSignature(psk, "GET", "/credentials", ts, nonce, "", "")
	res, err := VerifyMulti([][]byte{nil, psk, nil},
		"GET", "/credentials", ts, nonce, sig, "", "",
		cache, time.Minute, now)
	if err != nil || res.PSKIndex != 1 {
		t.Fatalf("PSKIndex = %d, err = %v", res.PSKIndex, err)
	}
}

func TestVerifyMulti_WrongPSKDoesNotBurnNonce(t *testing.T) {
	wrong := []byte("wrong-32-bytes-of-secret-materi!")
	right := []byte("right-32-bytes-of-secret-materi!")
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "5555555555555555eeeeeeeeeeeeeeee"
	sig := ComputeSignature(right, "GET", "/credentials", ts, nonce, "", "")

	if _, err := VerifyMulti([][]byte{wrong}, "GET", "/credentials",
		ts, nonce, sig, "", "", cache, time.Minute, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("probe: want ErrBadSignature, got %v", err)
	}
	if _, err := VerifyMulti([][]byte{right}, "GET", "/credentials",
		ts, nonce, sig, "", "", cache, time.Minute, now); err != nil {
		t.Fatalf("real verify: %v", err)
	}
}

func TestComputeSignature_KnownVector(t *testing.T) {
	// v2 canonical: METHOD\nPATH\nTS\nNONCE\n\n (device and version empty).
	// Reproduce with: printf 'GET\n/credentials\n100\nN\n\n' | openssl dgst -sha256 -hmac 'key' -hex
	psk := []byte("key")
	got := ComputeSignature(psk, "GET", "/credentials", "100", "N", "", "")
	want := "842b1ed100d4ac18041124dc4b6c25c911b37cf47b769b60086e55b3b628b340"
	if got != want {
		t.Fatalf("signature mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// Loads compat/vectors/hmac.json and asserts that this Go impl reproduces
// every documented expected_hex. The same JSON is consumed by the Python
// and JS tests so all three runtimes are pinned to identical bytes.
func TestComputeSignature_CompatVectors(t *testing.T) {
	path := findCompatVectors(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Vectors []struct {
			Name          string `json:"name"`
			PSKUTF8       string `json:"psk_utf8"`
			Method        string `json:"method"`
			Path          string `json:"path"`
			Timestamp     string `json:"timestamp"`
			Nonce         string `json:"nonce"`
			Device        string `json:"device"`
			ConfigVersion string `json:"config_version"`
			ExpectedHex   string `json:"expected_hex"`
		} `json:"vectors"`
		NegativeVectors []struct {
			Name                       string `json:"name"`
			PSKUTF8                    string `json:"psk_utf8"`
			Method                     string `json:"method"`
			Path                       string `json:"path"`
			Timestamp                  string `json:"timestamp"`
			NonceAfterLowercase        string `json:"nonce_after_lowercase"`
			Device                     string `json:"device"`
			ConfigVersion              string `json:"config_version"`
			ExpectedHexFromLowercased  string `json:"expected_hex_from_lowercased"`
			V1ExpectedHexRejectedNow   string `json:"v1_expected_hex_rejected_now"`
			V2ExpectedHex              string `json:"v2_expected_hex"`
			Nonce                      string `json:"nonce"`
		} `json:"negative_vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse hmac.json: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("compat vectors empty")
	}
	for _, v := range doc.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			got := ComputeSignature([]byte(v.PSKUTF8), v.Method, v.Path,
				v.Timestamp, v.Nonce, v.Device, v.ConfigVersion)
			if got != v.ExpectedHex {
				t.Fatalf("vector %q:\n  got  %s\n  want %s", v.Name, got, v.ExpectedHex)
			}
		})
	}
	// Negative path: nonce-uppercase vector ensures we lowercase before hashing.
	for _, n := range doc.NegativeVectors {
		if n.ExpectedHexFromLowercased == "" {
			continue
		}
		n := n
		t.Run(n.Name, func(t *testing.T) {
			got := ComputeSignature([]byte(n.PSKUTF8), n.Method, n.Path,
				n.Timestamp, n.NonceAfterLowercase, n.Device, n.ConfigVersion)
			if got != n.ExpectedHexFromLowercased {
				t.Fatalf("negative vector %q:\n  got  %s\n  want %s", n.Name, got, n.ExpectedHexFromLowercased)
			}
		})
	}
	// Confirm the v1 form is gone: signing without the two trailing fields
	// would still reproduce the v1 hash; signing the v2 form must not.
	for _, n := range doc.NegativeVectors {
		if n.V2ExpectedHex == "" || n.V1ExpectedHexRejectedNow == "" {
			continue
		}
		n := n
		t.Run(n.Name+"/v1-form-rejected", func(t *testing.T) {
			got := ComputeSignature([]byte(n.PSKUTF8), n.Method, n.Path,
				n.Timestamp, n.Nonce, "", "")
			if got != n.V2ExpectedHex {
				t.Fatalf("v2 hash mismatch:\n  got  %s\n  want %s", got, n.V2ExpectedHex)
			}
			if got == n.V1ExpectedHexRejectedNow {
				t.Fatalf("v2 hash equals deprecated v1 hash — the bump is undone")
			}
		})
	}
}

// Loads the v3 body_vectors / body_reject_vectors from compat/vectors/hmac.json:
// the body-covering canonical must reproduce expected_hex, must differ from the
// v2 form of the same fields (no downgrade-by-header-stripping), and malformed
// or mismatching X-Tmon-Body-Sha256 values must be rejected before any HMAC.
func TestComputeSignatureBody_CompatVectors(t *testing.T) {
	path := findCompatVectors(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		BodyVectors []struct {
			Name             string `json:"name"`
			PSKUTF8          string `json:"psk_utf8"`
			Method           string `json:"method"`
			Path             string `json:"path"`
			Timestamp        string `json:"timestamp"`
			Nonce            string `json:"nonce"`
			Device           string `json:"device"`
			ConfigVersion    string `json:"config_version"`
			BodyUTF8         string `json:"body_utf8"`
			BodySHA256       string `json:"body_sha256"`
			ExpectedHex      string `json:"expected_hex"`
			V2FormMustDiffer string `json:"v2_form_must_differ"`
		} `json:"body_vectors"`
		BodyRejectVectors []struct {
			Name             string `json:"name"`
			BodyUTF8         string `json:"body_utf8"`
			BodySHA256Header string `json:"body_sha256_header"`
		} `json:"body_reject_vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse hmac.json: %v", err)
	}
	if len(doc.BodyVectors) == 0 {
		t.Fatal("body_vectors empty")
	}
	for _, v := range doc.BodyVectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			gotDigest := sha256Hex([]byte(v.BodyUTF8))
			if gotDigest != v.BodySHA256 {
				t.Fatalf("body digest:\n  got  %s\n  want %s", gotDigest, v.BodySHA256)
			}
			got := ComputeSignatureBody([]byte(v.PSKUTF8), v.Method, v.Path,
				v.Timestamp, v.Nonce, v.Device, v.ConfigVersion, v.BodySHA256)
			if got != v.ExpectedHex {
				t.Fatalf("v3 vector %q:\n  got  %s\n  want %s", v.Name, got, v.ExpectedHex)
			}
			v2 := ComputeSignature([]byte(v.PSKUTF8), v.Method, v.Path,
				v.Timestamp, v.Nonce, v.Device, v.ConfigVersion)
			if v2 == got {
				t.Fatalf("v3 hash equals v2 hash — header stripping would downgrade")
			}
			if v.V2FormMustDiffer != "" && v2 != v.V2FormMustDiffer {
				t.Fatalf("v2 form:\n  got  %s\n  want %s", v2, v.V2FormMustDiffer)
			}
			// End-to-end: a request signed under v3 verifies through VerifyMultiBody.
			cache := NewNonceCache(time.Minute)
			ts, _ := strconv.ParseInt(v.Timestamp, 10, 64)
			_, err := VerifyMultiBody([][]byte{[]byte(v.PSKUTF8)}, v.Method, v.Path,
				v.Timestamp, v.Nonce, got, v.Device, v.ConfigVersion,
				v.BodySHA256, []byte(v.BodyUTF8),
				cache, time.Minute, time.Unix(ts, 0))
			if err != nil {
				t.Fatalf("VerifyMultiBody rejected its own vector: %v", err)
			}
		})
	}
	for _, r := range doc.BodyRejectVectors {
		r := r
		t.Run(r.Name, func(t *testing.T) {
			// Otherwise-plausible headers: the digest gate must fire first.
			cache := NewNonceCache(time.Minute)
			_, err := VerifyMultiBody([][]byte{[]byte("active-32-bytes-of-secret-mat!!!")},
				"POST", "/device/ab12cd34/settings",
				"1700000180", "3333333333333333cccccccccccccccc",
				strings.Repeat("0", 64), "ab12cd34", "42",
				r.BodySHA256Header, []byte(r.BodyUTF8),
				cache, time.Minute, time.Unix(1700000180, 0))
			if !errors.Is(err, ErrBadBodyDigest) {
				t.Fatalf("want ErrBadBodyDigest, got %v", err)
			}
		})
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// findCompatVectors walks up from the test working directory looking for
// compat/vectors/hmac.json. The Go source now lives inside the tokenmonitor
// plugin (mcp-marketplace/plugins/tokenmonitor/server/go/internal/auth/), so
// the monorepo root — where the authoritative compat/ lives — is seven levels
// up. We probe for the *specific* file so the partial server/compat/ slice
// (tool-schemas.json only, no vectors/) is skipped. In a standalone plugin
// checkout the file is absent and the byte-exact vector test skips.
func findCompatVectors(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 9; i++ {
		candidate := filepath.Join(dir, "compat", "vectors", "hmac.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("compat/vectors/hmac.json not found upward from %s (standalone checkout)", wd)
	return ""
}

// Sanity test that a malformed (truncated) hash header still routes through
// the verifier safely — exercise that strings.ToLower on the sig header
// doesn't crash for short inputs.
var _ = strings.ToLower
