// Package auth implements the HMAC-SHA256 request signing scheme shared
// between the tmon broker and the ESP32 firmware, plus a small TTL nonce
// cache used to reject replays.
//
// Signature input is canonicalised (v2) as:
//
//	HMAC-SHA256(psk,
//	  "<METHOD>\n<PATH>\n<TIMESTAMP>\n<NONCE>\n<DEVICE>\n<VERSION>")
//
// emitted as lowercase hex. DEVICE and VERSION are the X-Tmon-Device and
// X-Tmon-Config-Version header values verbatim, or the empty string when
// the header is absent. The firmware computes the same string before
// every poll, so any drift in this file must be mirrored there.
//
// See compat/HMAC_CANONICAL.md for the contract and
// compat/vectors/hmac.json for the test vectors every implementation
// must reproduce byte-for-byte.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NonceCache tracks nonces seen within the TTL window. Reaping is lazy on each
// insertion. Concurrent callers (one per HTTP request) are serialised by the
// mutex — the TTL window is short and the cache stays tiny.
type NonceCache struct {
	ttl  time.Duration
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{ttl: ttl, seen: make(map[string]time.Time)}
}

// CheckAndAdd records `nonce`. Returns true on first sight, false on replay.
func (c *NonceCache) CheckAndAdd(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reap(now)
	if _, ok := c.seen[nonce]; ok {
		return false
	}
	c.seen[nonce] = now
	return true
}

func (c *NonceCache) reap(now time.Time) {
	cutoff := now.Add(-c.ttl)
	for n, t := range c.seen {
		if t.Before(cutoff) {
			delete(c.seen, n)
		}
	}
}

// ComputeSignature reproduces the canonical request signature returned as
// lowercase hex. Pass the empty string for `device` and/or `configVersion`
// when the corresponding header is not sent — empty strings still
// contribute their trailing "\n" separators, so the result is distinct
// from the deprecated v1 form.
func ComputeSignature(psk []byte, method, path, ts, nonce, device, configVersion string) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(method))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(path))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(ts))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(nonce))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(device))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(configVersion))
	return hex.EncodeToString(mac.Sum(nil))
}

// ComputeSignatureBody is the v3 (body-covering) canonical form: the v2
// string with "\n" + BODY_SHA256 appended, where bodySHA256 is the
// lowercase-hex SHA-256 of the raw request body (the X-Tmon-Body-Sha256
// header value). Only used when that header is present — a request
// without the header keeps signing the v2 form, so the two canonicals
// can never collide (v2 never ends in "\n" + 64 hex of a digest the
// verifier also recomputes from the body).
func ComputeSignatureBody(psk []byte, method, path, ts, nonce, device, configVersion, bodySHA256 string) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(method))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(path))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(ts))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(nonce))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(device))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(configVersion))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(bodySHA256))
	return hex.EncodeToString(mac.Sum(nil))
}

var (
	ErrMissingHeaders = errors.New("missing headers")
	ErrBadTimestamp   = errors.New("bad timestamp")
	ErrTimestampSkew  = errors.New("timestamp skew")
	ErrBadNonceFormat = errors.New("bad nonce format")
	ErrBadSignature   = errors.New("bad signature")
	ErrNonceReplay    = errors.New("nonce replay")
	// ErrNonASCIIHeader rejects an auth header carrying a byte >= 0x80. The
	// canonical HMAC contract is ASCII-only (compat/HMAC_CANONICAL.md); an
	// explicit gate keeps parity with the py/js brokers (which reject before
	// signature computation) so a non-ASCII header is always a plain 401.
	ErrNonASCIIHeader = errors.New("non-ascii auth header")
	// ErrBadBodyDigest rejects a v3 request whose X-Tmon-Body-Sha256 header
	// is malformed (not exactly 64 lowercase hex — STRICT, no case folding,
	// unlike the nonce) or does not match the SHA-256 of the raw body.
	ErrBadBodyDigest = errors.New("bad body digest")
)

// isLowerHex64 reports whether s is exactly 64 lowercase hex chars — the
// strict format of X-Tmon-Body-Sha256 (the firmware always emits
// lowercase; the verifier deliberately does NOT case-fold this header
// because its verbatim bytes are part of the canonical input).
func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// allASCII reports whether every byte of every value is < 0x80. Empty strings
// (absent headers) pass.
func allASCII(values ...string) bool {
	for _, v := range values {
		for i := 0; i < len(v); i++ {
			if v[i] >= 0x80 {
				return false
			}
		}
	}
	return true
}

// Verify checks an incoming request's auth headers against the shared PSK.
// All non-nil error returns are reasons to reject with 401; never surface them
// to the client — log internally instead. Pass deviceHeader/configVersionHeader
// from r.Header.Get(...) verbatim — empty string when absent.
func Verify(
	psk []byte,
	method, path string,
	tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader string,
	cache *NonceCache,
	maxSkew time.Duration,
	now time.Time,
) error {
	if tsHeader == "" || nonceHeader == "" || sigHeader == "" {
		return ErrMissingHeaders
	}
	if !allASCII(tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader) {
		return ErrNonASCIIHeader
	}
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return ErrBadTimestamp
	}
	skew := now.Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(maxSkew/time.Second) {
		return ErrTimestampSkew
	}
	if !isHex32(nonceHeader) {
		return ErrBadNonceFormat
	}
	nonceLC := strings.ToLower(nonceHeader)
	expected := ComputeSignature(psk, method, path, tsHeader, nonceLC, deviceHeader, configVersionHeader)
	if !hmac.Equal([]byte(strings.ToLower(sigHeader)), []byte(expected)) {
		return ErrBadSignature
	}
	if !cache.CheckAndAdd(nonceLC, now) {
		return ErrNonceReplay
	}
	return nil
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// VerifyResult tells the caller which PSK satisfied the signature.
// PSKIndex is the position in the slice passed to VerifyMulti; the
// broker uses it to spot a "device signed with pending PSK" event and
// trigger registry.MaybePromote.
type VerifyResult struct {
	PSKIndex int
}

// VerifyMulti tries each PSK in order and returns the first one whose
// signature matches. Shape checks (timestamp present and parseable,
// nonce hex32, skew within window) run once; the per-PSK loop only
// retries the HMAC comparison. The replay nonce is consumed only after
// a PSK matched, so probing the wrong PSK does not burn the slot for
// the eventual right one. If every PSK is rejected, returns
// ErrBadSignature. A nil or empty `psks` slice returns ErrBadSignature.
func VerifyMulti(
	psks [][]byte,
	method, path string,
	tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader string,
	cache *NonceCache,
	maxSkew time.Duration,
	now time.Time,
) (VerifyResult, error) {
	if tsHeader == "" || nonceHeader == "" || sigHeader == "" {
		return VerifyResult{}, ErrMissingHeaders
	}
	if !allASCII(tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader) {
		return VerifyResult{}, ErrNonASCIIHeader
	}
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return VerifyResult{}, ErrBadTimestamp
	}
	skew := now.Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(maxSkew/time.Second) {
		return VerifyResult{}, ErrTimestampSkew
	}
	if !isHex32(nonceHeader) {
		return VerifyResult{}, ErrBadNonceFormat
	}
	nonceLC := strings.ToLower(nonceHeader)
	sigLC := strings.ToLower(sigHeader)

	matchedIdx := -1
	for i, psk := range psks {
		if len(psk) == 0 {
			continue
		}
		expected := ComputeSignature(psk, method, path, tsHeader, nonceLC, deviceHeader, configVersionHeader)
		if hmac.Equal([]byte(sigLC), []byte(expected)) {
			matchedIdx = i
			break
		}
	}
	if matchedIdx < 0 {
		return VerifyResult{}, ErrBadSignature
	}
	if !cache.CheckAndAdd(nonceLC, now) {
		return VerifyResult{}, ErrNonceReplay
	}
	return VerifyResult{PSKIndex: matchedIdx}, nil
}

// VerifyMultiBody is the body-aware variant of VerifyMulti for POST
// endpoints. The caller must have read the (size-bounded) raw body FIRST
// and pass it together with the X-Tmon-Body-Sha256 header verbatim.
//
//   - Header absent ("") → legacy v2 verification, body not covered
//     (firmware that predates v3; remove once the fleet is updated).
//   - Header present → must be exactly 64 lowercase hex AND match
//     sha256(body), then the v3 canonical (v2 + "\n" + digest) is
//     verified. Stripping or tampering the header breaks the signature,
//     so there is no downgrade for v3-signing firmware.
//
// The digest comparison is plain (not constant-time): the digest is not
// a secret — forging a request still requires the PSK-keyed HMAC.
func VerifyMultiBody(
	psks [][]byte,
	method, path string,
	tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader, bodySHAHeader string,
	body []byte,
	cache *NonceCache,
	maxSkew time.Duration,
	now time.Time,
) (VerifyResult, error) {
	if bodySHAHeader == "" {
		return VerifyMulti(psks, method, path,
			tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader,
			cache, maxSkew, now)
	}
	if tsHeader == "" || nonceHeader == "" || sigHeader == "" {
		return VerifyResult{}, ErrMissingHeaders
	}
	if !allASCII(tsHeader, nonceHeader, sigHeader, deviceHeader, configVersionHeader, bodySHAHeader) {
		return VerifyResult{}, ErrNonASCIIHeader
	}
	if !isLowerHex64(bodySHAHeader) {
		return VerifyResult{}, ErrBadBodyDigest
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != bodySHAHeader {
		return VerifyResult{}, ErrBadBodyDigest
	}
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return VerifyResult{}, ErrBadTimestamp
	}
	skew := now.Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(maxSkew/time.Second) {
		return VerifyResult{}, ErrTimestampSkew
	}
	if !isHex32(nonceHeader) {
		return VerifyResult{}, ErrBadNonceFormat
	}
	nonceLC := strings.ToLower(nonceHeader)
	sigLC := strings.ToLower(sigHeader)

	matchedIdx := -1
	for i, psk := range psks {
		if len(psk) == 0 {
			continue
		}
		expected := ComputeSignatureBody(psk, method, path, tsHeader, nonceLC, deviceHeader, configVersionHeader, bodySHAHeader)
		if hmac.Equal([]byte(sigLC), []byte(expected)) {
			matchedIdx = i
			break
		}
	}
	if matchedIdx < 0 {
		return VerifyResult{}, ErrBadSignature
	}
	if !cache.CheckAndAdd(nonceLC, now) {
		return VerifyResult{}, ErrNonceReplay
	}
	return VerifyResult{PSKIndex: matchedIdx}, nil
}

// --- response direction ------------------------------------------------

// ResponseSigPrefix is the domain-separation tag that opens the response
// canonical input. It exists so a response tag can never be confused with a
// request tag: the request forms start with an HTTP method, and no method is
// ever this string.
const ResponseSigPrefix = "tmon-resp-v1"

// ComputeResponseSignature reproduces the canonical RESPONSE signature —
// the value of the X-Tmon-Resp-Signature header — as lowercase hex:
//
//	HMAC-SHA256(psk,
//	  "tmon-resp-v1\n<DEVICE>\n<NONCE>\n<HOST>\n<PATH>\n<STATUS>\n<BODY_SHA256>")
//
// This is what lets the DEVICE authenticate the BROKER. The request HMAC only
// ever proved the other direction, which was enough while the broker's address
// was operator-configured; it is not enough now that the device locates the
// broker by mDNS, where anything on the LAN can answer (device_id is public —
// it travels in X-Tmon-Device on every request).
//
//   - DEVICE is the request's X-Tmon-Device verbatim ("" when absent).
//   - NONCE is the request's X-Tmon-Nonce, lower-cased — the same
//     normalisation Verify applies before checking the request signature.
//     Binding it makes this a challenge-response: the device picks the nonce,
//     so a tag cannot be precomputed or replayed onto a later request.
//   - HOST is the address THIS broker answered on — the connection's local
//     socket address as "<ipv4>:<port>", never the client-supplied Host
//     header. It is what makes the tag prove this address rather than merely
//     "somebody holding the PSK": without it an attacker can advertise the
//     service on its own IP, relay each request to the real broker, and hand
//     back a tag that verifies, at which point the device adopts and caches
//     the relay. See ResponseSigHost.
//   - PATH is canonicalised exactly as in the request forms.
//   - STATUS is the decimal HTTP status, so a 200 tag cannot be spliced onto
//     a 503.
//   - bodySHA256 is the lowercase-hex SHA-256 of the exact response body,
//     which is why the tag also authenticates the body and not just the
//     origin.
//
// See compat/HMAC_CANONICAL.md ("Response signature") for the contract.
func ComputeResponseSignature(psk []byte, device, nonce, host, path string, status int, bodySHA256 string) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(ResponseSigPrefix))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(device))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(strings.ToLower(nonce)))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(host))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(path))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(strconv.Itoa(status)))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(bodySHA256))
	return hex.EncodeToString(mac.Sum(nil))
}

// ResponseSigHost is the HOST field of the response canonical: the local
// address of the connection the request arrived on, as "<ipv4>:<port>".
//
// It MUST come from the socket, never from the Host header — a relay forwards
// the header untouched, so signing that would prove nothing about who actually
// answered. An IPv4-mapped local address ("::ffff:192.168.1.28", what a
// dual-stack listener reports) is unwrapped, so a broker bound to "::" and one
// bound to "0.0.0.0" sign the same bytes for the same device.
//
// Returns "" when the request carries no local address; a caller that gets ""
// must emit no tag rather than sign an empty host, which would canonicalise
// every address alike and switch the relay binding back off.
func ResponseSigHost(r *http.Request) string {
	addr, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if addr == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			host = v4.String()
		}
	}
	if host == "" || port == "" {
		return ""
	}
	return net.JoinHostPort(host, port)
}

// BodySHA256Hex is the lowercase-hex SHA-256 of a response body, the last
// field of the response canonical input. An empty body hashes as the SHA-256
// of the empty string, not as "" — there is no special case.
func BodySHA256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
