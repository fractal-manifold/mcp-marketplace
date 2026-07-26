package usbprov

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// findVectors walks up from the test working directory to the repo-root
// compat/vectors/provision_frames.json. That file is GENERATED from the
// firmware codec (firmware/test/host/gen_provision_vectors.c) and is the
// cross-runtime authority for the wire format — the Go, Python and JS
// decoders must all reproduce it. It is not vendored into server/compat/, so
// this walks all the way to the monorepo root. Skips on a standalone
// checkout that does not ship it.
func findVectors(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 9; i++ {
		candidate := filepath.Join(dir, "compat", "vectors", "provision_frames.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("compat/vectors/provision_frames.json not found upward from %s (standalone checkout)", wd)
	return ""
}

type vectorsDoc struct {
	CRC32Vectors []struct {
		Name    string `json:"name"`
		DataHex string `json:"data_hex"`
		CRCHex  string `json:"crc_hex"`
	} `json:"crc32_vectors"`
	EncodeVectors []struct {
		Name       string `json:"name"`
		Type       uint8  `json:"type"`
		Seq        uint8  `json:"seq"`
		Nonce      uint32 `json:"nonce"`
		PayloadHex string `json:"payload_hex"`
		FrameHex   string `json:"frame_hex"`
	} `json:"encode_vectors"`
	DecodeVectors []struct {
		Name     string `json:"name"`
		InputHex string `json:"input_hex"`
		SplitAt  *int   `json:"split_at"`
		Expected []struct {
			Type       uint8  `json:"type"`
			Seq        uint8  `json:"seq"`
			Nonce      uint32 `json:"nonce"`
			PayloadHex string `json:"payload_hex"`
		} `json:"expected"`
	} `json:"decode_vectors"`
}

func loadVectors(t *testing.T) vectorsDoc {
	t.Helper()
	raw, err := os.ReadFile(findVectors(t))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc vectorsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return doc
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestCRC32_MatchVectors(t *testing.T) {
	doc := loadVectors(t)
	if len(doc.CRC32Vectors) == 0 {
		t.Fatal("no crc32 vectors")
	}
	for _, v := range doc.CRC32Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			got := CRC32(mustHex(t, v.DataHex))
			wantBytes := mustHex(t, v.CRCHex)
			if len(wantBytes) != 4 {
				t.Fatalf("crc_hex %q is not 4 bytes", v.CRCHex)
			}
			// crc_hex is printed big-endian ("%08x") in the generator.
			want := uint32(wantBytes[0])<<24 | uint32(wantBytes[1])<<16 |
				uint32(wantBytes[2])<<8 | uint32(wantBytes[3])
			if got != want {
				t.Errorf("CRC32(%s) = %08x, want %08x", v.DataHex, got, want)
			}
		})
	}
}

func TestEncode_MatchVectors(t *testing.T) {
	doc := loadVectors(t)
	if len(doc.EncodeVectors) == 0 {
		t.Fatal("no encode vectors")
	}
	for _, v := range doc.EncodeVectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			got, err := Encode(v.Type, v.Seq, v.Nonce, mustHex(t, v.PayloadHex))
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			want := mustHex(t, v.FrameHex)
			if !bytes.Equal(got, want) {
				t.Errorf("Encode(%s):\n  got  %x\n  want %x", v.Name, got, want)
			}
		})
	}
}

// TestDecode_MatchVectors is the load-bearing one: the firmware decoder is
// the reference, so decode_vectors records exactly what it yields for the
// hard cases (interleaved console logs, garbage mid-candidate, back-to-back
// frames, bad CRC → nothing, END/ESC in payload, a lying length that still
// CRCs → nothing). The Go decoder must agree byte for byte.
func TestDecode_MatchVectors(t *testing.T) {
	doc := loadVectors(t)
	if len(doc.DecodeVectors) == 0 {
		t.Fatal("no decode vectors")
	}
	for _, v := range doc.DecodeVectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			input := mustHex(t, v.InputHex)

			// Feed the bytes. When split_at is present, feed in two chunks to
			// prove the streaming decoder is insensitive to buffer
			// boundaries (it must yield the identical frames).
			var got []Frame
			var d Decoder
			feed := func(bs []byte) {
				for _, b := range bs {
					if f, ok := d.DecodeByte(b); ok {
						got = append(got, f)
					}
				}
			}
			if v.SplitAt != nil {
				at := *v.SplitAt
				if at < 0 || at > len(input) {
					t.Fatalf("split_at %d out of range for %d bytes", at, len(input))
				}
				feed(input[:at])
				feed(input[at:])
			} else {
				feed(input)
			}

			if len(got) != len(v.Expected) {
				t.Fatalf("frame count: got %d, want %d", len(got), len(v.Expected))
			}
			for i, exp := range v.Expected {
				if got[i].Type != exp.Type || got[i].Seq != exp.Seq || got[i].Nonce != exp.Nonce {
					t.Errorf("frame %d header: got {type:%d seq:%d nonce:%d}, want {type:%d seq:%d nonce:%d}",
						i, got[i].Type, got[i].Seq, got[i].Nonce, exp.Type, exp.Seq, exp.Nonce)
				}
				wantPayload := mustHex(t, exp.PayloadHex)
				if !bytes.Equal(got[i].Payload, wantPayload) {
					t.Errorf("frame %d payload:\n  got  %x\n  want %x", i, got[i].Payload, wantPayload)
				}
			}
		})
	}
}

// A frame round-trips: Encode then DecodeAll yields exactly one frame with
// the same fields, including payloads carrying END/ESC bytes.
func TestEncodeDecode_RoundTrip(t *testing.T) {
	cases := []struct {
		typ, seq uint8
		nonce    uint32
		payload  []byte
	}{
		{MsgHELLO, 0, 0, nil},
		{MsgProvision, 42, 0x01020304, []byte(`{"pairing_code":"123456"}`)},
		{MsgProvision, 1, 0xA5A5A5A5, []byte{0x01, slipEND, 0x02, slipESC, 0x03, slipESCEnd, slipESCEsc}},
	}
	for i, c := range cases {
		frame, err := Encode(c.typ, c.seq, c.nonce, c.payload)
		if err != nil {
			t.Fatalf("case %d Encode: %v", i, err)
		}
		got := DecodeAll(frame)
		if len(got) != 1 {
			t.Fatalf("case %d: got %d frames, want 1", i, len(got))
		}
		f := got[0]
		if f.Type != c.typ || f.Seq != c.seq || f.Nonce != c.nonce || !bytes.Equal(f.Payload, c.payload) {
			t.Errorf("case %d round-trip mismatch: got {t:%d s:%d n:%d p:%x}, want {t:%d s:%d n:%d p:%x}",
				i, f.Type, f.Seq, f.Nonce, f.Payload, c.typ, c.seq, c.nonce, c.payload)
		}
	}
}

func TestEncode_PayloadTooLong(t *testing.T) {
	if _, err := Encode(MsgProvision, 0, 0, make([]byte, PayloadMax+1)); err == nil {
		t.Fatal("expected ErrPayloadTooLong for oversize payload")
	}
	if _, err := Encode(MsgProvision, 0, 0, make([]byte, PayloadMax)); err != nil {
		t.Fatalf("PayloadMax should encode: %v", err)
	}
}

// A full 1024-byte payload survives a full encode→decode round-trip (the
// vectors only cover the small cases and the encode-side length cap).
func TestMaxPayload_RoundTrip(t *testing.T) {
	payload := make([]byte, PayloadMax)
	for i := range payload {
		payload[i] = byte(i) // includes 0xC0 / 0xDB bytes to exercise escaping at scale
	}
	frame, err := Encode(MsgProvision, 7, 0xCAFEBABE, payload)
	if err != nil {
		t.Fatalf("Encode max payload: %v", err)
	}
	got := DecodeAll(frame)
	if len(got) != 1 {
		t.Fatalf("got %d frames, want 1", len(got))
	}
	if !bytes.Equal(got[0].Payload, payload) {
		t.Error("max payload did not round-trip")
	}
}

// The frameMax overflow threshold: a candidate of exactly frameMax unescaped
// bytes is retained (and simply fails to validate, yielding nothing), while
// frameMax+1 bytes trips overflow. Neither yields a frame, but both must
// leave the decoder able to parse the very next real frame — i.e. overflow
// must reset cleanly. Mirrors firmware `d->len >= sizeof d->buf`.
func TestOverflowBoundary_RecoversNextFrame(t *testing.T) {
	good, err := Encode(MsgHELLO, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{frameMax, frameMax + 1} {
		n := n
		t.Run(strconvItoa(n), func(t *testing.T) {
			var d Decoder
			// Feed n non-END, non-ESC bytes as one candidate (no END yet).
			for i := 0; i < n; i++ {
				if _, ok := d.DecodeByte(0x41); ok {
					t.Fatalf("no frame should emerge mid-candidate at byte %d", i)
				}
			}
			// Close the oversize candidate: it must yield nothing.
			if _, ok := d.DecodeByte(slipEND); ok {
				t.Fatal("an oversize candidate must not validate")
			}
			// The decoder must have reset cleanly and parse the next frame.
			var got []Frame
			for _, b := range good {
				if f, ok := d.DecodeByte(b); ok {
					got = append(got, f)
				}
			}
			if len(got) != 1 || got[0].Type != MsgHELLO {
				t.Fatalf("decoder did not recover after overflow: got %d frames", len(got))
			}
		})
	}
}

// A trailing ESC with no continuation before END: firmware and Go both drop
// the candidate (END resets without interpreting the pending escape), and the
// next frame still decodes.
func TestDanglingEscapeBeforeEnd_Recovers(t *testing.T) {
	good, _ := Encode(MsgBYE, 3, 0x11223344, nil)
	var d Decoder
	// magic-ish bytes then a dangling ESC, then END → nothing.
	for _, b := range []byte{magic0, magic1, wireVer, slipESC} {
		if _, ok := d.DecodeByte(b); ok {
			t.Fatal("no frame expected mid-candidate")
		}
	}
	if _, ok := d.DecodeByte(slipEND); ok {
		t.Fatal("a dangling escape must not validate")
	}
	got := feedAll(&d, good)
	if len(got) != 1 || got[0].Type != MsgBYE {
		t.Fatalf("no recovery after dangling escape: %d frames", len(got))
	}
}

// An invalid escape sequence poisons the candidate until END; the next frame
// decodes cleanly.
func TestInvalidEscape_ThenValidFrame(t *testing.T) {
	good, _ := Encode(MsgSessionAck, 9, 0xDEADBEEF, nil)
	var d Decoder
	// ESC followed by a byte that is neither ESC_END nor ESC_ESC → overflow.
	for _, b := range []byte{magic0, magic1, slipESC, 0x00} {
		if _, ok := d.DecodeByte(b); ok {
			t.Fatal("no frame expected while poisoned")
		}
	}
	if _, ok := d.DecodeByte(slipEND); ok {
		t.Fatal("a poisoned candidate must not validate")
	}
	got := feedAll(&d, good)
	if len(got) != 1 || got[0].Type != MsgSessionAck {
		t.Fatalf("no recovery after invalid escape: %d frames", len(got))
	}
}

// Raw 0xDC / 0xDD bytes NOT preceded by ESC are ordinary payload data (they
// are only special after an ESC). A payload full of them must round-trip.
func TestRawEscEndBytes_AreLiteral(t *testing.T) {
	payload := []byte{slipESCEnd, slipESCEsc, slipESCEnd, 0x00, slipESCEsc}
	frame, _ := Encode(MsgProvision, 2, 0x01020304, payload)
	got := DecodeAll(frame)
	if len(got) != 1 || !bytes.Equal(got[0].Payload, payload) {
		t.Fatalf("raw ESC_END/ESC_ESC bytes did not round-trip: %x", got)
	}
}

// A decoded Frame.Payload must NOT alias the decoder's internal buffer — a
// later frame must not mutate an earlier frame's payload.
func TestPayloadOwnership_NoAliasingAcrossFrames(t *testing.T) {
	f1, _ := Encode(MsgProvision, 1, 1, []byte("first-payload"))
	f2, _ := Encode(MsgProvision, 2, 2, []byte("second-xxxxxx"))
	var d Decoder
	var frames []Frame
	for _, b := range append(append([]byte{}, f1...), f2...) {
		if f, ok := d.DecodeByte(b); ok {
			frames = append(frames, f)
		}
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if string(frames[0].Payload) != "first-payload" {
		t.Errorf("first payload was mutated by the second frame: %q", frames[0].Payload)
	}
}

// Feeding the decoder a valid frame after every kind of failed candidate
// (empty, invalid, overflowed) always recovers.
func TestDecoderReuse_AfterEmptyCandidate(t *testing.T) {
	var d Decoder
	// Back-to-back ENDs (empty candidates) are common from the leading-END
	// rule and must not break anything.
	for i := 0; i < 4; i++ {
		if _, ok := d.DecodeByte(slipEND); ok {
			t.Fatal("an empty candidate must not validate")
		}
	}
	good, _ := Encode(MsgHELLOResp, 0, 0x12345678, []byte(`{"proto_ver":1}`))
	got := feedAll(&d, good)
	if len(got) != 1 || got[0].Nonce != 0x12345678 {
		t.Fatalf("decoder did not recover after empty candidates: %d frames", len(got))
	}
}

func feedAll(d *Decoder, data []byte) []Frame {
	var out []Frame
	for _, b := range data {
		if f, ok := d.DecodeByte(b); ok {
			out = append(out, f)
		}
	}
	return out
}

func strconvItoa(n int) string {
	if n == frameMax {
		return "frameMax"
	}
	return "frameMax+1"
}
