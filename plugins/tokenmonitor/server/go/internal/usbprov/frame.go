// Package usbprov implements the host side of the USB serial provisioning
// protocol (compat/PROVISION_WIRE.md): the SLIP+CRC32 wire codec, the
// hardcoded USB device-identity table, port enumeration and classification,
// and the leader-mediated port lease.
//
// The framing here is a byte-for-byte port of the firmware reference codec
// (firmware/components/provision/src/provision_frame.c). The firmware
// DECODER is the authority: the parity test in frame_test.go asserts this
// implementation reproduces compat/vectors/provision_frames.json, which is
// generated from that exact firmware source. Do not "improve" the decode
// behaviour here without regenerating the vectors from firmware first.
package usbprov

import "errors"

// Wire constants — must match firmware/components/provision/include/tmon_prov_frame.h.
const (
	magic0     = 0x54 // 'T'
	magic1     = 0x4D // 'M'
	wireVer    = 1
	hdrLen     = 11
	crcLen     = 4
	PayloadMax = 1024
	frameMax   = hdrLen + PayloadMax + crcLen

	slipEND    = 0xC0
	slipESC    = 0xDB
	slipESCEnd = 0xDC
	slipESCEsc = 0xDD
)

// Message types — must match the TMON_MSG_* enum in the firmware.
const (
	MsgHELLO        = 1 // host → device, no nonce yet
	MsgHELLOResp    = 2 // device → host, carries the session nonce (in the header)
	MsgSessionBegin = 3 // host → device, mute console
	MsgSessionAck   = 4
	MsgProvision    = 5 // host → device, same JSON as POST /provision
	MsgResult       = 6 // device → host
	MsgBYE          = 7 // host → device, restore console
)

// ErrPayloadTooLong is returned by Encode when the payload exceeds PayloadMax.
var ErrPayloadTooLong = errors.New("usbprov: payload exceeds PayloadMax")

// Frame is a decoded protocol frame. Payload is a fresh copy, owned by the
// caller.
type Frame struct {
	Ver     uint8
	Type    uint8
	Seq     uint8
	Nonce   uint32
	Payload []byte
}

// CRC32 computes CRC-32/ISO-HDLC (reflected poly 0xEDB88320, init/xorout
// 0xFFFFFFFF, refin/refout true) — the zlib/PNG CRC. This is a direct
// translation of tmon_prov_crc32(); the "123456789" check value is
// 0xCBF43926.
func CRC32(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ 0xFFFFFFFF
}

// Encode builds a complete on-wire frame (leading END, SLIP-escaped
// header+payload+CRC, trailing END). The leading END closes off whatever a
// previous writer left dangling so it is discarded as its own malformed
// frame rather than merging with this one.
func Encode(typ, seq uint8, nonce uint32, payload []byte) ([]byte, error) {
	if len(payload) > PayloadMax {
		return nil, ErrPayloadTooLong
	}
	plen := len(payload)
	body := make([]byte, 0, hdrLen+plen+crcLen)
	body = append(body,
		magic0, magic1, wireVer, typ, seq,
		byte(nonce), byte(nonce>>8), byte(nonce>>16), byte(nonce>>24),
		byte(plen), byte(plen>>8))
	body = append(body, payload...)
	crc := CRC32(body)
	body = append(body, byte(crc), byte(crc>>8), byte(crc>>16), byte(crc>>24))

	out := make([]byte, 0, len(body)*2+2)
	out = append(out, slipEND)
	for _, b := range body {
		switch b {
		case slipEND:
			out = append(out, slipESC, slipESCEnd)
		case slipESC:
			out = append(out, slipESC, slipESCEsc)
		default:
			out = append(out, b)
		}
	}
	out = append(out, slipEND)
	return out, nil
}

// Decoder is a streaming SLIP+CRC32 decoder. The zero value is ready to use.
// It mirrors tmon_prov_decoder_t / tmon_prov_decode_byte exactly, including
// the resynchronisation behaviour that lets a real protocol frame be picked
// out of a stream also carrying console logs, panic output and ROM garbage.
type Decoder struct {
	buf      []byte
	escaping bool
	overflow bool
}

// DecodeByte feeds one byte. It returns a decoded frame and true only when a
// complete, CRC-valid frame of a supported version has just been terminated;
// everything else (console text, truncated frames, bad CRC, a lying length,
// an unknown version) is consumed and discarded with (Frame{}, false).
func (d *Decoder) DecodeByte(b byte) (Frame, bool) {
	if b == slipEND {
		// Frame boundary. Evaluate whatever accumulated, then reset —
		// unconditionally, so a bad candidate cannot poison the next one.
		// An empty candidate (back-to-back ENDs from the leading-END rule)
		// is the common case and is not an error.
		var f Frame
		ok := false
		if !d.overflow && len(d.buf) > 0 {
			ok = d.validate(&f)
		}
		d.buf = d.buf[:0]
		d.escaping = false
		d.overflow = false
		return f, ok
	}

	if d.escaping {
		d.escaping = false
		switch b {
		case slipESCEnd:
			b = slipEND
		case slipESCEsc:
			b = slipESC
		default:
			// Invalid escape sequence: drop the candidate but keep scanning;
			// the next END re-syncs us.
			d.overflow = true
			return Frame{}, false
		}
	} else if b == slipESC {
		d.escaping = true
		return Frame{}, false
	}

	if d.overflow { // already doomed, wait for END
		return Frame{}, false
	}
	if len(d.buf) >= frameMax {
		// Console text between two ENDs can be arbitrarily long. Mark and
		// wait for the boundary rather than truncating into a candidate that
		// might accidentally validate.
		d.overflow = true
		return Frame{}, false
	}
	d.buf = append(d.buf, b)
	return Frame{}, false
}

// validate checks an unescaped candidate and, if it is a real frame, unpacks
// it. A mirror of the firmware validate(): magic, version, length-EQUALITY
// (not "fits"), then CRC.
func (d *Decoder) validate(out *Frame) bool {
	buf := d.buf
	if len(buf) < hdrLen+crcLen {
		return false
	}
	if buf[0] != magic0 || buf[1] != magic1 {
		return false
	}
	if buf[2] != wireVer {
		return false
	}
	plen := int(buf[9]) | int(buf[10])<<8
	if plen > PayloadMax {
		return false
	}
	// The declared length must account for EXACTLY the bytes received.
	// Equality (not "fits") stops a lying length being accepted with
	// trailing bytes ignored, and stops two concatenated frames reading as
	// one.
	if len(buf) != hdrLen+plen+crcLen {
		return false
	}
	crcAt := hdrLen + plen
	want := uint32(buf[crcAt]) | uint32(buf[crcAt+1])<<8 |
		uint32(buf[crcAt+2])<<16 | uint32(buf[crcAt+3])<<24
	if CRC32(buf[:crcAt]) != want {
		return false
	}
	out.Ver = buf[2]
	out.Type = buf[3]
	out.Seq = buf[4]
	out.Nonce = uint32(buf[5]) | uint32(buf[6])<<8 |
		uint32(buf[7])<<16 | uint32(buf[8])<<24
	out.Payload = append([]byte(nil), buf[hdrLen:hdrLen+plen]...)
	return true
}

// DecodeAll feeds every byte of data through a fresh Decoder and returns all
// frames it yields, in order. Convenience for callers that already hold a
// full buffer; the live session uses DecodeByte on a byte stream instead.
func DecodeAll(data []byte) []Frame {
	var d Decoder
	var frames []Frame
	for _, b := range data {
		if f, ok := d.DecodeByte(b); ok {
			frames = append(frames, f)
		}
	}
	return frames
}
