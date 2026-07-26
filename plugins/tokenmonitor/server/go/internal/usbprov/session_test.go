package usbprov

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDevice is a faithful in-memory model of the firmware serial session
// (firmware/components/provision/src/provision_serial_session.c): HELLO mints a
// fresh nonce and is the ONLY trigger for HELLO_RESP; every other frame must
// echo the session nonce or is dropped silently; SESSION_BEGIN must precede
// PROVISION; a duplicate (seq,payload) replays the cached RESULT. Fault knobs
// exercise the host's recovery paths.
type fakeDevice struct {
	deviceID   string
	baseNonce  uint32 // first minted nonce; 0 stays 0 (the invalid-nonce case)
	resultJSON []byte

	ignoreFirstHello     bool
	injectConsole        bool
	dropFirstResult      bool
	resetOnSessionBegin  bool // reboot on the first SESSION_BEGIN (before any code)
	resetOnProvision     bool // reboot on the first PROVISION (code already sent)
	silentAfterProvision bool // apply, but never answer (session stays alive)
	injectStaleResult    bool

	gotProvision atomic.Bool // set when a PROVISION is actually applied
}

func (fd *fakeDevice) describe() []byte {
	return []byte(fmt.Sprintf(
		`{"device_id":%q,"sku":"S1","fw":"1.0.0","state":"BOOT_NEEDS_CONFIG","proto_ver":1}`,
		fd.deviceID))
}

func (fd *fakeDevice) run(conn net.Conn) {
	defer conn.Close()
	var dec Decoder
	buf := make([]byte, 256)

	var nonce uint32 // 0 = no open session
	nextNonce := fd.baseNonce
	var open, haveLast bool
	var lastSeq, lastType uint8
	var lastReq, lastBody []byte
	var seenHello, droppedResult, didReset bool

	write := func(typ, seq uint8, n uint32, body []byte) {
		fr, _ := Encode(typ, seq, n, body)
		_, _ = conn.Write(fr)
	}

	for {
		n, err := conn.Read(buf)
		for i := 0; i < n; i++ {
			f, ok := dec.DecodeByte(buf[i])
			if !ok {
				continue
			}

			if f.Type == MsgHELLO {
				if fd.ignoreFirstHello && !seenHello {
					seenHello = true
					continue // force a HELLO retransmit
				}
				seenHello = true
				nonce = nextNonce
				if fd.baseNonce != 0 {
					nextNonce++ // a re-HELLO after reset yields a distinct nonce
					if nextNonce == 0 {
						nextNonce = 1
					}
				}
				open, haveLast = false, false
				if fd.injectConsole {
					_, _ = conn.Write([]byte("I (1234) wifi: connected\r\n\xc0junk\xc0"))
				}
				write(MsgHELLOResp, f.Seq, nonce, fd.describe())
				continue
			}

			// Nonce gate: a DTR-rebooted device (nonce==0) or a stale-nonce
			// frame is dropped silently, exactly as the firmware does.
			if nonce == 0 || f.Nonce != nonce {
				continue
			}

			// Retransmission replay of the cached RESULT.
			if haveLast && f.Seq == lastSeq && f.Type == lastType && bytes.Equal(f.Payload, lastReq) {
				write(MsgResult, f.Seq, nonce, lastBody)
				continue
			}

			switch f.Type {
			case MsgSessionBegin:
				// Model a DTR reset during the handshake (before any pairing
				// code is on the wire): the device reboots and answers nothing
				// until the host re-says HELLO. This path is safe to auto-recover.
				if fd.resetOnSessionBegin && !didReset {
					didReset = true
					nonce, open, haveLast = 0, false, false
					continue
				}
				open = true
				write(MsgSessionAck, f.Seq, nonce, nil)
			case MsgProvision:
				if !open {
					continue // SESSION_BEGIN first
				}
				// Model a mid-session DTR reset AFTER the pairing code was sent:
				// the device reboots and goes silent. The host must NOT blindly
				// re-apply (double-charge risk) — it reports outcome-unknown.
				if fd.resetOnProvision && !didReset {
					didReset = true
					nonce, open, haveLast = 0, false, false
					continue
				}
				fd.gotProvision.Store(true)
				if fd.silentAfterProvision {
					continue // applied, but the RESULT never goes out
				}
				haveLast = true
				lastSeq, lastType = f.Seq, f.Type
				lastReq = append([]byte(nil), f.Payload...)
				lastBody = append([]byte(nil), fd.resultJSON...)
				if fd.injectStaleResult {
					// A RESULT from a "previous session" (wrong nonce) that the
					// host must ignore.
					write(MsgResult, f.Seq, nonce^0xFFFF, []byte(`{"ok":false,"stale":true}`))
				}
				if fd.dropFirstResult && !droppedResult {
					droppedResult = true
					continue // cached; the host resends and gets the replay
				}
				write(MsgResult, f.Seq, nonce, fd.resultJSON)
			case MsgBYE:
				nonce, open, haveLast = 0, false, false
			}
		}
		if err != nil {
			return
		}
	}
}

func fastTimeouts() Timeouts {
	return Timeouts{
		HelloResp:    150 * time.Millisecond,
		SessionAck:   150 * time.Millisecond,
		Result:       150 * time.Millisecond,
		HelloTries:   6,
		SessionTries: 4,
		ResultTries:  4,
	}
}

func runWithFake(t *testing.T, fd *fakeDevice, opts ProvisionOpts) (*ProvisionResult, error) {
	t.Helper()
	host, dev := net.Pipe()
	go fd.run(dev)
	opts.Timeouts = fastTimeouts()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return RunProvision(ctx, host, opts)
}

func TestSession_HappyPath(t *testing.T) {
	fd := &fakeDevice{deviceID: "03abcdef", baseNonce: 0xDEADBEEF, resultJSON: []byte(`{"ok":true,"device_id":"03abcdef","next":"rebooting"}`)}
	res, err := runWithFake(t, fd, ProvisionOpts{ProvisionJSON: []byte(`{"pairing_code":"123456","wifi_ssid":"Home","wifi_pass":"pw"}`)})
	if err != nil {
		t.Fatalf("RunProvision: %v", err)
	}
	if res.Device.DeviceID != "03abcdef" || res.Device.Nonce != 0xDEADBEEF {
		t.Errorf("device info wrong: %+v", res.Device)
	}
	if string(res.ResultJSON) != `{"ok":true,"device_id":"03abcdef","next":"rebooting"}` {
		t.Errorf("result JSON: %s", res.ResultJSON)
	}
}

func TestSession_RetransmitOnLostResult(t *testing.T) {
	fd := &fakeDevice{deviceID: "aabbccdd", baseNonce: 0x11223344, resultJSON: []byte(`{"ok":true}`), dropFirstResult: true}
	res, err := runWithFake(t, fd, ProvisionOpts{ProvisionJSON: []byte(`{"pairing_code":"123456"}`)})
	if err != nil {
		t.Fatalf("a lost RESULT must be recovered by retransmission: %v", err)
	}
	if string(res.ResultJSON) != `{"ok":true}` {
		t.Errorf("result JSON: %s", res.ResultJSON)
	}
}

func TestSession_ConsoleInterleaving(t *testing.T) {
	fd := &fakeDevice{deviceID: "03abcdef", baseNonce: 0xABCDEF01, resultJSON: []byte(`{"ok":true}`), injectConsole: true}
	if _, err := runWithFake(t, fd, ProvisionOpts{ProvisionJSON: []byte(`{"pairing_code":"123456"}`)}); err != nil {
		t.Fatalf("console interleaving must not break the handshake: %v", err)
	}
}

func TestSession_HelloRetransmit(t *testing.T) {
	fd := &fakeDevice{deviceID: "03abcdef", baseNonce: 0x55667788, resultJSON: []byte(`{"ok":true}`), ignoreFirstHello: true}
	if _, err := runWithFake(t, fd, ProvisionOpts{ProvisionJSON: []byte(`{"pairing_code":"123456"}`)}); err != nil {
		t.Fatalf("an ignored first HELLO must be recovered by retransmission: %v", err)
	}
}

func TestSession_ResetBeforeProvisionRecoversByReHello(t *testing.T) {
	// A DTR reset during the handshake (device reboots on SESSION_BEGIN, before
	// any pairing code is sent) is safe to auto-recover: the host re-says HELLO,
	// the device mints a fresh nonce (baseNonce+1), and the exchange completes.
	fd := &fakeDevice{deviceID: "03abcdef", baseNonce: 0x01000000, resultJSON: []byte(`{"ok":true}`), resetOnSessionBegin: true}
	res, err := runWithFake(t, fd, ProvisionOpts{ProvisionJSON: []byte(`{"pairing_code":"123456"}`)})
	if err != nil {
		t.Fatalf("a pre-PROVISION reset must be recovered by re-HELLO: %v", err)
	}
	if res.Device.Nonce != 0x01000001 {
		t.Errorf("expected the adopted post-reset nonce 0x01000001, got %#x", res.Device.Nonce)
	}
}

func TestSession_ResetAfterProvisionReportsOutcomeUnknown(t *testing.T) {
	// A reset AFTER the pairing code was transmitted is observationally
	// ambiguous (the device may have committed). The host must NOT silently
	// re-apply — it returns ErrOutcomeUnknown so the caller decides.
	fd := &fakeDevice{deviceID: "03abcdef", baseNonce: 0x02000000, resultJSON: []byte(`{"ok":true}`), resetOnProvision: true}
	_, err := runWithFake(t, fd, ProvisionOpts{ProvisionJSON: []byte(`{"pairing_code":"123456"}`)})
	if !isErr(err, ErrOutcomeUnknown) {
		t.Fatalf("a post-PROVISION reset must return ErrOutcomeUnknown, got %v", err)
	}
}

func TestSession_StaleResultIgnored(t *testing.T) {
	// A CRC-valid RESULT bearing the wrong nonce (a leftover from another
	// session) must be ignored; only the correctly-bound RESULT counts.
	fd := &fakeDevice{deviceID: "03abcdef", baseNonce: 0x22334455, resultJSON: []byte(`{"ok":true,"real":true}`), injectStaleResult: true}
	res, err := runWithFake(t, fd, ProvisionOpts{ProvisionJSON: []byte(`{"pairing_code":"123456"}`)})
	if err != nil {
		t.Fatalf("RunProvision: %v", err)
	}
	if string(res.ResultJSON) != `{"ok":true,"real":true}` {
		t.Errorf("host accepted a stale-nonce RESULT: %s", res.ResultJSON)
	}
}

func TestSession_CancelAfterProvisionIsOutcomeUnknown(t *testing.T) {
	// The device applies PROVISION but never answers, then the caller cancels.
	// The cancellation must surface as ErrOutcomeUnknown (the code may have been
	// committed) while still preserving context.Canceled as the cause — never a
	// bare, retryable error that would invite a double-apply.
	fd := &fakeDevice{deviceID: "03abcdef", baseNonce: 0x0BADF00D, resultJSON: []byte(`{"ok":true}`), silentAfterProvision: true}
	host, dev := net.Pipe()
	go fd.run(dev)
	to := fastTimeouts()
	to.Result = 5 * time.Second // long, so cancellation (not the timer) ends the wait
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(60*time.Millisecond, cancel)
	defer cancel()
	_, err := RunProvision(ctx, host, ProvisionOpts{ProvisionJSON: []byte(`{"pairing_code":"123456"}`), Timeouts: to})
	if !isErr(err, ErrOutcomeUnknown) {
		t.Fatalf("a cancel after PROVISION must be ErrOutcomeUnknown, got %v", err)
	}
	if !isErr(err, context.Canceled) {
		t.Errorf("ErrOutcomeUnknown must preserve context.Canceled as the cause, got %v", err)
	}
	if !fd.gotProvision.Load() {
		t.Error("the device should have received the PROVISION in this scenario")
	}
}

func TestSession_DeviceMismatchAbortsBeforeWrite(t *testing.T) {
	fd := &fakeDevice{deviceID: "03abcdef", baseNonce: 0xDEADBEEF, resultJSON: []byte(`{"ok":true}`)}
	_, err := runWithFake(t, fd, ProvisionOpts{
		ProvisionJSON:  []byte(`{"pairing_code":"123456"}`),
		ExpectDeviceID: "99999999",
	})
	if !isErr(err, ErrDeviceMismatch) {
		t.Fatalf("a device_id mismatch must return ErrDeviceMismatch, got %v", err)
	}
	if fd.gotProvision.Load() {
		t.Error("a mismatched device must receive NO PROVISION write")
	}
}

func TestSession_UnsupportedProtoAbortsBeforeWrite(t *testing.T) {
	// A HELLO_RESP with proto_ver != 1 must abort before any write. The fake's
	// describe() hardcodes proto_ver:1, so override device behaviour by faking a
	// higher version through a custom device.
	fd := &protoDevice{deviceID: "03abcdef", nonce: 0x0A0B0C0D, protoVer: 2}
	host, dev := net.Pipe()
	go fd.run(dev)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := RunProvision(ctx, host, ProvisionOpts{ProvisionJSON: []byte(`{"pairing_code":"123456"}`), Timeouts: fastTimeouts()})
	if !isErr(err, ErrUnsupportedProto) {
		t.Fatalf("proto_ver mismatch must return ErrUnsupportedProto, got %v", err)
	}
	if fd.gotProvision.Load() {
		t.Error("an unsupported-proto device must receive NO PROVISION write")
	}
}

func TestSession_ZeroNonceRejected(t *testing.T) {
	// A HELLO_RESP with a zero nonce is the "no session" sentinel and must not
	// build a session; the host keeps retrying HELLO and ultimately fails.
	fd := &fakeDevice{deviceID: "03abcdef", baseNonce: 0, resultJSON: []byte(`{"ok":true}`)}
	if _, err := runWithFake(t, fd, ProvisionOpts{ProvisionJSON: []byte(`{"pairing_code":"123456"}`)}); !isErr(err, ErrHandshake) {
		t.Fatalf("a zero session nonce must fail the handshake, got %v", err)
	}
}

// protoDevice answers HELLO with a configurable proto_ver, otherwise behaving
// like a minimal device, to test the version gate.
type protoDevice struct {
	deviceID     string
	nonce        uint32
	protoVer     int
	gotProvision atomic.Bool
}

func (pd *protoDevice) run(conn net.Conn) {
	defer conn.Close()
	var dec Decoder
	buf := make([]byte, 256)
	for {
		n, err := conn.Read(buf)
		for i := 0; i < n; i++ {
			f, ok := dec.DecodeByte(buf[i])
			if !ok {
				continue
			}
			switch f.Type {
			case MsgHELLO:
				body := []byte(fmt.Sprintf(`{"device_id":%q,"sku":"S1","fw":"1.0.0","state":"x","proto_ver":%d}`, pd.deviceID, pd.protoVer))
				fr, _ := Encode(MsgHELLOResp, f.Seq, pd.nonce, body)
				_, _ = conn.Write(fr)
			case MsgProvision:
				pd.gotProvision.Store(true)
			}
		}
		if err != nil {
			return
		}
	}
}

func isErr(err, target error) bool { return errors.Is(err, target) }
