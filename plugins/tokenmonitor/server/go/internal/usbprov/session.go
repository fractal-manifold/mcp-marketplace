package usbprov

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// wireProtoVer is the protocol version this host speaks (matches the frame
// header ver and the HELLO_RESP proto_ver in compat/PROVISION_WIRE.md).
const wireProtoVer = 1

// maxResetRecoveries bounds how many times a stalled exchange is recovered by
// re-saying HELLO (which the device answers by minting a fresh nonce and
// abandoning any half-finished session — the documented DTR-reset cure). One
// recovery ⇒ at most two handshakes total; more would just prolong a genuinely
// dead port.
const maxResetRecoveries = 1

// Sequence numbers for the one-shot provisioning exchange. The device echoes
// seq in its reply, and retransmission identity is the exact (seq, payload)
// pair, so a resent PROVISION MUST reuse seqProvision with an identical payload
// (compat/PROVISION_WIRE.md §Retransmission).
const (
	seqHello        uint8 = 0
	seqSessionBegin uint8 = 1
	seqProvision    uint8 = 2
	seqBye          uint8 = 3
)

// Timeouts bound each step. Generous: the device throttles a failed pairing
// attempt and an NVS commit is not instant. Each *Tries count is the number of
// (re)transmissions of an idempotent request before the step is declared
// stalled.
type Timeouts struct {
	HelloResp    time.Duration // wait for HELLO_RESP after a HELLO
	SessionAck   time.Duration // wait for SESSION_ACK after a SESSION_BEGIN
	Result       time.Duration // wait for RESULT after a PROVISION
	HelloTries   int           // HELLOs before giving up on the handshake
	SessionTries int           // SESSION_BEGINs before declaring the exchange stalled
	ResultTries  int           // PROVISION (re)sends before declaring the exchange stalled
}

// DefaultTimeouts are used for any zero field.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		HelloResp:    1500 * time.Millisecond,
		SessionAck:   2 * time.Second,
		Result:       6 * time.Second,
		HelloTries:   5,
		SessionTries: 3,
		ResultTries:  4,
	}
}

func (t Timeouts) withDefaults() Timeouts {
	d := DefaultTimeouts()
	if t.HelloResp == 0 {
		t.HelloResp = d.HelloResp
	}
	if t.SessionAck == 0 {
		t.SessionAck = d.SessionAck
	}
	if t.Result == 0 {
		t.Result = d.Result
	}
	if t.HelloTries == 0 {
		t.HelloTries = d.HelloTries
	}
	if t.SessionTries == 0 {
		t.SessionTries = d.SessionTries
	}
	if t.ResultTries == 0 {
		t.ResultTries = d.ResultTries
	}
	return t
}

// DeviceInfo is what a HELLO_RESP reveals about the device. The session nonce
// is carried in the frame HEADER (fresh, non-zero), NOT in the JSON.
type DeviceInfo struct {
	Nonce    uint32 `json:"-"`
	DeviceID string `json:"device_id"`
	SKU      string `json:"sku"`
	FW       string `json:"fw"`
	State    string `json:"state"`
	ProtoVer int    `json:"proto_ver"`
}

// ProvisionOpts drives a full provisioning session.
type ProvisionOpts struct {
	// ProvisionJSON is the exact PROVISION payload (it already contains
	// pairing_code and any config/WiFi fields). The caller builds it.
	ProvisionJSON []byte
	// ExpectDeviceID, if non-empty, must equal the HELLO_RESP device_id or the
	// session aborts before any PROVISION write — the safety check that a
	// multi-device attach wrote to the intended unit. It is re-checked after
	// every (re)handshake, so a mid-session device swap cannot slip through.
	ExpectDeviceID string
	Timeouts       Timeouts
}

// ProvisionResult is the outcome of a session.
type ProvisionResult struct {
	Device DeviceInfo
	// ResultJSON is the device's RESULT payload verbatim (success or the
	// provisioning core's canonical error body). The caller maps it to a tool
	// result; this layer validates only that it is well-formed JSON, not
	// ok/next.
	ResultJSON []byte
}

var (
	// ErrDeviceMismatch is returned when ExpectDeviceID does not match the
	// HELLO_RESP — nothing is written.
	ErrDeviceMismatch = errors.New("usbprov: connected device_id does not match the requested device")
	// ErrHandshake is returned when the device never completes the handshake.
	ErrHandshake = errors.New("usbprov: device did not complete the handshake")
	// ErrUnsupportedProto is returned when the device announces a proto_ver this
	// host does not speak — nothing is written.
	ErrUnsupportedProto = errors.New("usbprov: device speaks an unsupported protocol version")
	// ErrOutcomeUnknown is returned when PROVISION was transmitted but no RESULT
	// came back even after in-session retransmits: the device MAY have applied
	// it (a lost RESULT, or a reset after committing). This is deliberately NOT
	// auto-recovered — re-sending the pairing code across a fresh HELLO would
	// clear the device's retransmit cache and risk a double-apply / a second
	// charged pairing attempt (firmware provision_serial_session.c). The caller
	// decides: reconnect and read device status, or re-run as a fresh user
	// action.
	ErrOutcomeUnknown = errors.New("usbprov: provisioning outcome unknown — PROVISION was sent but no RESULT was received; the device may have applied it")
)

// RunProvision executes the full HELLO → SESSION_BEGIN → PROVISION → BYE
// exchange over rwc (an already-opened, OS-exclusively-held serial fd). It
// tolerates console-log interleaving (the decoder resynchronises) and a
// mid-session device reset: a DTR-rebooted device silently drops frames bearing
// the stale nonce (compat/PROVISION_WIRE.md), so when an exchange stalls the
// host re-says HELLO to mint a fresh nonce and retries, bounded by
// maxResetRecoveries.
//
// It CONSUMES rwc: a blocked serial Read/Write can only be unblocked by closing
// the fd, so RunProvision closes rwc before returning (do not close it again).
// The OS-exclusive lock is held on a SEPARATE lock-file fd (see the
// "OS-exclusive serial open" contract), which the caller still owns and
// releases — closing the serial fd here does not touch it.
func RunProvision(ctx context.Context, rwc io.ReadWriteCloser, opts ProvisionOpts) (*ProvisionResult, error) {
	to := opts.Timeouts.withDefaults()
	fc := newFrameConn(rwc)
	defer fc.stop()

	// A blocked serial Write cannot see ctx.Done() on its own; the only way to
	// free it (like a blocked Read) is to close the fd. Watch ctx and stop() on
	// cancellation. The watcher is torn down on return; stop() is idempotent.
	watch := make(chan struct{})
	defer close(watch)
	go func() {
		select {
		case <-ctx.Done():
			fc.stop()
		case <-watch:
		}
	}()

	// A HELLO seq counter that is monotonic across the WHOLE session (not reset
	// per handshake), so a delayed HELLO_RESP from an earlier attempt — even one
	// from the previous doHandshake call in the recovery loop — carries a
	// different seq and is ignored. It is uint8, so collisions only recur 256
	// HELLOs apart; a session sends at most HelloTries×(maxResetRecoveries+1),
	// far below that for any sane config.
	var helloSeq uint8
	for attempt := 0; attempt <= maxResetRecoveries; attempt++ {
		// Every attempt (re)handshakes: the first establishes the session, a
		// later one recovers a device that reset. Both paths therefore re-run
		// the full identity validation below, so a mid-session device swap
		// cannot bypass the ExpectDeviceID / proto_ver checks.
		dev, err := doHandshake(ctx, fc, to, &helloSeq)
		if err != nil {
			return nil, err
		}
		if err := acceptDevice(dev, opts); err != nil {
			return nil, err
		}

		res, retryHandshake, err := runExchange(ctx, fc, dev, opts.ProvisionJSON, to)
		if err != nil {
			return nil, err
		}
		if retryHandshake {
			// The session stalled BEFORE any pairing code was transmitted (no
			// SESSION_ACK). No config left the host, so re-HELLO and retry is
			// safe — this is the DTR-reset-during-handshake cure.
			continue
		}
		return &ProvisionResult{Device: dev, ResultJSON: res}, nil
	}
	return nil, fmt.Errorf("%w: never got a SESSION_ACK across %d re-HELLO attempts", ErrHandshake, maxResetRecoveries+1)
}

// Identify performs ONLY the HELLO handshake and returns the device's
// self-report — the bounded identification write the scan's `probe` tier
// permits. It sends at most HelloTries HELLOs (mirroring RunProvision's
// recovery of a DTR-reset device) and NEVER opens a session or writes config,
// so it is safe to point at a shared Espressif VID/PID that a user explicitly
// selected. It consumes rwc (closes the serial fd before returning), like
// RunProvision. The OS-exclusive lock lives on a separate fd the caller owns.
func Identify(ctx context.Context, rwc io.ReadWriteCloser, to Timeouts) (DeviceInfo, error) {
	to = to.withDefaults()
	fc := newFrameConn(rwc)
	defer fc.stop()

	watch := make(chan struct{})
	defer close(watch)
	go func() {
		select {
		case <-ctx.Done():
			fc.stop()
		case <-watch:
		}
	}()

	var helloSeq uint8
	return doHandshake(ctx, fc, to, &helloSeq)
}

// acceptDevice enforces the invariants that must hold before ANY configuration
// write, on both the initial handshake and every reset recovery.
func acceptDevice(dev DeviceInfo, opts ProvisionOpts) error {
	if dev.ProtoVer != wireProtoVer {
		return fmt.Errorf("%w: device announced proto_ver %d, host speaks %d", ErrUnsupportedProto, dev.ProtoVer, wireProtoVer)
	}
	if opts.ExpectDeviceID != "" && dev.DeviceID != opts.ExpectDeviceID {
		return fmt.Errorf("%w: got %q, want %q", ErrDeviceMismatch, dev.DeviceID, opts.ExpectDeviceID)
	}
	return nil
}

// doHandshake sends HELLO and waits for a structurally valid HELLO_RESP,
// retried. A HELLO also recovers a device that reset (it mints a fresh nonce),
// so retrying is the DTR-reset cure. A malformed/junk HELLO_RESP (bad JSON,
// empty device_id, zero nonce) is ignored within the timeout rather than
// treated as fatal, so one CRC-valid noise frame cannot abort discovery.
func doHandshake(ctx context.Context, fc *frameConn, to Timeouts, seq *uint8) (DeviceInfo, error) {
	for try := 0; try < to.HelloTries; try++ {
		// Each HELLO carries a distinct, session-monotonic seq (echoed in the
		// HELLO_RESP), so a delayed HELLO_RESP from an earlier attempt — which
		// would carry a now-stale nonce — is not mistaken for this attempt's
		// answer. The device does not cache HELLO, so these seq values never
		// collide with the exchange's seqSessionBegin/seqProvision.
		helloSeq := *seq
		*seq++
		if err := fc.send(MsgHELLO, helloSeq, 0, nil); err != nil {
			return DeviceInfo{}, err
		}
		var dev DeviceInfo
		_, err := fc.await(ctx, to.HelloResp, func(f Frame) bool {
			d, ok := parseHelloResp(f, helloSeq)
			if ok {
				dev = d
			}
			return ok
		})
		if err == errTimeout {
			continue // resend HELLO
		}
		if err != nil {
			return DeviceInfo{}, err
		}
		return dev, nil
	}
	return DeviceInfo{}, fmt.Errorf("%w: no valid HELLO_RESP after %d tries", ErrHandshake, to.HelloTries)
}

// runExchange runs SESSION_BEGIN → SESSION_ACK → PROVISION → RESULT → BYE.
// Replies are bound to the session by matching the header nonce AND the echoed
// seq, so a stale/replayed frame from another session (or console noise that
// happened to frame) is ignored, not acted on.
//
// The return is deliberately asymmetric around the point where a pairing code
// first goes on the wire:
//   - (resultJSON, false, nil) — success.
//   - (nil, true, nil)         — stalled BEFORE PROVISION (no SESSION_ACK). No
//     config was transmitted, so the caller may safely re-HELLO and retry.
//   - (nil, false, ErrOutcomeUnknown) — PROVISION was transmitted but no RESULT
//     arrived. The device may have committed; the caller must NOT blindly
//     re-apply (see ErrOutcomeUnknown).
func runExchange(ctx context.Context, fc *frameConn, dev DeviceInfo, provisionJSON []byte, to Timeouts) ([]byte, bool, error) {
	nonce := dev.Nonce

	// SESSION_BEGIN → SESSION_ACK, retransmitted. SESSION_BEGIN is idempotent
	// (the device re-ACKs an already-open session).
	acked := false
	for i := 0; i < to.SessionTries; i++ {
		if err := fc.send(MsgSessionBegin, seqSessionBegin, nonce, nil); err != nil {
			return nil, false, err
		}
		_, err := fc.await(ctx, to.SessionAck, func(f Frame) bool {
			return f.Type == MsgSessionAck && f.Nonce == nonce && f.Seq == seqSessionBegin
		})
		if err == errTimeout {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		acked = true
		break
	}
	if !acked {
		// Nothing sensitive on the wire yet — safe to re-HELLO and retry.
		return nil, true, nil
	}

	// PROVISION → RESULT, resent with an identical (seq, payload). WITHIN the
	// same session the device replays its cached RESULT for a duplicate and does
	// not charge a pairing attempt, so these retransmits are safe.
	//
	// From the first PROVISION send onward the pairing code is (or may be) on
	// the wire, so EVERY failure that is not a clean RESULT is classified
	// outcome-unknown, never a plain retryable error: a caller must not assume
	// "nothing happened" and re-apply, because a send error can still leave a
	// complete frame on the line and a cancelled/broken await can drop a RESULT
	// the device already acted on.
	for i := 0; i < to.ResultTries; i++ {
		if err := fc.send(MsgProvision, seqProvision, nonce, provisionJSON); err != nil {
			return nil, false, errors.Join(ErrOutcomeUnknown, fmt.Errorf("PROVISION send failed: %w", err))
		}
		f, err := fc.await(ctx, to.Result, func(f Frame) bool {
			return f.Type == MsgResult && f.Nonce == nonce && f.Seq == seqProvision && json.Valid(f.Payload)
		})
		if err == errTimeout {
			continue // resend PROVISION with identical (seq, payload)
		}
		if err != nil {
			return nil, false, errors.Join(ErrOutcomeUnknown, fmt.Errorf("awaiting RESULT after PROVISION: %w", err))
		}
		// RESULT received. Best-effort BYE to restore the console; a lost BYE is
		// harmless (the device restores on session timeout / reboot) and must
		// NOT turn a committed provision into a failure, so its error is
		// deliberately ignored.
		_ = fc.send(MsgBYE, seqBye, nonce, nil)
		return f.Payload, false, nil
	}
	// PROVISION was transmitted but no RESULT arrived even after in-session
	// retransmits. Re-sending across a fresh HELLO would clear the device's
	// retransmit cache and risk a double-apply / a second charged pairing
	// attempt, so we do NOT auto-recover: surface the ambiguity explicitly.
	return nil, false, fmt.Errorf("%w (after %d PROVISION sends)", ErrOutcomeUnknown, to.ResultTries)
}

// parseHelloResp validates a frame as the HELLO_RESP for the HELLO that carried
// wantSeq, and extracts DeviceInfo. It returns ok=false for anything that must
// be ignored as noise: a non-HELLO_RESP type, a seq that does not echo this
// attempt's HELLO (a delayed answer to an earlier attempt, with a stale nonce),
// a zero session nonce (the "no session" sentinel / an echo of our own HELLO),
// an empty or malformed JSON body, or a body missing device_id. The proto_ver
// is carried through unvalidated here and checked in acceptDevice so a version
// mismatch surfaces as a clear error rather than a silent timeout.
func parseHelloResp(f Frame, wantSeq uint8) (DeviceInfo, bool) {
	if f.Type != MsgHELLOResp || f.Seq != wantSeq || f.Nonce == 0 || len(f.Payload) == 0 {
		return DeviceInfo{}, false
	}
	var dev DeviceInfo
	if err := json.Unmarshal(f.Payload, &dev); err != nil {
		return DeviceInfo{}, false
	}
	if dev.DeviceID == "" {
		return DeviceInfo{}, false
	}
	dev.Nonce = f.Nonce
	return dev, true
}
