package usbprov

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// errTimeout is the internal signal that an await() deadline elapsed with no
// matching frame. Callers translate it into a retransmit or a give-up.
var errTimeout = errors.New("usbprov: await timed out")

// frameConn wraps a serial transport with a background reader that feeds every
// byte through a resynchronising Decoder and delivers complete frames on a
// channel. This decouples per-step timeouts from the fd: a serial os.File does
// not reliably support read deadlines, so the only way to unblock a stuck Read
// is to close the fd (stop()), which the reader treats as end-of-stream.
type frameConn struct {
	w      io.Writer
	closer io.Closer

	frames chan Frame
	errc   chan error // buffered(1); holds the terminal read error, if any

	done     chan struct{}
	stopOnce sync.Once
}

func newFrameConn(rwc io.ReadWriteCloser) *frameConn {
	fc := &frameConn{
		w:      rwc,
		closer: rwc,
		frames: make(chan Frame, 8),
		errc:   make(chan error, 1),
		done:   make(chan struct{}),
	}
	go fc.readLoop(rwc)
	return fc
}

func (fc *frameConn) readLoop(r io.Reader) {
	defer close(fc.frames)
	var dec Decoder
	buf := make([]byte, 512)
	for {
		n, err := r.Read(buf)
		for i := 0; i < n; i++ {
			if f, ok := dec.DecodeByte(buf[i]); ok {
				select {
				case fc.frames <- f:
				case <-fc.done:
					return
				}
			}
		}
		if err != nil {
			// io.EOF and the "closed" error from stop() are both normal
			// termination; record whatever it was for await() to surface if it
			// was waiting.
			select {
			case fc.errc <- err:
			default:
			}
			return
		}
		select {
		case <-fc.done:
			return
		default:
		}
	}
}

// send encodes and writes one frame in full. io.Writer.Write may legally return
// a short count with a nil error, so loop until every byte is on the wire; a
// zero-progress write is treated as a short write rather than a silent
// truncation that would put a malformed frame on the line. All protocol sends
// happen from the single caller goroutine, so no write mutex is needed.
func (fc *frameConn) send(typ, seq uint8, nonce uint32, payload []byte) error {
	frame, err := Encode(typ, seq, nonce, payload)
	if err != nil {
		return err
	}
	for off := 0; off < len(frame); {
		n, werr := fc.w.Write(frame[off:])
		off += n
		if werr != nil {
			return werr
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// await returns the next frame matching pred within d, or errTimeout, or a
// ctx/read error. Non-matching frames (unrelated types, console noise that
// happened to frame) are skipped within the same deadline.
func (fc *frameConn) await(ctx context.Context, d time.Duration, pred func(Frame) bool) (Frame, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return Frame{}, ctx.Err()
		case <-timer.C:
			return Frame{}, errTimeout
		case f, ok := <-fc.frames:
			if !ok {
				select {
				case err := <-fc.errc:
					if err != nil && err != io.EOF {
						return Frame{}, err
					}
				default:
				}
				return Frame{}, io.ErrUnexpectedEOF
			}
			if pred(f) {
				return f, nil
			}
		}
	}
}

// stop ends the reader and closes the transport. Idempotent.
func (fc *frameConn) stop() {
	fc.stopOnce.Do(func() {
		close(fc.done)
		_ = fc.closer.Close()
	})
}
