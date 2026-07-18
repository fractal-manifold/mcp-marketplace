//go:build windows

package serial

import "context"

// tailOnce is unsupported on Windows: the tty/termios raw-mode plumbing has no
// portable equivalent, and reading firmware logs off the USB-CDC port is a
// leader-only convenience the rest of the broker never depends on. Run() logs
// this once (via errUnsupported) and returns instead of spinning.
func (t *Tailer) tailOnce(_ context.Context) error { return errUnsupported }
