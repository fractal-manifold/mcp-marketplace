//go:build linux || darwin

package serial

import "github.com/fractal-manifold/tokenmonitor-mcp/internal/usbprov"

// acquirePortLock takes the cross-runtime serial lock so the tailer participates
// in the same arbitration as a provisioning session: a follower holding the lock
// under a lease (which suspends this tailer) blocks the tailer from reacquiring
// until it releases, and vice versa. Returns usbprov.ErrPortBusy (retryable)
// when another cooperating runtime holds it. Shared by Linux and macOS — both
// are served by usbprov's POSIX open (serial_posix.go), so the tailer must fence
// on the same flock on both, or a macOS tailer could open a /dev/cu.* port a
// provisioning session already holds.
func acquirePortLock(canonical string) (func() error, error) {
	return usbprov.AcquirePortLock(canonical)
}
