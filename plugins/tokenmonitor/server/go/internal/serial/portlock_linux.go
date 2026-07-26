//go:build linux

package serial

import "github.com/fractal-manifold/tokenmonitor-mcp/internal/usbprov"

// acquirePortLock takes the cross-runtime serial lock so the tailer participates
// in the same arbitration as a provisioning session: a follower holding the lock
// under a lease (which suspends this tailer) blocks the tailer from reacquiring
// until it releases, and vice versa. Returns usbprov.ErrPortBusy (retryable)
// when another cooperating runtime holds it.
func acquirePortLock(canonical string) (func() error, error) {
	return usbprov.AcquirePortLock(canonical)
}
