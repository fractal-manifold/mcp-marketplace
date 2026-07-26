//go:build !linux

package serial

// acquirePortLock is a no-op off Linux: USB provisioning (and thus lease
// arbitration) is Linux-only for now, so there is no cooperating runtime to
// fence against on the tailer's port. The returned release is a no-op.
func acquirePortLock(string) (func() error, error) {
	return func() error { return nil }, nil
}
