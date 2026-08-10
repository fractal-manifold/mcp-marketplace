//go:build !linux && !darwin

package serial

// acquirePortLock is a no-op off POSIX: USB provisioning (and thus lease
// arbitration) is implemented on Linux + macOS (see portlock_posix.go); on other
// platforms there is no cooperating runtime to fence against on the tailer's
// port. The returned release is a no-op.
func acquirePortLock(string) (func() error, error) {
	return func() error { return nil }, nil
}
