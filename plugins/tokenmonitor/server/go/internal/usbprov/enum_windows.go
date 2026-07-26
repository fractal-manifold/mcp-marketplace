//go:build windows

package usbprov

// Windows enumeration is deferred (the plan marks it pending). When
// implemented it will enumerate COM<N> with their USB identity via the serial
// library. Note the launcher's `sh` shim already means no native Windows
// runtime today; under Git-Bash/MSYS the process is native and COM* is
// visible, but this remains unimplemented.
func enumerate() ([]Port, error) {
	return nil, ErrEnumerateUnsupported
}
