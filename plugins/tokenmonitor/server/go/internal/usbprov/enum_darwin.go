//go:build darwin

package usbprov

// macOS enumeration is deferred. When implemented it will parse
// `ioreg -r -c IOUSBHostDevice -a` (CGO-free) and map each USB device to its
// /dev/cu.* callout (NEVER /dev/tty.* — opening that waits for DCD, which a
// CDC gadget never asserts). Until then a scan on macOS reports the
// unsupported error rather than silently finding nothing.
func enumerate() ([]Port, error) {
	return nil, ErrEnumerateUnsupported
}
