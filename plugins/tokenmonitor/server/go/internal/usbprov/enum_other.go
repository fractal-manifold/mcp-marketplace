//go:build !linux && !darwin && !windows

package usbprov

func enumerate() ([]Port, error) {
	return nil, ErrEnumerateUnsupported
}
