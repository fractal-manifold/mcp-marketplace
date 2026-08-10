//go:build darwin

package usbprov

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// macOS has no sysfs. The IORegistry is the source of truth: every USB serial
// device hangs an IOSerialBSDClient node exposing "IOCalloutDevice" (/dev/cu.*),
// while the USB idVendor/idProduct/iSerial live on an ANCESTOR IOUSBHostDevice
// node. We read the IOUSBHostDevice subtree as an XML plist (`ioreg -a`,
// CGO-free) and inherit vid/pid/serial down to each callout node — the same
// shape sysfs gives on Linux. We map to /dev/cu.* (the callout), NEVER
// /dev/tty.* (the dialin node, which blocks on DCD a CDC gadget never asserts).
// Mirrors the JS enum.js and Python enum.py darwin paths. The plist parse and
// the IORegistry walk are OS-agnostic and live in enum_plist.go so they stay
// unit-testable on the (Linux) CI host.

func enumerate() ([]Port, error) {
	// Bound ioreg like the JS/Python runtimes (5 s): a stalled ioreg must be
	// killed and reaped rather than hanging the scan / an implicit enumeration
	// during provisioning indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ioreg", "-a", "-r", "-l", "-c", "IOUSBHostDevice").Output()
	if err != nil {
		return nil, fmt.Errorf("usbprov: ioreg failed: %w", err)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil // no IOUSBHostDevice present
	}
	root, err := parsePlist(out)
	if err != nil {
		return nil, fmt.Errorf("usbprov: parse ioreg plist: %w", err)
	}
	return portsFromPlist(root), nil
}
