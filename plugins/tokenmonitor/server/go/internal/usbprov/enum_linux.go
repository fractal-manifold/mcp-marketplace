//go:build linux

package usbprov

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// enumerate walks /sys/class/tty, keeping only USB-backed ttys (ttyACM* and
// ttyUSB*), and reads each one's USB VID/PID/iSerial from sysfs. It never
// hardcodes the /dev/serial/by-id name format (it varies by distro); it
// derives the /dev path from the tty name and reads identity from sysfs.
func enumerate() ([]Port, error) {
	const sysClassTTY = "/sys/class/tty"
	return enumerateSysfs(sysClassTTY, "/dev")
}

// enumerateSysfs is the testable core: it lists ttys under sysClassTTY and,
// for the USB-backed ones, resolves the sysfs device directory and reads USB
// attributes from it. devRoot is prefixed onto the tty name to form the port
// path (/dev in production).
func enumerateSysfs(sysClassTTY, devRoot string) ([]Port, error) {
	entries, err := os.ReadDir(sysClassTTY)
	if err != nil {
		// No /sys/class/tty (unusual) is "no ports", not a hard error — the
		// scan should report an empty list, not fail.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var ports []Port
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "ttyACM") && !strings.HasPrefix(name, "ttyUSB") {
			continue
		}
		// /sys/class/tty/<name>/device points at the USB *interface*; the USB
		// device directory (with idVendor/idProduct/serial) is one of its
		// ancestors. Resolve the symlink then walk up.
		devLink := filepath.Join(sysClassTTY, name, "device")
		real, err := filepath.EvalSymlinks(devLink)
		if err != nil {
			continue // no backing device dir → not a USB tty we can identify
		}
		vid, pid, serial, ok := readUSBAttrs(real)
		if !ok {
			continue // e.g. a non-USB serial port; skip rather than guess
		}
		ports = append(ports, Port{
			Path:       filepath.Join(devRoot, name),
			VID:        vid,
			PID:        pid,
			Serial:     serial,
			SerialNorm: NormalizeSerial(serial),
		})
	}
	return ports, nil
}

// readUSBAttrs walks up from a sysfs device directory looking for the nearest
// ancestor that carries both idVendor and idProduct (the USB device node),
// and returns the parsed VID/PID plus the serial (empty if the device exposes
// none). Walking up — rather than assuming a fixed depth — handles ttyACM
// (CDC, device→interface→usb-device) and ttyUSB (usb-serial) uniformly.
func readUSBAttrs(startDir string) (vid, pid uint16, serial string, ok bool) {
	dir := startDir
	for i := 0; i < 8; i++ { // bounded climb; USB nesting is shallow
		vidStr, vErr := readSysAttr(dir, "idVendor")
		pidStr, pErr := readSysAttr(dir, "idProduct")
		if vErr == nil && pErr == nil {
			v, err1 := strconv.ParseUint(vidStr, 16, 16)
			p, err2 := strconv.ParseUint(pidStr, 16, 16)
			if err1 != nil || err2 != nil {
				return 0, 0, "", false
			}
			// serial is optional; a device without one is still a valid port
			// (it just can never reach registry-match).
			s, _ := readSysAttr(dir, "serial")
			return uint16(v), uint16(p), s, true
		}
		parent := filepath.Dir(dir)
		if parent == dir || parent == "/" || parent == "." {
			break
		}
		dir = parent
	}
	return 0, 0, "", false
}

func readSysAttr(dir, attr string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, attr))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
