//go:build linux

package usbprov

import (
	"os"
	"path/filepath"
	"testing"
)

// writeAttr creates dir and writes a sysfs-style attribute file (trailing
// newline, as the kernel does).
func writeAttr(t *testing.T, dir, name, val string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(val+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadUSBAttrs_WalksUp(t *testing.T) {
	root := t.TempDir()
	// Simulate ttyACM: the "device" dir is the interface; idVendor/idProduct/
	// serial live two levels up on the USB device node.
	usbDev := filepath.Join(root, "usb1", "1-1")
	iface := filepath.Join(usbDev, "1-1:1.0", "tty", "ttyACM0")
	writeAttr(t, usbDev, "idVendor", "303a")
	writeAttr(t, usbDev, "idProduct", "1001")
	writeAttr(t, usbDev, "serial", "84F703ABCDEF")
	if err := os.MkdirAll(iface, 0o755); err != nil {
		t.Fatal(err)
	}

	vid, pid, serial, ok := readUSBAttrs(iface)
	if !ok {
		t.Fatal("expected to find USB attrs by walking up")
	}
	if vid != 0x303a || pid != 0x1001 {
		t.Errorf("id = %04x:%04x, want 303a:1001", vid, pid)
	}
	if serial != "84F703ABCDEF" {
		t.Errorf("serial = %q, want raw 84F703ABCDEF", serial)
	}
}

func TestReadUSBAttrs_MissingIsNotFound(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "platform-serial")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := readUSBAttrs(dir); ok {
		t.Error("a non-USB serial (no idVendor anywhere) must report not-found")
	}
}

func TestReadUSBAttrs_SerialOptional(t *testing.T) {
	root := t.TempDir()
	dev := filepath.Join(root, "3-2")
	writeAttr(t, dev, "idVendor", "0403")
	writeAttr(t, dev, "idProduct", "6001")
	// no serial file
	vid, pid, serial, ok := readUSBAttrs(dev)
	if !ok || vid != 0x0403 || pid != 0x6001 || serial != "" {
		t.Errorf("serial-less device: got %04x:%04x %q ok=%v", vid, pid, serial, ok)
	}
}

// enumerateSysfs against a fake /sys/class/tty tree with real symlinks: one
// ttyACM (Espressif), one ttyUSB (FTDI), and one non-USB tty that must be
// skipped.
func TestEnumerateSysfs_FakeTree(t *testing.T) {
	root := t.TempDir()
	sysClassTTY := filepath.Join(root, "sys", "class", "tty")
	if err := os.MkdirAll(sysClassTTY, 0o755); err != nil {
		t.Fatal(err)
	}

	// Espressif ttyACM0.
	acmDev := filepath.Join(root, "sys", "devices", "usb1", "1-1")
	acmIface := filepath.Join(acmDev, "1-1:1.0")
	writeAttr(t, acmDev, "idVendor", "303a")
	writeAttr(t, acmDev, "idProduct", "1001")
	writeAttr(t, acmDev, "serial", "84:F7:03:AB:CD:EF")
	if err := os.MkdirAll(acmIface, 0o755); err != nil {
		t.Fatal(err)
	}
	mkClassLink(t, sysClassTTY, "ttyACM0", acmIface)

	// FTDI ttyUSB0.
	usbDev := filepath.Join(root, "sys", "devices", "usb2", "2-1")
	usbIface := filepath.Join(usbDev, "2-1:1.0")
	writeAttr(t, usbDev, "idVendor", "0403")
	writeAttr(t, usbDev, "idProduct", "6001")
	if err := os.MkdirAll(usbIface, 0o755); err != nil {
		t.Fatal(err)
	}
	mkClassLink(t, sysClassTTY, "ttyUSB0", usbIface)

	// A platform (non-USB) serial port that must be ignored.
	platIface := filepath.Join(root, "sys", "devices", "platform", "serial8250")
	if err := os.MkdirAll(platIface, 0o755); err != nil {
		t.Fatal(err)
	}
	mkClassLink(t, sysClassTTY, "ttyS0", platIface)

	ports, err := enumerateSysfs(sysClassTTY, "/dev")
	if err != nil {
		t.Fatalf("enumerateSysfs: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("got %d ports, want 2 (ttyS0 must be skipped): %+v", len(ports), ports)
	}

	byPath := map[string]Port{}
	for _, p := range ports {
		byPath[p.Path] = p
	}
	acm, ok := byPath["/dev/ttyACM0"]
	if !ok {
		t.Fatal("ttyACM0 missing")
	}
	if acm.VID != 0x303a || acm.PID != 0x1001 {
		t.Errorf("ttyACM0 id = %04x:%04x", acm.VID, acm.PID)
	}
	if acm.SerialNorm != "84f703abcdef" {
		t.Errorf("ttyACM0 SerialNorm = %q, want normalised 84f703abcdef", acm.SerialNorm)
	}
	if _, ok := byPath["/dev/ttyUSB0"]; !ok {
		t.Error("ttyUSB0 missing")
	}
	if _, ok := byPath["/dev/ttyS0"]; ok {
		t.Error("ttyS0 (non-USB) must not be enumerated")
	}
}

// mkClassLink creates /sys/class/tty/<name> as a relative symlink to the
// interface dir's ../tty/<name>, mirroring how the kernel lays it out: the
// class entry's "device" symlink resolves to the interface. We create
// <iface>/tty/<name> as the real dir and point the class entry's "device" at
// the iface.
func mkClassLink(t *testing.T, sysClassTTY, name, ifaceDir string) {
	t.Helper()
	// Real tty node under the interface.
	ttyNode := filepath.Join(ifaceDir, "tty", name)
	if err := os.MkdirAll(ttyNode, 0o755); err != nil {
		t.Fatal(err)
	}
	// /sys/class/tty/<name> is a dir containing a "device" symlink → iface.
	classEntry := filepath.Join(sysClassTTY, name)
	if err := os.MkdirAll(classEntry, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ifaceDir, filepath.Join(classEntry, "device")); err != nil {
		t.Fatal(err)
	}
}
