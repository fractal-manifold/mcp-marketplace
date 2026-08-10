package usbprov

import "testing"

// macOS enumeration core: the ioreg XML-plist decode + the IORegistry walk that
// inherits USB idVendor/idProduct/iSerial down to each /dev/cu.* callout node.
// Mirrors the JS usbprov_enum_darwin.test.js and py test_usb_enum_darwin.py.
// OS-agnostic (no build tag), so it runs on the Linux CI host too.

// One Espressif USB device whose VID/PID/serial live on the top node, with the
// IOCalloutDevice buried two children deep, plus a sibling child with no callout
// that must be ignored, and an XML entity in a name to exercise unescaping.
const fixturePlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>idVendor</key><integer>12346</integer>
    <key>idProduct</key><integer>4097</integer>
    <key>USB Serial Number</key><string>3C:0F:02:C4:77:7C</string>
    <key>IORegistryEntryName</key><string>ESP32-S3 &amp; JTAG</string>
    <key>IORegistryEntryChildren</key>
    <array>
      <dict>
        <key>IORegistryEntryChildren</key>
        <array>
          <dict>
            <key>IOCalloutDevice</key><string>/dev/cu.usbmodem1101</string>
            <key>IODialinDevice</key><string>/dev/tty.usbmodem1101</string>
          </dict>
        </array>
      </dict>
      <dict>
        <key>IORegistryEntryName</key><string>some-other-interface</string>
      </dict>
    </array>
  </dict>
</array>
</plist>`

func parsePorts(t *testing.T, xml string) []Port {
	t.Helper()
	root, err := parsePlist([]byte(xml))
	if err != nil {
		t.Fatalf("parsePlist: %v", err)
	}
	return portsFromPlist(root)
}

func TestPortsFromPlist_InheritsDownToCallout(t *testing.T) {
	ports := parsePorts(t, fixturePlist)
	if len(ports) != 1 {
		t.Fatalf("got %d ports, want 1: %+v", len(ports), ports)
	}
	p := ports[0]
	if p.Path != "/dev/cu.usbmodem1101" { // callout, not dialin
		t.Errorf("path = %q, want /dev/cu.usbmodem1101", p.Path)
	}
	if p.VID != 0x303a || p.PID != 0x1001 {
		t.Errorf("id = %04x:%04x, want 303a:1001", p.VID, p.PID)
	}
	if p.Serial != "3C:0F:02:C4:77:7C" || p.SerialNorm != "3c0f02c4777c" {
		t.Errorf("serial = %q / %q", p.Serial, p.SerialNorm)
	}
}

func TestPortsFromPlist_KUSBSerialWins(t *testing.T) {
	xml := `<plist version="1.0"><array><dict>
		<key>idVendor</key><integer>1</integer>
		<key>idProduct</key><integer>2</integer>
		<key>kUSBSerialNumberString</key><string>AA:BB</string>
		<key>USB Serial Number</key><string>ZZ:ZZ</string>
		<key>IOCalloutDevice</key><string>/dev/cu.x</string>
	</dict></array></plist>`
	ports := parsePorts(t, xml)
	if len(ports) != 1 || ports[0].Serial != "AA:BB" || ports[0].SerialNorm != "aabb" {
		t.Fatalf("got %+v, want serial AA:BB / aabb", ports)
	}
}

func TestPortsFromPlist_EmptyKUSBSerialFallsBack(t *testing.T) {
	xml := `<plist version="1.0"><array><dict>
		<key>idVendor</key><integer>1</integer>
		<key>idProduct</key><integer>2</integer>
		<key>kUSBSerialNumberString</key><string></string>
		<key>USB Serial Number</key><string>3C:0F:02:C4:77:7C</string>
		<key>IOCalloutDevice</key><string>/dev/cu.x</string>
	</dict></array></plist>`
	ports := parsePorts(t, xml)
	if len(ports) != 1 || ports[0].Serial != "3C:0F:02:C4:77:7C" || ports[0].SerialNorm != "3c0f02c4777c" {
		t.Fatalf("got %+v, want serial falling back to USB Serial Number", ports)
	}
}

func TestPortsFromPlist_CalloutWithoutIDSkipped(t *testing.T) {
	xml := `<plist version="1.0"><array><dict>
		<key>IOCalloutDevice</key><string>/dev/cu.Bluetooth</string>
	</dict></array></plist>`
	if ports := parsePorts(t, xml); len(ports) != 0 {
		t.Fatalf("got %+v, want none", ports)
	}
}

func TestPortsFromPlist_OutOfRangeIDRejected(t *testing.T) {
	xml := `<plist version="1.0"><array><dict>
		<key>idVendor</key><integer>70000</integer>
		<key>idProduct</key><integer>1</integer>
		<key>IOCalloutDevice</key><string>/dev/cu.x</string>
	</dict></array></plist>`
	if ports := parsePorts(t, xml); len(ports) != 0 {
		t.Fatalf("got %+v, want none (vid out of uint16 range)", ports)
	}
}

func TestPortsFromPlist_EmptyYieldsNone(t *testing.T) {
	if ports := parsePorts(t, `<plist version="1.0"><array/></plist>`); len(ports) != 0 {
		t.Fatalf("got %+v, want none", ports)
	}
}

func TestPortsFromPlist_DuplicateCalloutDedupes(t *testing.T) {
	xml := `<plist version="1.0"><array><dict>
		<key>idVendor</key><integer>1</integer><key>idProduct</key><integer>2</integer>
		<key>IOCalloutDevice</key><string>/dev/cu.dup</string>
		<key>IORegistryEntryChildren</key><array><dict>
			<key>IOCalloutDevice</key><string>/dev/cu.dup</string>
		</dict></array>
	</dict></array></plist>`
	ports := parsePorts(t, xml)
	if len(ports) != 1 || ports[0].Path != "/dev/cu.dup" {
		t.Fatalf("got %+v, want single /dev/cu.dup", ports)
	}
}
