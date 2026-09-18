package mcp

import (
	"net"
	"strings"
	"testing"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

func cidr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return &net.IPNet{IP: ip.To4(), Mask: n.Mask}
}

// A laptop on WiFi and Ethernet at once has two usable addresses and only one
// of them is on the device's network. Handing out the wrong one does not just
// make the firmware_url unreachable: tmon_ota.c treats a foreign origin as
// reason to withhold the HMAC headers, so the download 401s too.
func TestPickLocalIP_PrefersTheDevicesSubnet(t *testing.T) {
	nets := []*net.IPNet{
		cidr(t, "10.0.0.5/24"),    // Ethernet, listed first
		cidr(t, "192.168.2.7/24"), // WiFi, where the device actually is
	}
	cases := []struct {
		deviceIP string
		want     string
	}{
		{"192.168.2.44", "192.168.2.7"},
		{"10.0.0.99", "10.0.0.5"},
		{"172.16.4.4", "10.0.0.5"}, // device on neither: fall back to the first
		{"", "10.0.0.5"},           // never seen yet
		{"garbage", "10.0.0.5"},
		{"fe80::1", "10.0.0.5"},
	}
	for _, c := range cases {
		if got := pickLocalIP(nets, c.deviceIP); got != c.want {
			t.Errorf("pickLocalIP(%q) = %s, want %s", c.deviceIP, got, c.want)
		}
	}
}

// A /16 and a /24 that overlap on the first three octets: the mask has to be
// honoured, not the octets eyeballed.
func TestPickLocalIP_HonoursTheMask(t *testing.T) {
	nets := []*net.IPNet{cidr(t, "192.168.1.5/24"), cidr(t, "192.168.0.9/16")}
	if got := pickLocalIP(nets, "192.168.99.3"); got != "192.168.0.9" {
		t.Errorf("got %s, want the /16 address", got)
	}
}

// The address the device dialled beats every guess: it is the only one known
// to equal the svc_url the firmware compares the download origin against, and
// a wrong guess costs a 401 that poisons the version on-device after 3 tries.
// This host may well have a "better looking" address on the device's subnet —
// it must still lose.
func TestFirmwareBase_PrefersTheProvenOrigin(t *testing.T) {
	d := Deps{Cfg: &config.Config{}}
	d.Cfg.Server.Port = 8765
	dev := &registry.Device{}
	dev.Active.LastIP = "192.168.2.44"
	dev.Active.LastLocalAddr = "192.168.2.28:8765"

	got, err := firmwareBase(d, dev)
	if err != nil {
		t.Fatalf("firmwareBase: %v", err)
	}
	if got.url != "http://192.168.2.28:8765" {
		t.Fatalf("url = %q, want the dialled address", got.url)
	}
	if !strings.Contains(got.how, "dialled") {
		t.Fatalf("the operator must be told the origin is proven, got %q", got.how)
	}
}

// A broker on a non-default port is reached on that port, and the proven
// address already carries it — the configured port must not be re-appended.
func TestFirmwareBase_KeepsTheDialledPort(t *testing.T) {
	d := Deps{Cfg: &config.Config{}}
	d.Cfg.Server.Port = 8765
	dev := &registry.Device{}
	dev.Active.LastLocalAddr = "192.168.2.28:9999"

	got, err := firmwareBase(d, dev)
	if err != nil {
		t.Fatalf("firmwareBase: %v", err)
	}
	if got.url != "http://192.168.2.28:9999" {
		t.Fatalf("url = %q, want the port the device actually dialled", got.url)
	}
}

// With no proven origin the old behaviour stands — this host's interfaces,
// ranked by the device's subnet — and the tool result says so, because that
// answer is a guess and the operator should know before spending a reboot on
// it.
func TestFirmwareBase_FallsBackAndSaysSo(t *testing.T) {
	d := Deps{Cfg: &config.Config{}}
	d.Cfg.Server.Port = 8765
	dev := &registry.Device{}

	got, err := firmwareBase(d, dev)
	if err != nil {
		// A host with no usable LAN address is a legitimate outcome here and
		// has its own message; nothing to assert about the choice.
		t.Skipf("no LAN address on this host: %v", err)
	}
	if strings.Contains(got.how, "dialled") {
		t.Fatalf("nothing was proven; %q claims otherwise", got.how)
	}
	if !strings.HasPrefix(got.url, "http://") {
		t.Fatalf("url = %q", got.url)
	}
}
