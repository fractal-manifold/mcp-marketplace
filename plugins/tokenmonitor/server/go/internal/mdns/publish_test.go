package mdns

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestBuildTXTDedupSortAndRuntime(t *testing.T) {
	txt := buildTXT([]string{"bb", "aa"})
	if txt[0] != "v=1" || txt[1] != "runtime=go" {
		t.Fatalf("header entries wrong: %v", txt)
	}
	if txt[2] != "devs=aa,bb" {
		t.Fatalf("devs entry wrong: %v", txt[2])
	}
}

func TestBuildTXTEmpty(t *testing.T) {
	txt := buildTXT(nil)
	if txt[len(txt)-1] != "devs=" {
		t.Fatalf("empty list must still publish devs=: %v", txt)
	}
}

func TestBuildTXTCapsAtWholeIDBoundary(t *testing.T) {
	var ids []string
	for i := 0; i < 40; i++ { // 40×9 bytes joined > 250 cap
		ids = append(ids, fmt.Sprintf("%08x", i))
	}
	txt := buildTXT(ids)
	devs := strings.TrimPrefix(txt[len(txt)-1], "devs=")
	if len(devs) > 255-len("devs=") {
		t.Fatalf("devs over cap: %d", len(devs))
	}
	if strings.HasSuffix(devs, ",") {
		t.Fatalf("devs ends mid-boundary: %q", devs)
	}
	for _, id := range strings.Split(devs, ",") {
		if len(id) != 8 {
			t.Fatalf("truncated id survived: %q", id)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for bind, want := range map[string]bool{
		"":              false,
		"0.0.0.0":       false,
		"::":             false,
		"127.0.0.1":     true,
		"::1":           true,
		"192.168.1.142": false,
	} {
		if got := isLoopback(bind); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", bind, got, want)
		}
	}
}

func TestIfaceFingerprintEmptyAndDeterministic(t *testing.T) {
	if got := ifaceFingerprint(nil); got != "" {
		t.Fatalf("nil ifaces must fingerprint to empty, got %q", got)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("no interfaces: %v", err)
	}
	a := ifaceFingerprint(ifaces)
	b := ifaceFingerprint(ifaces)
	if a != b {
		t.Fatalf("fingerprint not deterministic: %q vs %q", a, b)
	}
}
