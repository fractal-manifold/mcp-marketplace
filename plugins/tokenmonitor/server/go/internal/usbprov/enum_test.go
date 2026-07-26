package usbprov

import "testing"

func TestNormalizeSerial(t *testing.T) {
	cases := map[string]string{
		"84:F7:03:AB:CD:EF": "84f703abcdef",
		"84f703abcdef":      "84f703abcdef",
		"84-F7-03-AB-CD-EF": "84f703abcdef",
		"  84F703ABCDEF  ":  "84f703abcdef",
		"AB_CD_EF":          "abcdef",
		"":                  "",
	}
	for in, want := range cases {
		if got := NormalizeSerial(in); got != want {
			t.Errorf("NormalizeSerial(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeviceIDFromSerial(t *testing.T) {
	// Full MAC (normalised) → last 8 hex, matching firmware mac[2..5].
	if id, ok := DeviceIDFromSerial("84f703abcdef"); !ok || id != "03abcdef" {
		t.Errorf("full MAC: got %q/%v, want 03abcdef/true", id, ok)
	}
	// Exactly 8 hex → itself.
	if id, ok := DeviceIDFromSerial("03abcdef"); !ok || id != "03abcdef" {
		t.Errorf("8-hex: got %q/%v, want 03abcdef/true", id, ok)
	}
	// Too short → no candidate.
	if _, ok := DeviceIDFromSerial("abcd"); ok {
		t.Error("a <8-char serial must not yield a device_id")
	}
	// Non-hex tail → no candidate (a bridge's arbitrary iSerial).
	if _, ok := DeviceIDFromSerial("cp2102nserialx"); ok {
		t.Error("a non-hex tail must not yield a device_id")
	}
	// Uppercase should already be normalised away by NormalizeSerial; a raw
	// uppercase tail here is treated as non-hex (defensive).
	if _, ok := DeviceIDFromSerial("0123ABCD"); ok {
		t.Error("DeviceIDFromSerial expects an already-normalised (lowercase) serial")
	}
}
