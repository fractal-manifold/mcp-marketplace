package textutil

import (
	"testing"
	"unicode/utf8"
)

func TestClipRunes(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 15, ""},
		{"short", 15, "short"},
		{"exactly15chars!", 15, "exactly15chars!"},
		{"sixteen chars!!!", 15, "sixteen chars!!"},
		// Multibyte: "Dragón de fuego" is 15 code points, 16 bytes.
		{"Dragón de fuego", 15, "Dragón de fuego"},
		{"Dragón de fuegoX", 15, "Dragón de fuego"},
		// Byte-based s[:15] would split the ó (2 bytes at index 14).
		{"aaaaaaaaaaaaaaó", 15, "aaaaaaaaaaaaaaó"},
		{"aaaaaaaaaaaaaaóZ", 15, "aaaaaaaaaaaaaaó"},
		// Astral (4-byte) code points count as one each.
		{"🐉🐉🐉", 2, "🐉🐉"},
		{"🐉🐉🐉", 15, "🐉🐉🐉"},
		{"abc", 0, ""},
	}
	for _, c := range cases {
		got := ClipRunes(c.in, c.n)
		if got != c.want {
			t.Errorf("ClipRunes(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("ClipRunes(%q, %d) produced invalid UTF-8: %q", c.in, c.n, got)
		}
	}
}
