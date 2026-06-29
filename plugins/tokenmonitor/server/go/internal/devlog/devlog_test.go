package devlog

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var epoch = time.Unix(0, 0).UTC()

func TestStampLinesBasic(t *testing.T) {
	got := StampLines("alpha\nbeta\n\n  \ngamma\r\n", epoch)
	want := []string{
		"[1970-01-01T00:00:00Z] alpha",
		"[1970-01-01T00:00:00Z] beta",
		"[1970-01-01T00:00:00Z] gamma",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A misbehaving device could upload huge single lines; every stored line
// must stay <= MaxLineBytes, remain valid UTF-8 (never split a rune), and
// carry the truncation marker. Mirrors the Python and JS impls.
func TestStampLinesTruncates(t *testing.T) {
	for _, unit := range []string{"x", "é", "世", "🙂"} {
		in := strings.Repeat(unit, 5000)
		got := StampLines(in, epoch)
		if len(got) != 1 {
			t.Fatalf("%q: got %d lines", unit, len(got))
		}
		line := got[0]
		if len(line) > MaxLineBytes {
			t.Errorf("%q: line is %d bytes, over cap %d", unit, len(line), MaxLineBytes)
		}
		if !utf8.ValidString(line) {
			t.Errorf("%q: truncation produced invalid UTF-8", unit)
		}
		if !strings.HasSuffix(line, truncMarker) {
			t.Errorf("%q: missing truncation marker", unit)
		}
	}
}

func TestAppendCapsAndRoundTrips(t *testing.T) {
	devices := filepath.Join(t.TempDir(), "devices")
	dir := DirFor(devices)
	id := "ab12cd34"

	// First batch.
	if err := Append(dir, id, []string{"one", "two"}); err != nil {
		t.Fatal(err)
	}
	lines, err := Read(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "one" || lines[1] != "two" {
		t.Fatalf("round-trip = %q", lines)
	}

	// Overflow the retention cap; only the most recent MaxLines survive.
	big := make([]string, MaxLines+50)
	for i := range big {
		big[i] = "line"
	}
	if err := Append(dir, id, big); err != nil {
		t.Fatal(err)
	}
	lines, err = Read(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != MaxLines {
		t.Fatalf("retained %d lines, want cap %d", len(lines), MaxLines)
	}
}

func TestReadMissingIsEmpty(t *testing.T) {
	lines, err := Read(DirFor(filepath.Join(t.TempDir(), "devices")), "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 0 {
		t.Fatalf("missing file should read empty, got %q", lines)
	}
}
