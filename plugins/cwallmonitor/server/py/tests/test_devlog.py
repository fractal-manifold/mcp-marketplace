"""Per-device diagnostic log store — stamping, truncation, retention.

Mirrors the Go (internal/devlog/devlog_test.go) and JS (test/devlog.test.js)
behaviour so the three impls stay wire-compatible.
"""

from datetime import datetime, timezone

from cwm_mcp import devlog

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def test_stamp_lines_basic():
    got = devlog.stamp_lines("alpha\nbeta\n\n  \ngamma\r\n", EPOCH)
    assert got == [
        "[1970-01-01T00:00:00Z] alpha",
        "[1970-01-01T00:00:00Z] beta",
        "[1970-01-01T00:00:00Z] gamma",
    ]


def test_stamp_lines_truncates():
    # A misbehaving device can upload giant single lines; each stored line
    # must stay <= MAX_LINE_BYTES, remain valid UTF-8, and carry the marker.
    for unit in ("x", "é", "世", "🙂"):
        got = devlog.stamp_lines(unit * 5000, EPOCH)
        assert len(got) == 1
        line = got[0]
        raw = line.encode("utf-8")
        assert len(raw) <= devlog.MAX_LINE_BYTES, (unit, len(raw))
        raw.decode("utf-8")  # raises if a rune was split
        assert line.endswith(" [truncated]")


def test_append_caps_and_round_trips(tmp_path):
    devices = str(tmp_path / "devices")
    dev = "ab12cd34"

    devlog.append(devices, dev, ["one", "two"])
    assert devlog.read(devices, dev) == ["one", "two"]

    devlog.append(devices, dev, ["line"] * (devlog.MAX_LINES + 50))
    assert len(devlog.read(devices, dev)) == devlog.MAX_LINES


def test_read_missing_is_empty(tmp_path):
    assert devlog.read(str(tmp_path / "devices"), "deadbeef") == []
