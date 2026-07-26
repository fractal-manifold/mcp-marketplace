"""Install-loop breaker, Python side.

Two independent triggers stop a device from re-downloading a firmware that
installs cleanly but cannot boot:

  * the DEVICE-reported X-Tmon-Ota-Fail header, parsed by
    broker.server._parse_ota_fail (precise, needs firmware that sends it);
  * the broker's own consecutive-stage streak in ota._decide (blunt, works
    against firmware too old to send the header).

Both must behave identically in go/py/js — the tombstone they write
(blocked_firmware_version) is persisted and honoured by all three. These cases
mirror Go's TestDeviceSync_BlocksOnOTAFailHeader /
TestDeviceSync_DoesNotBlockOnWeakOTAFailReports / TestCheckBlocksInstallLoop and
the JS ones in js/test/broker_sync.test.js.
"""

from __future__ import annotations

import pytest

from tmon_mcp.broker.server import (
    MIN_FAILED_INSTALLS_HARD,
    MIN_FAILED_INSTALLS_SOFT,
    _parse_ota_fail,
)


def test_parses_a_definitive_failure_report():
    assert _parse_ota_fail("0.10.5:2:panic") == ("0.10.5", 2, "panic")
    assert _parse_ota_fail("  0.10.5:3:wdt  ") == ("0.10.5", 3, "wdt")
    assert _parse_ota_fail("0.10.5-dev.202607181200:4:noconfirm") == (
        "0.10.5-dev.202607181200",
        4,
        "noconfirm",
    )


def test_threshold_is_state_aware():
    """The broker must not tombstone before the DEVICE would give up, or it
    silently shortens the firmware's own retry budget. Hard faults (panic/wdt)
    condemn at 2; circumstantial states take 4. Mirrors TMON_OTA_MAX_INSTALLS
    and TMON_OTA_MAX_INSTALLS_SOFT."""
    for hard in ("panic", "wdt"):
        assert _parse_ota_fail(f"0.10.5:{MIN_FAILED_INSTALLS_HARD}:{hard}") is not None
        assert _parse_ota_fail(f"0.10.5:{MIN_FAILED_INSTALLS_HARD - 1}:{hard}") is None
    for soft in ("brownout", "noconfirm", "unknown"):
        # Exactly the case the firmware is still willing to retry.
        assert _parse_ota_fail(f"0.10.5:{MIN_FAILED_INSTALLS_HARD}:{soft}") is None
        assert _parse_ota_fail(f"0.10.5:{MIN_FAILED_INSTALLS_SOFT - 1}:{soft}") is None
        assert _parse_ota_fail(f"0.10.5:{MIN_FAILED_INSTALLS_SOFT}:{soft}") is not None
    # An unrecognised state gets the SOFT threshold, not a rejection: firmware
    # and broker version independently, so a future state must not silently
    # disable the breaker.
    assert _parse_ota_fail("0.10.5:2:someday") is None
    assert _parse_ota_fail("0.10.5:4:someday") is not None


def test_install_count_is_bounded_to_the_firmware_range():
    """tmon_ota_fail_parse enforces 0..255, so anything else is not a record we
    wrote. Python ints are unbounded, so without the check an absurd count
    would sail past every threshold."""
    assert _parse_ota_fail("0.10.5:255:panic") == ("0.10.5", 255, "panic")
    assert _parse_ota_fail("0.10.5:256:panic") is None
    assert _parse_ota_fail("0.10.5:99999999999999999999:panic") is None


@pytest.mark.parametrize(
    "header,why",
    [
        ("", "absent"),
        ("none", "explicit sentinel"),
        ("   ", "whitespace only"),
        ("0.10.5:2:pending", "still armed — the install may yet succeed"),
        ("0.10.5:1:panic", "below the hard threshold"),
        ("0.10.5:3:brownout", "below the soft threshold"),
        ("0.10.5:4:", "empty state"),
        ("0.10.5:4", "wrong field count"),
        ("0.10.5:2:panic:extra", "wrong field count"),
        ("not-a-version:5:panic", "unparseable version"),
        ("0.10.06:2:panic", "leading zero — valid_version rejects it"),
        # Bare int() would take these; Go's strconv.Atoi does not, and all three
        # runtimes have to agree on exactly which headers are actionable.
        ("0.10.5:1_0:panic", "python underscore literal"),
        ("0.10.5:2abc:panic", "trailing garbage in the count"),
        ("0.10.5: 2 :panic", "padded count"),
        ("0.10.5:0x2:panic", "hex count"),
        ("x" * 65, "over-long"),
    ],
)
def test_rejects_everything_that_does_not_prove_a_failure(header, why):
    assert _parse_ota_fail(header) is None, why


def test_negative_and_zero_counts_are_rejected():
    # Syntactically fine for Atoi, semantically below the threshold.
    assert _parse_ota_fail("0.10.5:-3:panic") is None
    assert _parse_ota_fail("0.10.5:0:panic") is None
    # A signed value at or above the threshold is still accepted, as in Go.
    assert _parse_ota_fail("0.10.5:+2:panic") == ("0.10.5", 2, "panic")


def test_max_auto_stages_matches_the_other_runtimes():
    """The streak threshold is a cross-runtime constant; a silent drift here
    means a Go-led and a py-led broker give the fleet different budgets."""
    from tmon_mcp.ota import MAX_AUTO_STAGES

    assert MAX_AUTO_STAGES == 5
    assert MIN_FAILED_INSTALLS_HARD == 2
    assert MIN_FAILED_INSTALLS_SOFT == 4
