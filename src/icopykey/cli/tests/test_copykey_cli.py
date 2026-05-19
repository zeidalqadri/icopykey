"""Tests for the top-level CLI dispatcher (`copykey_cli.main` and helpers).

Focused on the stale-config VID/PID fallback in
``_parse_vid_pid_args`` — when the user's ``~/.copykey_cli/config.json``
still contains placeholder values from early development
(``0x0483/0x5740``), the function must rescue them by falling through
to the authoritative ``constants.DEVICE_VID`` / ``DEVICE_PID`` when
those constants enumerate a real device.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from ..constants import DEVICE_PID, DEVICE_VID
from ..copykey_cli import _parse_vid_pid_args


def _cfg(vid_str: str, pid_str: str) -> SimpleNamespace:
    """Build the minimal ConfigManager().config shape the parser needs."""
    return SimpleNamespace(device=SimpleNamespace(vid=vid_str, pid=pid_str))


def test_explicit_vid_pid_wins_over_config() -> None:
    """--vid/--pid on the command line trumps both config and constants."""
    argv = ["copykey-cli", "probe", "--vid", "0x1234", "--pid", "0xABCD"]
    cfg = _cfg("0x0483", "0x5740")  # stale config
    with patch("hid.enumerate", return_value=[]):
        # Even if 0x1234/0xABCD doesn't enumerate, explicit args are honored.
        vid, pid = _parse_vid_pid_args(argv, cfg)
    assert (vid, pid) == (0x1234, 0xABCD)


def test_stale_config_falls_through_to_constants() -> None:
    """Stale config + real device present => fall through to constants."""
    argv = ["copykey-cli", "probe"]
    cfg = _cfg("0x0483", "0x5740")  # stale

    def fake_enumerate(vid: int = 0, pid: int = 0):
        # Only the constants enumerate a device on this fake bus.
        if vid == DEVICE_VID and pid == DEVICE_PID:
            return [{"path": b"FAKE"}]
        return []

    with patch("hid.enumerate", side_effect=fake_enumerate):
        vid, pid = _parse_vid_pid_args(argv, cfg)
    assert (vid, pid) == (DEVICE_VID, DEVICE_PID)


def test_config_matches_device_keeps_config() -> None:
    """If the config-derived IDs DO enumerate, leave them alone."""
    argv = ["copykey-cli", "probe"]
    cfg = _cfg("0x0483", "0x5740")

    def fake_enumerate(vid: int = 0, pid: int = 0):
        # Pretend the config-stated device is present (e.g. a different
        # firmware revision).
        if vid == 0x0483 and pid == 0x5740:
            return [{"path": b"OTHER"}]
        return []

    with patch("hid.enumerate", side_effect=fake_enumerate):
        vid, pid = _parse_vid_pid_args(argv, cfg)
    assert (vid, pid) == (0x0483, 0x5740)


def test_neither_device_present_keeps_config_values() -> None:
    """If NO device is present, don't silently rewrite the IDs.

    The downstream code will report Device-not-found; we don't want to
    pretend the constants would have worked.
    """
    argv = ["copykey-cli", "probe"]
    cfg = _cfg("0x0483", "0x5740")
    with patch("hid.enumerate", return_value=[]):
        vid, pid = _parse_vid_pid_args(argv, cfg)
    assert (vid, pid) == (0x0483, 0x5740)


def test_config_already_matches_constants_no_rescue() -> None:
    """When config = constants, no fallback logic kicks in."""
    argv = ["copykey-cli", "probe"]
    cfg = _cfg(f"0x{DEVICE_VID:04X}", f"0x{DEVICE_PID:04X}")
    # We don't need to mock hid because the rescue branch is skipped
    # when (vid, pid) already equals the constants.
    vid, pid = _parse_vid_pid_args(argv, cfg)
    assert (vid, pid) == (DEVICE_VID, DEVICE_PID)


def test_positional_args_count_as_explicit() -> None:
    """Legacy descriptor invocation (positional VID PID) must be honored."""
    argv = ["copykey-cli", "descriptor", "0x1234", "0xABCD"]
    cfg = _cfg("0x0483", "0x5740")
    with patch("hid.enumerate", return_value=[]):
        vid, pid = _parse_vid_pid_args(argv, cfg)
    assert (vid, pid) == (0x1234, 0xABCD)
