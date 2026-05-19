"""Round-trip tests: write a pcapng, then read it back via the existing
``analyze_capture.parse_pcapng`` parser and assert equality.

If these tests fail, the writer's byte layout has drifted from what the
reader expects — fix the writer (or the reader, if intentional), not the
test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ..analyze_capture import parse_pcapng
from ..pcap_writer import PcapNgWriter


# Real-protocol frame: starts with REPORT_PREFIX (0x95). The reader filters
# anything that doesn't, so test frames must use this prefix.
def _frame(cmd: int, fill: int = 0x00) -> bytes:
    buf = bytearray(64)
    buf[0] = 0x95
    buf[1] = cmd  # not strictly the protocol layout, just a sentinel
    for i in range(2, 64):
        buf[i] = fill
    return bytes(buf)


def test_round_trip_single_pair(tmp_path: Path) -> None:
    """Write one OUT + one IN, read them back, assert equality."""
    out_frame = _frame(0x0D, 0xAA)
    in_frame = _frame(0xC9, 0xBB)
    path = tmp_path / "single.pcapng"

    with PcapNgWriter(path) as w:
        w.write_frame("OUT", out_frame)
        w.write_frame("IN", in_frame)

    parsed = parse_pcapng(str(path))
    assert parsed == [("OUT", out_frame), ("IN", in_frame)]


def test_round_trip_many_frames(tmp_path: Path) -> None:
    """Write 20 alternating frames; reader must return them in order."""
    expected: list[tuple[str, bytes]] = []
    path = tmp_path / "many.pcapng"

    with PcapNgWriter(path) as w:
        for i in range(20):
            direction = "OUT" if i % 2 == 0 else "IN"
            frame = _frame(i, 0xCC if direction == "IN" else 0xDD)
            w.write_frame(direction, frame)
            expected.append((direction, frame))

    parsed = parse_pcapng(str(path))
    assert parsed == expected


def test_filter_drops_non_95_prefix(tmp_path: Path) -> None:
    """Frames not starting with 0x95 must be filtered out by the reader."""
    bad = bytes([0x00] * 64)
    good = _frame(0x0D)
    path = tmp_path / "mixed.pcapng"

    with PcapNgWriter(path) as w:
        w.write_frame("OUT", bad)
        w.write_frame("OUT", good)
        w.write_frame("IN", bad)
        w.write_frame("IN", good)

    parsed = parse_pcapng(str(path))
    assert parsed == [("OUT", good), ("IN", good)]


def test_rejects_wrong_payload_size(tmp_path: Path) -> None:
    """Anything other than exactly 64 bytes must raise."""
    with PcapNgWriter(tmp_path / "x.pcapng") as w:
        with pytest.raises(ValueError):
            w.write_frame("OUT", b"\x95" * 63)
        with pytest.raises(ValueError):
            w.write_frame("OUT", b"\x95" * 65)


def test_rejects_bad_direction(tmp_path: Path) -> None:
    """Direction must be 'IN' or 'OUT'."""
    frame = _frame(0x0D)
    with PcapNgWriter(tmp_path / "x.pcapng") as w:
        with pytest.raises(ValueError):
            w.write_frame("BOTH", frame)


def test_write_after_close_raises(tmp_path: Path) -> None:
    w = PcapNgWriter(tmp_path / "x.pcapng")
    w.write_frame("OUT", _frame(0x0D))
    w.close()
    with pytest.raises(ValueError, match="closed"):
        w.write_frame("OUT", _frame(0x0D))


def test_context_manager_closes(tmp_path: Path) -> None:
    """Exiting the `with` block must close the file and flush all writes."""
    path = tmp_path / "ctx.pcapng"
    with PcapNgWriter(path) as w:
        w.write_frame("OUT", _frame(0x0D))
        assert w.frames_written == 1
    # File must be readable and contain the frame.
    parsed = parse_pcapng(str(path))
    assert len(parsed) == 1


def test_creates_parent_dir(tmp_path: Path) -> None:
    """If the output path's parent directory doesn't exist, create it."""
    nested = tmp_path / "a" / "b" / "c" / "out.pcapng"
    assert not nested.parent.exists()
    with PcapNgWriter(nested) as w:
        w.write_frame("OUT", _frame(0x0D))
    assert nested.exists()
    parsed = parse_pcapng(str(nested))
    assert len(parsed) == 1
