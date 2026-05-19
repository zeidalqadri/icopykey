"""Tests for the ``recorder`` hook on CopyKeyDevice / CopyKeyRemoteDevice.

When a writer is attached, every ``write_read`` exchange must produce
one OUT frame followed by one IN frame in the writer.  The hook must
not break the I/O path even if the writer raises.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ..device import CopyKeyDevice
from ..pcap_writer import PcapNgWriter
from ..analyze_capture import parse_pcapng


def _fake_hid(in_response: bytes = b"\x95" + b"\x55" * 63) -> MagicMock:
    """Build a MagicMock hidapi device that echoes a canned IN frame."""
    fake = MagicMock()
    fake.write = MagicMock(return_value=64)
    fake.read = MagicMock(return_value=list(in_response))
    fake.set_nonblocking = MagicMock(return_value=None)
    fake.close = MagicMock(return_value=None)
    return fake


def test_recorder_captures_one_pair(tmp_path: Path) -> None:
    """A single write_read writes one OUT + one IN to the recorder."""
    path = tmp_path / "one_pair.pcapng"
    dev = CopyKeyDevice()
    dev.device = _fake_hid()  # bypass connect()
    dev.recorder = PcapNgWriter(path)

    out_frame = b"\x95\x0D" + b"\x00" * 62
    resp = dev.write_read(out_frame, timeout_ms=10)
    assert resp is not None and len(resp) == 64

    dev.disconnect()  # closes the recorder

    parsed = parse_pcapng(str(path))
    assert len(parsed) == 2
    assert parsed[0][0] == "OUT"
    assert parsed[0][1] == out_frame
    assert parsed[1][0] == "IN"
    assert parsed[1][1][:2] == b"\x95\x55"


def test_recorder_off_means_no_file(tmp_path: Path) -> None:
    """When recorder is None, no file is created and I/O still works."""
    dev = CopyKeyDevice()
    dev.device = _fake_hid()
    assert dev.recorder is None

    out_frame = b"\x95\x0D" + b"\x00" * 62
    resp = dev.write_read(out_frame, timeout_ms=10)
    assert resp is not None

    # No file should have been touched
    assert list(tmp_path.iterdir()) == []


def test_recorder_pads_short_payload(tmp_path: Path) -> None:
    """The hook pads sub-64-byte payloads up to 64 before logging."""
    path = tmp_path / "short.pcapng"
    dev = CopyKeyDevice()
    dev.device = _fake_hid()
    dev.recorder = PcapNgWriter(path)

    short = b"\x95\x0D\x44\x52"  # 4 bytes; should be padded to 64
    resp = dev.write_read(short, timeout_ms=10)
    assert resp is not None

    dev.disconnect()

    parsed = parse_pcapng(str(path))
    assert len(parsed) == 2
    # OUT frame is padded but still starts with the bytes we sent
    assert parsed[0][1][:4] == short
    assert all(b == 0 for b in parsed[0][1][4:])


def test_recorder_exception_does_not_break_io(tmp_path: Path) -> None:
    """If the writer raises, the I/O still returns the response."""

    class ExplodingWriter:
        def write_frame(self, direction: str, payload: bytes) -> None:
            raise RuntimeError("boom")

        def close(self) -> None:
            pass

    dev = CopyKeyDevice()
    dev.device = _fake_hid()
    dev.recorder = ExplodingWriter()

    resp = dev.write_read(b"\x95" + b"\x00" * 63, timeout_ms=10)
    assert resp is not None and len(resp) == 64


def test_disconnect_closes_recorder(tmp_path: Path) -> None:
    """disconnect() must close the recorder once and then clear it."""
    path = tmp_path / "close.pcapng"
    dev = CopyKeyDevice()
    dev.device = _fake_hid()
    dev.recorder = PcapNgWriter(path)

    dev.write_read(b"\x95\x0D" + b"\x00" * 62, timeout_ms=10)
    assert dev.recorder is not None
    dev.disconnect()
    assert dev.recorder is None
    # Calling disconnect again is a no-op (and must not raise).
    dev.disconnect()
