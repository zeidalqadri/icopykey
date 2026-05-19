"""Tests for the ``icopyzed sniff`` subcommand.

These tests do NOT touch real USB.  Every external dependency
(``shutil.which``, ``subprocess.run``, ``subprocess.Popen``,
``Path.read_text``, ``sys.platform``) is mocked.  The goal is to
verify the wiring: argparse, platform branching, auto-detection
parsing, subprocess invocation, missing-tool fallbacks.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ..sniff import (
    _autodetect_linux_bus,
    _autodetect_windows_filter,
    _build_parser,
    _find_usbpcap_cmd,
    _parse_linux_devices_file,
    _resolve_out_path,
    _windows_filter_has_copykey,
)


# ── Arg parsing ───────────────────────────────────────────────────


def test_parser_defaults() -> None:
    parser = _build_parser()
    args = parser.parse_args([])
    assert args.out is None
    assert args.bus is None
    assert args.duration is None
    assert args.list is False


def test_parser_accepts_all_flags() -> None:
    parser = _build_parser()
    args = parser.parse_args(
        ["--out", "x.pcapng", "--bus", "3", "--duration", "30", "--list"]
    )
    assert args.out == "x.pcapng"
    assert args.bus == 3
    assert args.duration == 30
    assert args.list is True


# ── Output path resolution ────────────────────────────────────────


def test_resolve_out_path_default_uses_timestamp(tmp_path: Path) -> None:
    with patch("icopykey.cli.sniff.DEFAULT_CAPTURE_DIR", tmp_path):
        out = _resolve_out_path(None)
    assert out.parent == tmp_path
    assert out.name.startswith("sniff_")
    assert out.suffix == ".pcapng"


def test_resolve_out_path_explicit_overrides(tmp_path: Path) -> None:
    target = tmp_path / "abc.pcapng"
    out = _resolve_out_path(str(target))
    # `_resolve_out_path` calls `.resolve()` which canonicalises symlinks
    # (e.g. /tmp → /private/tmp on macOS); compare via resolved paths.
    assert out == target.resolve()


# ── Windows filter parsing ────────────────────────────────────────


def test_windows_filter_has_copykey_typical_output() -> None:
    sample = (
        "1 \\.\\USBPcap1\n"
        "[Device 5]\n"
        "  vendor_id      0x6300\n"
        "  product_id     0x1991\n"
        "  serial         00000000001B\n"
    )
    assert _windows_filter_has_copykey(sample) is True


def test_windows_filter_has_copykey_wrong_device() -> None:
    sample = (
        "1 \\.\\USBPcap1\n"
        "[Device 5]\n"
        "  vendor_id      0x0483\n"
        "  product_id     0x5740\n"
    )
    assert _windows_filter_has_copykey(sample) is False


def test_find_usbpcap_cmd_via_which() -> None:
    with patch(
        "icopykey.cli.sniff.shutil.which",
        side_effect=lambda name: r"C:\Tools\USBPcapCMD.exe"
        if name in ("USBPcapCMD", "USBPcapCMD.exe")
        else None,
    ):
        assert _find_usbpcap_cmd() == r"C:\Tools\USBPcapCMD.exe"


def test_find_usbpcap_cmd_via_install_path(tmp_path: Path) -> None:
    fake_install = tmp_path / "USBPcapCMD.exe"
    fake_install.write_text("stub")
    with patch("icopykey.cli.sniff.shutil.which", return_value=None), patch(
        "icopykey.cli.sniff.USBPCAP_INSTALL_PATHS", (str(fake_install),)
    ):
        assert _find_usbpcap_cmd() == str(fake_install)


def test_find_usbpcap_cmd_none() -> None:
    with patch("icopykey.cli.sniff.shutil.which", return_value=None), patch(
        "icopykey.cli.sniff.USBPCAP_INSTALL_PATHS", ()
    ):
        assert _find_usbpcap_cmd() is None


# ── Auto-detect filter ────────────────────────────────────────────


def test_autodetect_windows_filter_finds_copykey() -> None:
    """Filter 1 has noise; filter 2 has the CopyKEY; returns 2."""
    import subprocess as _sub

    def fake_run(cmd, **_):
        if cmd[-1].endswith("USBPcap1"):
            return _sub.CompletedProcess(
                cmd, 0, stdout="vendor_id 0x1234 product_id 0xABCD\n", stderr=""
            )
        if cmd[-1].endswith("USBPcap2"):
            return _sub.CompletedProcess(
                cmd, 0, stdout="vendor_id 0x6300 product_id 0x1991\n", stderr=""
            )
        return _sub.CompletedProcess(cmd, 1, stdout="", stderr="no filter")

    with patch("icopykey.cli.sniff.subprocess.run", side_effect=fake_run):
        bus = _autodetect_windows_filter(r"C:\Tools\USBPcapCMD.exe")
    assert bus == 2


def test_autodetect_windows_filter_no_match_returns_none() -> None:
    import subprocess as _sub

    with patch(
        "icopykey.cli.sniff.subprocess.run",
        return_value=_sub.CompletedProcess(
            ["x"], 0, stdout="nothing relevant", stderr=""
        ),
    ):
        bus = _autodetect_windows_filter(r"C:\Tools\USBPcapCMD.exe")
    assert bus is None


# ── Linux usbmon parsing ──────────────────────────────────────────


_DEVICES_FIXTURE = """\
T:  Bus=01 Lev=00 Prnt=00 Port=00 Cnt=00 Dev#=  1 Spd=480 MxCh= 6
P:  Vendor=1d6b ProdID=0002 Rev= 1.00
S:  Manufacturer=Linux 6.5
S:  Product=xhci_hcd

T:  Bus=02 Lev=00 Prnt=00 Port=00 Cnt=00 Dev#=  3 Spd=12 MxCh= 0
P:  Vendor=6300 ProdID=1991 Rev= 1.00
S:  Manufacturer=CopyKEY
S:  Product=CopyKEY Smart Card Copy Machine
S:  SerialNumber=00000000001B

T:  Bus=02 Lev=00 Prnt=00 Port=01 Cnt=00 Dev#=  4 Spd=480 MxCh= 0
P:  Vendor=0bda ProdID=8153 Rev= 3.10
S:  Product=USB 10/100/1000 LAN
"""


def test_parse_linux_devices_file() -> None:
    buses = _parse_linux_devices_file(_DEVICES_FIXTURE)
    assert set(buses.keys()) == {1, 2}
    assert len(buses[1]) == 1
    assert buses[1][0][1:3] == (0x1D6B, 0x0002)  # vid, pid
    assert len(buses[2]) == 2
    vids_pids = {(vid, pid) for _, vid, pid, _ in buses[2]}
    assert (0x6300, 0x1991) in vids_pids
    assert (0x0BDA, 0x8153) in vids_pids


def test_autodetect_linux_bus_finds_copykey(tmp_path: Path) -> None:
    fake_devices = tmp_path / "devices"
    fake_devices.write_text(_DEVICES_FIXTURE)
    with patch("icopykey.cli.sniff.Path") as p:
        # Only intercept the specific /sys path the function uses.
        original = Path

        def _path_side_effect(arg):
            if arg == "/sys/kernel/debug/usb/devices":
                return fake_devices
            return original(arg)

        p.side_effect = _path_side_effect
        bus = _autodetect_linux_bus()
    assert bus == 2


def test_autodetect_linux_bus_no_devices_file() -> None:
    with patch("icopykey.cli.sniff.Path") as p:
        fake = MagicMock()
        fake.exists.return_value = False
        p.return_value = fake
        bus = _autodetect_linux_bus()
    assert bus is None
