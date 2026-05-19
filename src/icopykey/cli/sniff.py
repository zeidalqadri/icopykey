"""``icopyzed sniff`` — built-in USB capture for CopyKEY HID traffic.

Wraps the OS-native USB sniffer (``USBPcapCMD.exe`` on Windows,
``tcpdump -i usbmonN`` on Linux) so that anyone can capture the
official CopyKEY Manager app's traffic — or any other host-side app
talking to the device — without separately installing Wireshark and
hunting for the right root-hub filter.

Both Linux usbmon and Windows USBPcap capture per-USB-bus (not per-
device); the output ``.pcapng`` therefore contains traffic from every
device on the bus.  The existing parser in
:func:`icopykey.cli.analyze_capture.parse_pcapng` only surfaces HID
frames whose first byte equals ``0x95`` (the CopyKEY report prefix),
so noise from other devices on the same bus is filtered at analysis
time.

The implementation is a thin process supervisor: it shells out to the
native tool, streams its stdout/stderr through the user's terminal,
and forwards Ctrl-C so the capture stops cleanly.  We never parse raw
USB packets in Python; everything that hits disk is produced by the
upstream tool's own pcapng writer.

Platform support
----------------

* **Windows**: requires `USBPcap`_.  Auto-locates ``USBPcapCMD.exe``
  via ``shutil.which`` and the standard install location.
* **Linux**: requires ``tcpdump`` and the ``usbmon`` kernel module
  (``sudo modprobe usbmon``).  Capture itself typically needs ``sudo``.
* **macOS**: not supported — Apple does not ship an equivalent of
  Linux's ``usbmon``, and the userspace-accessible IOKit USB hooks do
  not expose host-to-device packet traces.  ``icopyzed sniff --list``
  still works on macOS and reports the limitation.

.. _USBPcap: https://desowin.org/usbpcap/
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from .constants import DEVICE_PID, DEVICE_VID


DEFAULT_CAPTURE_DIR = Path.home() / ".copykey_cli" / "captures"
USBPCAP_INSTALL_PATHS = (
    r"C:\Program Files\USBPcap\USBPcapCMD.exe",
    r"C:\Program Files (x86)\USBPcap\USBPcapCMD.exe",
)


# ── Public entry point ─────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list:
        return _list_buses()

    out_path = _resolve_out_path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform == "win32":
        return _sniff_windows(out_path, args.bus, args.duration)
    if sys.platform.startswith("linux"):
        return _sniff_linux(out_path, args.bus, args.duration)
    _print_unsupported_platform()
    return 2


# ── Argparse ──────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="icopyzed sniff",
        description=(
            "Capture USB HID traffic between any host application and the "
            "CopyKEY device. Output is a pcapng file readable by "
            "`icopyzed convert` / `analyze_capture.py`."
        ),
    )
    p.add_argument(
        "--out",
        metavar="FILE",
        help="Output .pcapng path (default: ~/.copykey_cli/captures/sniff_<ts>.pcapng)",
    )
    p.add_argument(
        "--bus",
        metavar="N",
        type=int,
        help="USB bus to capture (Windows: USBPcap filter index; Linux: usbmonN). Auto-detected if omitted.",
    )
    p.add_argument(
        "--duration",
        metavar="SECONDS",
        type=int,
        help="Stop after N seconds (default: run until Ctrl-C)",
    )
    p.add_argument(
        "--list",
        action="store_true",
        help="Enumerate available USB buses and exit (does not capture).",
    )
    return p


def _resolve_out_path(out: str | None) -> Path:
    if out:
        return Path(out).expanduser().resolve()
    ts = time.strftime("%Y%m%d-%H%M%S")
    return DEFAULT_CAPTURE_DIR / f"sniff_{ts}.pcapng"


# ── --list ────────────────────────────────────────────────────────


def _list_buses() -> int:
    """Enumerate available buses and report which one the CopyKEY is on."""
    if sys.platform == "win32":
        return _list_windows_filters()
    if sys.platform.startswith("linux"):
        return _list_linux_busses()
    _print_unsupported_platform()
    return 0


def _list_windows_filters() -> int:
    cmd_path = _find_usbpcap_cmd()
    if cmd_path is None:
        print(
            "USBPcap is not installed.  Download from https://desowin.org/usbpcap/",
            file=sys.stderr,
        )
        return 1
    # USBPcap exposes filters as \\.\USBPcap1..N.  Probe up to 8.
    found_any = False
    for n in range(1, 9):
        filt = rf"\\.\USBPcap{n}"
        try:
            result = subprocess.run(
                [cmd_path, "--devices", "-d", filt],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        if result.returncode != 0 and not result.stdout:
            continue
        found_any = True
        copykey_marker = _windows_filter_has_copykey(result.stdout)
        marker = "  ← CopyKEY here" if copykey_marker else ""
        print(f"USBPcap{n}{marker}")
        for line in result.stdout.splitlines():
            print(f"  {line}")
    if not found_any:
        print("No USBPcap filters available. Is the driver installed and active?")
        return 1
    return 0


def _list_linux_busses() -> int:
    devices_file = Path("/sys/kernel/debug/usb/devices")
    if not devices_file.exists():
        print(
            "Cannot read /sys/kernel/debug/usb/devices.\n"
            "Load the usbmon module:  sudo modprobe usbmon",
            file=sys.stderr,
        )
        return 1
    buses = _parse_linux_devices_file(devices_file.read_text())
    if not buses:
        print("No USB devices visible — is usbmon loaded?", file=sys.stderr)
        return 1
    for bus, entries in sorted(buses.items()):
        any_copykey = any(_is_copykey(vid, pid) for _, vid, pid, _ in entries)
        marker = "  ← CopyKEY here" if any_copykey else ""
        print(f"usbmon{bus}{marker}")
        for path, vid, pid, name in entries:
            print(f"  {vid:04x}:{pid:04x}  {name}  ({path})")
    return 0


# ── Sniffer implementations ────────────────────────────────────────


def _sniff_windows(out_path: Path, bus: int | None, duration: int | None) -> int:
    cmd_path = _find_usbpcap_cmd()
    if cmd_path is None:
        print(
            "USBPcap is not installed.  Download from https://desowin.org/usbpcap/\n"
            "Then re-run `icopyzed sniff`.",
            file=sys.stderr,
        )
        return 1

    if bus is None:
        bus = _autodetect_windows_filter(cmd_path)
        if bus is None:
            print(
                "Could not auto-detect the USBPcap filter for the CopyKEY device.\n"
                "Run `icopyzed sniff --list` to see filters; pass --bus N to override.",
                file=sys.stderr,
            )
            return 1
        print(f"[sniff] auto-detected CopyKEY on USBPcap{bus}", file=sys.stderr)

    filt = rf"\\.\USBPcap{bus}"
    argv = [cmd_path, "-d", filt, "-o", str(out_path)]
    print(f"[sniff] capturing to {out_path}", file=sys.stderr)
    print(f"[sniff] command: {' '.join(argv)}", file=sys.stderr)
    print("[sniff] press Ctrl-C to stop.", file=sys.stderr)
    return _run_capture(argv, duration)


def _sniff_linux(out_path: Path, bus: int | None, duration: int | None) -> int:
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        print(
            "tcpdump is not installed.  apt: `sudo apt install tcpdump`",
            file=sys.stderr,
        )
        return 1

    if bus is None:
        bus = _autodetect_linux_bus()
        if bus is None:
            print(
                "Could not auto-detect the usbmon bus for the CopyKEY device.\n"
                "Run `icopyzed sniff --list` to see buses; pass --bus N to override.",
                file=sys.stderr,
            )
            return 1
        print(f"[sniff] auto-detected CopyKEY on usbmon{bus}", file=sys.stderr)

    argv = [tcpdump, "-i", f"usbmon{bus}", "-s", "0", "-w", str(out_path)]
    # tcpdump on usbmon usually needs root; nudge the user.
    if os.geteuid() != 0:
        argv = ["sudo"] + argv
        print(
            "[sniff] tcpdump on usbmon usually needs root — prepending sudo.",
            file=sys.stderr,
        )
    print(f"[sniff] capturing to {out_path}", file=sys.stderr)
    print(f"[sniff] command: {' '.join(argv)}", file=sys.stderr)
    print("[sniff] press Ctrl-C to stop.", file=sys.stderr)
    return _run_capture(argv, duration)


def _run_capture(argv: list[str], duration: int | None) -> int:
    """Run the upstream sniffer as a subprocess, forward Ctrl-C cleanly."""
    try:
        proc = subprocess.Popen(argv)
    except (OSError, FileNotFoundError) as exc:
        print(f"[sniff] failed to start: {exc}", file=sys.stderr)
        return 1

    def _stop(_signum, _frame):
        proc.send_signal(signal.SIGINT)

    signal.signal(signal.SIGINT, _stop)
    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    finally:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    rc = proc.returncode if proc.returncode is not None else 0
    print(f"[sniff] capture exited with rc={rc}", file=sys.stderr)
    return 0 if rc in (0, None, -2) else rc


# ── Helpers ────────────────────────────────────────────────────────


def _print_unsupported_platform() -> None:
    print(
        f"`icopyzed sniff` is not supported on {sys.platform}.\n"
        "Use `--record FILE` to log icopyzed's own device I/O, or run on "
        "Windows/Linux for full bus capture.",
        file=sys.stderr,
    )


def _find_usbpcap_cmd() -> str | None:
    which = shutil.which("USBPcapCMD") or shutil.which("USBPcapCMD.exe")
    if which:
        return which
    for candidate in USBPCAP_INSTALL_PATHS:
        if Path(candidate).exists():
            return candidate
    return None


def _autodetect_windows_filter(cmd_path: str) -> int | None:
    for n in range(1, 9):
        filt = rf"\\.\USBPcap{n}"
        try:
            result = subprocess.run(
                [cmd_path, "--devices", "-d", filt],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        if _windows_filter_has_copykey(result.stdout):
            return n
    return None


def _windows_filter_has_copykey(usbpcap_devices_output: str) -> bool:
    """Look for the CopyKEY VID/PID in USBPcap --devices output.

    USBPcap prints device lines like:
       Bus 1, Address 5, Class HID, Sub-class 00, Protocol 00, VID 0x6300, PID 0x1991
    """
    return _output_has_vid_pid(usbpcap_devices_output, DEVICE_VID, DEVICE_PID)


def _output_has_vid_pid(text: str, vid: int, pid: int) -> bool:
    vid_hex = f"{vid:04x}"
    pid_hex = f"{pid:04x}"
    pattern = re.compile(
        rf"\b(?:VID|Vendor|vendor_id|vid)[^0-9a-fA-F]*0?x?{vid_hex}\b.*"
        rf"\b(?:PID|ProdID|Product|product_id|pid)[^0-9a-fA-F]*0?x?{pid_hex}\b",
        re.IGNORECASE | re.DOTALL,
    )
    if pattern.search(text):
        return True
    # Fallback: a line that has BOTH the vid hex and the pid hex.
    for line in text.splitlines():
        ll = line.lower()
        if vid_hex in ll and pid_hex in ll:
            return True
    return False


def _autodetect_linux_bus() -> int | None:
    path = Path("/sys/kernel/debug/usb/devices")
    if not path.exists():
        return None
    buses = _parse_linux_devices_file(path.read_text())
    for bus, entries in buses.items():
        for _path, vid, pid, _name in entries:
            if _is_copykey(vid, pid):
                return bus
    return None


def _is_copykey(vid: int, pid: int) -> bool:
    return vid == DEVICE_VID and pid == DEVICE_PID


# /sys/kernel/debug/usb/devices format reference:
# T:  Bus=01 Lev=00 Prnt=00 Port=00 Cnt=00 Dev#=  1 Spd=480 MxCh= 6
# P:  Vendor=6300 ProdID=1991 Rev= 1.00
# S:  Manufacturer=CopyKEY
# S:  Product=CopyKEY Smart Card Copy Machine
# S:  SerialNumber=00000000001B
_T_LINE_RE = re.compile(r"^T:\s+Bus=(\d+)")
_P_LINE_RE = re.compile(r"^P:\s+Vendor=([0-9a-fA-F]{4})\s+ProdID=([0-9a-fA-F]{4})")
_PRODUCT_RE = re.compile(r"^S:\s+Product=(.+)$")


def _parse_linux_devices_file(text: str) -> dict[int, list[tuple[str, int, int, str]]]:
    """Parse /sys/kernel/debug/usb/devices into {bus: [(path, vid, pid, name), ...]}."""
    buses: dict[int, list[tuple[str, int, int, str]]] = {}
    current_bus: int | None = None
    current_vid: int | None = None
    current_pid: int | None = None
    current_name: str = "?"
    current_path: str = ""

    def _flush() -> None:
        if current_bus is not None and current_vid is not None and current_pid is not None:
            buses.setdefault(current_bus, []).append(
                (current_path, current_vid, current_pid, current_name)
            )

    for line in text.splitlines():
        if line.startswith("T:"):
            _flush()
            m = _T_LINE_RE.match(line)
            current_bus = int(m.group(1)) if m else None
            current_vid = current_pid = None
            current_name = "?"
            current_path = line.strip()
        elif line.startswith("P:"):
            m = _P_LINE_RE.match(line)
            if m:
                current_vid = int(m.group(1), 16)
                current_pid = int(m.group(2), 16)
        elif line.startswith("S:"):
            m = _PRODUCT_RE.match(line)
            if m:
                current_name = m.group(1).strip()
    _flush()
    return buses


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
