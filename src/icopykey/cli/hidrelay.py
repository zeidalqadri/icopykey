#!/usr/bin/env python3
"""
HID Relay Server — TCP bridge to a local HID device.

Accepts a single TCP client and relays 64-byte output/input HID reports
to/from a connected USB HID device.  Protocol constants and frame helpers
live in ``_relay_protocol.py`` (stdlib only).

Run directly:   python3 hidrelay.py --port 9999 --vid 0x6300 --pid 0x1991
Or via package: icopyzed relay-server --port 9999 --vid 0x6300 --pid 0x1991
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import sys
import time
from typing import Any

try:
    import hid

    HID_OK = True
except ImportError:
    HID_OK = False

from ._relay_protocol import (
    MSG_ENUMERATE,
    MSG_OPEN,
    MSG_WRITE_READ,
    MSG_GET_DESCRIPTOR,
    MSG_CLOSE,
    MSG_READ_ONLY,
    MSG_GET_INPUT_REPORT,
    MSG_SET_FEATURE_REPORT,
    HID_REPORT_SIZE,
    HEADER_SIZE,
    recv_frame,
    send_frame,
)

logger = logging.getLogger("hidrelay")


# ── HID Device wrapper ────────────────────────────────────────────


class HIDDevice:
    """Thin wrapper around hidapi for the relay server."""

    def __init__(self, vid: int, pid: int) -> None:
        self.vid = vid
        self.pid = pid
        self.device: Any = None
        self.path: bytes | None = None
        self.manufacturer: str = ""
        self.product: str = ""
        self.serial: str = ""

    def _filter_devices(self, devices: list[dict]) -> list[dict]:
        """Filter devices by configured VID/PID locally (macOS hidapi quirk)."""
        return [d for d in devices if d.get("vendor_id") == self.vid and d.get("product_id") == self.pid]

    def open(self, path: bytes | None = None) -> bool:
        """Connect to the first matching HID device (or specific path)."""
        try:
            all_devices = hid.enumerate()
            devices = self._filter_devices(all_devices)
        except Exception as e:
            logger.error("hid.enumerate failed: %s", e)
            return False

        if not devices:
            logger.warning("No HID device at VID=0x%04X PID=0x%04X", self.vid, self.pid)
            return False

        target = None
        if path:
            for d in devices:
                if d.get("path") == path:
                    target = path
                    break
            if target is None:
                logger.warning("Requested path not found in device list")
                return False
        else:
            target = devices[0]["path"]

        try:
            self.device = hid.device()
            self.device.open_path(target)
            self.path = target
            self.manufacturer = self.device.get_manufacturer_string()
            self.product = self.device.get_product_string()
            self.serial = self.device.get_serial_number_string()
        except Exception as e:
            logger.error("Failed to open device at %s: %s", target, e)
            self.device = None
            return False

        logger.info(
            "Opened: %s %s (SN: %s) at %s",
            self.manufacturer,
            self.product,
            self.serial,
            target,
        )
        return True

    def close(self) -> None:
        """Close the HID device."""
        if self.device:
            try:
                self.device.close()
            except Exception:
                pass
            self.device = None
            self.path = None
            logger.info("Device closed")

    @property
    def is_open(self) -> bool:
        return self.device is not None

    def write_read(self, data: bytes, timeout_ms: int) -> bytes | None:
        """Write 64 bytes, read 64 bytes.  Returns response or None."""
        if not self.device:
            return None

        buf = bytearray(data)
        if len(buf) < HID_REPORT_SIZE:
            buf.extend(b"\x00" * (HID_REPORT_SIZE - len(buf)))
        buf = buf[:HID_REPORT_SIZE]

        try:
            self.device.write(bytes(buf))
        except Exception as e:
            logger.error("HID write error: %s", e)
            return None

        time.sleep(0.05)  # small gap for device processing

        try:
            self.device.set_nonblocking(True)
            response = self.device.read(HID_REPORT_SIZE, timeout_ms)
            if response:
                return bytes(response)
            return b""
        except Exception as e:
            logger.debug("HID read: %s", e)
            return None

    def get_descriptor(self) -> bytes | None:
        """Return raw HID report descriptor bytes."""
        if not self.device:
            return None
        try:
            desc = self.device.get_report_descriptor()
            return bytes(desc) if desc else None
        except Exception as e:
            logger.error("get_report_descriptor failed: %s", e)
            return None

    def enumerate_all(self) -> list[dict[str, Any]]:
        """Return all devices matching configured VID/PID."""
        try:
            return self._filter_devices(hid.enumerate())
        except Exception as e:
            logger.error("enumerate error: %s", e)
            return []


# ── Session handler ───────────────────────────────────────────────


def _handle_session(sock: socket.socket, vid: int, pid: int) -> None:
    """Serve a single client connection."""
    dev = HIDDevice(vid, pid)
    sock.settimeout(30.0)

    logger.info("Client connected")

    while True:
        frame = recv_frame(sock, timeout=60.0)
        if frame is None:
            logger.info("Client disconnected (EOF or timeout)")
            break

        msg_type, payload = frame

        if msg_type == MSG_ENUMERATE:
            devices = dev.enumerate_all()
            json_data = json.dumps(devices, default=str).encode("utf-8")
            send_frame(sock, MSG_ENUMERATE, json_data)

        elif msg_type == MSG_OPEN:
            path = payload if payload else None
            ok = dev.open(path)
            if ok:
                info = json.dumps(
                    {
                        "manufacturer": dev.manufacturer,
                        "product": dev.product,
                        "serial": dev.serial,
                        "path": dev.path.decode() if dev.path else "",
                        "vid": dev.vid,
                        "pid": dev.pid,
                    }
                ).encode("utf-8")
                send_frame(sock, MSG_OPEN, b"\x01" + info)
            else:
                send_frame(sock, MSG_OPEN, b"\x00" + b"{}")

        elif msg_type == MSG_WRITE_READ:
            if not dev.is_open:
                send_frame(sock, MSG_WRITE_READ, b"\x00" + b"\x00" * HID_REPORT_SIZE)
                continue

            if len(payload) < 4:
                send_frame(sock, MSG_WRITE_READ, b"\x00" + b"\x00" * HID_REPORT_SIZE)
                continue

            timeout_ms = struct.unpack(">I", payload[:4])[0]
            data = payload[4:68] if len(payload) >= 68 else payload[4:]

            result = dev.write_read(data, timeout_ms)
            if result is not None:
                send_frame(sock, MSG_WRITE_READ, b"\x01" + result)
            else:
                send_frame(sock, MSG_WRITE_READ, b"\x00" + b"\x00" * HID_REPORT_SIZE)

        elif msg_type == MSG_GET_DESCRIPTOR:
            if not dev.is_open:
                send_frame(sock, MSG_GET_DESCRIPTOR, b"")
                continue
            desc = dev.get_descriptor()
            if desc is not None:
                send_frame(sock, MSG_GET_DESCRIPTOR, desc)
            else:
                send_frame(sock, MSG_GET_DESCRIPTOR, b"")

        elif msg_type == MSG_CLOSE:
            dev.close()
            send_frame(sock, MSG_CLOSE, b"\x01")

        elif msg_type == MSG_READ_ONLY:
            if not dev.is_open:
                send_frame(sock, MSG_READ_ONLY, b"\x00" + b"\x00" * 64)
                continue
            timeout_ms = 500
            if len(payload) >= 4:
                timeout_ms = struct.unpack(">I", payload[:4])[0]
            try:
                dev.device.set_nonblocking(True)
                result = dev.device.read(HID_REPORT_SIZE, timeout_ms)
                if result:
                    send_frame(sock, MSG_READ_ONLY, b"\x01" + bytes(result))
                else:
                    send_frame(sock, MSG_READ_ONLY, b"\x00" + b"\x00" * 64)
            except Exception as e:
                logger.debug("Passive read: %s", e)
                send_frame(sock, MSG_READ_ONLY, b"\x00" + b"\x00" * 64)

        elif msg_type == MSG_GET_INPUT_REPORT:
            if not dev.is_open:
                send_frame(sock, MSG_GET_INPUT_REPORT, b"\x00" + b"\x00" * 64)
                continue
            try:
                report_id = 0
                buf = dev.device.get_input_report(report_id, HID_REPORT_SIZE)
                if buf and any(b != 0 for b in buf):
                    send_frame(sock, MSG_GET_INPUT_REPORT, b"\x01" + bytes(buf))
                else:
                    send_frame(sock, MSG_GET_INPUT_REPORT, b"\x00" + b"\x00" * 64)
            except Exception as e:
                logger.debug("get_input_report: %s", e)
                send_frame(sock, MSG_GET_INPUT_REPORT, b"\x00" + b"\x00" * 64)

        elif msg_type == MSG_SET_FEATURE_REPORT:
            if not dev.is_open:
                send_frame(sock, MSG_SET_FEATURE_REPORT, b"\x00")
                continue
            try:
                data = payload[:HID_REPORT_SIZE] if len(payload) >= HID_REPORT_SIZE else payload
                dev.device.send_feature_report(data)
                send_frame(sock, MSG_SET_FEATURE_REPORT, b"\x01")
            except Exception as e:
                logger.debug("send_feature_report: %s", e)
                send_frame(sock, MSG_SET_FEATURE_REPORT, b"\x00")

        else:
            logger.warning("Unknown message type: 0x%02X", msg_type)

    dev.close()


# ── Server ────────────────────────────────────────────────────────


def run_server(host: str, port: int, vid: int, pid: int) -> int:
    """Listen for clients and serve one at a time.  Runs until Ctrl-C."""
    if not HID_OK:
        print(
            "Error: hidapi not installed.  Install with: pip install hidapi",
            file=sys.stderr,
        )
        return 1

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((host, port))
        server.listen(1)
    except OSError as e:
        print(f"Error: Cannot bind to {host}:{port} — {e}", file=sys.stderr)
        return 1

    print(f"HID Relay Server listening on {host}:{port}")
    print(f"  VID: 0x{vid:04X}  PID: 0x{pid:04X}")
    print("  Waiting for client connection...")
    print("  Press Ctrl-C to stop.")

    try:
        while True:
            conn, addr = server.accept()
            logger.info("Connection from %s:%d", addr[0], addr[1])
            try:
                _handle_session(conn, vid, pid)
            except Exception as e:
                logger.exception("Session error: %s", e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            print("  Ready for next client...")
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.close()

    return 0


# ── CLI ───────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="icopyzed relay-server",
        description="HID Relay Server — TCP bridge to a local USB HID device (e.g. X100)",
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=9999, help="TCP port (default: 9999)"
    )
    parser.add_argument(
        "--vid", metavar="HEX", default="0x6300", help="USB Vendor ID (default: 0x6300)"
    )
    parser.add_argument(
        "--pid", metavar="HEX", default="0x1991", help="USB Product ID (default: 0x1991)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    vid = int(args.vid, 16) if args.vid.startswith("0x") else int(args.vid, 16)
    pid = int(args.pid, 16) if args.pid.startswith("0x") else int(args.pid, 16)

    return run_server(args.host, args.port, vid, pid)


if __name__ == "__main__":
    raise SystemExit(main())
