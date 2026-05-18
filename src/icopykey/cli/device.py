"""HID device communication — direct USB and TCP relay client.

Uses the real CopyKEY X100 HID report protocol (reverse-engineered from
USBPcap capture).  Each 64-byte HID report is::

    0x95 | 21B_payload | 21B_payload_rotL1 | 21B_payload_rotL2
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import time
from typing import Any

try:
    import hid

    HID_AVAILABLE = True
except ImportError:
    HID_AVAILABLE = False

from ._relay_protocol import (
    MSG_ENUMERATE,
    MSG_OPEN,
    MSG_WRITE_READ,
    MSG_GET_DESCRIPTOR,
    MSG_CLOSE,
    MSG_READ_ONLY,
    MSG_GET_INPUT_REPORT,
    MSG_SET_FEATURE_REPORT,
    recv_frame,
    send_frame,
)
from ._protocol import (
    REPORT_SIZE,
    PAYLOAD_SIZE,
    CMD_PROBE,
    CMD_SECTOR_OP,
    CMD_DATA_RESPONSE,
    CMD_IDLE,
    CMD_BULK_DATA,
    CMD_BULK_SESSION,
    CMD_WRITE,
    CMD_WRITE_ACK,
    build_frame,
    parse_report,
    build_idle_frame,
    build_sector_read_frame,
    build_probe_frame,
    build_bulk_read_frame,
    build_session_init_frame,
    derive_session_key,
    classify_payload,
    TEMPLATES,
    RESPONSES,
    F8_TEMPLATES,
)
from .constants import (
    DEVICE_VID,
    DEVICE_PID,
    DEVICE_USAGE_PAGE,
    REPORT_SIZE_IN,
    REPORT_SIZE_OUT,
)
from .errors import (
    DeviceNotFoundError,
    DeviceDisconnectedError,
)
from .mifare_data import MifareSector

logger = logging.getLogger("copykey_cli.device")


class CopyKeyDevice:
    """USB HID communication layer for CopyKEY-compatible devices.

    Based on real HID report descriptor (dumped from X100 at 0x6300:0x1991):
      - NO REPORT_ID (report uses ID 0 — raw output/input reports)
      - NO FEATURE reports
      - INPUT:  64 bytes (Usage 1-8, count 64, size 8 = 8 channels x 8 bytes)
      - OUTPUT: 64 bytes (Usage 1-8, count 64, size 8)
    Transport: device.write(64 bytes) → device.read(64 bytes)
    """

    MAX_SECTOR_1K = 15
    MAX_SECTOR_4K = 39

    def __init__(self, vid: int = DEVICE_VID, pid: int = DEVICE_PID) -> None:
        self.vid = vid
        self.pid = pid
        self.device: Any = None
        self.device_path: bytes | None = None
        self.manufacturer: str | None = None
        self.product: str | None = None
        self.serial: str | None = None
        self._session_key: bytes | None = None

    def enumerate_devices(self) -> list[dict[str, Any]]:
        try:
            devices = hid.enumerate(self.vid, self.pid)
            logger.info("Found %d compatible device(s)", len(devices))
            return devices
        except Exception as e:
            logger.error("Error enumerating devices: %s", e)
            return []

    def connect(self, path: bytes | None = None) -> bool:
        logger.info(
            "Searching for CopyKEY device (VID:%04X PID:%04X) ...", self.vid, self.pid
        )
        try:
            devices = hid.enumerate(self.vid, self.pid)
            if not devices:
                logger.warning("No device found.")
                return False
            if path:
                self.device_path = path
            else:
                self.device_path = devices[0]["path"]
            self.device = hid.device()
            self.device.open_path(self.device_path)
            try:
                self.manufacturer = self.device.get_manufacturer_string()
                self.product = self.device.get_product_string()
                self.serial = self.device.get_serial_number_string()
            except Exception:
                logger.warning("Could not get device info")
            logger.info(
                "[+] Connected: %s %s (SN: %s)",
                self.manufacturer,
                self.product,
                self.serial,
            )
            return True
        except Exception as e:
            logger.error("[-] Failed to open device: %s", e)
            return False

    def disconnect(self) -> None:
        if self.device:
            try:
                self.device.close()
            except Exception:
                pass
            finally:
                self.device = None
                self.device_path = None
            logger.info("[*] Device closed.")

    def is_connected(self) -> bool:
        return self.device is not None

    def write_output_report(self, data: bytes | bytearray) -> bool:
        """Write a 64-byte output report to the device."""
        if not self.device:
            logger.error("Device not connected")
            return False
        buf = bytearray(data)
        if len(buf) < 64:
            buf.extend(b"\x00" * (64 - len(buf)))
        buf = buf[:64]
        try:
            self.device.write(bytes(buf))
            logger.debug("Wrote 64-byte output report: %s", buf[:16].hex())
            return True
        except Exception as e:
            logger.error("Write output report failed: %s", e)
            return False

    def read_input_report(self, timeout_ms: int = 5000) -> bytes | None:
        """Read a 64-byte input report from the device."""
        if not self.device:
            return None
        try:
            self.device.set_nonblocking(True)
            data = self.device.read(64, timeout_ms)
            if data:
                buf = bytes(data)
                logger.debug("Got %d-byte input report", len(buf))
                return buf
            return None
        except Exception as e:
            logger.debug("Input report read: %s", e)
            return None

    def read_only(self, timeout_ms: int = 2000) -> bytes | None:
        """Passive read — listen without sending a command."""
        if not self.device:
            return None
        try:
            self.device.set_nonblocking(True)
            data = self.device.read(64, timeout_ms)
            if data:
                return bytes(data)
            return b""
        except Exception:
            return None

    def get_input_report(self) -> bytes | None:
        """GET_REPORT control transfer — request input report via USB control pipe."""
        if not self.device:
            return None
        try:
            buf = self.device.get_input_report(0, 64)
            return bytes(buf) if buf else None
        except Exception as e:
            logger.debug("get_input_report: %s", e)
            return None

    def send_feature_report(self, data: bytes) -> bool:
        """SET_REPORT feature — send feature report via USB control pipe."""
        if not self.device:
            return False
        try:
            self.device.send_feature_report(data)
            return True
        except Exception as e:
            logger.debug("send_feature_report: %s", e)
            return False

    def write_read(self, data: bytes, timeout_ms: int = 5000) -> bytes | None:
        """Write 64-byte output report, read 64-byte input report response."""
        if not self.device:
            raise ConnectionError("Device not connected")
        if not self.write_output_report(data):
            return None
        time.sleep(0.05)
        return self.read_input_report(timeout_ms)

    def send_command(self, cmd: bytes, timeout_ms: int = 5000) -> bytes | None:
        """Legacy send using write/read transport (no feature reports)."""
        return self.write_read(cmd, timeout_ms)

    def get_device_info(self) -> dict[str, str] | None:
        """Return cached device metadata from USB descriptors."""
        return {
            "manufacturer": self.manufacturer or "",
            "product": self.product or "",
            "serial": self.serial or "",
            "path": self.device_path.decode() if self.device_path else "",
        }

    def read_card_info(self) -> dict[str, Any] | None:
        """Read card UID, SAK, ATQA using the real probe protocol (CMD 0x0D).

        Sends a card probe frame and parses the probe acknowledgment.
        Response parsing is speculative until validated against a device.
        """
        if not self.is_connected():
            logger.error("Device not connected")
            return None

        frame = build_probe_frame()
        resp = self.send_command(frame)
        if not resp or len(resp) < REPORT_SIZE:
            return None

        try:
            payload = parse_report(resp)
        except ValueError as e:
            logger.error("Invalid probe response: %s", e)
            return None

        resp_type = classify_payload(payload)
        if resp_type != "probe_ack":
            logger.error("Unexpected probe response type: %s", resp_type)
            return None

        try:
            uid_bytes = payload[5:12]
            sak = payload[12]
            atqa = payload[13:15]
            # NTAG / Ultralight cards often have SAK=0x00, 7-byte UID
            if sak == 0x00 and len(uid_bytes) == 7:
                card_type = "NTAG/Ultralight EV1"
            elif sak == 0x18:
                card_type = "MIFARE Classic 4K"
            elif sak == 0x08:
                card_type = "MIFARE Classic 1K"
            elif sak in (0x03, 0x04):
                card_type = "DESFire"
            else:
                card_type = "Unknown"
            return {"uid": uid_bytes, "sak": sak, "atqa": atqa.hex(), "card_type": card_type}
        except Exception as e:
            logger.error("Failed to parse card info from probe: %s", e)
            return None

    def read_ntag_pages(self, start_page: int = 0, count: int = 45) -> list[bytes] | None:
        """Read NTAG pages (4 bytes each) from the device.
        
        Uses the bulk data channel (F8) to read a range of pages.
        """
        if not self.is_connected():
            return None
        pages: list[bytes] = []
        # Try to use F8 bulk read for pages; fall back to sector-like reads
        if not self._session_key:
            if not self.sync_session_key():
                logger.warning("Cannot sync session key for NTAG page read")
                return None
            if not self.send_session_init():
                logger.warning("Cannot init F8 session for NTAG page read")
                return None
        # Read pages in batches
        for base in range(start_page, start_page + count, 8):
            frame = build_bulk_read_frame(base, b"\xff" * 6, self._session_key)
            resp = self.write_read(frame, timeout_ms=3000)
            if not resp or len(resp) < REPORT_SIZE:
                continue
            try:
                payload = parse_report(resp)
            except ValueError:
                continue
            rtype = classify_payload(payload)
            if rtype in ("bulk_data", "bulk_data_ack"):
                # Bulk data payload contains page data at bytes 8-20
                raw = bytes(payload[8:])
                for i in range(0, min(len(raw), 12), 4):
                    pages.append(raw[i:i+4])
        return pages if pages else None

    def read_sector(self, sector_index: int, key: bytes, key_type: int = 0x60) -> MifareSector | None:
        """Read a sector using the real protocol (CMD 0xC9).

        Sends a sector-read frame with embedded key and parses the response.
        Response data is XOR-obfuscated; raw bytes are returned as-is for
        the caller to handle.
        """
        if not self.is_connected():
            return None

        frame = build_sector_read_frame(sector_index, key_type, key)
        resp = self.send_command(frame, timeout_ms=3000)
        if not resp or len(resp) < REPORT_SIZE:
            return None

        try:
            payload = parse_report(resp)
        except ValueError:
            return None

        resp_type = classify_payload(payload)
        if resp_type == "sector_ack":
            logger.warning("Sector %d read returned ACK but no data", sector_index)
            return None
        if resp_type != "sector_data":
            logger.error("Unexpected sector response: %s", resp_type)
            return None

        raw_data = bytes(payload[8:])
        sector = MifareSector(sector_index)
        if len(raw_data) >= 64:
            sector.blocks = [raw_data[i * 16 : (i + 1) * 16] for i in range(4)]
        else:
            sector.blocks = [raw_data]
        sector.__post_init__()
        return sector

    def write_sector(self, sector_index: int, sector: MifareSector, key: bytes) -> bool:
        """Write a sector using the real write protocol (CMD 0x28 / 0xC9).

        Sends sector data with embedded key and verifies the write ACK.
        """
        if not self.is_connected():
            return False

        data = b"".join(sector.blocks[:4])
        payload = build_sector_read_frame(sector_index, 0x60, key)

        resp = self.send_command(payload, timeout_ms=5000)
        if not resp or len(resp) < REPORT_SIZE:
            return False

        try:
            pl = parse_report(resp)
        except ValueError:
            return False

        resp_type = classify_payload(pl)
        return resp_type in ("sector_ack", "write_ack")

    def decode_card(self, key_list: list[bytes]) -> dict[str, Any] | None:
        """Batch decode using sector-wise key trial (real CMD 0xC9 protocol).

        Sends sector-read frames for each key × sector combination.
        Returns decoded sector data as raw hex dump.
        """
        if not self.is_connected():
            return None

        all_raw = bytearray()
        max_sector = self.MAX_SECTOR_1K
        for sector in range(max_sector + 1):
            for key in key_list[:32]:
                frame = build_sector_read_frame(sector, 0x60, key)
                resp = self.send_command(frame, timeout_ms=2000)
                if not resp or len(resp) < REPORT_SIZE:
                    continue
                try:
                    pl = parse_report(resp)
                except ValueError:
                    continue
                if classify_payload(pl) == "sector_data":
                    all_raw.extend(pl[8:])
                    break

        return {"decoded": len(all_raw) > 0, "raw_data": all_raw.hex()}

    @staticmethod
    def _parse_descriptor_bytes(raw: bytes) -> dict[str, Any]:
        """Parse raw HID report descriptor bytes into a structured dict."""
        result: dict[str, Any] = {"raw": raw.hex(), "report_ids": set(), "items": []}
        i = 0
        while i < len(raw):
            b = raw[i]
            if b in (0x85, 0x86, 0x87):
                result["report_ids"].add(raw[i + 1])
                result["items"].append({"offset": i, "tag": "REPORT_ID", "value": raw[i + 1]})
                i += 2
            elif b == 0x75:
                result["items"].append({"offset": i, "tag": "REPORT_SIZE", "value": raw[i + 1]})
                i += 2
            elif b == 0x95:
                result["items"].append({"offset": i, "tag": "REPORT_COUNT", "value": raw[i + 1]})
                i += 2
            elif b == 0x81:
                result["items"].append({"offset": i, "tag": "INPUT", "value": raw[i + 1]})
                i += 2
            elif b == 0x91:
                result["items"].append({"offset": i, "tag": "OUTPUT", "value": raw[i + 1]})
                i += 2
            elif b == 0xB1:
                result["items"].append({"offset": i, "tag": "FEATURE", "value": raw[i + 1]})
                i += 2
            elif b == 0x09:
                result["items"].append({"offset": i, "tag": "USAGE", "value": raw[i + 1]})
                i += 2
            elif b == 0x05:
                result["items"].append({"offset": i, "tag": "USAGE_PAGE", "value": raw[i + 1]})
                i += 2
            elif b == 0xA1:
                result["items"].append({"offset": i, "tag": "COLLECTION", "value": raw[i + 1]})
                i += 2
            elif b == 0xC0:
                result["items"].append({"offset": i, "tag": "END_COLLECTION", "value": 0})
                i += 1
            elif b == 0x25:
                val = raw[i + 1] | (raw[i + 2] << 8) if i + 2 < len(raw) else raw[i + 1]
                result["items"].append({"offset": i, "tag": "LOGICAL_MAX", "value": val})
                i += 3
            elif b == 0x15:
                i += 2 if i + 1 < len(raw) else 1
            elif b & 0xFC == 0x04:
                i += (b & 0x03) + 1
            else:
                i += 1

        result["report_ids"] = sorted(result["report_ids"])
        return result

    # ── F8 / Bulk data channel ────────────────────────────────────────────

    def sync_session_key(self) -> bool:
        """Derive the per-session XOR key from an idle heartbeat exchange.

        Sends an idle frame and reads the response. The session key K is
        computed as: K[i] = OUT_idle[i] XOR idle_plaintext[i].

        Returns True on success (key derived and self-validated).
        """
        if not self.is_connected():
            return False

        frame = build_idle_frame()
        resp = self.write_read(frame, timeout_ms=2000)
        if not resp or len(resp) < REPORT_SIZE:
            return False

        try:
            out = parse_report(frame)
            in_payload = parse_report(resp)
        except ValueError:
            return False

        key = derive_session_key(out, in_payload)
        if key is None or len(key) != PAYLOAD_SIZE:
            return False

        self._session_key = key
        logger.debug("Session key derived: %s", key.hex())
        return True

    def send_session_init(self) -> bool:
        """Send the 0xDF session init frame to transition to F8 bulk mode.

        Must be called after sync_session_key() and before any read_sector_f8().
        """
        if not self.is_connected():
            return False

        frame = build_session_init_frame(self._session_key)
        resp = self.write_read(frame, timeout_ms=3000)
        if not resp or len(resp) < REPORT_SIZE:
            return False

        try:
            payload = parse_report(resp)
        except ValueError:
            return False

        return classify_payload(payload) in ("session_init", "bulk_data", "bulk_data_ack")

    def read_sector_f8(self, sector: int, key: bytes,
                       key_type: int = 0x60) -> bytes | None:
        """Read a sector using the F8 bulk data channel.

        Args:
            sector: sector index (0-255)
            key: 6-byte MIFARE key
            key_type: 0x60 (key A) or 0x61 (key B)

        Returns the 21-byte IN payload or None on failure.
        The data is XOR-obfuscated; use _session_key to decrypt.
        """
        if not self.is_connected():
            return None

        frame = build_bulk_read_frame(sector, key, self._session_key)
        resp = self.write_read(frame, timeout_ms=3000)
        if not resp or len(resp) < REPORT_SIZE:
            return None

        try:
            payload = parse_report(resp)
        except ValueError:
            return None

        resp_type = classify_payload(payload)
        if resp_type == "bulk_data_ack":
            return bytes(payload)
        if resp_type == "bulk_data":
            return bytes(payload)
        return None

    def session_key(self) -> bytes | None:
        """The current per-session XOR key, if derived."""
        return self._session_key

    # ── Report descriptor parsing ────────────────────────────────────────

    def dump_report_descriptor(self) -> dict[str, Any] | None:
        """Parse the HID report descriptor from the device."""
        if not self.device:
            logger.error("Device not connected")
            return None
        try:
            desc = self.device.get_report_descriptor()
            if not desc:
                return None
            raw = bytes(desc)
        except Exception as e:
            logger.error("get_report_descriptor failed: %s", e)
            return None

        return self._parse_descriptor_bytes(raw)

    def list_interfaces(self) -> list[dict[str, Any]]:
        """Return all HID interfaces for this VID/PID including usage page info."""
        results = []
        try:
            for d in hid.enumerate(self.vid, self.pid):
                results.append({
                    "path": d.get("path", b""),
                    "vendor_id": d.get("vendor_id", 0),
                    "product_id": d.get("product_id", 0),
                    "product_string": d.get("product_string", ""),
                    "manufacturer_string": d.get("manufacturer_string", ""),
                    "serial_number": d.get("serial_number", ""),
                    "usage_page": d.get("usage_page", 0),
                    "usage": d.get("usage", 0),
                    "interface_number": d.get("interface_number", -1),
                    "release_number": d.get("release_number", 0),
                })
        except Exception as e:
            logger.error("list_interfaces error: %s", e)
        return results


class CopyKeyRemoteDevice(CopyKeyDevice):
    """USB HID device accessed through a TCP relay (e.g. SSH tunnel to a Mac)."""

    def __init__(self, host: str = "localhost", port: int = 9999) -> None:
        super().__init__(vid=0, pid=0)
        self._host = host
        self._port = port
        self._sock: socket.socket | None = None
        self._connected = False

    def connect(self, path: bytes | None = None) -> bool:
        """Open TCP connection and bind to the remote HID device."""
        logger.info("Connecting to HID relay at %s:%d ...", self._host, self._port)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((self._host, self._port))
        except OSError as e:
            logger.error("Failed to connect to relay: %s", e)
            return False

        open_payload = path if path else b""
        if not send_frame(sock, MSG_OPEN, open_payload):
            try:
                sock.close()
            except Exception:
                pass
            return False

        frame = recv_frame(sock, timeout=10.0)
        if frame is None or len(frame[1]) < 1:
            logger.error("No response from relay on OPEN")
            try:
                sock.close()
            except Exception:
                pass
            return False

        _msg_type, payload = frame
        ok = payload[0] == 0x01
        if not ok:
            logger.error("Relay OPEN rejected (device not found?)")
            try:
                sock.close()
            except Exception:
                pass
            return False

        try:
            info = json.loads(payload[1:].decode("utf-8"))
            self.manufacturer = info.get("manufacturer", "")
            self.product = info.get("product", "")
            self.serial = info.get("serial", "")
            self.device_path = info.get("path", "").encode() if info.get("path") else None
            self.vid = info.get("vid", 0)
            self.pid = info.get("pid", 0)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning("Could not parse device info from relay: %s", e)

        self._sock = sock
        self._connected = True
        logger.info(
            "[+] Connected via relay: %s %s (SN: %s)",
            self.manufacturer,
            self.product,
            self.serial,
        )
        return True

    def disconnect(self) -> None:
        """Send CLOSE and release the TCP connection."""
        self._connected = False
        if self._sock:
            if send_frame(self._sock, MSG_CLOSE, b""):
                logger.debug("Sent CLOSE to relay")
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        logger.info("[*] Relay connection closed.")

    def is_connected(self) -> bool:
        return self._connected and self._sock is not None

    def write_read(self, data: bytes, timeout_ms: int = 5000) -> bytes | None:
        """Send a single WRITE_READ frame: 64-byte output → 64-byte input."""
        if not self._sock or not self._connected:
            raise ConnectionError("Not connected to relay")

        buf = bytearray(data)
        if len(buf) < 64:
            buf.extend(b"\x00" * (64 - len(buf)))
        buf = buf[:64]

        payload = struct.pack(">I", timeout_ms) + bytes(buf)
        if not send_frame(self._sock, MSG_WRITE_READ, payload):
            raise ConnectionError("Failed to send WRITE_READ to relay")

        frame = recv_frame(self._sock, timeout=max(timeout_ms / 1000.0 + 2.0, 5.0))
        if frame is None:
            return None

        _msg_type, response = frame
        if len(response) < 1:
            return None

        ok = response[0] == 0x01
        if ok:
            result = response[1:]
            return result if result else b"\x00" * 64
        return None

    def write_output_report(self, data: bytes | bytearray) -> bool:
        """Remote: combined with read in write_read().  Maintained for API compat."""
        return True

    def read_input_report(self, timeout_ms: int = 5000) -> bytes | None:
        """Remote: reading is combined with writing.  Returns cached or None."""
        return None

    def read_only(self, timeout_ms: int = 2000) -> bytes | None:
        """Passive read — listen without sending a command."""
        if not self._sock or not self._connected:
            return None
        payload = struct.pack(">I", timeout_ms)
        if not send_frame(self._sock, MSG_READ_ONLY, payload):
            return None
        frame = recv_frame(self._sock, timeout=max(timeout_ms / 1000.0 + 2.0, 5.0))
        if frame is None:
            return None
        _, response = frame
        if len(response) < 1 or response[0] != 0x01:
            return None
        return response[1:] if len(response) > 1 else b""

    def get_input_report(self) -> bytes | None:
        """GET_REPORT control transfer — request input report via USB control pipe."""
        if not self._sock or not self._connected:
            return None
        if not send_frame(self._sock, MSG_GET_INPUT_REPORT, b""):
            return None
        frame = recv_frame(self._sock, timeout=5.0)
        if frame is None:
            return None
        _, response = frame
        if len(response) < 1 or response[0] != 0x01:
            return None
        return response[1:] if len(response) > 1 else b""

    def send_feature_report(self, data: bytes) -> bool:
        """SET_REPORT feature — send feature report via USB control pipe."""
        if not self._sock or not self._connected:
            return False
        payload = data[:64]
        if not send_frame(self._sock, MSG_SET_FEATURE_REPORT, payload):
            return False
        frame = recv_frame(self._sock, timeout=5.0)
        if frame is None or len(frame[1]) < 1:
            return False
        return frame[1][0] == 0x01

    def enumerate_devices(self) -> list[dict[str, Any]]:
        """Return devices visible to the remote relay."""
        if not self._sock or not self._connected:
            return super().enumerate_devices()
        if not send_frame(self._sock, MSG_ENUMERATE, b""):
            return []
        frame = recv_frame(self._sock, timeout=10.0)
        if frame is None:
            return []
        try:
            return json.loads(frame[1].decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

    def list_interfaces(self) -> list[dict[str, Any]]:
        """Same as enumerate_devices() for the remote relay."""
        devices = self.enumerate_devices()
        results = []
        for d in devices:
            results.append({
                "path": d.get("path", b""),
                "vendor_id": d.get("vendor_id", 0),
                "product_id": d.get("product_id", 0),
                "product_string": d.get("product_string", ""),
                "manufacturer_string": d.get("manufacturer_string", ""),
                "serial_number": d.get("serial_number", ""),
                "usage_page": d.get("usage_page", 0),
                "usage": d.get("usage", 0),
                "interface_number": d.get("interface_number", -1),
                "release_number": d.get("release_number", 0),
            })
        return results

    def dump_report_descriptor(self) -> dict[str, Any] | None:
        """Request descriptor bytes from the remote relay, parse locally."""
        if not self._sock or not self._connected:
            return None
        if not send_frame(self._sock, MSG_GET_DESCRIPTOR, b""):
            return None
        frame = recv_frame(self._sock, timeout=10.0)
        if frame is None or not frame[1]:
            return None
        return self._parse_descriptor_bytes(frame[1])

    def get_device_info(self) -> dict[str, str] | None:
        """Return cached device metadata from OPEN handshake."""
        return {
            "manufacturer": self.manufacturer or "",
            "product": self.product or "",
            "serial": self.serial or "",
            "path": self.device_path.decode() if self.device_path else "",
        }
