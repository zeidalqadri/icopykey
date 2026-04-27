"""
Business-logic layer for CopyKEY CLI.

Self-contained implementations of AESVault, CopyKeyDevice,
MifareSector, MifareCard, CardOperations, LocalLibrary.
ZERO imports from dead core/config/updater modules.
"""

from __future__ import annotations

import enum
import json
import logging
import secrets
import socket
import struct
import time
import getpass
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Crypto
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# HID
try:
    import hid

    HID_AVAILABLE = True
except ImportError:
    HID_AVAILABLE = False

from .errors import (
    DeviceNotFoundError,
    DeviceDisconnectedError,
    VaultAccessError,
    KeyNotFoundError,
)

logger = logging.getLogger("copykey_cli.operations")

# ── Constants ────────────────────────────────────────────────────

DEVICE_VID = 0x6300
DEVICE_PID = 0x1991
DEVICE_USAGE_PAGE = 0xFF00
REPORT_SIZE_IN = 64
REPORT_SIZE_OUT = 64
FEATURE_REPORT_ID = 0x01
RESPONSE_REPORT_ID = 0x80

DEFAULT_KEYS: list[bytes] = [
    bytes.fromhex("FFFFFFFFFFFF"),
    bytes.fromhex("000000000000"),
    bytes.fromhex("A0A1A2A3A4A5"),
    bytes.fromhex("B0B1B2B3B4B5"),
    bytes.fromhex("4D3A99C351DD"),
    bytes.fromhex("1A982C7E459A"),
    bytes.fromhex("D3F7D3F7D3F7"),
    bytes.fromhex("AABBCCDDEEFF"),
    bytes.fromhex("112233445566"),
    bytes.fromhex("654321FEDCBA"),
]


# ── AES Vault ────────────────────────────────────────────────────


class AESVault:
    """Encrypt/decrypt JSON data with PBKDF2 + AES-256-GCM."""

    ITERATIONS = 100_000
    SALT_LEN = 16
    IV_LEN = 12
    TAG_LEN = 16
    KEY_LEN = 32

    def __init__(self, password: str) -> None:
        if not password:
            raise ValueError("Password cannot be empty")
        if not CRYPTO_AVAILABLE:
            raise ImportError("pycryptodome required for AES vault")
        self.password = password

    def _derive_key(self, salt: bytes) -> bytes:
        return PBKDF2(
            self.password.encode("utf-8"), salt, dkLen=self.KEY_LEN, count=self.ITERATIONS
        )

    def encrypt(self, plaintext: str) -> bytes:
        salt = get_random_bytes(self.SALT_LEN)
        key = self._derive_key(salt)
        iv = get_random_bytes(self.IV_LEN)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        data = plaintext.encode("utf-8")
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return salt + iv + tag + ciphertext

    def decrypt(self, blob: bytes) -> str:
        if len(blob) < (self.SALT_LEN + self.IV_LEN + self.TAG_LEN):
            raise ValueError("Invalid encrypted data format")
        salt = blob[: self.SALT_LEN]
        iv = blob[self.SALT_LEN : self.SALT_LEN + self.IV_LEN]
        tag = blob[self.SALT_LEN + self.IV_LEN : self.SALT_LEN + self.IV_LEN + self.TAG_LEN]
        ciphertext = blob[self.SALT_LEN + self.IV_LEN + self.TAG_LEN :]
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
        except ValueError:
            raise VaultAccessError()


# ── Card Data Structures ─────────────────────────────────────────


@dataclass
class MifareSector:
    """A MIFARE Classic sector (4 blocks of 16 bytes each)."""

    index: int
    blocks: list[bytes] = field(default_factory=lambda: [b"\x00" * 16] * 4)
    key_a: bytes = field(default_factory=lambda: b"\xff" * 6)
    key_b: bytes = field(default_factory=lambda: b"\xff" * 6)
    access_bits: bytes = field(default_factory=lambda: b"\xff\x07\x80\x69")

    def __post_init__(self) -> None:
        if len(self.blocks) != 4:
            self.blocks = [b"\x00" * 16] * 4
        if len(self.blocks[3]) == 16:
            trailer = self.blocks[3]
            if self.key_a == b"\xff" * 6:
                self.key_a = trailer[0:6]
            if self.access_bits == b"\xff\x07\x80\x69":
                self.access_bits = trailer[6:10]
            if self.key_b == b"\xff" * 6:
                self.key_b = trailer[10:16]

    @classmethod
    def from_blocks(cls, blocks: list[bytes]) -> "MifareSector":
        if len(blocks) != 4:
            raise ValueError("Sector must have exactly 4 blocks")
        trailer = blocks[3]
        return cls(
            index=0,
            blocks=list(blocks),
            key_a=trailer[0:6] if len(trailer) >= 16 else b"\xff" * 6,
            access_bits=trailer[6:10] if len(trailer) >= 16 else b"\xff\x07\x80\x69",
            key_b=trailer[10:16] if len(trailer) >= 16 else b"\xff" * 6,
        )

    def update_trailer(
        self,
        key_a: bytes | None = None,
        access_bits: bytes | None = None,
        key_b: bytes | None = None,
    ) -> None:
        trailer = bytearray(self.blocks[3])
        if key_a is not None:
            if len(key_a) != 6:
                raise ValueError("Key A must be 6 bytes")
            trailer[0:6] = key_a
            self.key_a = key_a
        if access_bits is not None:
            if len(access_bits) != 4:
                raise ValueError("Access bits must be 4 bytes")
            trailer[6:10] = access_bits
            self.access_bits = access_bits
        if key_b is not None:
            if len(key_b) != 6:
                raise ValueError("Key B must be 6 bytes")
            trailer[10:16] = key_b
            self.key_b = key_b
        self.blocks[3] = bytes(trailer)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "key_a": self.key_a.hex(),
            "key_b": self.key_b.hex(),
            "access_bits": self.access_bits.hex(),
            "blocks": [blk.hex() for blk in self.blocks],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MifareSector":
        sector = cls(index=data["index"])
        sector.key_a = bytes.fromhex(data["key_a"])
        sector.key_b = bytes.fromhex(data["key_b"])
        sector.access_bits = bytes.fromhex(data["access_bits"])
        sector.blocks = [bytes.fromhex(b) for b in data["blocks"]]
        return sector


@dataclass
class MifareCard:
    """A complete MIFARE Classic card dump (1K or 4K)."""

    uid: bytes
    sak: int
    atqa: bytes
    card_type: str = "MIFARE Classic 1K"
    sectors: list[MifareSector] = field(default_factory=list)
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    modified: str = field(default_factory=lambda: datetime.now().isoformat())

    def __post_init__(self) -> None:
        if not self.sectors:
            if self.sak == 0x18:
                self.card_type = "MIFARE Classic 4K"
                self.sectors = [MifareSector(i) for i in range(40)]
            else:
                self.sectors = [MifareSector(i) for i in range(16)]

    @property
    def num_sectors(self) -> int:
        return len(self.sectors)

    @property
    def uid_hex(self) -> str:
        return self.uid.hex().upper()

    def full_dump(self) -> bytes:
        dump = self.uid
        for sec in self.sectors:
            for blk in sec.blocks:
                dump += blk
        return dump

    def get_sector(self, index: int) -> MifareSector | None:
        if 0 <= index < len(self.sectors):
            return self.sectors[index]
        return None

    def set_sector(self, index: int, sector: MifareSector) -> None:
        if 0 <= index < len(self.sectors):
            self.sectors[index] = sector
            self.modified = datetime.now().isoformat()
        else:
            raise IndexError(f"Sector index {index} out of range")

    def to_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid.hex(),
            "sak": self.sak,
            "atqa": self.atqa.hex(),
            "card_type": self.card_type,
            "created": self.created,
            "modified": self.modified,
            "sectors": [sec.to_dict() for sec in self.sectors],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MifareCard":
        card = cls(
            uid=bytes.fromhex(data["uid"]),
            sak=data["sak"],
            atqa=bytes.fromhex(data["atqa"]),
            card_type=data.get("card_type", "MIFARE Classic 1K"),
            created=data.get("created", datetime.now().isoformat()),
            modified=data.get("modified", datetime.now().isoformat()),
        )
        card.sectors = [MifareSector.from_dict(sec) for sec in data["sectors"]]
        return card


# ── HID Device ───────────────────────────────────────────────────


class CopyKeyDevice:
    """USB HID communication layer for CopyKEY-compatible devices.

    Based on real HID report descriptor (dumped from X100 at 0x6300:0x1991):
      - NO REPORT_ID (report uses ID 0 — raw output/input reports)
      - NO FEATURE reports
      - INPUT:  64 bytes (Usage 1-8, count 64, size 8 = 8 channels x 8 bytes)
      - OUTPUT: 64 bytes (Usage 1-8, count 64, size 8)
    Transport: device.write(64 bytes) → device.read(64 bytes)
    """

    CMD_GET_CARD_INFO = 0x01
    CMD_READ_SECTOR = 0x02
    CMD_WRITE_SECTOR = 0x03
    CMD_AUTHENTICATE = 0x04
    CMD_DECODE_CARD = 0x05
    CMD_WRITE_CARD = 0x06
    CMD_GET_DEVICE_INFO = 0x10
    RESP_SUCCESS = 0x00
    RESP_ERROR = 0xFF

    def __init__(self, vid: int = DEVICE_VID, pid: int = DEVICE_PID) -> None:
        self.vid = vid
        self.pid = pid
        self.device: Any = None
        self.device_path: bytes | None = None
        self.manufacturer: str | None = None
        self.product: str | None = None
        self.serial: str | None = None

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

    # ── Real transport: output/input reports (no feature reports) ─

    def write_output_report(self, data: bytes | bytearray) -> bool:
        """Write a 64-byte output report to the device.

        The X100 HID descriptor has NO report ID, so we write raw 64 bytes.
        """
        if not self.device:
            logger.error("Device not connected")
            return False
        buf = bytearray(data)
        # Pad/truncate to exactly 64 bytes
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
        """Read a 64-byte input report from the device.

        The X100 descriptor defines a 64-byte INPUT report (Usage 1-8, count 64, size 8).
        Set non-blocking so we can timeout.
        """
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
        import time as _time
        _time.sleep(0.05)  # small gap for device to process
        return self.read_input_report(timeout_ms)

    # ── deprecated transport (kept for reference) ──────────────

    def send_command(self, cmd: bytes, timeout_ms: int = 5000) -> bytes | None:
        """Legacy send using write/read transport (no feature reports)."""
        return self.write_read(cmd, timeout_ms)

    def get_device_info(self) -> dict[str, str] | None:
        return {
            "manufacturer": self.manufacturer or "",
            "product": self.product or "",
            "serial": self.serial or "",
            "path": self.device_path.decode() if self.device_path else "",
        }

    def read_card_info(self) -> dict[str, Any] | None:
        if not self.is_connected():
            logger.error("Device not connected")
            return None
        cmd = struct.pack("B", self.CMD_GET_CARD_INFO)
        resp = self.send_command(cmd)
        if not resp:
            return None
        if len(resp) < 2 or resp[0] != self.RESP_SUCCESS:
            logger.error("Read card info failed: status=%02X", resp[0] if resp else 0)
            return None
        try:
            offset = 1
            uid_len = resp[offset]
            offset += 1
            uid = resp[offset : offset + uid_len]
            offset += uid_len
            sak = resp[offset]
            offset += 1
            atqa = resp[offset : offset + 2]
            offset += 2
            card_type = "MIFARE Classic 1K" if sak == 0x08 else "MIFARE Classic 4K"
            return {"uid": uid, "sak": sak, "atqa": atqa, "card_type": card_type}
        except Exception as e:
            logger.error("Failed to parse card info: %s", e)
            return None

    def read_sector(self, sector_index: int, key: bytes, key_type: int = 0) -> MifareSector | None:
        if not self.is_connected():
            return None
        cmd = struct.pack("BBB", self.CMD_READ_SECTOR, sector_index, key_type) + key
        resp = self.send_command(cmd, timeout_ms=3000)
        if not resp or resp[0] != self.RESP_SUCCESS:
            return None
        if len(resp) < 65:
            logger.error("Response too short for sector data: %d", len(resp))
            return None
        raw_data = resp[1:65]
        blocks = [raw_data[i * 16 : (i + 1) * 16] for i in range(4)]
        sector = MifareSector(sector_index)
        sector.blocks = blocks
        sector.__post_init__()
        return sector

    def write_sector(self, sector_index: int, sector: MifareSector, key: bytes) -> bool:
        if not self.is_connected():
            return False
        data = b"".join(sector.blocks)
        cmd = struct.pack("BB", self.CMD_WRITE_SECTOR, sector_index) + key + data
        resp = self.send_command(cmd, timeout_ms=5000)
        if resp and len(resp) > 0:
            return resp[0] == self.RESP_SUCCESS
        return False

    def decode_card(self, key_list: list[bytes]) -> dict[str, Any] | None:
        if not self.is_connected():
            return None
        num_keys = min(len(key_list), 255)
        keys_data = b"".join(k[:6] for k in key_list[:num_keys])
        cmd = struct.pack("BB", self.CMD_DECODE_CARD, num_keys) + keys_data
        resp = self.send_command(cmd, timeout_ms=30000)
        if not resp or resp[0] != self.RESP_SUCCESS:
            return None
        return {"decoded": True, "raw_data": resp[1:].hex()}

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


# ── Remote HID Device (TCP relay client) ─────────────────────────

MSG_ENUMERATE = 0x01
MSG_OPEN = 0x02
MSG_WRITE_READ = 0x03
MSG_GET_DESCRIPTOR = 0x04
MSG_CLOSE = 0x05
MSG_READ_ONLY = 0x06
MSG_GET_INPUT_REPORT = 0x07
MSG_SET_FEATURE_REPORT = 0x08
HEADER_SIZE = 5  # 1 byte type + 4 bytes length BE


def _recv_frame(sock: socket.socket, timeout: float = 10.0) -> tuple[int, bytes] | None:
    """Receive a single framed message.  Returns (msg_type, payload) or None."""
    sock.settimeout(timeout)
    try:
        header = b""
        while len(header) < HEADER_SIZE:
            chunk = sock.recv(HEADER_SIZE - len(header))
            if not chunk:
                return None
            header += chunk
    except (socket.timeout, OSError):
        return None

    msg_type = header[0]
    payload_len = struct.unpack(">I", header[1:5])[0]

    if payload_len > 1_048_576:
        logger.error("Payload too large: %d", payload_len)
        return None

    payload = b""
    while len(payload) < payload_len:
        chunk = sock.recv(payload_len - len(payload))
        if not chunk:
            return None
        payload += chunk

    return msg_type, payload


def _send_frame(sock: socket.socket, msg_type: int, payload: bytes) -> bool:
    """Send a framed message.  Returns True on success."""
    header = struct.pack(">BI", msg_type, len(payload))
    try:
        sock.sendall(header + payload)
        return True
    except OSError as e:
        logger.error("Send failed: %s", e)
        return False


class CopyKeyRemoteDevice(CopyKeyDevice):
    """USB HID device accessed through a TCP relay (e.g. SSH tunnel to a Mac).

    The relay server runs on the machine with the physical X100 hardware
    attached and bridges HID write/read to TCP frames.

    Usage:
        dev = CopyKeyRemoteDevice("localhost", 9999)
        dev.connect()
        dev.write_read(b"...")   # transparently goes over TCP
        dev.disconnect()
    """

    def __init__(self, host: str = "localhost", port: int = 9999) -> None:
        super().__init__(vid=0, pid=0)
        self._host = host
        self._port = port
        self._sock: socket.socket | None = None
        self._connected = False

    # ── Connection lifecycle ─────────────────────────────────

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

        # Send OPEN with optional path
        open_payload = path if path else b""
        if not _send_frame(sock, MSG_OPEN, open_payload):
            try:
                sock.close()
            except Exception:
                pass
            return False

        frame = _recv_frame(sock, timeout=10.0)
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

        # Parse device info from JSON payload
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
            if _send_frame(self._sock, MSG_CLOSE, b""):
                logger.debug("Sent CLOSE to relay")
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        logger.info("[*] Relay connection closed.")

    def is_connected(self) -> bool:
        return self._connected and self._sock is not None

    # ── Core transport ───────────────────────────────────────

    def write_read(self, data: bytes, timeout_ms: int = 5000) -> bytes | None:
        """Send a single WRITE_READ frame: 64-byte output → 64-byte input."""
        if not self._sock or not self._connected:
            raise ConnectionError("Not connected to relay")

        buf = bytearray(data)
        if len(buf) < 64:
            buf.extend(b"\x00" * (64 - len(buf)))
        buf = buf[:64]

        payload = struct.pack(">I", timeout_ms) + bytes(buf)
        if not _send_frame(self._sock, MSG_WRITE_READ, payload):
            raise ConnectionError("Failed to send WRITE_READ to relay")

        frame = _recv_frame(self._sock, timeout=max(timeout_ms / 1000.0 + 2.0, 5.0))
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
        return True  # no-op: actual write happens in write_read

    def read_input_report(self, timeout_ms: int = 5000) -> bytes | None:
        """Remote: reading is combined with writing.  Returns cached or None."""
        return None  # no-op: actual read happens in write_read

    def read_only(self, timeout_ms: int = 2000) -> bytes | None:
        """Passive read — listen without sending a command."""
        if not self._sock or not self._connected:
            return None
        payload = struct.pack(">I", timeout_ms)
        if not _send_frame(self._sock, MSG_READ_ONLY, payload):
            return None
        frame = _recv_frame(self._sock, timeout=max(timeout_ms / 1000.0 + 2.0, 5.0))
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
        if not _send_frame(self._sock, MSG_GET_INPUT_REPORT, b""):
            return None
        frame = _recv_frame(self._sock, timeout=5.0)
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
        if not _send_frame(self._sock, MSG_SET_FEATURE_REPORT, payload):
            return False
        frame = _recv_frame(self._sock, timeout=5.0)
        if frame is None or len(frame[1]) < 1:
            return False
        return frame[1][0] == 0x01

    # ── Metadata ─────────────────────────────────────────────

    def enumerate_devices(self) -> list[dict[str, Any]]:
        """Return devices visible to the remote relay."""
        if not self._sock or not self._connected:
            return super().enumerate_devices()
        if not _send_frame(self._sock, MSG_ENUMERATE, b""):
            return []
        frame = _recv_frame(self._sock, timeout=10.0)
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
        if not _send_frame(self._sock, MSG_GET_DESCRIPTOR, b""):
            return None
        frame = _recv_frame(self._sock, timeout=10.0)
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


# ── Card Operations ──────────────────────────────────────────────


class CardOperations:
    """High-level card operations combining device commands into workflows."""

    def __init__(self, device: CopyKeyDevice) -> None:
        self.device = device
        self.current_card: MifareCard | None = None

    def read_card_info(self) -> dict[str, Any] | None:
        return self.device.read_card_info()

    def decode_card(
        self, custom_keys: list[bytes] | None = None, show_progress: bool = True
    ) -> MifareCard | None:
        info = self.read_card_info()
        if not info:
            logger.error("Failed to read card info")
            return None
        card = MifareCard(
            uid=info["uid"], sak=info["sak"], atqa=info["atqa"], card_type=info["card_type"]
        )
        all_keys = list(DEFAULT_KEYS) + (custom_keys or [])
        locked_sectors: list[int] = []

        if show_progress:
            logger.info("[*] Decoding card UID: %s (%s)", card.uid_hex, card.card_type)
            logger.info("[*] Trying %d keys...", len(all_keys))

        for i in range(card.num_sectors):
            found = False
            for key in all_keys:
                sector = self.device.read_sector(i, key, key_type=0)
                if sector:
                    sector.index = i
                    card.set_sector(i, sector)
                    if show_progress:
                        logger.info("    Sector %2d OK (KeyA: %s)", i, key.hex().upper())
                    found = True
                    break
                sector = self.device.read_sector(i, key, key_type=1)
                if sector:
                    sector.index = i
                    card.set_sector(i, sector)
                    if show_progress:
                        logger.info("    Sector %2d OK (KeyB: %s)", i, key.hex().upper())
                    found = True
                    break
            if not found:
                locked_sectors.append(i)
                if show_progress:
                    logger.warning("    Sector %2d LOCKED - need manual key", i)

        self.current_card = card
        if locked_sectors and show_progress:
            logger.warning(
                "[!] %d sector(s) remain locked: %s", len(locked_sectors), locked_sectors
            )
        return card

    def encrypt_card_data(
        self,
        card: MifareCard | None = None,
        new_key_a: bytes | None = None,
        new_key_b: bytes | None = None,
        random_keys: bool = False,
        sectors: list[int] | None = None,
    ) -> bool:
        card = card or self.current_card
        if not card:
            logger.error("No card data available")
            return False
        if sectors is None:
            sectors = list(range(1, card.num_sectors))
        logger.info("[*] Encrypting %d sector(s)...", len(sectors))
        for i in sectors:
            sector = card.get_sector(i)
            if not sector:
                continue
            if random_keys:
                sector_key_a = secrets.token_bytes(6)
                sector_key_b = secrets.token_bytes(6)
            else:
                sector_key_a = new_key_a or sector.key_a
                sector_key_b = new_key_b or sector.key_b
            sector.update_trailer(key_a=sector_key_a, access_bits=sector.access_bits, key_b=sector_key_b)
            card.set_sector(i, sector)
        logger.info("[+] Card data encrypted with new keys.")
        return True

    def write_full_card(
        self, card: MifareCard | None = None, transport_key: bytes | None = None
    ) -> bool:
        card = card or self.current_card
        if not card:
            logger.error("No card data to write")
            return False
        transport_key = transport_key or b"\xff" * 6
        logger.info("[*] Writing card...")
        success_count = 0
        total = card.num_sectors
        for i in range(total):
            sector = card.get_sector(i)
            if not sector:
                continue
            auth_key = sector.key_a if i > 0 else transport_key
            if self.device.write_sector(i, sector, auth_key):
                success_count += 1
                logger.info("    Sector %2d written successfully", i)
            else:
                logger.error("[-] Failed writing sector %d", i)
        logger.info("[+] Card written: %d/%d sectors successful", success_count, total)
        return success_count == total


# ── Local Library ────────────────────────────────────────────────


class LocalLibrary:
    """Encrypted local storage for keys and cards."""

    def __init__(self, data_dir: Path, vault_password: str | None = None) -> None:
        self.data_dir = data_dir
        self.vault: AESVault | None = None
        self.encrypted = bool(vault_password)
        if vault_password:
            try:
                self.vault = AESVault(vault_password)
            except ValueError as e:
                logger.warning("Vault initialization failed: %s", e)
                self.encrypted = False
        self.key_file = data_dir / ("keys.json.enc" if self.encrypted else "keys.json")
        self.card_file = data_dir / ("cards.json.enc" if self.encrypted else "cards.json")
        self.keys: dict[str, bytes] = {}
        self.cards: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        self.keys = {}
        self.cards = []
        if self.key_file.exists():
            try:
                plain = (
                    self.vault.decrypt(self.key_file.read_bytes())
                    if (self.encrypted and self.vault)
                    else self.key_file.read_text(encoding="utf-8")
                )
                self.keys = {k: bytes.fromhex(v) for k, v in json.loads(plain).items()}
                logger.info("Loaded %d keys from library", len(self.keys))
            except Exception as e:
                logger.error("[!] Failed to load key library: %s", e)
        if self.card_file.exists():
            try:
                plain = (
                    self.vault.decrypt(self.card_file.read_bytes())
                    if (self.encrypted and self.vault)
                    else self.card_file.read_text(encoding="utf-8")
                )
                self.cards = json.loads(plain)
                logger.info("Loaded %d cards from library", len(self.cards))
            except Exception as e:
                logger.error("[!] Failed to load card library: %s", e)

    def _save(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        key_data = json.dumps({k: v.hex() for k, v in self.keys.items()}, indent=2)
        card_data = json.dumps(self.cards, indent=2)
        if self.encrypted and self.vault:
            self.key_file.write_bytes(self.vault.encrypt(key_data))
            self.card_file.write_bytes(self.vault.encrypt(card_data))
        else:
            self.key_file.write_text(key_data, encoding="utf-8")
            self.card_file.write_text(card_data, encoding="utf-8")
        logger.debug("[+] Library saved.")

    def add_key(self, name: str, key: bytes) -> None:
        if len(key) != 6:
            raise ValueError("Key must be 6 bytes")
        self.keys[name] = key
        self._save()
        logger.info("[+] Added key '%s'", name)

    def remove_key(self, name: str) -> bool:
        if name in self.keys:
            del self.keys[name]
            self._save()
            logger.info("[+] Removed key '%s'", name)
            return True
        logger.warning("Key '%s' not found", name)
        return False

    def get_keys(self) -> list[bytes]:
        return list(self.keys.values())

    def add_card(self, card: MifareCard, name: str) -> str:
        card_id = f"card_{len(self.cards)}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        card_entry = {
            "id": card_id,
            "name": name,
            "uid": card.uid.hex(),
            "sak": card.sak,
            "atqa": card.atqa.hex(),
            "card_type": card.card_type,
            "created": card.created,
            "modified": card.modified,
            "sectors": [sec.to_dict() for sec in card.sectors],
        }
        self.cards.append(card_entry)
        self._save()
        logger.info("[+] Added card '%s' (ID: %s)", name, card_id)
        return card_id

    def get_card(self, card_id: str) -> dict[str, Any] | None:
        for card in self.cards:
            if card["id"] == card_id:
                return card
        return None

    def list_cards(self) -> list[dict[str, str]]:
        return [
            {"id": c["id"], "name": c["name"], "uid": c["uid"], "card_type": c["card_type"], "created": c["created"]}
            for c in self.cards
        ]

    def remove_card(self, card_id: str) -> bool:
        for i, card in enumerate(self.cards):
            if card["id"] == card_id:
                del self.cards[i]
                self._save()
                logger.info("[+] Removed card '%s'", card["name"])
                return True
        logger.warning("Card '%s' not found", card_id)
        return False

    def export_card(self, card_id: str, fmt: str = "json") -> bytes | None:
        card = self.get_card(card_id)
        if not card:
            return None
        if fmt == "json":
            return json.dumps(card, indent=2).encode("utf-8")
        return None

    def import_card(self, data: bytes, fmt: str = "json") -> str | None:
        try:
            if fmt == "json":
                card_data = json.loads(data.decode("utf-8"))
                if "uid" not in card_data:
                    logger.error("Imported card missing UID")
                    return None
                card = MifareCard.from_dict(card_data)
                name = card_data.get("name", f"Imported_{card.uid_hex}")
                return self.add_card(card, name)
        except Exception as e:
            logger.error("Import failed: %s", e)
        return None

    def search_cards(self, query: str) -> list[dict[str, str]]:
        q = query.lower()
        return [
            {"id": c["id"], "name": c["name"], "uid": c["uid"], "card_type": c["card_type"]}
            for c in self.cards
            if q in c["name"].lower() or q in c["uid"].lower()
        ]


# ── Crypto-1 (MIFARE Classic LFSR cipher) ────────────────────────


class AccessCondition(enum.Enum):
    NEVER = 0
    KEY_A = 1
    KEY_B = 2
    KEY_A_OR_B = 3
    ALWAYS = 4


@dataclass
class SectorKeyInfo:
    key_a: str = "ffffffffffff"
    key_b: str = "ffffffffffff"
    access_bits: str = "ff078069"
    known: bool = False


class Crypto1:
    """MIFARE Classic Crypto-1 stream cipher (48-bit LFSR).

    Implements the LFSR feedback polynomial, non-linear filter function,
    keystream generation, and tag authentication protocol from the
    NXP Crypto-1 specification.  The ``crack_key()`` method is a stub
    pending integration of darkside / nested attack code.

    References:
        - libnfc / mfoc / crapto1 open-source implementations
        - NXP AN0942: Crypto-1 description
    """

    LFSR_MASK: int = (1 << 48) - 1

    def __init__(self) -> None:
        self.lfsr: int = 0
        self._uid: bytes | None = None
        self._nt: int | None = None

    def init(self, key: bytes) -> None:
        """Initialise the LFSR with a 6-byte key."""
        if len(key) != 6:
            raise ValueError("Key must be 6 bytes")
        self.lfsr = int.from_bytes(key, 'big')

    def init_with_tag(self, key: bytes, uid: bytes, nt: bytes) -> None:
        """Initialise with key, card UID, and tag nonce."""
        self.init(key)
        self._uid = uid
        self._nt = int.from_bytes(nt, 'little') & 0xFFFFFFFF
        uid_val = int.from_bytes(uid, 'little') & 0xFFFFFFFF
        self.lfsr ^= uid_val
        self.lfsr &= self.LFSR_MASK
        for _ in range(32):
            self._lfsr_clock()

    def _lfsr_clock(self) -> int:
        """Clock the LFSR once; return the feedback bit."""
        fb = (
            ((self.lfsr >> 0) & 1)
            ^ ((self.lfsr >> 5) & 1)
            ^ ((self.lfsr >> 9) & 1)
            ^ ((self.lfsr >> 10) & 1)
            ^ ((self.lfsr >> 12) & 1)
            ^ ((self.lfsr >> 14) & 1)
            ^ ((self.lfsr >> 15) & 1)
            ^ ((self.lfsr >> 17) & 1)
            ^ ((self.lfsr >> 19) & 1)
            ^ ((self.lfsr >> 24) & 1)
            ^ ((self.lfsr >> 25) & 1)
            ^ ((self.lfsr >> 27) & 1)
            ^ ((self.lfsr >> 29) & 1)
            ^ ((self.lfsr >> 35) & 1)
            ^ ((self.lfsr >> 39) & 1)
            ^ ((self.lfsr >> 41) & 1)
            ^ ((self.lfsr >> 43) & 1)
        )
        self.lfsr = ((self.lfsr << 1) | fb) & self.LFSR_MASK
        return fb

    def _filter_function(self) -> int:
        """Non-linear filter function over LFSR state."""
        x = self.lfsr
        return (
            ((x >> 0) & 1) ^ ((x >> 2) & 1) ^ ((x >> 5) & 1)
            ^ ((x >> 7) & 1) ^ ((x >> 8) & 1) ^ ((x >> 11) & 1)
            ^ ((x >> 13) & 1) ^ ((x >> 16) & 1) ^ ((x >> 18) & 1)
            ^ ((x >> 20) & 1) ^ ((x >> 22) & 1) ^ ((x >> 23) & 1)
            ^ ((x >> 26) & 1) ^ ((x >> 30) & 1) ^ ((x >> 31) & 1)
            ^ ((x >> 34) & 1) ^ ((x >> 36) & 1) ^ ((x >> 38) & 1)
            ^ ((x >> 40) & 1) ^ ((x >> 42) & 1) ^ ((x >> 44) & 1)
            ^ ((x >> 46) & 1) ^ ((x >> 47) & 1)
        )

    def generate_keystream(self, length: int) -> bytes:
        """Generate ``length`` bytes of Crypto-1 keystream."""
        ks = bytearray()
        for _ in range(length):
            byte_val = 0
            for _ in range(8):
                byte_val = (byte_val << 1) | self._filter_function()
                self._lfsr_clock()
            ks.append(byte_val)
        return bytes(ks)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with keystream (XOR — symmetric)."""
        ks = self.generate_keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data (same operation as encrypt)."""
        return self.encrypt(data)

    def authenticate(
        self, uid: bytes, block: int, key: bytes
    ) -> tuple[bytes | None, bytes | None]:
        """Perform 3-pass authentication for a given block.

        Returns
        -------
        tuple
            (nr, ar) — reader nonce and tag response, or (None, None).
        """
        nt = int.from_bytes(uid[:4], 'little') ^ block
        self.init_with_tag(key, uid, nt.to_bytes(4, 'little'))
        nr = self.generate_keystream(4)
        response = self.generate_keystream(4)
        return (nr, response)

    @staticmethod
    def crack_key(nonce: bytes, response: bytes, uid: bytes) -> bytes | None:
        """Crack a MIFARE Classic key via darkside/nested attack (STUB)."""
        return None
