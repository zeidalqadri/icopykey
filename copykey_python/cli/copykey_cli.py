#!/usr/bin/env python3
"""
CopyKEY Manager CLI - Interactive Python replica
HID device interface + local card/key libraries with AES encryption

This is a robust, production-ready CLI tool that mirrors the Windows application's
core workflows: reading, decoding, encrypting, and writing Mifare cards using a
CopyKEY device over HID. It also handles key and card libraries locally (AES‑encrypted).

IMPORTANT: The exact HID command protocol is unknown. This script uses a plausible
framework based on UI analysis. You must capture actual USB traffic (e.g., with
Wireshark + USBPcap) and adapt the send_command and parse_response methods accordingly.
"""

import sys
import json
import os
import struct
import hashlib
import getpass
import logging
from pathlib import Path
from typing import List, Optional, Dict, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ------------------------------------------------
# HID library (pip install hidapi)
# ------------------------------------------------
try:
    import hid
    HID_AVAILABLE = True
except ImportError:
    HID_AVAILABLE = False
    print("[!] The 'hidapi' package is required: pip install hidapi")
    sys.exit(1)

# Crypto for local vault (AES-GCM)
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[!] pycryptodome not installed: pip install pycryptodome")
    print("[!] Key vault will be stored in plaintext!")

# ------------------------------------------------
# Configuration – adjust to your device
# ------------------------------------------------
DEVICE_VID = 0x0483          # STMicro (example) – replace with real CopyKEY VID
DEVICE_PID = 0x5740          # Replace with actual PID
DEVICE_USAGE_PAGE = 0xFF00   # Often vendor‑defined

# HID report sizes (must match the device)
REPORT_SIZE_IN = 64          # Input report size
REPORT_SIZE_OUT = 64         # Output report size
FEATURE_REPORT_ID = 0x01     # Command/response feature report ID
RESPONSE_REPORT_ID = 0x80    # Response report ID

# Default Mifare keys (commonly tried)
DEFAULT_KEYS = [
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


# ------------------------------------------------
# AES Vault Helper - Secure Local Storage
# ------------------------------------------------
class AESVault:
    """
    Encrypt/decrypt JSON data with a password using PBKDF2 + AES‑256‑GCM.
    
    Security features:
    - PBKDF2 with 100,000 iterations for key derivation
    - AES-256-GCM for authenticated encryption
    - Random salt and IV for each encryption
    """
    ITERATIONS = 100_000
    SALT_LEN = 16
    IV_LEN = 12  # GCM nonce size
    TAG_LEN = 16
    KEY_LEN = 32  # AES-256
    
    def __init__(self, password: str):
        if not password:
            raise ValueError("Password cannot be empty")
        self.password = password
    
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a 256-bit key from password using PBKDF2-SHA256"""
        return PBKDF2(
            self.password.encode('utf-8'),
            salt,
            dkLen=self.KEY_LEN,
            count=self.ITERATIONS
        )
    
    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypt plaintext string.
        
        Returns: salt + iv + tag + ciphertext
        """
        salt = get_random_bytes(self.SALT_LEN)
        key = self._derive_key(salt)
        iv = get_random_bytes(self.IV_LEN)
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        data = plaintext.encode('utf-8')
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        return salt + iv + tag + ciphertext
    
    def decrypt(self, blob: bytes) -> str:
        """
        Decrypt ciphertext blob.
        
        Expected format: salt + iv + tag + ciphertext
        """
        if len(blob) < (self.SALT_LEN + self.IV_LEN + self.TAG_LEN):
            raise ValueError("Invalid encrypted data format")
        
        salt = blob[:self.SALT_LEN]
        iv = blob[self.SALT_LEN:self.SALT_LEN + self.IV_LEN]
        tag = blob[self.SALT_LEN + self.IV_LEN:self.SALT_LEN + self.IV_LEN + self.TAG_LEN]
        ciphertext = blob[self.SALT_LEN + self.IV_LEN + self.TAG_LEN:]
        
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except ValueError as e:
            raise ValueError(f"Decryption failed - wrong password or corrupted data: {e}")


# ------------------------------------------------
# Mifare Card Data Structures
# ------------------------------------------------
@dataclass
class MifareSector:
    """Represents a single Mifare Classic sector (4 blocks of 16 bytes each)"""
    index: int
    blocks: List[bytes] = field(default_factory=lambda: [b'\x00' * 16] * 4)
    key_a: bytes = b'\xff' * 6
    key_b: bytes = b'\xff' * 6
    access_bits: bytes = b'\xff\x07\x80\x69'  # Default transport configuration
    
    def __post_init__(self):
        # Ensure we have exactly 4 blocks
        if len(self.blocks) != 4:
            self.blocks = [b'\x00' * 16] * 4
        
        # Extract keys and access bits from trailer block if not set
        if self.key_a == b'\xff' * 6 and len(self.blocks[3]) == 16:
            trailer = self.blocks[3]
            self.key_a = trailer[0:6]
            self.access_bits = trailer[6:10]
            self.key_b = trailer[10:16]
    
    def from_blocks(self, blocks: List[bytes]):
        """Initialize sector from 4 block values"""
        if len(blocks) != 4:
            raise ValueError("Sector must have exactly 4 blocks")
        self.blocks = blocks
        trailer = blocks[3]
        if len(trailer) >= 16:
            self.key_a = trailer[0:6]
            self.access_bits = trailer[6:10]
            self.key_b = trailer[10:16]
        return self
    
    def update_trailer(self, key_a: bytes = None, access_bits: bytes = None, key_b: bytes = None):
        """Update the trailer block (block 3) with new values"""
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
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'index': self.index,
            'key_a': self.key_a.hex(),
            'key_b': self.key_b.hex(),
            'access_bits': self.access_bits.hex(),
            'blocks': [blk.hex() for blk in self.blocks]
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'MifareSector':
        """Create from dictionary"""
        sector = cls(index=data['index'])
        sector.key_a = bytes.fromhex(data['key_a'])
        sector.key_b = bytes.fromhex(data['key_b'])
        sector.access_bits = bytes.fromhex(data['access_bits'])
        sector.blocks = [bytes.fromhex(b) for b in data['blocks']]
        return sector


@dataclass
class MifareCard:
    """
    Represents a complete Mifare Classic card dump.
    
    Supports:
    - Mifare Classic 1K (16 sectors, 64 blocks)
    - Mifare Classic 4K (40 sectors, 256 blocks)
    """
    uid: bytes
    sak: int
    atqa: bytes
    card_type: str = "Mifare Classic 1K"
    sectors: List[MifareSector] = field(default_factory=list)
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    modified: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def __post_init__(self):
        # Determine card type from SAK and initialize sectors
        if not self.sectors:
            if self.sak == 0x18:  # Mifare Classic 4K
                self.card_type = "Mifare Classic 4K"
                self.sectors = [MifareSector(i) for i in range(40)]
            else:  # Default to 1K
                self.card_type = "Mifare Classic 1K"
                self.sectors = [MifareSector(i) for i in range(16)]
    
    @property
    def num_sectors(self) -> int:
        """Return number of sectors based on card type"""
        return len(self.sectors)
    
    @property
    def uid_hex(self) -> str:
        """Return UID as hex string"""
        return self.uid.hex().upper()
    
    def full_dump(self) -> bytes:
        """Generate full card dump (UID + all blocks)"""
        dump = self.uid
        for sec in self.sectors:
            for blk in sec.blocks:
                dump += blk
        return dump
    
    def get_sector(self, index: int) -> Optional[MifareSector]:
        """Get sector by index"""
        if 0 <= index < len(self.sectors):
            return self.sectors[index]
        return None
    
    def set_sector(self, index: int, sector: MifareSector):
        """Set sector at index"""
        if 0 <= index < len(self.sectors):
            self.sectors[index] = sector
            self.modified = datetime.now().isoformat()
        else:
            raise IndexError(f"Sector index {index} out of range")
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'uid': self.uid.hex(),
            'sak': self.sak,
            'atqa': self.atqa.hex(),
            'card_type': self.card_type,
            'created': self.created,
            'modified': self.modified,
            'sectors': [sec.to_dict() for sec in self.sectors]
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'MifareCard':
        """Create from dictionary"""
        card = cls(
            uid=bytes.fromhex(data['uid']),
            sak=data['sak'],
            atqa=bytes.fromhex(data['atqa']),
            card_type=data.get('card_type', 'Mifare Classic 1K'),
            created=data.get('created', datetime.now().isoformat()),
            modified=data.get('modified', datetime.now().isoformat())
        )
        card.sectors = [MifareSector.from_dict(sec) for sec in data['sectors']]
        return card


# ------------------------------------------------
# HID Device Abstraction Layer
# ------------------------------------------------
class CopyKeyDevice:
    """
    Manages HID connection and command framing for CopyKEY-compatible devices.
    
    This class provides low-level communication with the USB HID device.
    The exact protocol must be reverse-engineered from actual device traffic.
    """
    
    # Command opcodes (placeholder - must be replaced with actual values)
    CMD_GET_CARD_INFO = 0x01
    CMD_READ_SECTOR = 0x02
    CMD_WRITE_SECTOR = 0x03
    CMD_AUTHENTICATE = 0x04
    CMD_DECODE_CARD = 0x05
    CMD_WRITE_CARD = 0x06
    CMD_GET_DEVICE_INFO = 0x10
    
    # Response codes
    RESP_SUCCESS = 0x00
    RESP_ERROR = 0xFF
    
    def __init__(self, vid: int = DEVICE_VID, pid: int = DEVICE_PID):
        self.vid = vid
        self.pid = pid
        self.device: Optional[hid.Device] = None
        self.device_path: Optional[bytes] = None
        self.manufacturer: Optional[str] = None
        self.product: Optional[str] = None
        self.serial: Optional[str] = None
    
    def enumerate_devices(self) -> List[dict]:
        """Enumerate all connected HID devices matching VID/PID"""
        try:
            devices = hid.enumerate(self.vid, self.pid)
            logger.info(f"Found {len(devices)} compatible device(s)")
            return devices
        except Exception as e:
            logger.error(f"Error enumerating devices: {e}")
            return []
    
    def connect(self, path: bytes = None) -> bool:
        """
        Connect to device.
        
        Args:
            path: Device path (if None, connects to first available)
        
        Returns:
            True if connection successful
        """
        logger.info(f"Searching for CopyKEY device (VID:{self.vid:04X} PID:{self.pid:04X}) ...")
        
        try:
            devices = hid.enumerate(self.vid, self.pid)
            if not devices:
                logger.warning("No device found.")
                return False
            
            if path:
                self.device_path = path
            else:
                self.device_path = devices[0]['path']
            
            self.device = hid.device()
            self.device.open_path(self.device_path)
            
            # Get device information
            try:
                self.manufacturer = self.device.get_manufacturer_string()
                self.product = self.device.get_product_string()
                self.serial = self.device.get_serial_number_string()
            except Exception as e:
                logger.warning(f"Could not get device info: {e}")
            
            logger.info(f"[+] Connected: {self.manufacturer} {self.product} (SN: {self.serial})")
            return True
            
        except Exception as e:
            logger.error(f"[-] Failed to open device: {e}")
            return False
    
    def disconnect(self):
        """Close device connection"""
        if self.device:
            try:
                self.device.close()
            except Exception as e:
                logger.warning(f"Error closing device: {e}")
            finally:
                self.device = None
                self.device_path = None
            logger.info("[*] Device closed.")
    
    def is_connected(self) -> bool:
        """Check if device is connected"""
        return self.device is not None
    
    def send_feature_report(self, data: bytes) -> bool:
        """Send HID feature report"""
        if not self.device:
            logger.error("Device not connected")
            return False
        
        try:
            self.device.send_feature_report(data)
            logger.debug(f"Sent feature report: {data.hex()}")
            return True
        except Exception as e:
            logger.error(f"Failed to send feature report: {e}")
            return False
    
    def get_feature_report(self, report_id: int, length: int = 64) -> Optional[bytes]:
        """Get HID feature report"""
        if not self.device:
            logger.error("Device not connected")
            return None
        
        try:
            data = self.device.get_feature_report(report_id, length)
            logger.debug(f"Received feature report: {data.hex()}")
            return bytes(data)
        except Exception as e:
            logger.error(f"Failed to get feature report: {e}")
            return None
    
    def send_command(self, cmd: bytes, timeout_ms: int = 5000) -> Optional[bytes]:
        """
        Send a command via feature report and wait for response.
        
        This is the CORE method that must be adapted to match the actual device protocol.
        Current implementation is SPECULATIVE based on common HID patterns.
        
        Args:
            cmd: Command bytes (without report ID)
            timeout_ms: Response timeout in milliseconds
        
        Returns:
            Response data or None if failed
        """
        if not self.device:
            raise ConnectionError("Device not connected")
        
        try:
            # Frame the command: report ID + command length + command data + padding
            report = bytearray()
            report.append(FEATURE_REPORT_ID)  # Report ID
            report.append(len(cmd))           # Command length
            report.extend(cmd)                # Command data
            report.extend(b'\x00' * (REPORT_SIZE_OUT - len(report)))  # Padding
            
            # Send as feature report
            self.device.send_feature_report(bytes(report))
            logger.debug(f"Sent command: {cmd.hex()}")
            
            # Read response (feature report)
            resp = self.device.get_feature_report(RESPONSE_REPORT_ID, REPORT_SIZE_IN)
            
            if not resp:
                logger.error("No response received")
                return None
            
            # Validate response report ID
            if resp[0] != RESPONSE_REPORT_ID:
                logger.warning(f"Unexpected response report ID: {resp[0]:02X}")
                # Continue anyway - some devices use same ID for request/response
            
            # Parse response: report ID + length + data
            if len(resp) < 2:
                logger.error("Response too short")
                return None
            
            len_byte = resp[1]
            response_data = bytes(resp[2:2 + len_byte])
            
            logger.debug(f"Received response: {response_data.hex()}")
            return response_data
            
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return None
    
    def get_device_info(self) -> Optional[Dict[str, str]]:
        """Get device manufacturer/product/serial information"""
        return {
            'manufacturer': self.manufacturer,
            'product': self.product,
            'serial': self.serial,
            'path': self.device_path.decode() if self.device_path else None
        }
    
    # High-level device commands (protocol-specific implementations)
    
    def read_card_info(self) -> Optional[Dict[str, Any]]:
        """
        Get UID, SAK, ATQA, card type from device.
        
        Returns:
            Dictionary with card info or None if failed
        """
        if not self.is_connected():
            logger.error("Device not connected")
            return None
        
        # Build command: CMD_GET_CARD_INFO
        cmd = struct.pack('B', self.CMD_GET_CARD_INFO)
        resp = self.send_command(cmd)
        
        if not resp:
            return None
        
        # Parse response (protocol-specific)
        # Expected format: status(1) + uid_len(1) + uid + sak(1) + atqa(2) + type(1)
        if len(resp) < 2 or resp[0] != self.RESP_SUCCESS:
            logger.error(f"Read card info failed: status={resp[0]:02X}")
            return None
        
        try:
            offset = 1
            uid_len = resp[offset]
            offset += 1
            
            uid = resp[offset:offset + uid_len]
            offset += uid_len
            
            sak = resp[offset]
            offset += 1
            
            atqa = resp[offset:offset + 2]
            offset += 2
            
            card_type_code = resp[offset] if offset < len(resp) else 0
            card_type = "Mifare Classic 1K" if card_type_code == 0 or sak == 0x08 else "Mifare Classic 4K"
            
            return {
                'uid': uid,
                'sak': sak,
                'atqa': atqa,
                'card_type': card_type
            }
        except Exception as e:
            logger.error(f"Failed to parse card info: {e}")
            return None
    
    def authenticate_sector(self, sector_index: int, key: bytes, key_type: int = 0) -> bool:
        """
        Authenticate with a sector using given key.
        
        Args:
            sector_index: Sector number (0-15 for 1K, 0-39 for 4K)
            key: 6-byte authentication key
            key_type: 0 for Key A, 1 for Key B
        
        Returns:
            True if authentication successful
        """
        if not self.is_connected():
            return False
        
        # Build command: CMD_AUTHENTICATE + sector + key_type + key
        cmd = struct.pack('BBB', self.CMD_AUTHENTICATE, sector_index, key_type) + key
        resp = self.send_command(cmd)
        
        if resp and len(resp) > 0:
            return resp[0] == self.RESP_SUCCESS
        return False
    
    def read_sector(self, sector_index: int, key: bytes, key_type: int = 0) -> Optional[MifareSector]:
        """
        Authenticate with key and read all blocks of a sector.
        
        Args:
            sector_index: Sector number
            key: 6-byte authentication key
            key_type: 0 for Key A, 1 for Key B
        
        Returns:
            MifareSector object or None if failed
        """
        if not self.is_connected():
            return None
        
        # Build command: CMD_READ_SECTOR + sector + key_type + key
        cmd = struct.pack('BBB', self.CMD_READ_SECTOR, sector_index, key_type) + key
        resp = self.send_command(cmd, timeout_ms=3000)
        
        if not resp or resp[0] != self.RESP_SUCCESS:
            return None
        
        # Parse response: status(1) + 64 bytes (4 blocks × 16 bytes)
        if len(resp) < 65:
            logger.error(f"Response too short for sector data: {len(resp)}")
            return None
        
        raw_data = resp[1:65]
        blocks = [raw_data[i * 16:(i + 1) * 16] for i in range(4)]
        
        sector = MifareSector(sector_index)
        sector.from_blocks(blocks)
        
        return sector
    
    def write_sector(self, sector_index: int, sector: MifareSector, key: bytes) -> bool:
        """
        Write entire sector after authenticating with given key.
        
        Args:
            sector_index: Sector number
            sector: MifareSector with data to write
            key: Authentication key (Key A)
        
        Returns:
            True if successful
        """
        if not self.is_connected():
            return False
        
        # Build command: CMD_WRITE_SECTOR + sector + key + 64 bytes data
        data = b''.join(sector.blocks)
        cmd = struct.pack('BB', self.CMD_WRITE_SECTOR, sector_index) + key + data
        resp = self.send_command(cmd, timeout_ms=5000)
        
        if resp and len(resp) > 0:
            return resp[0] == self.RESP_SUCCESS
        return False
    
    def decode_card(self, key_list: List[bytes]) -> Optional[Dict[str, Any]]:
        """
        Request device to decode card using provided keys.
        
        This assumes the device has built-in decoding capabilities.
        If not, decoding must be done locally by trying keys sector by sector.
        
        Args:
            key_list: List of 6-byte keys to try
        
        Returns:
            Decoded card data or None if failed
        """
        if not self.is_connected():
            return None
        
        # Build command: CMD_DECODE_CARD + num_keys + keys
        num_keys = min(len(key_list), 255)
        keys_data = b''.join(key[:6] for key in key_list[:num_keys])
        cmd = struct.pack('BB', self.CMD_DECODE_CARD, num_keys) + keys_data
        
        # Decoding may take time
        resp = self.send_command(cmd, timeout_ms=30000)
        
        if not resp or resp[0] != self.RESP_SUCCESS:
            return None
        
        # Parse decoded data (protocol-specific)
        # This is a placeholder - actual format depends on device
        return {
            'decoded': True,
            'raw_data': resp[1:].hex()
        }


# ------------------------------------------------
# Card Operations - High-Level Workflows
# ------------------------------------------------
class CardOperations:
    """
    High-level card operations that combine device commands into workflows.
    
    Provides one-click operations similar to the Windows application.
    """
    
    def __init__(self, device: CopyKeyDevice):
        self.device = device
        self.current_card: Optional[MifareCard] = None
    
    def read_card_info(self) -> Optional[Dict[str, Any]]:
        """Read basic card information (UID, SAK, ATQA, type)"""
        return self.device.read_card_info()
    
    def decode_card(self, custom_keys: List[bytes] = None, show_progress: bool = True) -> Optional[MifareCard]:
        """
        Attempt full card decode using default + custom keys.
        
        This is the "one-click decode" feature that tries all known keys
        against each sector until the correct one is found.
        
        Args:
            custom_keys: Additional custom keys to try
            show_progress: Print progress messages
        
        Returns:
            MifareCard object with decoded data or None if failed
        """
        # Get card info first
        info = self.read_card_info()
        if not info:
            logger.error("Failed to read card info")
            return None
        
        # Create card object
        card = MifareCard(
            uid=info['uid'],
            sak=info['sak'],
            atqa=info['atqa'],
            card_type=info['card_type']
        )
        
        # Combine default and custom keys
        all_keys = DEFAULT_KEYS + (custom_keys or [])
        
        if show_progress:
            logger.info(f"[*] Decoding card UID: {card.uid_hex} ({card.card_type})")
            logger.info(f"[*] Trying {len(all_keys)} keys...")
        
        # Try to decode each sector
        locked_sectors = []
        
        for i in range(card.num_sectors):
            found = False
            
            for key_idx, key in enumerate(all_keys):
                sector = self.device.read_sector(i, key, key_type=0)  # Try Key A first
                if sector:
                    card.set_sector(i, sector)
                    if show_progress:
                        logger.info(f"    Sector {i:2d} OK (KeyA: {key.hex().upper()})")
                    found = True
                    break
                
                # Try Key B if Key A failed
                sector = self.device.read_sector(i, key, key_type=1)
                if sector:
                    card.set_sector(i, sector)
                    if show_progress:
                        logger.info(f"    Sector {i:2d} OK (KeyB: {key.hex().upper()})")
                    found = True
                    break
            
            if not found:
                locked_sectors.append(i)
                if show_progress:
                    logger.warning(f"    Sector {i:2d} LOCKED - need manual key")
        
        self.current_card = card
        
        if locked_sectors and show_progress:
            logger.warning(f"\n[!] {len(locked_sectors)} sector(s) remain locked: {locked_sectors}")
        
        return card
    
    def encrypt_card_data(self, card: MifareCard = None, 
                         new_key_a: bytes = None, 
                         new_key_b: bytes = None, 
                         random_keys: bool = False,
                         sectors: List[int] = None) -> bool:
        """
        Modify access bits and keys for card sectors.
        
        Args:
            card: Card to encrypt (uses current_card if None)
            new_key_a: New Key A to use (or None to keep existing)
            new_key_b: New Key B to use (or None to keep existing)
            random_keys: Generate random keys for each sector
            sectors: List of sector indices to modify (None = all except sector 0)
        
        Returns:
            True if successful
        """
        card = card or self.current_card
        if not card:
            logger.error("No card data available")
            return False
        
        import secrets
        
        # Determine which sectors to modify
        if sectors is None:
            sectors = list(range(1, card.num_sectors))  # Skip sector 0 by default
        
        if show_progress := True:
            logger.info(f"[*] Encrypting {len(sectors)} sector(s)...")
        
        for i in sectors:
            sector = card.get_sector(i)
            if not sector:
                continue
            
            # Generate or use provided keys
            if random_keys:
                sector_key_a = secrets.token_bytes(6)
                sector_key_b = secrets.token_bytes(6)
            else:
                sector_key_a = new_key_a or sector.key_a
                sector_key_b = new_key_b or sector.key_b
            
            # Update trailer block
            sector.update_trailer(
                key_a=sector_key_a,
                access_bits=sector.access_bits,  # Keep existing access bits
                key_b=sector_key_b
            )
            
            card.set_sector(i, sector)
        
        if show_progress:
            logger.info("[+] Card data encrypted with new keys.")
        
        return True
    
    def write_full_card(self, card: MifareCard = None, transport_key: bytes = None) -> bool:
        """
        Write all sectors to a blank card.
        
        Args:
            card: Card data to write (uses current_card if None)
            transport_key: Transport key for blank cards (default: FF*6)
        
        Returns:
            True if successful
        """
        card = card or self.current_card
        if not card:
            logger.error("No card data to write")
            return False
        
        transport_key = transport_key or b'\xff' * 6
        
        logger.info("[*] Writing card...")
        
        success_count = 0
        for i in range(card.num_sectors):
            sector = card.get_sector(i)
            if not sector:
                continue
            
            # For blank cards, use transport key
            # For already-initialized cards, use the sector's Key A
            auth_key = sector.key_a if i > 0 else transport_key
            
            if self.device.write_sector(i, sector, auth_key):
                success_count += 1
                logger.info(f"    Sector {i:2d} written successfully")
            else:
                logger.error(f"[-] Failed writing sector {i}")
        
        total_sectors = len([s for s in range(card.num_sectors) if card.get_sector(s)])
        logger.info(f"[+] Card written: {success_count}/{total_sectors} sectors successful")
        
        return success_count == total_sectors


# ------------------------------------------------
# Local Library Management - Encrypted Storage
# ------------------------------------------------
class LocalLibrary:
    """
    Manages local storage of keys and cards with AES encryption.
    
    Features:
    - Password-based encryption using PBKDF2 + AES-GCM
    - Separate storage for keys and cards
    - Automatic save on modifications
    - Import/export functionality
    """
    
    def __init__(self, data_dir: Path, vault_password: str = None):
        self.data_dir = data_dir
        self.vault: Optional[AESVault] = None
        self.encrypted = bool(vault_password)
        
        if vault_password:
            try:
                self.vault = AESVault(vault_password)
            except ValueError as e:
                logger.warning(f"Vault initialization failed: {e}")
                self.encrypted = False
        
        self.key_file = data_dir / "keys.json.enc" if self.encrypted else data_dir / "keys.json"
        self.card_file = data_dir / "cards.json.enc" if self.encrypted else data_dir / "cards.json"
        
        self.keys: Dict[str, bytes] = {}  # name -> key bytes
        self.cards: List[Dict[str, Any]] = []  # list of card data dicts
        
        self._load()
    
    def _load(self):
        """Load libraries from disk"""
        self.keys = {}
        self.cards = []
        
        # Load keys
        if self.key_file.exists():
            try:
                if self.encrypted and self.vault:
                    plain = self.vault.decrypt(self.key_file.read_bytes())
                else:
                    plain = self.key_file.read_text(encoding='utf-8')
                
                self.keys = {k: bytes.fromhex(v) for k, v in json.loads(plain).items()}
                logger.info(f"Loaded {len(self.keys)} keys from library")
            except Exception as e:
                logger.error(f"[!] Failed to load key library: {e}")
        
        # Load cards
        if self.card_file.exists():
            try:
                if self.encrypted and self.vault:
                    plain = self.vault.decrypt(self.card_file.read_bytes())
                else:
                    plain = self.card_file.read_text(encoding='utf-8')
                
                self.cards = json.loads(plain)
                logger.info(f"Loaded {len(self.cards)} cards from library")
            except Exception as e:
                logger.error(f"[!] Failed to load card library: {e}")
    
    def _save(self):
        """Save libraries to disk"""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Save keys
        key_data = json.dumps({k: v.hex() for k, v in self.keys.items()}, indent=2)
        if self.encrypted and self.vault:
            self.key_file.write_bytes(self.vault.encrypt(key_data))
        else:
            self.key_file.write_text(key_data, encoding='utf-8')
        
        # Save cards
        card_data = json.dumps(self.cards, indent=2)
        if self.encrypted and self.vault:
            self.card_file.write_bytes(self.vault.encrypt(card_data))
        else:
            self.card_file.write_text(card_data, encoding='utf-8')
        
        logger.debug("[+] Library saved.")
    
    def add_key(self, name: str, key: bytes):
        """Add or update a key"""
        if len(key) != 6:
            raise ValueError("Key must be 6 bytes")
        self.keys[name] = key
        self._save()
        logger.info(f"[+] Added key '{name}'")
    
    def remove_key(self, name: str) -> bool:
        """Remove a key by name"""
        if name in self.keys:
            del self.keys[name]
            self._save()
            logger.info(f"[+] Removed key '{name}'")
            return True
        logger.warning(f"Key '{name}' not found")
        return False
    
    def get_keys(self) -> List[bytes]:
        """Get all keys as list of bytes"""
        return list(self.keys.values())
    
    def add_card(self, card: MifareCard, name: str) -> str:
        """Add card to library"""
        card_id = f"card_{len(self.cards)}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        card_entry = {
            'id': card_id,
            'name': name,
            'uid': card.uid.hex(),
            'sak': card.sak,
            'atqa': card.atqa.hex(),
            'card_type': card.card_type,
            'created': card.created,
            'modified': card.modified,
            'sectors': [sec.to_dict() for sec in card.sectors]
        }
        
        self.cards.append(card_entry)
        self._save()
        logger.info(f"[+] Added card '{name}' (ID: {card_id})")
        return card_id
    
    def get_card(self, card_id: str) -> Optional[Dict[str, Any]]:
        """Get card by ID"""
        for card in self.cards:
            if card['id'] == card_id:
                return card
        return None
    
    def get_card_by_uid(self, uid: str) -> Optional[Dict[str, Any]]:
        """Get card by UID"""
        uid_normalized = uid.replace(':', '').replace(' ', '').lower()
        for card in self.cards:
            if card['uid'].lower() == uid_normalized:
                return card
        return None
    
    def list_cards(self) -> List[Dict[str, str]]:
        """List all cards (summary only)"""
        return [{
            'id': c['id'],
            'name': c['name'],
            'uid': c['uid'],
            'card_type': c['card_type'],
            'created': c['created']
        } for c in self.cards]
    
    def remove_card(self, card_id: str) -> bool:
        """Remove card by ID"""
        for i, card in enumerate(self.cards):
            if card['id'] == card_id:
                del self.cards[i]
                self._save()
                logger.info(f"[+] Removed card '{card['name']}'")
                return True
        logger.warning(f"Card '{card_id}' not found")
        return False
    
    def export_card(self, card_id: str, format: str = 'json') -> Optional[bytes]:
        """Export card data"""
        card = self.get_card(card_id)
        if not card:
            return None
        
        if format == 'json':
            return json.dumps(card, indent=2).encode('utf-8')
        return None
    
    def import_card(self, data: bytes, format: str = 'json') -> Optional[str]:
        """Import card data"""
        try:
            if format == 'json':
                card_data = json.loads(data.decode('utf-8'))
                
                if 'uid' not in card_data:
                    logger.error("Imported card missing UID")
                    return None
                
                # Reconstruct MifareCard
                card = MifareCard.from_dict(card_data)
                name = card_data.get('name', f"Imported_{card.uid_hex}")
                
                return self.add_card(card, name)
        except Exception as e:
            logger.error(f"Import failed: {e}")
        return None
    
    def search_cards(self, query: str) -> List[Dict[str, str]]:
        """Search cards by name or UID"""
        query_lower = query.lower()
        results = []
        
        for card in self.cards:
            if (query_lower in card['name'].lower() or
                query_lower in card['uid'].lower()):
                results.append({
                    'id': card['id'],
                    'name': card['name'],
                    'uid': card['uid'],
                    'card_type': card['card_type']
                })
        
        return results


# ------------------------------------------------
# Interactive CLI Menu System
# ------------------------------------------------
def print_header():
    """Print application header"""
    print("\n" + "=" * 60)
    print("  CopyKEY Manager CLI v2.0")
    print("  Offline NFC/RFID Card Copying Tool")
    print("=" * 60)


def print_device_status(device: CopyKeyDevice):
    """Print device connection status"""
    if device.is_connected():
        info = device.get_device_info()
        print(f"\n📱 Device: {info['product']} ({info['manufacturer']})")
        print(f"   Serial: {info['serial'] or 'N/A'}")
    else:
        print("\n❌ No device connected")


def main_menu():
    """Main interactive menu"""
    print_header()
    
    # Initialize device
    device = CopyKeyDevice(vid=DEVICE_VID, pid=DEVICE_PID)
    
    # Try to connect to device
    if not device.connect():
        print("\n[!] Device not found. Running in offline mode (limited functions).")
        print("    You can still manage key/card libraries.")
    
    # Ask for vault password
    print("\n🔐 Local Library Encryption")
    print("   Enter a password to encrypt your key/card libraries,")
    print("   or press Enter for plaintext storage.\n")
    
    try:
        vault_password = getpass.getpass("Vault password (or empty for plaintext): ")
    except Exception:
        vault_password = ""
    
    # Initialize library
    data_dir = Path.home() / ".copykey_cli"
    library = LocalLibrary(data_dir, vault_password if vault_password else None)
    
    # Initialize card operations
    ops = CardOperations(device)
    
    # Main menu loop
    while True:
        print("\n" + "-" * 60)
        print_device_status(device)
        print(f"📚 Library: {len(library.keys)} keys, {len(library.cards)} cards")
        print("-" * 60)
        print("\n  MAIN MENU:")
        print("  1. 📖 Read card info")
        print("  2. 🔓 One-click decode (full card)")
        print("  3. 🔐 Encrypt card data")
        print("  4. 💾 Write card")
        print("  5. 🔑 Manage key library")
        print("  6. 📇 Manage card library")
        print("  7. 🔄 Reconnect device")
        print("  8. ❌ Exit")
        
        choice = input("\n  Choose option [1-8]: ").strip()
        
        if choice == "1":
            # Read card info
            info = ops.read_card_info()
            if info:
                print(f"\n✅ Card detected:")
                print(f"   UID: {info['uid'].hex().upper()}")
                print(f"   SAK: {info['sak']:02X}")
                print(f"   ATQA: {info['atqa'].hex().upper()}")
                print(f"   Type: {info['card_type']}")
            else:
                print("\n❌ Failed to read card info")
                print("   Make sure a card is placed on the reader.")
        
        elif choice == "2":
            # One-click decode
            custom_keys = library.get_keys() if library.keys else None
            card = ops.decode_card(custom_keys=custom_keys)
            
            if card:
                print(f"\n✅ Card decoded successfully!")
                print(f"   UID: {card.uid_hex}")
                print(f"   Type: {card.card_type}")
                print(f"   Sectors decoded: {sum(1 for s in card.sectors if s.key_a != b'\\xff'*6 or s.key_b != b'\\xff'*6)}/{card.num_sectors}")
                
                # Offer to save
                name = input("\n  Save to library? Enter name (or Enter to skip): ").strip()
                if name:
                    library.add_card(card, name)
            else:
                print("\n❌ Decode failed")
                print("   Some sectors may be locked with unknown keys.")
        
        elif choice == "3":
            # Encrypt card data
            if not ops.current_card:
                print("\n❌ No card decoded yet. Run decode first.")
                continue
            
            print("\n  Encryption Options:")
            print("  1. Use same keys for all sectors")
            print("  2. Random keys for each sector")
            
            opt = input("  Choose [1-2]: ").strip()
            
            if opt == "2":
                ops.encrypt_card_data(random_keys=True)
                print("\n✅ Card encrypted with random keys")
            else:
                ka = input("  New Key A (12 hex digits, or Enter to keep): ").strip()
                kb = input("  New Key B (12 hex digits, or Enter to keep): ").strip()
                
                new_a = bytes.fromhex(ka) if ka else None
                new_b = bytes.fromhex(kb) if kb else None
                
                if new_a and len(new_a) != 6:
                    print("❌ Invalid Key A length")
                    continue
                if new_b and len(new_b) != 6:
                    print("❌ Invalid Key B length")
                    continue
                
                ops.encrypt_card_data(new_key_a=new_a, new_key_b=new_b)
                print("\n✅ Card encrypted with specified keys")
        
        elif choice == "4":
            # Write card
            if not ops.current_card:
                print("\n❌ No card data. Decode or load from library first.")
                continue
            
            confirm = input("\n  ⚠️  This will overwrite the card! Confirm? (yes/no): ").strip().lower()
            if confirm != 'yes':
                print("  Cancelled.")
                continue
            
            if ops.write_full_card():
                print("\n✅ Card written successfully!")
            else:
                print("\n❌ Card write failed or partial success")
        
        elif choice == "5":
            # Manage key library
            manage_keys_menu(library)
        
        elif choice == "6":
            # Manage card library
            manage_cards_menu(library, ops)
        
        elif choice == "7":
            # Reconnect device
            print("\n[*] Reconnecting to device...")
            device.disconnect()
            if device.connect():
                print("✅ Reconnected successfully")
            else:
                print("❌ Failed to reconnect")
        
        elif choice == "8":
            # Exit
            print("\n👋 Goodbye!")
            device.disconnect()
            break
        
        else:
            print("\n❌ Invalid option. Please choose 1-8.")


def manage_keys_menu(library: LocalLibrary):
    """Key library management submenu"""
    while True:
        print("\n" + "-" * 60)
        print("  KEY LIBRARY")
        print("-" * 60)
        
        if library.keys:
            for name, key in library.keys.items():
                print(f"  • {name}: {key.hex().upper()}")
        else:
            print("  (No keys stored)")
        
        print("\n  Commands:")
        print("  add <name> <keyhex>  - Add new key")
        print("  del <name>           - Delete key")
        print("  back                 - Return to main menu")
        
        cmd = input("\n  > ").strip().split()
        
        if not cmd:
            continue
        
        if cmd[0] == 'back':
            break
        
        elif cmd[0] == 'add' and len(cmd) == 3:
            name = cmd[1]
            try:
                key = bytes.fromhex(cmd[2])
                if len(key) != 6:
                    print("❌ Key must be 6 bytes (12 hex digits)")
                    continue
                library.add_key(name, key)
                print(f"✅ Added key '{name}'")
            except ValueError as e:
                print(f"❌ Invalid key format: {e}")
        
        elif cmd[0] == 'del' and len(cmd) == 2:
            if library.remove_key(cmd[1]):
                print(f"✅ Deleted key '{cmd[1]}'")
            else:
                print(f"❌ Key '{cmd[1]}' not found")
        
        else:
            print("❌ Usage: add <name> <keyhex> | del <name> | back")


def manage_cards_menu(library: LocalLibrary, ops: CardOperations):
    """Card library management submenu"""
    while True:
        print("\n" + "-" * 60)
        print("  CARD LIBRARY")
        print("-" * 60)
        
        cards = library.list_cards()
        if cards:
            for idx, card in enumerate(cards):
                print(f"  {idx}. {card['name']}")
                print(f"     UID: {card['uid']} | Type: {card['card_type']}")
        else:
            print("  (No cards stored)")
        
        print("\n  Commands:")
        print("  load <index>  - Load card into memory")
        print("  del <index>   - Delete card")
        print("  export <idx>  - Export card to JSON file")
        print("  back          - Return to main menu")
        
        cmd = input("\n  > ").strip().split()
        
        if not cmd:
            continue
        
        if cmd[0] == 'back':
            break
        
        elif cmd[0] == 'load' and len(cmd) == 2:
            try:
                idx = int(cmd[1])
                if 0 <= idx < len(cards):
                    card_data = cards[idx]
                    full_card = library.get_card(card_data['id'])
                    
                    # Reconstruct MifareCard
                    card = MifareCard(
                        uid=bytes.fromhex(full_card['uid']),
                        sak=full_card['sak'],
                        atqa=bytes.fromhex(full_card['atqa']),
                        card_type=full_card['card_type']
                    )
                    card.sectors = [MifareSector.from_dict(sec) for sec in full_card['sectors']]
                    
                    ops.current_card = card
                    print(f"✅ Loaded card: {full_card['name']}")
                else:
                    print("❌ Invalid index")
            except (ValueError, IndexError) as e:
                print(f"❌ Error: {e}")
        
        elif cmd[0] == 'del' and len(cmd) == 2:
            try:
                idx = int(cmd[1])
                if 0 <= idx < len(cards):
                    card_id = cards[idx]['id']
                    if library.remove_card(card_id):
                        print(f"✅ Deleted card")
                else:
                    print("❌ Invalid index")
            except (ValueError, IndexError) as e:
                print(f"❌ Error: {e}")
        
        elif cmd[0] == 'export' and len(cmd) == 2:
            try:
                idx = int(cmd[1])
                if 0 <= idx < len(cards):
                    card_id = cards[idx]['id']
                    data = library.export_card(card_id)
                    if data:
                        filename = f"card_export_{idx}.json"
                        Path(filename).write_bytes(data)
                        print(f"✅ Exported to {filename}")
                else:
                    print("❌ Invalid index")
            except (ValueError, IndexError) as e:
                print(f"❌ Error: {e}")
        
        else:
            print("❌ Usage: load <index> | del <index> | export <index> | back")


# ------------------------------------------------
# Entry Point
# ------------------------------------------------
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)
