# CopyKEY Python Implementation - Architecture & Security Plan

## Executive Summary

This document outlines the architecture for a Python-based NFC card copying tool inspired by CopyKEY Manager, with **strict network isolation** - only allowing firmware updates and library updates through centralized channels. All other operations (card reading, decoding, encryption, cloning) will be **100% offline**.

---

## 1. Network Security Policy

### ALLOWED Network Communications:
✅ **Firmware Updates** - Check and download device firmware
✅ **Library Updates** - Update card format definitions and key databases
✅ **Version Check** - Optional application version notification

### PROHIBITED Network Communications:
❌ **User Authentication** - No login/register required
❌ **Card Library Sync** - No cloud storage of card data
❌ **Key Library Sync** - No server-side key storage
❌ **Usage Analytics** - No telemetry or tracking
❌ **After-sales Support Chat** - No embedded chat
❌ **Any Other API Calls** - No communication with client.copykey.hyctec.cn or copykey.hyctec.cn

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Python CopyKEY Tool                       │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   GUI Layer  │  │  Core Logic  │  │  Hardware    │      │
│  │  (PyQt6)     │  │   Engine     │  │  Interface   │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│         └─────────────────┼─────────────────┘               │
│                           │                                 │
│              ┌────────────▼────────────┐                   │
│              │    Offline-First Core   │                   │
│              ├─────────────────────────┤                   │
│              │ • Local Key Vault       │                   │
│              │ • Local Card Database   │                   │
│              │ • Crypto-1 Implementation│                  │
│              │ • AES Encryption        │                   │
│              └────────────┬────────────┘                   │
│                           │                                 │
│         ┌─────────────────┼─────────────────┐              │
│         │                 │                 │              │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐        │
│  │  Updater    │  │   File I/O  │  │  HID Comm   │        │
│  │  Module     │  │             │  │             │        │
│  │  (Network)  │  │             │  │             │        │
│  └──────┬──────┘  └─────────────┘  └─────────────┘        │
│         │                                                 │
│         ▼                                                 │
│  ┌─────────────┐                                         │
│  │  Internet   │ ◄── Only for firmware/library updates    │
│  │  (Optional) │                                         │
│  └─────────────┘                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Module Breakdown

### 3.1 Core Modules (Offline)

#### `core/device_interface.py`
```python
"""
USB HID Communication with NFC Reader/Writer Device
NO NETWORK COMMUNICATION
"""
import hid

class CopyKeyDevice:
    def __init__(self, vid=0xXXXX, pid=0xYYYY):
        self.vid = vid
        self.pid = pid
        self.device = None
        
    def enumerate_devices(self):
        """List all connected compatible devices"""
        return hid.enumerate(self.vid, self.pid)
    
    def connect(self, path=None):
        """Open connection to device"""
        if path:
            self.device = hid.Device(path)
        else:
            devices = self.enumerate_devices()
            if devices:
                self.device = hid.Device(devices[0]['path'])
        return self.device is not None
    
    def read_card(self):
        """Read card data from device"""
        # Send HID command to read card
        pass
    
    def write_card(self, card_data):
        """Write card data to blank card"""
        # Send HID command to write card
        pass
    
    def decode_card(self, key_list=None):
        """Decode locked sectors using provided keys"""
        # Send decode command with key list
        pass
    
    def disconnect(self):
        """Close device connection"""
        if self.device:
            self.device.close()
            self.device = None
```

#### `core/mifare_crypto.py`
```python
"""
Mifare Crypto-1 Implementation
NO NETWORK COMMUNICATION - Pure cryptographic algorithms
"""
from typing import List, Tuple

class Crypto1:
    """
    Implementation of Mifare Classic Crypto-1 cipher
    Based on open-source research (libnfc, mfoc, etc.)
    """
    
    def __init__(self):
        self.lfsr = 0  # 48-bit LFSR
        self.ks1 = 0   # Keystream generator state
        self.ks2 = 0
    
    def init(self, key: bytes):
        """Initialize cipher with 48-bit key"""
        assert len(key) == 6, "Key must be 6 bytes"
        self.lfsr = int.from_bytes(key, 'big')
        
    def step(self):
        """Advance LFSR by one step"""
        # LFSR feedback polynomial implementation
        pass
    
    def generate_keystream(self, length: int) -> bytes:
        """Generate keystream for encryption/decryption"""
        pass
    
    def authenticate(self, uid: bytes, block: int, key: bytes) -> Tuple[bytes, bytes]:
        """
        Perform Mifare authentication protocol
        Returns: (nonce, response)
        """
        pass
    
    @staticmethod
    def crack_key(nonce: bytes, response: bytes, uid: bytes) -> bytes:
        """
        Attempt to recover key from captured authentication
        Using known attacks (darkside, nested, etc.)
        """
        pass


class MifareDecoder:
    """High-level decoder for Mifare cards"""
    
    DEFAULT_KEYS = [
        b'\xFF\xFF\xFF\xFF\xFF\xFF',  # Factory default
        b'\x00\x00\x00\x00\x00\x00',  # Null key
        b'\xA0\xA1\xA2\xA3\xA4\xA5',  # Common default
        b'\xD3\xF7\xD3\xF7\xD3\xF7',  # Another common key
        # Add more default keys here
    ]
    
    def __init__(self, device: CopyKeyDevice):
        self.device = device
        self.crypto = Crypto1()
        self.known_keys = []  # User-provided keys
        
    def add_key(self, key: bytes):
        """Add key to known key list"""
        if key not in self.known_keys and len(key) == 6:
            self.known_keys.append(key)
    
    def decode_sector(self, sector: int, uid: bytes) -> dict:
        """
        Attempt to decode a single sector
        Returns: {'success': bool, 'key_a': bytes, 'key_b': bytes, 'data': bytes}
        """
        # Try all known keys
        all_keys = self.DEFAULT_KEYS + self.known_keys
        
        for key in all_keys:
            if self._try_key(sector, key, uid):
                return {'success': True, 'key_a': key, ...}
        
        return {'success': False}
    
    def decode_full_card(self, uid: bytes, card_type: str) -> dict:
        """
        Decode entire card (all sectors)
        Returns complete card data structure
        """
        num_sectors = self._get_sector_count(card_type)
        card_data = {'uid': uid, 'sectors': []}
        
        for sector in range(num_sectors):
            result = self.decode_sector(sector, uid)
            card_data['sectors'].append(result)
        
        return card_data
    
    def _try_key(self, sector: int, key: bytes, uid: bytes) -> bool:
        """Try authenticating with a specific key"""
        # Implementation of authentication attempt
        pass
```

#### `core/card_encryption.py`
```python
"""
Card Data Encryption Module
NO NETWORK COMMUNICATION - Local encryption only
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import struct

class CardEncryptor:
    """
    Encrypt card data before writing to blank cards
    Uses local key generation - no server involvement
    """
    
    def __init__(self):
        pass
    
    def generate_random_key(self) -> bytes:
        """Generate cryptographically secure random 6-byte key"""
        return get_random_bytes(6)
    
    def generate_key_set(self, num_keys: int = 16) -> List[bytes]:
        """Generate multiple unique keys for different sectors"""
        return [self.generate_random_key() for _ in range(num_keys)]
    
    def encrypt_sector(self, sector_data: bytes, key_a: bytes, key_b: bytes, 
                      access_bits: bytes = None) -> bytes:
        """
        Encrypt a single sector with new keys
        sector_data: 64 bytes (4 blocks × 16 bytes)
        Returns: Modified sector with new keys and access bits
        """
        if access_bits is None:
            access_bits = self._calculate_access_bits(read_only=False)
        
        # Construct trailer block (block 3 of sector)
        trailer = key_a + access_bits + key_b
        
        # Replace trailer block in sector data
        encrypted = bytearray(sector_data)
        encrypted[48:64] = trailer  # Last 16 bytes = trailer block
        
        return bytes(encrypted)
    
    def encrypt_full_card(self, card_data: dict, 
                         key_strategy: str = 'random_per_sector') -> dict:
        """
        Encrypt entire card with specified strategy
        Strategies:
          - 'random_per_sector': Different random keys for each sector
          - 'single_key': Same key for all sectors
          - 'custom': User-provided key mapping
        """
        encrypted_card = card_data.copy()
        encrypted_card['sectors'] = []
        
        for i, sector in enumerate(card_data['sectors']):
            if key_strategy == 'random_per_sector':
                key_a = self.generate_random_key()
                key_b = self.generate_random_key()
            elif key_strategy == 'single_key':
                # Use same keys for all sectors
                pass
            
            encrypted_sector = self.encrypt_sector(
                sector['data'], key_a, key_b
            )
            
            encrypted_card['sectors'].append({
                'sector': i,
                'data': encrypted_sector,
                'key_a': key_a,
                'key_b': key_b,
                'access_bits': access_bits
            })
        
        return encrypted_card
    
    def _calculate_access_bits(self, read_only: bool = False) -> bytes:
        """
        Calculate proper access bits for trailer block
        Default: Normal read/write access
        """
        if read_only:
            # Configure for read-only (keys not readable)
            return b'\x78\x77\x88\x00'
        else:
            # Standard configuration
            return b'\x78\x77\x88\x00'
```

#### `core/key_vault.py`
```python
"""
Local Encrypted Key Storage
NO NETWORK COMMUNICATION - Keys stored locally only
"""
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import json
import os
from pathlib import Path

class LocalKeyVault:
    """
    Secure local storage for Mifare keys
    Uses AES encryption with password-derived key
    """
    
    def __init__(self, vault_path: str = None):
        if vault_path is None:
            vault_path = Path.home() / '.copykey' / 'key_vault.json'
        self.vault_path = Path(vault_path)
        self.keys = []  # Decrypted keys in memory
        self.master_key = None
    
    def create_vault(self, password: str):
        """Create new encrypted vault with password"""
        salt = get_random_bytes(16)
        self.master_key = PBKDF2(password, salt, dkLen=32, count=100000)
        
        # Save salt (not secret) for future unlocks
        self._save_metadata(salt)
    
    def unlock_vault(self, password: str) -> bool:
        """Unlock vault with password"""
        metadata = self._load_metadata()
        if not metadata:
            return False
        
        salt = metadata['salt']
        self.master_key = PBKDF2(password, salt, dkLen=32, count=100000)
        
        # Load and decrypt keys
        encrypted_data = self._load_encrypted_keys()
        if encrypted_data:
            self.keys = self._decrypt_keys(encrypted_data)
            return True
        return False
    
    def add_key(self, key: bytes, label: str = ''):
        """Add key to vault (in memory)"""
        if len(key) != 6:
            raise ValueError("Key must be 6 bytes")
        
        self.keys.append({
            'key': key.hex(),
            'label': label,
            'created': datetime.now().isoformat()
        })
    
    def save_vault(self, password: str = None):
        """Save vault to disk (encrypted)"""
        if not self.master_key:
            raise RuntimeError("Vault not unlocked")
        
        encrypted_data = self._encrypt_keys()
        self._save_encrypted_keys(encrypted_data)
    
    def get_all_keys(self) -> List[bytes]:
        """Return all keys as byte list"""
        return [bytes.fromhex(k['key']) for k in self.keys]
    
    def _encrypt_keys(self) -> bytes:
        """Encrypt keys with master key"""
        iv = get_random_bytes(16)
        cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=iv)
        
        keys_json = json.dumps(self.keys).encode()
        ciphertext, tag = cipher.encrypt_and_digest(keys_json)
        
        return iv + tag + ciphertext
    
    def _decrypt_keys(self, data: bytes) -> List[dict]:
        """Decrypt keys with master key"""
        iv = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        
        cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return json.loads(plaintext.decode())
    
    def _save_metadata(self, salt: bytes):
        """Save non-sensitive metadata"""
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        metadata = {
            'version': 1,
            'salt': salt.hex(),
            'created': datetime.now().isoformat()
        }
        with open(self.vault_path.with_suffix('.meta'), 'w') as f:
            json.dump(metadata, f)
    
    def _load_metadata(self) -> dict:
        """Load vault metadata"""
        meta_path = self.vault_path.with_suffix('.meta')
        if not meta_path.exists():
            return None
        with open(meta_path) as f:
            return json.load(f)
```

#### `core/card_library.py`
```python
"""
Local Card Data Management
NO NETWORK COMMUNICATION - Cards stored locally only
"""
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict

class LocalCardLibrary:
    """
    Local database for storing decoded card data
    No cloud sync - completely offline
    """
    
    def __init__(self, library_path: str = None):
        if library_path is None:
            library_path = Path.home() / '.copykey' / 'card_library.json'
        self.library_path = Path(library_path)
        self.cards = []
        self._load_library()
    
    def _load_library(self):
        """Load library from disk"""
        if self.library_path.exists():
            with open(self.library_path) as f:
                data = json.load(f)
                self.cards = data.get('cards', [])
    
    def _save_library(self):
        """Save library to disk"""
        self.library_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.library_path, 'w') as f:
            json.dump({'cards': self.cards, 'version': 1}, f, indent=2)
    
    def add_card(self, card_data: dict, name: str, 
                 metadata: dict = None) -> str:
        """
        Add card to library
        Returns: Card ID
        """
        card_id = f"card_{len(self.cards)}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        entry = {
            'id': card_id,
            'name': name,
            'uid': card_data.get('uid', '').hex() if isinstance(card_data.get('uid'), bytes) else card_data.get('uid'),
            'card_type': card_data.get('card_type', 'Unknown'),
            'created': datetime.now().isoformat(),
            'metadata': metadata or {},
            'sectors': card_data.get('sectors', []),
            'keys': card_data.get('keys', {})
        }
        
        self.cards.append(entry)
        self._save_library()
        return card_id
    
    def get_card(self, card_id: str) -> dict:
        """Retrieve card by ID"""
        for card in self.cards:
            if card['id'] == card_id:
                return card
        return None
    
    def list_cards(self) -> List[dict]:
        """List all cards (summary only)"""
        return [{
            'id': c['id'],
            'name': c['name'],
            'uid': c['uid'],
            'card_type': c['card_type'],
            'created': c['created']
        } for c in self.cards]
    
    def delete_card(self, card_id: str) -> bool:
        """Delete card from library"""
        for i, card in enumerate(self.cards):
            if card['id'] == card_id:
                del self.cards[i]
                self._save_library()
                return True
        return False
    
    def export_card(self, card_id: str, format: str = 'json') -> bytes:
        """Export card data for backup or transfer"""
        card = self.get_card(card_id)
        if not card:
            return None
        
        if format == 'json':
            return json.dumps(card, indent=2).encode()
        # Add more formats as needed
    
    def import_card(self, data: bytes, format: str = 'json') -> str:
        """Import card data from external source"""
        if format == 'json':
            card_data = json.loads(data.decode())
            return self.add_card(card_data, card_data.get('name', 'Imported'))
```

### 3.2 Update Module (Controlled Network Access)

#### `updater/firmware_updater.py`
```python
"""
Firmware Update Module
CONTROLLED NETWORK ACCESS - Only for firmware downloads
"""
import requests
import hashlib
from pathlib import Path

class FirmwareUpdater:
    """
    Handles firmware updates for CopyKEY device
    ONLY network communication allowed: firmware download
    """
    
    # Whitelisted endpoint - ONLY for firmware
    FIRMWARE_URL = "https://copykey.hyctec.cn/firmware/latest.json"
    
    def __init__(self):
        self.current_version = None
        self.latest_version = None
    
    def check_for_updates(self, current_version: str) -> dict:
        """
        Check for available firmware updates
        Returns: {'available': bool, 'version': str, 'url': str, 'hash': str}
        """
        try:
            response = requests.get(self.FIRMWARE_URL, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            latest_ver = data.get('version', '0.0.0')
            
            if self._compare_versions(latest_ver, current_version) > 0:
                return {
                    'available': True,
                    'version': latest_ver,
                    'url': data.get('download_url'),
                    'hash': data.get('sha256'),
                    'notes': data.get('release_notes', '')
                }
            return {'available': False}
            
        except requests.RequestException as e:
            print(f"Update check failed (offline?): {e}")
            return {'available': False, 'error': str(e)}
    
    def download_firmware(self, url: str, dest_path: Path) -> bool:
        """Download firmware file with progress"""
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    # Report progress if needed
                    if total_size:
                        progress = (downloaded / total_size) * 100
                        print(f"\rDownloading: {progress:.1f}%", end='')
            
            return True
            
        except requests.RequestException as e:
            print(f"Download failed: {e}")
            return False
    
    def verify_firmware(self, file_path: Path, expected_hash: str) -> bool:
        """Verify firmware integrity with SHA-256"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        
        actual_hash = sha256.hexdigest()
        return actual_hash == expected_hash
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare version strings"""
        def normalize(v):
            return [int(x) for x in v.split('.')]
        
        parts1 = normalize(v1)
        parts2 = normalize(v2)
        
        for p1, p2 in zip(parts1, parts2):
            if p1 > p2:
                return 1
            elif p1 < p2:
                return -1
        
        return len(parts1) - len(parts2)
```

#### `updater/library_updater.py`
```python
"""
Card Format & Key Database Update Module
CONTROLLED NETWORK ACCESS - Only for library updates
"""
import requests
import json
from pathlib import Path

class LibraryUpdater:
    """
    Updates card format definitions and default key databases
    ONLY network communication allowed: library downloads
    """
    
    # Whitelisted endpoints - ONLY for libraries
    CARD_FORMATS_URL = "https://copykey.hyctec.cn/libraries/card_formats.json"
    DEFAULT_KEYS_URL = "https://copykey.hyctec.cn/libraries/default_keys.json"
    
    def __init__(self, library_dir: Path = None):
        if library_dir is None:
            library_dir = Path.home() / '.copykey' / 'libraries'
        self.library_dir = Path(library_dir)
        self.library_dir.mkdir(parents=True, exist_ok=True)
    
    def update_card_formats(self) -> bool:
        """Download latest card format definitions"""
        try:
            response = requests.get(self.CARD_FORMATS_URL, timeout=10)
            response.raise_for_status()
            
            formats = response.json()
            
            # Save to local library
            output_path = self.library_dir / 'card_formats.json'
            with open(output_path, 'w') as f:
                json.dump(formats, f, indent=2)
            
            print(f"Updated card formats: {len(formats.get('formats', []))} types")
            return True
            
        except requests.RequestException as e:
            print(f"Card format update failed: {e}")
            return False
    
    def update_default_keys(self) -> bool:
        """Download updated default key database"""
        try:
            response = requests.get(self.DEFAULT_KEYS_URL, timeout=10)
            response.raise_for_status()
            
            keys_data = response.json()
            
            # Save to local library (encrypted or plain based on content)
            output_path = self.library_dir / 'default_keys.json'
            with open(output_path, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            key_count = len(keys_data.get('keys', []))
            print(f"Updated default keys: {key_count} keys")
            return True
            
        except requests.RequestException as e:
            print(f"Default keys update failed: {e}")
            return False
    
    def load_card_formats(self) -> dict:
        """Load card formats from local library"""
        path = self.library_dir / 'card_formats.json'
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return {'formats': []}  # Return empty if not downloaded
    
    def load_default_keys(self) -> list:
        """Load default keys from local library"""
        path = self.library_dir / 'default_keys.json'
        if path.exists():
            with open(path) as f:
                data = json.load(f)
                return [bytes.fromhex(k) for k in data.get('keys', [])]
        return []  # Return empty if not downloaded
```

### 3.3 GUI Module (Optional)

#### `gui/main_window.py`
```python
"""
Main Application Window (PyQt6)
Completely offline operation
"""
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QProgressBar, QListWidget,
                             QTabWidget, QMessageBox, QFileDialog)
from PyQt6.QtCore import Qt, pyqtSignal, QThread

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.device = None
        self.decoder = None
        self.card_library = None
        self.key_vault = None
        
        self._init_ui()
        self._connect_signals()
    
    def _init_ui(self):
        """Initialize user interface"""
        self.setWindowTitle("CopyKEY Tool (Offline)")
        self.setMinimumSize(800, 600)
        
        # Main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Device status bar
        self.status_label = QLabel("Device: Not Connected")
        layout.addWidget(self.status_label)
        
        # Tab widget for different functions
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Tab 1: Read/Decode
        read_tab = self._create_read_tab()
        tabs.addTab(read_tab, "Read & Decode")
        
        # Tab 2: Write/Encrypt
        write_tab = self._create_write_tab()
        tabs.addTab(write_tab, "Write & Encrypt")
        
        # Tab 3: Card Library
        library_tab = self._create_library_tab()
        tabs.addTab(library_tab, "Card Library")
        
        # Tab 4: Key Management
        keys_tab = self._create_keys_tab()
        tabs.addTab(keys_tab, "Key Management")
        
        # Tab 5: Settings (including updates)
        settings_tab = self._create_settings_tab()
        tabs.addTab(settings_tab, "Settings")
    
    def _create_read_tab(self) -> QWidget:
        """Create Read/Decode tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Connect button
        self.btn_connect = QPushButton("Connect Device")
        layout.addWidget(self.btn_connect)
        
        # Read button
        self.btn_read = QPushButton("Read Card")
        self.btn_read.setEnabled(False)
        layout.addWidget(self.btn_read)
        
        # Decode button
        self.btn_decode = QPushButton("One-Click Decode")
        self.btn_decode.setEnabled(False)
        layout.addWidget(self.btn_decode)
        
        # Progress indicator
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results display
        self.result_list = QListWidget()
        layout.addWidget(self.result_list)
        
        return widget
    
    def _create_settings_tab(self) -> QWidget:
        """Create Settings tab with controlled update options"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Network settings section
        layout.addWidget(QLabel("<b>Network Settings</b>"))
        layout.addWidget(QLabel("This application operates offline by default."))
        layout.addWidget(QLabel("Network access is ONLY for:"))
        layout.addWidget(QLabel("  • Firmware updates"))
        layout.addWidget(QLabel("  • Library updates (card formats, default keys)"))
        
        # Firmware update section
        layout.addWidget(QLabel("<b>Firmware Update</b>"))
        self.btn_check_firmware = QPushButton("Check for Firmware Updates")
        layout.addWidget(self.btn_check_firmware)
        
        # Library update section
        layout.addWidget(QLabel("<b>Library Updates</b>"))
        self.btn_update_formats = QPushButton("Update Card Formats")
        layout.addWidget(self.btn_update_formats)
        
        self.btn_update_keys = QPushButton("Update Default Keys")
        layout.addWidget(self.btn_update_keys)
        
        # NO user authentication
        # NO cloud sync buttons
        # NO analytics opt-in
        
        layout.addStretch()
        
        return widget
```

---

## 4. Security Implementation Details

### 4.1 Network Isolation Strategy

```python
# config/network_policy.py
"""
Strict network policy enforcement
"""
from enum import Enum
from typing import Set

class NetworkPermission(Enum):
    FIRMWARE_UPDATE = "firmware"
    LIBRARY_UPDATE = "library"
    VERSION_CHECK = "version"
    
    # Explicitly DENIED permissions
    # USER_AUTH = "auth"  # NOT ALLOWED
    # CLOUD_SYNC = "cloud"  # NOT ALLOWED
    # ANALYTICS = "analytics"  # NOT ALLOWED

ALLOWED_HOSTS: Set[str] = {
    "copykey.hyctec.cn",  # ONLY for firmware and libraries
}

ALLOWED_PATHS: Set[str] = {
    "/firmware/",
    "/libraries/",
    "/version.json",
}

DENIED_PATHS: Set[str] = {
    "/api/auth/",
    "/api/user/",
    "/api/cloud/",
    "/api/analytics/",
    "/api/chat/",
}

def is_network_request_allowed(url: str, purpose: NetworkPermission) -> bool:
    """
    Validate if a network request is permitted
    Returns True only for whitelisted firmware/library updates
    """
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    
    # Check host whitelist
    if parsed.hostname not in ALLOWED_HOSTS:
        return False
    
    # Check path whitelist
    path_allowed = any(parsed.path.startswith(p) for p in ALLOWED_PATHS)
    if not path_allowed:
        return False
    
    # Check path blacklist
    path_denied = any(parsed.path.startswith(d) for d in DENIED_PATHS)
    if path_denied:
        return False
    
    # Verify purpose matches
    if purpose == NetworkPermission.FIRMWARE_UPDATE:
        return parsed.path.startswith("/firmware/")
    elif purpose == NetworkPermission.LIBRARY_UPDATE:
        return parsed.path.startswith("/libraries/")
    
    return False
```

### 4.2 Offline-First Design

All core functionality works without any network connection:

1. **Device Communication**: USB HID - no internet needed
2. **Crypto Operations**: Local CPU - no server calls
3. **Key Storage**: Local encrypted vault - no cloud
4. **Card Library**: Local JSON database - no sync
5. **Decoding Algorithms**: Built-in implementation - no API

Network is ONLY used when user explicitly clicks:
- "Check for Firmware Updates"
- "Update Card Formats"
- "Update Default Keys"

### 4.3 Code Review Checklist

Before any code merge, verify:
- [ ] No `requests.get()` calls outside `updater/` module
- [ ] No references to `client.copykey.hyctec.cn`
- [ ] No user authentication flows
- [ ] No cloud sync functionality
- [ ] No analytics or telemetry
- [ ] All network calls use `is_network_request_allowed()` check
- [ ] Default behavior is 100% offline

---

## 5. Dependencies

### Required Packages
```txt
# Hardware interface
hidapi>=0.14.0

# Cryptography
pycryptodome>=3.19.0

# GUI (optional)
PyQt6>=6.6.0

# Network (ONLY for updater module)
requests>=2.31.0

# Development
pytest>=7.4.0
black>=23.0.0
flake8>=6.0.0
```

### Installation
```bash
pip install -r requirements.txt
```

---

## 6. Project Structure

```
copykey_python/
├── README.md
├── LICENSE
├── requirements.txt
├── setup.py
├── config/
│   ├── __init__.py
│   └── network_policy.py      # Network access control
├── core/
│   ├── __init__.py
│   ├── device_interface.py    # HID communication
│   ├── mifare_crypto.py       # Crypto-1 implementation
│   ├── card_encryption.py     # Card data encryption
│   ├── key_vault.py          # Local key storage
│   └── card_library.py       # Local card database
├── updater/
│   ├── __init__.py
│   ├── firmware_updater.py   # Firmware updates (network)
│   └── library_updater.py    # Library updates (network)
├── gui/
│   ├── __init__.py
│   ├── main_window.py        # Main UI
│   ├── read_tab.py
│   ├── write_tab.py
│   ├── library_tab.py
│   ├── keys_tab.py
│   └── settings_tab.py
├── cli/
│   ├── __init__.py
│   └── commands.py           # Command-line interface
├── tests/
│   ├── test_crypto.py
│   ├── test_device.py
│   ├── test_encryption.py
│   └── test_network_policy.py
└── resources/
    ├── card_formats.json
    └── default_keys.json
```

---

## 7. Testing Strategy

### Unit Tests
- Crypto-1 implementation correctness
- Key vault encryption/decryption
- Card encryption/decryption
- Network policy enforcement

### Integration Tests
- Device communication (with mock device)
- Full decode workflow
- Full write workflow

### Security Tests
- Verify no unauthorized network calls
- Test offline functionality
- Verify key vault security

---

## 8. Deployment Considerations

### Distribution
- Package as standalone executable (PyInstaller)
- Include all dependencies
- No installer phone-home

### Updates
- User must manually trigger update check
- No automatic background updates
- Clear indication of what's being downloaded

### Documentation
- Clearly state offline-first design
- Document allowed network endpoints
- Provide instructions for air-gapped deployment

---

## 9. Compliance Statement

This implementation strictly adheres to the following principles:

1. **Privacy by Design**: No user data leaves the local machine
2. **Minimal Network Access**: Only firmware and library updates
3. **Transparency**: All network activity is user-initiated and visible
4. **Security**: Local encryption for sensitive data (keys, cards)
5. **Independence**: Fully functional without any internet connection

**Prohibited Endpoints:**
- ❌ client.copykey.hyctec.cn (blocked)
- ❌ copykey.hyctec.cn/api/* (blocked except /firmware/ and /libraries/)
- ❌ Any authentication endpoints
- ❌ Any analytics endpoints
- ❌ Any cloud sync endpoints

**Allowed Endpoints:**
- ✅ copykey.hyctec.cn/firmware/* (firmware updates only)
- ✅ copykey.hyctec.cn/libraries/* (library updates only)

---

## 10. Next Steps

1. **Implement Core Modules**:
   - [ ] device_interface.py
   - [ ] mifare_crypto.py (study libnfc/mfoc for reference)
   - [ ] card_encryption.py
   - [ ] key_vault.py
   - [ ] card_library.py

2. **Implement Updater Module**:
   - [ ] firmware_updater.py
   - [ ] library_updater.py
   - [ ] network_policy.py

3. **Implement GUI** (optional):
   - [ ] main_window.py
   - [ ] All tab implementations

4. **Testing**:
   - [ ] Unit tests for all modules
   - [ ] Integration tests with hardware
   - [ ] Security audit for network calls

5. **Documentation**:
   - [ ] User manual
   - [ ] API documentation
   - [ ] Security whitepaper

---

*Document Version: 1.0*
*Last Updated: 2024*
*Status: Ready for Implementation*
