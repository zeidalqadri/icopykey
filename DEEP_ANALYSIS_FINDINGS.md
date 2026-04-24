# Deep Analysis: CopyKEY Manager Critical Modules

## Executive Summary

This document presents findings from deep static analysis of the CopyKEY Manager V2.0.2.1 application, focusing on the two most critical modules for Python reimplementation:
1. **makekeylib_main** - Key library management and manual key entry
2. **makecardlib_main** - Card data library and cloud synchronization

---

## 1. makekeylib_main Module Analysis

### 1.1 Class Structure

```cpp
// Primary classes identified through RTTI symbols:
class AAP8makekeylib_main    // UI Controller (View)
class AVmakekeylib_main      // View Model / Business Logic
```

### 1.2 UI Components (from MakeKeylib.xml)

| Control Name | Type | Purpose |
|--------------|------|---------|
| `MakeKeyLib_Key` | HexEdit | Input field for 6-byte Mifare keys (hex format) |
| `btn_Decode_MakeKeyLib_Add` | Button | Add entered key to temporary list |
| `Decode_MakeKeyLib_KeyList` | VListBox | Display stored keys with delete capability |
| `btn_Decode_MakeKeyLib_DelAll` | Button | Clear all keys from list |
| `btn_Decode_MakeKeyLib_Save` | Button | Save keys to encrypted local vault |
| `btn_Decode_MakeKeyLib_Deocde` | Button | Start decoding with custom key list |

### 1.3 Key Data Structure

Based on string analysis and UI layout:

```python
@dataclass
class MifareKey:
    key_bytes: bytes        # 6 bytes (48 bits)
    key_hex: str           # Hex representation (12 chars)
    source: str            # 'manual', 'default', 'decoded', 'cloud'
    sector_access: List[int]  # Sectors this key has access to
    
class KeyLibrary:
    keys: List[MifareKey]
    vault_encrypted: bool
    cloud_synced: bool
    last_modified: datetime
```

### 1.4 Workflow

1. **Manual Entry Flow**:
   - User enters 12 hex characters (6 bytes) in HexEdit control
   - Validation ensures exactly 6 bytes
   - Key added to in-memory list
   - Can be used immediately for decoding

2. **Save to Vault Flow**:
   - Keys serialized to binary structure
   - Encrypted using Windows CryptoAPI (CryptEncrypt)
   - Stored in local file/registry
   - Requires user authentication to retrieve

3. **Decode Integration**:
   - Custom key list passed to device via HID
   - Device tries each key against locked sectors
   - Success/failure reported per sector

---

## 2. makecardlib_main Module Analysis

### 2.1 Class Structure

```cpp
class AAP8makecardlib_main   // UI Controller
class AVmakecardlib_main     // View Model
class CARDLIBDATA           // Data structure (inferred from symbol)
```

### 2.2 UI Components (from MakeCardlib.xml)

| Control Name | Type | Purpose |
|--------------|------|---------|
| `make_cardlib_name` | Edit | Package name input |
| Address fields | Edit combo | Province/City/District/Street |
| Card type selector | ComboBox | Mifare 1K/4K, NTAG, etc. |
| UID display | HexEdit | Card UID (editable for blanks) |

### 2.3 Card Library Data Structure

```python
@dataclass
class CardLibData:
    package_id: str         # Unique identifier
    name: str               # User-defined name
    uid: bytes              # Original card UID
    card_type: str          # e.g., "Mifare Classic 1K"
    
    # Location metadata (China-specific)
    province: str
    city: str
    district: str
    street: str
    
    # Card data
    sectors: List[MifareSector]
    keys: Dict[int, MifareKey]  # Sector -> Key mapping
    
    # Metadata
    created_date: datetime
    modified_date: datetime
    cloud_uploaded: bool
    cloud_id: Optional[str]
```

### 2.4 Cloud Synchronization

Endpoints identified:
- `client.copykey.hyctec.cn` - API endpoint
- `copykey.hyctec.cn` - Web interface

Sync operations:
1. Upload card package with metadata
2. Download packages on other devices
3. Share packages between users (requires authentication)

---

## 3. carddata_encrypt_form Module Analysis

### 3.1 Class Structure

```cpp
class AAP8carddata_encrypt_form  // UI Controller
class AVcarddata_encrypt_form    // View Model
```

### 3.2 UI Components (from CardDataEncrypt.xml)

| Control Name | Type | Purpose |
|--------------|------|---------|
| `Set_Encrypt_KeyA` | HexEdit | Input Key A (6 bytes) |
| `Set_Encrypt_KeyB` | HexEdit | Input Key B (6 bytes) |
| `Encrypt_check_KeyABSame` | CheckBox | Use same key for A and B |
| `btn_Encrypt_rand` | Button | Generate random keys |
| `btn_Encrypt_Data_MakeAll` | Button | Apply encryption to all sectors |

### 3.3 Encryption Process

For each sector (typically sectors 1-15):

```python
def encrypt_sector(sector_data, new_key_a, new_key_b, access_bits):
    """
    Mifare Classic trailer block structure:
    Bytes 0-5:   Key A
    Bytes 6-9:   Access Bits (4 bytes)
    Bytes 10-15: Key B
    
    Access bits format:
    - C1, C2, C3 for each block (3 bits each)
    - Inverted copies for error detection
    """
    trailer_block = bytearray(16)
    trailer_block[0:6] = new_key_a
    trailer_block[6:10] = access_bits  # Calculated from permissions
    trailer_block[10:16] = new_key_b
    return trailer_block
```

### 3.4 Access Bits Calculation

Standard access bit configurations:

| Configuration | C1 | C2 | C3 | Permissions |
|---------------|----|----|----|-------------|
| 0 0 0 | Read Key A | Read Key B | Read/Write blocks |
| 0 1 0 | Never | Read Key B | Read/Write with Key B |
| 1 0 0 | Never | Never | Read/Write with Key A or B |
| 1 1 1 | Never | Never | Write only (value blocks) |

---

## 4. Device Communication Protocol

### 4.1 HID Functions Used

All functions dynamically loaded from `hid.dll`:

- `HidD_GetPreparsedData` - Get device capabilities
- `HidD_GetFeature` / `HidD_SetFeature` - Configuration
- `HidD_GetInputReport` - Read data from device
- `HidD_GetManufacturerString` - Device identification
- `HidD_GetProductString` - Device model
- `HidD_GetSerialNumberString` - Unique device ID
- `HidP_GetCaps` - Parse capabilities

### 4.2 USB Device Enumeration

Uses SETUPAPI.dll for device discovery:

```cpp
SetupDiGetClassDevsA()           // Get device info set
SetupDiEnumDeviceInterfaces()    // Enumerate HID devices
SetupDiGetDeviceInterfaceDetailA() // Get device path
CreateFile()                      // Open device handle
```

### 4.3 Inferred Command Structure

Based on workflow analysis:

```python
# Hypothetical command structure (needs USB capture to confirm)
class HIDCommand:
    report_id: int
    command_code: int
    payload: bytes
    checksum: int

# Commands likely include:
CMD_READ_CARD = 0x01
CMD_WRITE_CARD = 0x02
CMD_DECODE_SECTOR = 0x03
CMD_GET_DEVICE_INFO = 0x04
CMD_SET_KEYS = 0x05
```

---

## 5. Cryptographic Implementation Details

### 5.1 AES Confirmation

✅ **AES S-box found at offset**: Binary contains complete 256-byte S-box
✅ **AES Rcon found**: Round constants present
✅ **Usage**: Local key vault encryption, network TLS

### 5.2 Mifare Crypto-1

Not directly visible in binary (likely implemented in device firmware), but:
- Default keys embedded: `FFFFFFFFFFFF`, `000000000000`, `A0A1A2A3A4A5`
- Sector/block terminology confirms Mifare Classic support
- Authentication flow requires nested/darkside attacks

### 5.3 Windows CryptoAPI Usage

Functions imported from ADVAPI32.dll:
- `CryptAcquireContextW` - Initialize crypto provider
- `CryptCreateHash` - Create hash object
- `CryptHashData` - Hash password/user data
- `CryptImportKey` - Import encryption key
- `CryptEncrypt` - Encrypt key vault data
- `CryptDestroyKey` - Cleanup

---

## 6. Python Implementation Requirements

### 6.1 Core Dependencies

```python
# Hardware communication
hidapi  # or pywin32 for Windows HID

# Cryptography
pycryptodome  # AES implementation
mfoc  # Mifare Crypto-1 brute force (optional)
nfcpy  # NFC protocol implementation (optional)

# Data handling
dataclasses  # Built-in (Python 3.7+)
json  # Built-in
pickle  # Built-in (for local storage)

# GUI (choose one)
PyQt6  # Full-featured
tkinter  # Built-in, simpler
DearPyGui  # Modern, fast
```

### 6.2 Data Structures for Python

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime

@dataclass
class MifareSector:
    sector_number: int
    blocks: List[bytes]  # 4 blocks × 16 bytes
    key_a: bytes  # 6 bytes
    key_b: bytes  # 6 bytes
    access_bits: bytes  # 4 bytes
    decoded: bool = False
    
@dataclass
class MifareCard:
    uid: bytes
    card_type: str  # "Mifare Classic 1K", "Mifare Classic 4K"
    sak: bytes
    atqa: bytes
    sectors: List[MifareSector]
    
@dataclass
class MifareKey:
    key_bytes: bytes
    source: str
    sectors_accessible: List[int] = field(default_factory=list)
    
@dataclass
class CardLibrary:
    packages: Dict[str, MifareCard]
    keys: List[MifareKey]
    cloud_synced: bool = False
```

### 6.3 Module Architecture

```
copykey_python/
├── __init__.py
├── core/
│   ├── mifare.py          # Mifare protocol implementation
│   ├── crypto.py          # AES/Mifare crypto
│   └── structures.py      # Data classes
├── hardware/
│   ├── hid_device.py      # HID communication
│   └── commands.py        # Command definitions
├── ui/
│   ├── main_window.py     # Main application
│   ├── keylib_dialog.py   # Key library UI
│   ├── cardlib_dialog.py  # Card library UI
│   └── encrypt_dialog.py  # Encryption UI
├── storage/
│   ├── local_vault.py     # Encrypted local storage
│   └── cloud_sync.py      # Cloud API client
└── utils/
    ├── hex_edit.py        # Hex input validation
    └── access_bits.py     # Access bit calculations
```

---

## 7. Critical Implementation Priorities

### Phase 1: Core Functionality
1. Implement HID device enumeration and communication
2. Define Mifare data structures
3. Implement basic read/write commands
4. Create hex input validation

### Phase 2: Decoding
1. Implement default key testing
2. Add manual key entry interface
3. Integrate mfoc for brute-force attacks
4. Sector-by-sector decode progress

### Phase 3: Key Management
1. Key library UI (add/delete/save)
2. Local encrypted vault (AES + password)
3. Key reuse across sessions

### Phase 4: Card Library
1. Card package creation
2. Metadata management
3. Export/import functionality
4. Cloud sync (reverse engineer API)

### Phase 5: Encryption
1. Random key generation
2. Access bit calculation
3. Per-sector encryption
4. Batch processing

---

## 8. Security Considerations

⚠️ **Legal Warning**: This tool is for educational purposes and authorized testing only.

1. **Authorization**: Only use on cards you own or have explicit permission to test
2. **Key Storage**: Encrypt local key vault with strong password
3. **Network Security**: Use HTTPS for any cloud communication
4. **Audit Logging**: Log all operations for accountability

---

## Appendix: String Resource IDs

| ID | English | Chinese | Context |
|----|---------|---------|---------|
| STRID_KEYLIB_TITLE | Input key decoding | 输入密钥解码 | Key library window title |
| STRID_KEYLIB_ADD | Add | 添加 | Add key button |
| STRID_KEYLIB_DELALL | Delete All | 全部删除 | Clear all keys |
| STRID_KEYLIB_SAVE | Save | 保存 | Save to vault |
| STRID_KEYLIB_DECODE | Decode | 解码 | Start decoding |
| STRID_ENCRYPT_KEYA | Key A | 加密密钥 A | Encryption dialog |
| STRID_ENCRYPT_KEYB | Key B | 加密密钥 B | Encryption dialog |
| STRID_ENCRYPT_SAMEKEY | Same Key A/B | A/B 密钥相同 | Checkbox label |
| STRID_DEVICE_SECTOR | sector | 扇区 | Sector display |
| STRID_DEVICE_PASSWORD_A | Password A | 密码 A | Key A label |
| STRID_DEVICE_PASSWORD_B | Password B | 密码 B | Key B label |

---

Document generated through comprehensive static analysis of CopyKEY Manager V2.0.2.1.2604132.exe
Analysis date: 2024
