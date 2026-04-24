# CopyKEY Manager V2.0.2.1 - Comprehensive Reverse Engineering Analysis

## Executive Summary

This document provides a detailed technical analysis of the CopyKEY Manager application, 
a Windows-based tool for NFC/RFID card copying and management, specifically targeting 
Mifare Classic and related card technologies.

---

## 1. Application Overview

### Basic Information
- **Application Name**: CopyKEY Manager V2.0.2.1 (Build 2604132)
- **Architecture**: 32-bit x86 Windows executable
- **File Size**: ~3.76 MB
- **Framework**: ATL/WTL (Windows Template Library) with nbase UI framework
- **Compiler**: Visual C++ (MSVC)

### Purpose
The application is designed for:
- Reading and decoding Mifare Classic cards (1K/4K)
- Cloning cards to various blank types (CUID, FUID, UFUID, Gen3)
- Managing card data libraries ("CardLib")
- Managing cryptographic key libraries ("KeyLib")
- Encrypting/decrypting card sector data

---

## 2. Critical Modules Identified

### 2.1 makekeylib_main (Key Library Module)
**Class Names**: `AAP8makekeylib_main`, `AVmakekeylib_main`

**Functionality**:
- User interface for entering decryption keys manually
- Key management (add, delete, delete all, save to local vault)
- Integration with decoding process

**UI Elements** (from MakeKeylib.xml):
- `MakeKeyLib_Key`: HexEdit control for entering 6-byte Mifare keys
- `btn_Decode_MakeKeyLib_Add`: Button to add keys to list
- `Decode_MakeKeyLib_KeyList`: List box displaying stored keys
- `btn_Decode_MakeKeyLib_Back`: Close button

**Key Operations**:
1. User inputs known Mifare keys (typically 6 bytes in hex format)
2. Keys are added to a temporary list
3. Keys can be saved to local password vault (encrypted storage)
4. During decoding, these keys are tried against locked sectors

### 2.2 makecardlib_main (Card Library Module)
**Class Names**: `AAP8makecardlib_main`, `AVmakecardlib_main`

**Functionality**:
- Creating "card packages" containing decoded card data
- Storing card metadata (name, address, UID)
- Uploading/downloading card data to cloud service
- Managing card data for repeated cloning operations

**UI Elements** (from MakeCardlib.xml):
- `make_cardlib_name`: Card package name input
- Address fields (province, city, district, street)
- Card type selector
- UID display/edit field

**Data Structure** (inferred):
```
CardLib {
    string name;
    string uid;           // 4, 7, or 10 bytes hex
    string card_type;     // Mifare Classic 1K/4K, NTAG, etc.
    string address_info;  // Location metadata
    byte[] sector_data;   // 16 sectors × 4 blocks × 16 bytes (for 1K)
    KeySet keys;          // Associated keys
}
```

### 2.3 carddata_encrypt_form (Encryption Module)
**Class Names**: `AAP8carddata_encrypt_form`, `AVcarddata_encrypt_form`

**Functionality**:
- Encrypting card data before writing to blanks
- Setting custom Key A and Key B values per sector
- Generating random keys
- One-click full card encryption

**UI Elements** (from CardDataEncrypt.xml):
- `Set_Encrypt_KeyA`: Key A input (hex)
- `Set_Encrypt_KeyB`: Key B input (hex)
- Checkbox for different A/B keys
- Random key generator button
- One-click encrypt button

**Encryption Process**:
1. Load decoded card data
2. For each sector (typically sectors 1-15, sector 0 is read-only):
   - Generate or input new Key A (6 bytes)
   - Generate or input new Key B (6 bytes)
   - Set access bits (bytes 6-9 of trailer block)
   - Write modified trailer block
3. Calculate and update UID XOR if needed

### 2.4 CopyKeyDeviceWork / CHIDWork (Device Communication)
**Class Names**: `AVCopyKeyDeviceWork`, `AVCHIDWork`, `VCDeviceWorkTask`

**Functionality**:
- USB HID communication with physical CopyKEY device
- Sending commands to read/write cards
- Receiving card data from device
- Device status monitoring

**HID Functions Used**:
- `HidD_GetPreparsedData`
- `HidD_GetFeature` / `HidD_SetFeature`
- `HidD_GetInputReport`
- `HidD_GetManufacturerString`
- `HidD_GetProductString`
- `HidD_GetSerialNumberString`
- `SetupDiEnumDeviceInterfaces` (device enumeration)

**Communication Protocol** (inferred):
- Uses HID Feature Reports for configuration
- Uses HID Input/Output Reports for data transfer
- Commands include: Read Card, Write Card, Get Device Info, Decode

### 2.5 Device_Decoding (Decoding Workflow)
**UI Flow** (from Device_Decoding.xml):
1. `Device_Decoding_waitting`: Initial state, waiting for card
2. `Device_Decoding_start`: Decoding in progress
3. Display: Card ID, Card Type, Sector/Block status
4. Progress indication with animation

**Decoding States**:
- `STRID_DEVICE_LINKING`: Connecting to device
- `STRID_DEVICE_CARD_ID`: Displaying card UID
- `STRID_DEVICE_CARD_TYPE`: Identifying card type
- Sector-by-sector decode progress

---

## 3. Cryptographic Analysis

### 3.1 Confirmed Algorithms

**AES Encryption** ✓ CONFIRMED
- AES S-box constant found in binary
- AES round constants (Rcon) found
- Used for: Local key vault encryption, network communication

**Mifare Crypto-1** (INFERRED)
- Standard Mifare Classic authentication
- 48-bit LFSR-based stream cipher
- Keys are 6 bytes (48 bits)

### 3.2 Key Storage

**Local Key Vault**:
- Keys saved via `CryptEncrypt` (Windows CryptoAPI)
- Likely uses AES or DESX through CryptoAPI
- Stored encrypted on disk

**Network Transmission**:
- Keys transmitted to/from server encrypted
- Uses libcurl for HTTPS communication
- Endpoints: client.copykey.hyctec.cn

### 3.3 Access Bits Handling

Mifare Classic trailer block structure (block 3 of each sector):
```
Bytes 0-5:   Key A
Bytes 6-9:   Access Bits (4 bytes, but only 3 unique + inverted)
Bytes 10-15: Key B (or user data for sector 0)
```

Access bits control:
- Key A/B readability
- Block read/write permissions
- Key A/B write permissions
- Value block operations

---

## 4. Supported Card Types

Based on string analysis:

### Mifare Family
- Mifare Classic 1K (S50)
- Mifare Classic 4K (S70)
- Mifare Mini
- Mifare Gen3 (CUID/FUID/UFUID variants)

### Other Technologies
- NTAG (NXP NFC tags)
- Ultralight (Mifare Ultralight)
- T5577 (LF RFID, 125kHz)
- EM4305 (LF RFID, 125kHz)
- HDC (High Density Card)

### Special Cards Mentioned
- "新型国产卡" (New domestic Chinese cards)
- "无漏洞卡" (Non-vulnerable cards - likely Mifare Plus/DESFire)
- "N-in-1 composite cards"

---

## 5. Network Architecture

### Server Endpoints
1. **client.copykey.hyctec.cn** - Primary API endpoint
2. **copykey.hyctec.cn** - Web services

### Network Operations
- User authentication (login/register)
- Card library sync (upload/download)
- Key library sync
- Firmware updates
- After-sales support chat
- Usage analytics

### Protocol
- HTTP/HTTPS via libcurl 7.72.0
- JSON or XML data format (inferred)
- Authentication tokens for session management

---

## 6. File Structure

### Embedded Resources (ZIP archive in resource section)
```
resources/
├── lang/
│   ├── zh_CN/gdstrings.ini  (Chinese strings)
│   ├── zh_TW/gdstrings.ini  (Traditional Chinese)
│   ├── en_US/gdstrings.ini  (English)
│   ├── th_TH/gdstrings.ini  (Thai)
│   └── vi_VN/gdstrings.ini  (Vietnamese)
├── themes/
│   └── default/
│       ├── copykey/         (UI XML layouts)
│       │   ├── MakeKeylib.xml
│       │   ├── MakeCardlib.xml
│       │   ├── CardDataEncrypt.xml
│       │   ├── Device_Decoding.xml
│       │   ├── CardDataAdvanced.xml
│       │   ├── CardDataClear.xml
│       │   ├── login.xml
│       │   ├── main.xml
│       │   └── ...
│       ├── drawable/        (Icons and images)
│       ├── list/            (List item templates)
│       ├── menu/            (Menu definitions)
│       └── public/          (Shared UI components)
```

### External Dependencies
- hid.dll (HID device communication)
- libcurl.dll (HTTP client)
- gdiplus.dll (Graphics rendering)
- Windows CryptoAPI (Encryption)

---

## 7. Key Workflows

### 7.1 One-Click Decoding Flow
1. User clicks "一键解码" (One-Click Decode)
2. Application sends command to device via HID
3. Device reads card UID and identifies type
4. For each sector:
   a. Try default keys (FF×6, 00×6, etc.)
   b. Try user-provided keys from KeyLib
   c. If authenticated, read all 4 blocks
   d. Store sector data
5. If all sectors decoded: success
6. If some sectors fail: prompt for manual key entry
7. Save decoded data to device memory
8. Prompt user to insert blank card for writing

### 7.2 Manual Key Decoding Flow
1. User opens KeyLib window
2. Enters known keys (6 bytes hex each)
3. Adds keys to list
4. Starts decode with custom key list
5. Application tries each key against locked sectors

### 7.3 Card Encryption Flow
1. User loads decoded card data
2. Opens encryption dialog
3. Sets Key A and/or Key B (can generate random)
4. Optionally sets different keys per sector
5. Application modifies trailer blocks:
   - Inserts new Key A
   - Calculates access bits
   - Inserts new Key B
6. Writes encrypted data to blank card

### 7.4 Card Library Management
1. Create card package with metadata
2. Upload to cloud (requires login)
3. Download on another device
4. Use for quick cloning without re-decoding

---

## 8. Security Implications

### Vulnerabilities Identified
1. **Hardcoded Default Keys**: Application likely contains factory default keys
2. **Local Key Storage**: Encrypted but potentially extractable
3. **No Card Authentication**: Any decoded card can be cloned
4. **Network Transmission**: Keys sent to server (trust required)

### Anti-Analysis Measures
- No obvious packing detected
- Standard PE structure
- Strings not heavily obfuscated
- Crypto constants in plaintext (S-box)

---

## 9. Python Implementation Considerations

For creating a Python version, the following components are needed:

### 9.1 Hardware Interface
```python
# Using hidapi library
import hid

# Device enumeration
devices = hid.enumerate(VID, PID)

# Open device
device = hid.Device(path)

# Send/receive reports
device.send_feature_report(data)
device.get_feature_report(report_id, length)
device.write(data)
device.read(length)
```

### 9.2 Mifare Protocol Implementation
```python
# Crypto-1 implementation needed
# Or use existing library like:
# - python-nfc
# - nfcpy
# - libnfc bindings

# Key components:
# - LFSR implementation
# - Nonce generation
# - Stream cipher
# - Authentication protocol
```

### 9.3 AES Encryption
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# For key vault
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(data)
```

### 9.4 Data Structures
```python
@dataclass
class MifareSector:
    sector_number: int
    blocks: List[bytes]  # 4 blocks of 16 bytes
    key_a: bytes         # 6 bytes
    key_b: bytes         # 6 bytes
    access_bits: bytes   # 4 bytes

@dataclass  
class MifareCard:
    uid: bytes
    card_type: str
    sectors: List[MifareSector]
    sak: bytes
    atqa: bytes
```

### 9.5 GUI Framework Options
- PyQt5/PyQt6
- tkinter (built-in)
- Kivy
- Dear PyGui

---

## 10. Recommended Next Steps

1. **Protocol Reverse Engineering**:
   - Capture USB HID traffic between app and device
   - Document command/response format
   - Identify all supported commands

2. **Crypto-1 Implementation**:
   - Study open-source implementations (libnfc, mfoc)
   - Implement nested authentication attack
   - Implement darkside attack

3. **Device Firmware Analysis**:
   - Extract firmware from device if possible
   - Analyze embedded crypto routines

4. **Network Protocol Analysis**:
   - Capture HTTPS traffic (with MITM)
   - Document API endpoints
   - Understand authentication flow

---

## Appendix A: Class Reference

| Class Name | Module | Purpose |
|------------|--------|---------|
| AAP8makekeylib_main | makekeylib | Key library UI controller |
| AVmakekeylib_main | makekeylib | Key library view model |
| AAP8makecardlib_main | makecardlib | Card library UI controller |
| AVmakecardlib_main | makecardlib | Card library view model |
| AAP8carddata_encrypt_form | carddata_encrypt | Encryption UI controller |
| AVcarddata_encrypt_form | carddata_encrypt | Encryption view model |
| AVCopyKeyDeviceWork | device_work | Device communication worker |
| AVCHIDWork | hid_work | HID layer abstraction |
| AAP8MainForm | main | Main application window |
| AAP8login_main | login | Login dialog |

## Appendix B: Important String IDs

| String ID | English | Chinese |
|-----------|---------|---------|
| STRID_KEYLIB_TITLE | Input key decoding | 输入密钥解码 |
| STRID_DEVICE_CTRL_ONEKEYDECODE | Decode | 一键解码 |
| STRID_DEVICE_CTRL_ONEKEYENCRYPT | Encrypt data | 一键加密 |
| STRID_ENCRYPT_KEYA | Key A | 加密密钥 A |
| STRID_ENCRYPT_KEYB | Key B | 加密密钥 B |
| STRID_DEVICE_SECTOR | sector | 扇区 |
| STRID_DEVICE_BLOCK | block | 区块 |

---

Document generated through static analysis of CopyKEY Manager V2.0.2.1.2604132.exe
Analysis date: 2024
