
# CopyKEY Manager V2.0.2.1 - Reverse Engineering Analysis Report

## Overview
- **Application**: CopyKEY Manager (CopyKey NFC Tools)
- **Version**: 2.0.2.1 (Released: 2026-04-13)
- **Purpose**: ID/IC card copier Windows management application
- **Architecture**: x86 (32-bit)
- **Framework**: C++ with ATL/WTL UI framework, nbase library

## Critical Components Identified

### 1. Core Application Classes
- `CopyKeyDeviceWork` - Main device communication handler
- `CDeviceWorkTask` - Device work task processor
- `CHIDWork` - HID (Human Interface Device) communication
- `CNetWorkTask` - Network communication handler
- `WorkTask` - Base work task class

### 2. Card Data Processing Modules
- `carddata_encrypt_form` - Card data encryption interface
- `carddata_clear_form` - Card data clearing interface  
- `carddata_advanced_form` - Advanced card operations
- `card_data_proprietarycopy_form` - Proprietary card copying
- `makecardlib_main` - Card library generation
- `makekeylib_main` - Key library generation (CRITICAL)
- `Cardlib_Info` - Card library information structure

### 3. Mifare/Card Specific Structures
- `_hyc_mifare_sector` - Mifare sector data structure
- `MifareSendcmdShort` - Mifare short command sending
- `Transceive_bits` - Bit-level transceive operation
- `USB_Transceive_bits` - USB bit-level transceive

### 4. User Interface Forms
- `MainForm` - Main application window
- `login_main` - Login/authentication interface
- `user_main` - User management
- `analysisinfo_form` - Card analysis information
- `app_setting_form` - Application settings
- `update_form` - Software update interface
- `notice_form` - Notifications
- `about_form` - About dialog

### 5. Cryptographic Operations
- `CryptImportKey` - Import cryptographic keys
- `CryptDestroyKey` - Destroy cryptographic keys
- `CryptEncrypt` - Encryption operations
- `AES` - AES encryption class
- `Data not multiple of Block Size` - Block cipher handling

### 6. Communication APIs
- **HID Functions**: HidD_GetFeature, HidD_SetFeature, HidD_GetInputReport
- **USB Functions**: DeviceIoControl for device communication
- **Network**: libcurl 7.72.0 for HTTP/HTTPS communications

### 7. External Dependencies
- **Domains**: 
  - client.copykey.hyctec.cn
  - copykey.hyctec.cn
  - admin.hyctec.cn (for downloads)
- **Libraries**: libcurl, LZ4 compression, Gdiplus, ATL/WTL

### 8. Supported Card Types (from website changelog)
- Mifare Classic (S50, S70, Mini)
- Mifare Gen3 (including non-vulnerable Gen3 cards)
- FUID/UFUID/CUID magic cards
- NTAG series
- Ultralight/Ultralight EV1
- T5577 (ID cards)
- EM4305
- HDC cards
- Mifare Plus S2

### 9. Key Features (from changelog)
- Three-generation card fast decoding (75% time reduction)
- FUID card unlock functionality
- ID/PID/NSC card read/write
- Decoding algorithm optimization
- Card data export/import
- Cloud card bag upload

## Critical Files for Further Analysis
1. The main executable contains embedded resources
2. Key generation library (makekeylib_main) - likely contains decryption algorithms
3. Card library module (makecardlib_main) - card format definitions
4. Device communication layer (CopyKeyDeviceWork, CHIDWork)

## Next Steps for Deep Analysis
1. Extract and analyze embedded resources from PE file
2. Dynamic analysis with device connected
3. Network traffic analysis to identify API endpoints
4. String extraction for hardcoded keys/algorithms
5. Decompile or disassemble critical functions
