# CopyKEY Python Tool

Offline-first NFC/RFID card copying tool inspired by CopyKEY Manager.

## Security Policy

**This application operates with strict network isolation:**

✅ **ALLOWED Network Communications:**
- Firmware updates (copykey.hyctec.cn/firmware/*)
- Library updates - card formats & default keys (copykey.hyctec.cn/libraries/*)

❌ **PROHIBITED Network Communications:**
- User authentication (NO login/register)
- Card library cloud sync (NO cloud storage)
- Key library cloud sync (NO server-side key storage)
- Usage analytics (NO telemetry)
- After-sales support chat
- Any communication with client.copykey.hyctec.cn

## Features

- 🔒 **100% Offline Operation** - All core functions work without internet
- 🛡️ **Local Key Vault** - AES-encrypted local storage for keys
- 💾 **Local Card Library** - No cloud sync, complete privacy
- 🔑 **Crypto-1 Implementation** - Mifare Classic decoding
- 📱 **USB HID Device Support** - Compatible with CopyKEY hardware
- 🔐 **Card Encryption** - Generate random keys for cloned cards

The sibling `x100_decrypt/` project provides dump format detection, normalisation, and key recovery for MIFARE Classic dumps — see its [README](../x100_decrypt/README.md) for details.

## Project Structure

```
copykey_python/
├── config/              # Configuration and network policy
│   ├── __init__.py
│   └── network_policy.py    # Strict network access control
├── core/                # Core offline functionality
│   ├── __init__.py
│   ├── device_interface.py  # USB HID communication
│   ├── card_library.py      # Local card database
│   ├── mifare_crypto.py     # Crypto-1 implementation
│   ├── card_encryption.py   # Card data encryption
│   └── key_vault.py         # Local key storage
├── updater/             # Controlled network updates
│   ├── __init__.py
│   ├── firmware_updater.py  # Firmware updates only
│   └── library_updater.py   # Library updates only
├── gui/                 # PyQt6 GUI (TODO)
├── cli/                 # Command-line interface
└── tests/               # Unit and integration tests
```

## Installation

```bash
# Clone or download the project
cd copykey_python

# Install dependencies
pip install -r requirements.txt
```

## Requirements

- Python 3.8+
- hidapi (for USB HID communication)
- pycryptodome (for AES encryption)
- requests (ONLY for updater module)
- PyQt6 (optional, for GUI)

## Usage

### Network Policy Verification

```bash
# Test the network policy enforcement
python config/network_policy.py
```

### Programmatic Usage

```python
from core.device_interface import CopyKeyDevice
from core.card_library import LocalCardLibrary
from updater.library_updater import LibraryUpdater

# Device communication (offline)
device = CopyKeyDevice()
if device.connect():
    print(f"Connected: {device.get_device_info()}")
    
# Card library (offline, local storage)
library = LocalCardLibrary()
print(f"Cards in library: {len(library)}")

# Update libraries (requires internet, controlled)
updater = LibraryUpdater()
updater.update_card_formats()  # Only allowed network call
updater.update_default_keys()  # Only allowed network call
```

## Security Audit

The network policy is enforced at multiple levels:

1. **URL Whitelisting** - Only specific hosts and paths allowed
2. **Purpose Validation** - Each network call must declare its purpose
3. **Code Auditing** - Static analysis detects unauthorized network calls
4. **Defense in Depth** - Both whitelist and blacklist enforcement

Run security audit on codebase:

```python
from config.network_policy import audit_network_calls

# Check all Python files for unauthorized network calls
import glob
for file in glob.glob('**/*.py', recursive=True):
    issues = audit_network_calls(file)
    if issues:
        print(f"\n{file}:")
        for issue in issues:
            print(f"  Line {issue.get('line', 'N/A')}: {issue['issue']}")
```

## Development Status

- ✅ Network policy enforcement
- ✅ Device interface skeleton
- ✅ Card library implementation
- ✅ Firmware updater (controlled network)
- ✅ Library updater (controlled network)
- ✅ **CLI Implementation** - Full interactive command-line interface
  - AES-256-GCM encrypted vault for keys/cards
  - Mifare Classic 1K/4K support
  - One-click decode with default + custom keys
  - Card encryption with random or custom keys
  - Interactive menu system
  - Import/export functionality
- ✅ Crypto-1 implementation
- ✅ Card encryption module
- ✅ Key vault implementation
- ⏳ GUI implementation (TODO)

## License

MIT License

## Disclaimer

This tool is for educational and authorized testing purposes only. 
Always ensure you have proper authorization before copying or cloning RFID/NFC cards.
