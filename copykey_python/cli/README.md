# CopyKEY Manager CLI

A robust, production-ready command-line interface for copying and managing Mifare Classic NFC/RFID cards using CopyKEY-compatible HID devices.

## Features

- 🔒 **100% Offline Operation** - All core functions work without internet
- 🛡️ **AES-256-GCM Encrypted Vault** - Password-based encryption for key/card libraries using PBKDF2 (100,000 iterations)
- 💾 **Local Card Library** - Store and manage decoded card dumps locally
- 🔑 **Default Key Dictionary** - 10 common Mifare keys for automatic decoding
- 📱 **USB HID Device Support** - Compatible with CopyKEY hardware (VID/PID configurable)
- 🔐 **Card Encryption** - Generate random or custom keys for cloned cards
- 🎯 **One-Click Decode** - Automatic sector-by-sector key discovery
- 📤 **Import/Export** - JSON format for card data backup and transfer

## Installation

### Prerequisites

- Python 3.8+
- pip package manager

### Install Dependencies

```bash
cd copykey_python
pip install hidapi pycryptodome
```

**Linux users** may need to install libhidapi first:
```bash
# Debian/Ubuntu
sudo apt-get install libhidapi-dev

# Fedora/RHEL
sudo dnf install hidapi-devel

# Arch Linux
sudo pacman -S hidapi
```

## Usage

### Running the CLI

```bash
python cli/copykey_cli.py
```

On first run, you'll be prompted to:
1. Connect to a CopyKEY device (optional - can run in offline mode)
2. Set a vault password for encrypting your local libraries (or press Enter for plaintext)

### Main Menu Options

1. **Read card info** - Get UID, SAK, ATQA, and card type
2. **One-click decode** - Attempt full card decode using default + custom keys
3. **Encrypt card data** - Modify keys and access bits for all sectors
4. **Write card** - Write decoded/encrypted data to a blank card
5. **Manage key library** - Add/remove custom authentication keys
6. **Manage card library** - Save, load, export, delete stored cards
7. **Reconnect device** - Reattempt USB device connection
8. **Exit** - Close the application

### Key Library Commands

In the key library menu:
- `add <name> <keyhex>` - Add a new key (e.g., `add mykey AABBCCDDEEFF`)
- `del <name>` - Delete a key by name
- `back` - Return to main menu

### Card Library Commands

In the card library menu:
- `load <index>` - Load a card into memory for writing/editing
- `del <index>` - Delete a card from the library
- `export <index>` - Export card to JSON file
- `back` - Return to main menu

## Configuration

### Device VID/PID

Edit the following constants in `cli/copykey_cli.py` to match your device:

```python
DEVICE_VID = 0x0483  # Replace with your device's Vendor ID
DEVICE_PID = 0x5740  # Replace with your device's Product ID
```

Find your device VID/PID:
- **Linux**: `lsusb`
- **Windows**: Device Manager → Properties → Details → Hardware Ids
- **macOS**: `system_profiler SPUSBDataType`

### HID Report Sizes

If your device uses different report sizes, adjust:

```python
REPORT_SIZE_IN = 64    # Input report size
REPORT_SIZE_OUT = 64   # Output report size
FEATURE_REPORT_ID = 0x01
RESPONSE_REPORT_ID = 0x80
```

## Protocol Reverse Engineering

**IMPORTANT**: The exact HID command protocol is unknown and must be reverse-engineered from actual device traffic.

The current implementation uses speculative command opcodes:
- `CMD_GET_CARD_INFO = 0x01`
- `CMD_READ_SECTOR = 0x02`
- `CMD_WRITE_SECTOR = 0x03`
- `CMD_AUTHENTICATE = 0x04`
- `CMD_DECODE_CARD = 0x05`

To capture actual protocol:
1. Use **Wireshark** with **USBPcap** on Windows
2. Or use **usbmon** on Linux
3. Record traffic while using the official CopyKEY Manager software
4. Update the `send_command()` and parsing methods accordingly

## Security Features

### Vault Encryption

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2-SHA256 with 100,000 iterations
- **Salt**: 16 bytes random per encryption
- **Nonce**: 12 bytes random per encryption
- **Authentication**: 16-byte GCM tag prevents tampering

### Wrong Password Detection

The GCM authentication tag ensures that wrong passwords are detected immediately during decryption, preventing silent data corruption.

### Local-Only Storage

- No cloud sync
- No telemetry
- No network communication (except optional firmware/library updates via separate updater module)
- All data stored in `~/.copykey_cli/`

## Data Structures

### MifareSector

Represents a single Mifare Classic sector:
- 4 blocks × 16 bytes each
- Key A (6 bytes)
- Access bits (4 bytes)
- Key B (6 bytes)

### MifareCard

Complete card representation:
- UID, SAK, ATQA
- Card type (1K/4K)
- List of sectors
- Creation/modification timestamps

## Testing

Run the built-in test suite:

```bash
python -c "
from cli.copykey_cli import *
# Run tests as shown in development
"
```

All core components have been tested:
- ✓ AES Vault encryption/decryption
- ✓ Wrong password detection
- ✓ MifareSector operations
- ✓ MifareCard serialization
- ✓ LocalLibrary (plaintext and encrypted modes)
- ✓ Default keys loading

## Troubleshooting

### Device Not Found

1. Check VID/PID configuration
2. Ensure device is properly connected
3. Check USB permissions (Linux): 
   ```bash
   sudo usermod -a -G plugdev $USER
   # Then logout/login
   ```

### HID Report Errors

If you get HID report size errors:
1. Verify `REPORT_SIZE_IN` and `REPORT_SIZE_OUT` match your device
2. Check if device uses interrupt transfers instead of feature reports
3. Capture actual USB traffic to verify protocol

### Decryption Failed

If you get "Decryption failed - wrong password":
1. Ensure you're using the correct vault password
2. Check that the encrypted files haven't been corrupted
3. If password is lost, data cannot be recovered (by design)

## Architecture

```
cli/copykey_cli.py
├── AESVault           # Encryption/decryption helper
├── MifareSector       # Sector data structure
├── MifareCard         # Complete card structure
├── CopyKeyDevice      # HID device communication
├── CardOperations     # High-level workflows
├── LocalLibrary       # Key/card storage management
└── Interactive Menu   # CLI user interface
```

## Limitations

1. **Protocol Unknown**: HID command protocol is speculative and must be reverse-engineered
2. **No GUI**: Command-line only (GUI can be added separately)
3. **Mifare Classic Only**: Does not support other card types (DESFire, etc.)
4. **No Advanced Attacks**: Does not implement nested/darkside attacks (requires mfoc integration)

## Future Enhancements

- [ ] Actual HID protocol implementation (after reverse engineering)
- [ ] MFOC integration for hardnested attacks
- [ ] Support for Mifare DESFire and other card types
- [ ] PyQt6 GUI frontend
- [ ] Batch card operations
- [ ] Card format templates
- [ ] Access bit calculator/editor

## License

MIT License

## Disclaimer

This tool is for **educational and authorized testing purposes only**. Always ensure you have proper authorization before copying or cloning RFID/NFC cards. Unauthorized copying of access cards may violate laws in your jurisdiction.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues related to:
- **HID Protocol**: Capture USB traffic and submit findings
- **Encryption**: Review AESVault implementation
- **Features**: Open an issue with detailed requirements
