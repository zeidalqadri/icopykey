# CopyKEY CLI v2.1

Interactive command-line interface for NFC/RFID card management with the CopyKEY / X100 Smart
Card Replicator device.

## Features

- **Read** MIFARE Classic, ID/PID/NSC, and NTAG/Ultralight EV1 cards via USB HID device
- **One-click decode** — automatically try all known keys against encrypted sectors
- **Encrypt** card data with new keys, random per sector or uniform
- **Write** decoded/encrypted data to blank clone cards (CUID, FUID, UFUID, Gen3)
- **Key & Card libraries** with optional AES-256-GCM encrypted storage
- **Import/Export** card dumps as JSON, MFD, or BIN files
- **Configurable** VID/PID, persistent settings via JSON config file
- **Batch mode** — scriptable via command-line arguments
- **Color output** — uses `rich` when available, falls back gracefully

## Requirements

- Python 3.8+
- **hidapi** — USB HID device communication (via `pip install hidapi`)
- **pycryptodome** — AES encryption for vault storage
- **rich** (optional) — enhanced terminal formatting

### macOS

```bash
brew install hidapi
pip install hidapi pycryptodome rich
```

### Linux

```bash
sudo apt install libhidapi-hidraw0 libhidapi-dev
pip install hidapi pycryptodome rich
```

### Windows

```bash
pip install hidapi pycryptodome rich
```

## Quick Start

```bash
# Launch interactive menu
python -m copykey_python.cli.copykey_cli

# or if installed via pip:
copykey-cli
```

### Interactive Menu

```
══════════════════════════════════════════════════════════
  CopyKEY CLI v2.1
  NFC/RFID Card Management Tool
══════════════════════════════════════════════════════════
  Device:  Connected     Library: 12 keys, 5 cards
─────────────────────────────────────────────────────────
 1. Read Card          Read MIFARE/ID/NTAG from device
 2. One-Click Decode   Auto-decrypt all sectors
 3. Encrypt Data       Modify sector keys & access bits
 4. Write Card         Write data to blank/clone card
 5. Key Library        Manage authentication keys
 6. Card Library       Browse saved cards
 7. Import Card        Load .json/.mfd/.bin file
 8. Export Card        Export card to file
 9. Device Settings    VID/PID, info, reconnect
 h. Help               Show usage guide
 q. Quit               Exit application
```

## Batch / Scripting Mode

```bash
# Read a card and print info
copykey-cli --read

# One-click decode
copykey-cli --decode

# List stored cards
copykey-cli --list-cards

# List stored keys
copykey-cli --list-keys

# Import a card dump
copykey-cli --import card_dump.json

# Export card by index
copykey-cli --export 0 --output ./exports/

# Delete card by index
copykey-cli --delete 2

# Show device information
copykey-cli --device-info

# Custom VID/PID
copykey-cli --vid 0x1234 --pid 0x5678 --read

# Verbose logging
copykey-cli --verbose
```

## Configuration

Settings are stored in `~/.copykey_cli/config.json`. The file is auto-created with defaults
on first run.

```json
{
  "device": {
    "vid": "0x6300",
    "pid": "0x1991"
  },
  "paths": {
    "vault_dir": "~/.copykey_cli",
    "library_dir": "~/.copykey_cli/cards",
    "export_dir": "~/Documents"
  },
  "display": {
    "colors": true,
    "progress_bars": true
  },
  "security": {
    "confirm_writes": true,
    "backup_before_write": true
  }
}
```

## Module Structure

```
cli/
├── copykey_cli.py      # Main entry point (argparse + interactive loop)
├── operations.py       # Business logic (device, crypto, library, card ops)
├── commands.py         # Command handlers with display integration
├── menus.py            # Interactive menu renderer and sub-menus
├── display.py          # Terminal formatting (color, tables, panels)
├── progress.py         # Progress bars and spinners
├── validators.py       # Input validation (keys, UIDs, paths, etc.)
├── config_manager.py   # JSON configuration persistence
├── logger_setup.py     # Logging configuration
├── errors.py           # Typed exception hierarchy
└── tests/
    ├── test_validators.py
    ├── test_commands.py
    ├── test_config.py
    └── test_display.py
```

## Running Tests

```bash
pytest copykey_python/cli/tests/ -v
```

## Notes

- The HID protocol commands are **speculative**. Exact command opcodes require USB traffic
  capture with Wireshark/USBPcap.
- Device VID/PID defaults (`0x6300:0x1991`) match the CopyKEY HID device — enumerate with the
  Device Settings menu if your hardware differs.
- Vault encryption uses PBKDF2-SHA256 (100K iterations) + AES-256-GCM. Do not lose your password.
- This tool is for legal use only — cards you own or have authorization to analyze.
