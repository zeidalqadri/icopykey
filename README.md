# icopyzed

Offline-first command-line tool for NFC/RFID card management with CopyKEY / X100 Smart Card Replicator devices. Read, decode, encrypt, and clone MIFARE Classic, ID, and NTAG cards — no cloud, no telemetry, no network calls during card operations.

## Quick Start

```bash
# macOS: install USB HID library first
brew install hidapi

# Install
pip install icopyzed

# Launch interactive menu
icopyzed
```

## Three Commands, One Tool

```
icopyzed              Interactive menu: read, decode, encrypt, write, library management
icopyzed decrypt      kopized — real-time decryption service for X100 encrypted sectors
icopyzed convert      Batch dump normalizer: .x100 / .mfd / .bin → .json
```

### Interactive Menu

```
 1. Read Card          Read MIFARE/ID/NTAG from device
 2. One-Click Decode   Auto-decrypt all sectors with known keys
 3. Encrypt Data       Modify sector keys & access bits
 4. Write Card         Write data to blank/clone card
 5. Key Library        Manage authentication keys
 6. Card Library       Browse saved cards
 7. Import Card        Load .json/.mfd/.bin dump file
 8. Export Card        Export card to file
 9. Device Settings    VID/PID, info, reconnect
```

### Batch Mode

```bash
icopyzed --read                        # Read card, print UID, exit
icopyzed --decode                      # One-click decode all sectors
icopyzed --list-cards                  # Show saved cards
icopyzed --import card_dump.json       # Import from file
icopyzed --export 0 -o ./exports       # Export card #0
icopyzed --vid 0x0483 --pid 0x5740 --device-info
```

### Decrypt Subcommand

```bash
icopyzed decrypt                      # Interactive: paste device output
icopyzed decrypt --demo               # Demo mode, no hardware needed
icopyzed decrypt -k FFFFFFFFFFFF      # Add custom key
icopyzed decrypt -f keys.txt          # Load keys from file
icopyzed decrypt -o results.json      # Save results
```

### Convert Subcommand

```bash
icopyzed convert dump.x100 -o ./output
icopyzed convert dump1.mfd dump2.bin --format json --workers 4
icopyzed convert encrypted.x100 --recover-keys --strict
```

## Features

- **Offline-first**: all card, key, and crypto operations work without internet
- **Encrypted vault**: PBKDF2 + AES-256-GCM storage for keys and cards
- **Key brute-force**: automatically tries 10 factory defaults + your custom keys
- **Crypto-1 LFSR**: built-in MIFARE Classic stream cipher implementation
- **Cross-platform**: macOS, Linux, Windows (requires `hidapi`)
- **Rich terminal UX**: colored tables, progress bars, spinners (falls back to plain text)

## Supported Cards

| Type | Read | Decode | Write |
|------|------|--------|-------|
| MIFARE Classic 1K (S50) | ✓ | ✓ | ✓ |
| MIFARE Classic 4K (S70) | ✓ | ✓ | ✓ |
| ID/PID/NSC | ✓ | — | ✓ |
| NTAG/Ultralight EV1 | ✓ | — | ✓ |

## Requirements

- Python 3.9+
- `hidapi` — see [platform notes](#platform-notes) below

### Platform Notes

**macOS**: `brew install hidapi` before `pip install icopyzed`

**Linux**: `sudo apt install libhidapi-hidraw0 libhidapi-dev`

**Windows**: `hidapi` installs via pip without extra steps

## Development

```bash
git clone https://github.com/zeidalqadri/icopykey.git
cd icopykey
pip install -e ".[dev]"
pytest src/icopykey/cli/tests/ src/icopykey/x100/tests/ -v
```

## Legal

This tool is for use on cards you own or have explicit authorization to analyze. Unauthorized cloning or decryption of smart cards may violate local laws.

## License

MIT
