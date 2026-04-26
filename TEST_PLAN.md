# Test Plan: icopykey — X100 Smart Card Replicator Integration Testing

**Document Version:** 1.0
**Date:** 2026-04-26
**Target Platform:** macOS (user's MacBook)
**Target Device:** X100 Smart Card Replicator (USB HID NFC reader/writer)

---

## 1. System Under Test

### 1.1 Purpose

**icopykey** is an offline-first, reverse-engineered Python reimplementation of CopyKEY Manager V2.0.2.1 — a tool for reading, decoding, encrypting, and cloning MIFARE Classic 1K/4K NFC/RFID cards. It permanently blocks all cloud/auth/analytics endpoints from the original app.

### 1.2 Components

| Component | Path | Role |
|-----------|------|------|
| **Device Interface** | `copykey_python/core/device_interface.py` (358 LOC) | USB HID enumeration, connect/disconnect, feature report send/receive, high-level card operations |
| **Main CLI** | `copykey_python/cli/copykey_cli.py` (1406 LOC) | Interactive menu: read card, one-click decode, encrypt, write, key/card library management, AES vault |
| **Crypto-1 Cipher** | `copykey_python/core/mifare_crypto.py` (287 LOC) | 48-bit LFSR stream cipher, sector/card dataclasses |
| **Card Encryption** | `copykey_python/core/card_encryption.py` (104 LOC) | Sector-level key replacement, access bit modification |
| **Key Vault** | `copykey_python/core/key_vault.py` (144 LOC) | PBKDF2 + AES-256-GCM encrypted key storage |
| **Card Library** | `copykey_python/core/card_library.py` (326 LOC) | Local JSON card database (search, import, export) |
| **Network Policy** | `copykey_python/config/network_policy.py` (261 LOC) | Whitelist/blacklist enforcement, static audit |
| **kopized Service** | `x100_decrypt/kopized.py` (548 LOC) | Real-time decryption: parses X100 text output, tries keys, returns `WRITE_KEY` commands |
| **kopized CLI** | `x100_decrypt/kopized_cli.py` (322 LOC) | Three modes: `--demo`, `--interactive` (stdin paste), `--listen-usb` (stub) |
| **Dump Engine** | `x100_decrypt/engine.py` (351 LOC) | Batch converter: X100/raw → `.mfd`/`.bin`/`.json` with optional key recovery |
| **Crypto Primitives** | `x100_decrypt/crypto.py` (470 LOC) | AES-128/192/256 (ECB/CBC), DES/3DES, key derivation |
| **Key Manager** | `x100_decrypt/keymanager.py` (491 LOC) | Secure key loading from hex/files/env, validation, masking |

### 1.3 Corrections Applied (Recent Commits)

| Commit | Summary |
|--------|---------|
| `abf4982` | Fixed test imports (`format_strategies` → `strategies`), deleted 5 redundant docs, fixed lazy import in `raw_format.py`, removed `__pycache__` from tracking |
| `049a46a` | Deduplicated `format_strategies.py` + `strategies.py` → `strategies/` subpackage, fixed all import paths, implemented missing `mifare_crypto.py`, `card_encryption.py`, `key_vault.py` |
| `cae65f8` | Merged x100 decrypt module with strategies and engine |
| `aae8248` | Merged interactive CLI emulator |

---

## 2. Device Under Test

### 2.1 Identification

| Attribute | Value |
|-----------|-------|
| **Device** | X100 Smart Card Replicator |
| **Interface** | USB HID (Human Interface Device) |
| **Expected VID** | `0x0483` (STMicroelectronics — speculative, needs verification) |
| **Expected PID** | `0x5740` (speculative, needs verification) |
| **Connection** | USB cable to MacBook |
| **Supported cards** | MIFARE Classic 1K (S50) / 4K (S70), CUID/FUID/UFUID/Gen3 magic cards |

### 2.2 Communication Protocol

The X100 device has **two known communication modes**:

**Mode A — Text-based output (usable)**:
When the device scans a card with encrypted sectors, it outputs ASCII text via its USB-serial interface:

```
CN: 16198219
Model: IC/MI-S50+
UID: 4B 2A F7 53
ATQA: 04 00       SAK: 08

TIPS
There are encrypted sectors. Please connect to the computer
and use decryption software to decrypt
```

This is the protocol that `kopized` intercepts and processes.

**Mode B — HID feature reports (speculative)**:
The device uses HID Feature Reports for command/response. The exact command opcodes (`CMD_GET_CARD_INFO=0x01`, `CMD_READ_SECTOR=0x02`, etc.) are placeholders requiring USB traffic capture with Wireshark/USBPcap for validation.

---

## 3. Definition of "Interaction"

### 3.1 Interaction Levels

| Level | Name | Actions | Expected Outcomes |
|-------|------|---------|-------------------|
| **L0** | Demo/Smoke Test | Run `kopized --demo` and `x100-decrypt` with sample data | All modules import, strategy detection works, decryption pipeline produces expected JSON, no crashes |
| **L1** | kopized Interactive | Copy real X100 device text output, paste into `kopized` interactive mode | Card info parsed correctly (UID, model, ATQA, SAK), key recovery attempts logged, `WRITE_KEY` commands generated |
| **L2** | USB Device Detection | Connect X100 device, enumerate HID devices via the Python tool | Device found at expected VID/PID, manufacturer/product/serial strings readable, connection opened successfully |
| **L3** | USB HID Command | Send a read-card command, receive response | Device responds with valid card UID and sector data, response format matches (or informs) protocol assumptions |
| **L4** | End-to-End Clone | Read card → decode sectors → encrypt → write to blank card | Full clone workflow completes, written card is readable and matches source |

### 3.2 Specific Actions and Expected Outcomes

#### L0 — Demo/Smoke Test

| # | Action | Command | Expected Outcome |
|---|--------|---------|-----------------|
| L0.1 | Verify imports | `python -c "from x100_decrypt import kopized, engine, crypto, keymanager, strategies, cli"` | No ImportError, all modules load |
| L0.2 | Verify copykey imports | `python -c "from copykey_python.core import device_interface, mifare_crypto, card_encryption, key_vault, card_library"` | No ImportError (may warn about hidapi if not installed) |
| L0.3 | Run kopized demo | `kopized --demo` | Parses sample card, generates decryption response, prints `WRITE_KEY` commands, exit code 0 |
| L0.4 | Run existing tests | `cd x100_decrypt && python -m pytest tests/ -v` | All 4 tests pass |
| L0.5 | Batch decrypt demo | `x100-decrypt ...` (with sample dump) | Dump normalized to `.json`, base64 data round-trips correctly |

#### L1 — kopized Interactive with Real Device

| # | Action | Command | Expected Outcome |
|---|--------|---------|-----------------|
| L1.1 | Launch interactive mode | `kopized --interactive --verbose` | Prints prompt, waits for input |
| L1.2 | Paste device output | Paste X100 text output (from device scan) | `DecryptionRequest.from_device_output()` parses all fields: CN, Model, UID, ATQA, SAK |
| L1.3 | Observe sector count | — | 16 sectors for S50/1K, 40 sectors for S70/4K |
| L1.4 | Observe key recovery | — | Each sector checked against default keys (10 built-in + any user-provided), matches logged |
| L1.5 | Observe WRITE_KEY commands | — | One `WRITE_KEY N (A\|B) HEXHEXHEX` per decrypted sector, terminated by `DECRYPTION_COMPLETE ACK` |
| L1.6 | Save to JSON | `kopized --interactive -o results.json` | Valid JSON file produced with `success`, `card_info`, `decrypted_sectors`, `keys_recovered`, `time_taken_ms` |
| L1.7 | Custom key file | `kopized --interactive -f mykeys.txt -v` | Keys from file loaded, count logged (`Loaded N keys`), used in decryption attempts |
| L1.8 | Add individual key | `kopized --interactive -k AABBCCDDEEFF` | Custom key added to pool and tried alongside defaults |

#### L2 — USB Device Detection

| # | Action | Command | Expected Outcome |
|---|--------|---------|-----------------|
| L2.1 | Install hidapi | `pip install hidapi` | Success (may need `brew install hidapi` first on macOS) |
| L2.2 | Enumerate USB HID devices | Run device_interface enumerate or `python -c "import hid; print(hid.enumerate())"` | Lists all HID devices, X100 should appear in list |
| L2.3 | Identify actual VID/PID | From enumeration output | Compare against expected (`0x0483`, `0x5740`). Update `DEVICE_VID`/`DEVICE_PID` if different |
| L2.4 | Connect to device | `CopyKeyDevice(vid=..., pid=...).connect()` | `is_connected()` returns True, manufacturer/product/serial strings populated |
| L2.5 | Get device info | `device.get_device_info()` | Returns dict with manufacturer, product, serial, path |
| L2.6 | Disconnect | `device.disconnect()` | `is_connected()` returns False, no exceptions |

#### L3 — USB HID Command (Protocol Discovery)

| # | Action | Expected Outcome |
|---|--------|-----------------|
| L3.1 | Send `CMD_GET_DEVICE_INFO` (opcode `0x10`) | Device responds, response format documented (whether correct or not) |
| L3.2 | Send `CMD_GET_CARD_INFO` (opcode `0x01`) | If card present, response contains UID bytes. If no card, device returns error status |
| L3.3 | Send `CMD_READ_SECTOR` (opcode `0x02`) with sector 0 | Response contains 64 bytes (4 blocks x 16 bytes). Compare trailer block with known defaults |
| L3.4 | Record actual protocol | All responses logged in hex. Compare with assumed format: `[report_id(0x80) \| len \| data]` |
| L3.5 | Timeout behavior | Commands sent without card present — observe timeout handling, device does not hang |

#### L4 — End-to-End Clone (if HID protocol validated)

| # | Action | Expected Outcome |
|---|--------|-----------------|
| L4.1 | Read source card | Card UID, type, all readable sector data captured |
| L4.2 | Decode encrypted sectors | All 16/40 sectors decrypted (default keys + custom keys), each sector has Key A and Key B populated |
| L4.3 | Encrypt card data | Sector trailer blocks updated with new keys, `will_read_only` flag respected |
| L4.4 | Write to blank card | Write command acknowledged with success, no errors |
| L4.5 | Verify written card | Re-read blank card — UID matches (or is CUID/FUID if magic card), sector keys match encrypted values |
| L4.6 | Cross-validate with kopized | Card data from HID read matches kopized text output for same card |

---

## 4. Step-by-Step Testing Procedure

### 4.1 Phase 0 — Prerequisites Setup

**Time estimate:** 10 minutes

1. **Install system dependencies:**
   ```bash
   # On MacBook
   brew install hidapi    # Required for USB HID access
   ```

2. **Install Python dependencies:**
   ```bash
   cd /path/to/icopykey

   # Install x100_decrypt (packaged)
   pip install -e ./x100_decrypt

   # Install copykey_python requirements
   pip install -r ./copykey_python/requirements.txt
   ```

3. **Verify installation:**
   ```bash
   python -c "import hid; print('HID OK')"
   python -c "from x100_decrypt import kopized; print('x100 OK')"
   python -c "from copykey_python.core import device_interface; print('copykey OK')"
   ```

4. **Connect X100 device** to MacBook USB port. Ensure the device powers on (LED indicator).

### 4.2 Phase 1 — Demo / Smoke Tests (No Hardware Required)

**Time estimate:** 5 minutes
**Prerequisite:** Phase 0 complete

| Step | Command | Observation Point | Pass If |
|------|---------|-------------------|---------|
| 1.1 | `pytest x100_decrypt/tests/ -v` | Terminal output | All 4 tests pass (green dots) |
| 1.2 | `kopized --demo` | Parsed card info, decryption results, WRITE_KEY commands | Exit code 0, no exceptions |
| 1.3 | `kopized --demo --verbose` | Verbose debug output including key attempts | Each sector logged with "Found Key A" or "No matching key" |
| 1.4 | `kopized --demo --no-defaults` | Decryption with no default keys | Fewer/no keys recovered, error message shown |
| 1.5 | `kopized --demo -k A0A1A2A3A4A5 -k FFFFFFFFFFFF` | Custom keys only | Keys recovered limited to provided keys |
| 1.6 | `kopized --version` | Prints `kopized 0.1.0` | Version string correct |

### 4.3 Phase 2 — kopized Interactive with Real Device

**Time estimate:** 15 minutes
**Prerequisite:** Phase 1 passed, X100 device connected

| Step | Action | Observation Point | Pass If |
|------|--------|-------------------|---------|
| 2.1 | Launch: `kopized --interactive --verbose` | Prompts for paste input | Ready prompt displayed |
| 2.2 | Scan a MIFARE Classic card with X100 device | Device displays text on its screen/LCD | Card detected with encrypted sectors message |
| 2.3 | Transcribe device output (or use serial terminal to capture it) | Copy the exact text output | Text matches format: `CN:`, `Model:`, `UID:`, `ATQA:`, `SAK:` |
| 2.4 | Paste transcribed output into kopized, press Enter twice | kopized parses and processes | `request_id` generated, card UID matches device output |
| 2.5 | Observe decryption results | Sector-by-sector output | At least some sectors decrypted (factory-default cards should fully decrypt) |
| 2.6 | Review WRITE_KEY commands | Command list printed | Format: `WRITE_KEY N (A\|B) HEXHEXHEX` |
| 2.7 | Save: `kopized --interactive -o test_results.json` | JSON file created | Valid JSON with all fields populated |
| 2.8 | Repeat with custom key file | `kopized --interactive -f keys.txt -v` | Custom keys loaded and tried |
| 2.9 | Test with no card / error input | Paste garbled text | Graceful error, no crash, descriptive error message |
| 2.10 | Ctrl+C to exit | Process exits cleanly | Exit code 0, "Exiting..." printed |

### 4.4 Phase 3 — USB HID Device Detection

**Time estimate:** 10 minutes
**Prerequisite:** Phase 1 passed, X100 USB connected

| Step | Action | Observation Point | Pass If |
|------|--------|-------------------|---------|
| 3.1 | `python -c "import hid; devices = hid.enumerate(); print(f'Total HID devices: {len(devices)}'); [print(f'{d[\"vendor_id\"]:04x}:{d[\"product_id\"]:04x} {d.get(\"product_string\",\"?\")}') for d in devices]"` | List of all USB HID devices | X100 device appears in list |
| 3.2 | Record actual VID/PID of X100 | From enumeration output | Identified with certainty |
| 3.3 | `python -c "from copykey_python.core.device_interface import CopyKeyDevice; d = CopyKeyDevice(vid=0x????, pid=0x????); print(d.enumerate_devices())"` | Enumerate with actual VID/PID | One or more devices found |
| 3.4 | `python -c "... d.connect(); print(d.get_device_info()); d.disconnect()"` | Device info printed | Manufacturer, product, serial, path all populated |
| 3.5 | Test reconnection | Connect → disconnect → connect again | Second connect succeeds |
| 3.6 | Test with device unplugged | `d.enumerate_devices()` | Empty list, no crash |
| 3.7 | Test connect with no device | `d.connect()` | Returns False, logged warning |

### 4.5 Phase 4 — USB HID Command Discovery

**Time estimate:** 20 minutes
**Prerequisite:** Phase 3 passed, device VID/PID confirmed

| Step | Action | Observation Point | Pass If |
|------|--------|-------------------|---------|
| 4.1 | Create test script `test_hid_protocol.py` using `CopyKeyDevice` class | — | Script runs without import errors |
| 4.2 | Connect and send `get_device_info` command: `bytes([0x10])` | Response logged in hex | Any non-timeout response received or timeout handled gracefully |
| 4.3 | Place MIFARE card on device, send `get_card_info` command: `bytes([0x01])` | Response logged | Response contains recognizable UID bytes, or absence documented |
| 4.4 | Send read sector 0 command: `bytes([0x02, 0x00])` | Response logged | 16+ bytes returned |
| 4.5 | Send read sector 15 command: `bytes([0x02, 0x0F])` | Response logged | Compare sector 0 vs sector 15 trailer blocks |
| 4.6 | Send invalid opcode: `bytes([0xFF])` | Response logged | Graceful error or no response (device doesn't crash) |
| 4.7 | Send oversized command | Response logged | Error handling in Python code works |
| 4.8 | Rapid send two commands without reading | Second command | Device state remains stable |
| 4.9 | Document actual protocol vs assumed | Comparison table | Gaps identified, next steps for protocol reverse engineering defined |

### 4.6 Phase 5 — End-to-End Clone (Conditional)

**Time estimate:** 30 minutes
**Prerequisite:** Phase 4 passed with validated protocol

Execute the full clone workflow per Section 3.2, L4 actions. This phase is **conditional** on successful protocol discovery in Phase 4. If the HID protocol remains unvalidated, this phase is deferred.

---

## 5. Success Criteria (Measurable & Verifiable)

| Criterion ID | Description | Threshold | Measurement Method |
|-------------|-------------|-----------|-------------------|
| **SC-1** | All existing unit tests pass | 4/4 tests pass | `pytest x100_decrypt/tests/ -v` exit code 0 |
| **SC-2** | kopized demo mode runs to completion | Exit code 0 | `kopized --demo; echo $?` |
| **SC-3** | kopized parses real device output without error | 100% of fields extracted (CN, Model, UID, ATQA, SAK) | Compare parsed dict against device display |
| **SC-4** | Factory-default card yields >=2 decrypted sectors | >=2 sectors | Count `decrypted_sectors` in `DecryptionResponse` |
| **SC-5** | Decryption request processed within time limit | < 5 seconds | `time_taken_ms` field in response |
| **SC-6** | JSON output is structurally valid | Passes `json.load()` without error | `kopized -o out.json && python -c "import json; json.load(open('out.json'))"` |
| **SC-7** | Custom key loading from file works | Loaded keys count = lines in file (excluding comments/blanks) | Verbose log output |
| **SC-8** | Device detected via HID enumeration | X100 appears in `hid.enumerate()` results | Manual verification of VID/PID/product string |
| **SC-9** | HID connection succeeds | `is_connected()` returns True | Programmatic check |
| **SC-10** | Device info retrieval succeeds | manufacturer/product/serial non-None | `get_device_info()` dict populated |
| **SC-11** | No crashes on error conditions | 0 unhandled exceptions | Run through Sections 4.4-4.5 with varied inputs |
| **SC-12** | No network calls during offline operations | 0 network connections opened | Network monitoring (e.g., `lsof -i` or Little Snitch on macOS) |

---

## 6. Logging and Error Handling Strategy

### 6.1 Logging Configuration

All components use Python's `logging` module:

```python
# Default: INFO level with timestamps
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Verbose mode: DEBUG level
# kopized: --verbose flag
# copykey_cli: --debug flag (if added)
```

### 6.2 Log Capture

| Method | Purpose | Command |
|--------|---------|---------|
| Terminal output | Real-time observation | Default (stderr) |
| Redirect to file | Persistent audit trail | `kopized --demo 2>&1 | tee test_log.txt` |
| Python logging file handler | Structured capture | Add `FileHandler` in test harness |

### 6.3 Error Handling Categories

| Category | Expected Behavior | Recovery Action |
|----------|------------------|-----------------|
| **hidapi not installed** | ImportError with install instructions | `pip install hidapi` (or `brew install hidapi && pip install hidapi` on macOS) |
| **Device not found** | Warning logged, `connect()` returns False | Check USB connection, verify VID/PID, try different port |
| **Device disconnected mid-operation** | `IOError` or `HIDException` caught, logged, `is_connected()` returns False | Reconnect via menu option or restart |
| **HID read timeout** | Returns `None` after timeout_ms | Retry up to 3 times with 1.5x timeout multiplier |
| **Invalid device output** | `DecryptionRequest.from_device_output()` tolerates missing fields | Partial parsing, warn on missing critical fields (UID, model) |
| **No key found for sector** | `attempt_sector_decryption()` returns None, sector marked as failed | Try additional keys, use external `mfoc` tool |
| **AES vault wrong password** | `cipher.decrypt_and_verify()` raises ValueError | Clear error message, request password retry (3 attempts max) |
| **Corrupted vault file** | ValueError on salt/iv/tag extraction | Backup vault file before operation, restore from backup |
| **Network policy violation** | `NetworkPolicyError` raised before request | Operation rejected, logged with details of blocked endpoint |

### 6.4 Test-Specific Logging

For each test phase, create a timestamped log directory:

```bash
TEST_RUN=$(date +%Y%m%d_%H%M%S)
mkdir -p test_results/$TEST_RUN
```

Capture:
- `phase1_demo.log` — kopized demo output
- `phase2_interactive.log` — kopized interactive session
- `phase3_enumeration.log` — HID device list
- `phase4_protocol.log` — command/response hex dumps
- `phase5_e2e.log` — full clone workflow

---

## 7. Rollback and Recovery Plan

### 7.1 Device Safety

| Risk | Mitigation |
|------|-----------|
| **Device firmware corruption** | HID protocol commands are read-only until Phase 5. No firmware update attempted unless explicitly confirmed. The firmware updater (`firmware_updater.py`) is separate and not part of this test plan. |
| **Device bricking from invalid commands** | Phase 4 sends one command at a time with observation pauses. Start with read-only commands (`get_device_info`, `get_card_info`). Only proceed to write commands (`CMD_WRITE_SECTOR`, `CMD_WRITE_CARD`) after read commands validated. |
| **Device stuck in bad state** | Power cycle device (unplug USB, wait 5 seconds, reconnect). Re-enumerate and reconnect. |
| **Card corruption** | Use test/dummy cards for write operations. Never use valuable/one-of-a-kind cards for write testing. Have at least 3 blank writable cards available. |

### 7.2 System Recovery

| Risk | Recovery |
|------|----------|
| **Corrupted key vault** | Vault auto-creates backup before save. Restore: `cp vault.bak vault.json` |
| **Corrupted card library** | Library is plain JSON — restore from manual backup or re-scan cards |
| **Python environment broken** | `pip install -e ./x100_decrypt` reinstall, or create fresh virtualenv: `python -m venv testenv && source testenv/bin/activate && pip install -e ./x100_decrypt && pip install -r copykey_python/requirements.txt` |
| **hidapi conflicts on macOS** | `brew uninstall hidapi && brew install hidapi && pip install --force-reinstall hidapi` |

### 7.3 Abort Conditions

Stop testing and escalate if:
1. Device becomes unresponsive and does not recover after power cycle
2. Any command causes the device to emit smoke, unusual heat, or sounds
3. HID writes succeed but subsequent reads return corrupted/garbage data repeatedly
4. macOS kernel panics or USB subsystem crashes

---

## 8. Results Template

### 8.1 Test Execution Record

```
============================================================================
TEST EXECUTION RECORD
============================================================================
Date:            YYYY-MM-DD
Tester:          <name>
Device:          X100 Smart Card Replicator
Device VID/PID:  ____:____ (as detected)
Device Serial:   _________________
macOS Version:   _________________
Python Version:  ____.___.___
Card(s) Used:    <type, UID if known>
============================================================================
```

### 8.2 Phase Results

```
PHASE 0: PREREQUISITES
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[ ] P0.1  brew install hidapi                    PASS / FAIL
[ ] P0.2  pip install -e ./x100_decrypt          PASS / FAIL
[ ] P0.3  pip install -r requirements.txt        PASS / FAIL
[ ] P0.4  Import verification                    PASS / FAIL
[ ] P0.5  Device connected and powered on        PASS / FAIL

PHASE 1: DEMO / SMOKE TESTS
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[ ] 1.1  pytest tests/ -v (4 tests)              PASS / FAIL  __/4 passed
[ ] 1.2  kopized --demo                          PASS / FAIL  exit=__
[ ] 1.3  kopized --demo --verbose                PASS / FAIL
[ ] 1.4  kopized --demo --no-defaults            PASS / FAIL
[ ] 1.5  kopized --demo -k <key1> -k <key2>      PASS / FAIL
[ ] 1.6  kopized --version                       PASS / FAIL

PHASE 2: KOPIZED INTERACTIVE WITH REAL DEVICE
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[ ] 2.1  Launch interactive mode                 PASS / FAIL
[ ] 2.2  Scan card with X100 device              PASS / FAIL
[ ] 2.3  Transcribe/capture device output        PASS / FAIL
[ ] 2.4  Paste and parse device output           PASS / FAIL
[ ] 2.5  Decryption results observed             PASS / FAIL  __ sectors
[ ] 2.6  WRITE_KEY commands generated            PASS / FAIL
[ ] 2.7  JSON output saved (-o)                  PASS / FAIL
[ ] 2.8  Custom key file (-f)                    PASS / FAIL  __ keys
[ ] 2.9  Error handling (bad input)              PASS / FAIL
[ ] 2.10 Clean exit (Ctrl+C)                     PASS / FAIL

PHASE 3: USB HID DEVICE DETECTION
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[ ] 3.1  hid.enumerate() lists all devices       PASS / FAIL  __ devices
[ ] 3.2  X100 VID/PID identified                 PASS / FAIL  ____:____
[ ] 3.3  CopyKeyDevice.enumerate_devices()       PASS / FAIL
[ ] 3.4  Connect + get_device_info()             PASS / FAIL
[ ] 3.5  Reconnect test                          PASS / FAIL
[ ] 3.6  No-device enumeration                   PASS / FAIL
[ ] 3.7  No-device connect attempt               PASS / FAIL

PHASE 4: USB HID COMMAND DISCOVERY
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[ ] 4.1  Test script created/runs                PASS / FAIL
[ ] 4.2  get_device_info command (0x10)          PASS / FAIL
         Response hex: _________________________
[ ] 4.3  get_card_info command (0x01)            PASS / FAIL
         Response hex: _________________________
[ ] 4.4  read sector 0 command (0x02)            PASS / FAIL
         Response hex: _________________________
[ ] 4.5  read sector 15 command                  PASS / FAIL
[ ] 4.6  Invalid opcode (0xFF)                   PASS / FAIL
[ ] 4.7  Oversized command                       PASS / FAIL
[ ] 4.8  Rapid double-send test                  PASS / FAIL
[ ] 4.9  Protocol gap analysis completed         PASS / FAIL

PHASE 5: END-TO-END CLONE (conditional)
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[ ] 5.1  Read source card                        PASS / FAIL
[ ] 5.2  Decode encrypted sectors                PASS / FAIL  __/__ sectors
[ ] 5.3  Encrypt card data                       PASS / FAIL
[ ] 5.4  Write to blank card                     PASS / FAIL
[ ] 5.5  Verify written card                     PASS / FAIL
[ ] 5.6  Cross-validate kopized <-> HID          PASS / FAIL
```

### 8.3 Observations / Corrective Actions

```
OBSERVATIONS:
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
<Free-form notes: unexpected behavior, protocol discoveries, performance
issues, warnings, environment quirks>

CORRECTIVE ACTIONS NEEDED:
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
1. ___________________________________________________________ Priority: ___
2. ___________________________________________________________ Priority: ___
3. ___________________________________________________________ Priority: ___

PROTOCOL DISCOVERIES (Phase 4 only):
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  Assumed opcode       Actual behavior        Correct command format
  - - - - - - - - - -  - - - - - - - - - - -  - - - - - - - - - - - - - - -
  0x01 (card info)     _________________     __________________________
  0x02 (read sector)   _________________     __________________________
  0x10 (device info)   _________________     __________________________
```

### 8.4 Success Criteria Summary

```
CRITERIA SUMMARY:
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
SC-1  All tests pass               [ ] PASS / FAIL
SC-2  kopized demo exit 0          [ ] PASS / FAIL
SC-3  Device output parsed 100%    [ ] PASS / FAIL
SC-4  >=2 sectors decrypted         [ ] PASS / FAIL
SC-5  Decrypt < 5 seconds          [ ] PASS / FAIL
SC-6  JSON output valid            [ ] PASS / FAIL
SC-7  Key file loading works       [ ] PASS / FAIL
SC-8  Device found in enumeration  [ ] PASS / FAIL
SC-9  HID connection succeeds      [ ] PASS / FAIL
SC-10 Device info non-None         [ ] PASS / FAIL
SC-11 No crashes on errors         [ ] PASS / FAIL
SC-12 No network calls             [ ] PASS / FAIL

OVERALL RESULT:  PASS / PARTIAL / FAIL    (__/12 criteria met)
```

---

## Appendix A: Key Files and Locations

| Item | Path |
|------|------|
| Installable package | `x100_decrypt/` (has `pyproject.toml`) |
| Main CLI script | `copykey_python/cli/copykey_cli.py` |
| Device interface | `copykey_python/core/device_interface.py` |
| kopized service | `x100_decrypt/kopized.py` |
| kopized CLI | `x100_decrypt/kopized_cli.py` |
| Dump engine | `x100_decrypt/engine.py` |
| Existing tests | `x100_decrypt/tests/test_core.py` |
| Canonical analysis | `ANALYSIS.md` |

## Appendix B: Known Limitations

1. **HID protocol is speculative** — command opcodes and response format are educated guesses; Phase 4 will determine actual protocol
2. **`kopized --listen-usb` is a stub** — USB listener mode not yet implemented
3. **`crack_key()` is a stub** — the darkside/nested attack for Crypto-1 key recovery is not implemented; relies on `mfoc` external tool or known-key dictionary
4. **No GUI** — `copykey_python/gui/` is an empty stub
5. **macOS hidapi** requires `brew install hidapi` before `pip install hidapi`
6. **USB-serial vs HID** — the X100 device may expose both a serial port (for text output) and HID interface; Phase 3 enumeration will clarify
