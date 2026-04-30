# CopyKEY Manager V2.0.2.1 — Reverse Engineering Analysis

## Overview

CopyKEY Manager is a Windows desktop application (3.76 MB, MSVC-compiled 32-bit x86, ATL/WTL framework) for NFC/RFID card cloning, specifically MIFARE Classic 1K/4K. The app manages card reading, decoding, encryption, cloning to blank cards (CUID, FUID, UFUID, Gen3), and cloud-synced key/card libraries.

The Python reimplementation (`src/icopykey/`) is **offline-first** — all cloud/auth/analytics endpoints are permanently blocked only the HID relay protocol permits TCP connections to localhost or authorized peers.

---

## Windows App Architecture

| Module | Class(es) | Function |
|--------|-----------|----------|
| `makekeylib_main` | `AAP8makekeylib_main`, `AVmakekeylib_main` | Key library UI — add/delete/save keys to encrypted vault |
| `makecardlib_main` | `AAP8makecardlib_main`, `AVmakecardlib_main` | Card library — name/UID/address metadata, cloud sync |
| `carddata_encrypt_form` | `AAP8carddata_encrypt_form`, `AVcarddata_encrypt_form` | Encrypt card sector data with new keys |
| `CopyKeyDeviceWork` | — | HID USB communication thread |
| Network modules | — | Auth (`/api/auth/`), cloud sync (`/api/cloud/`), analytics (`/api/analytics/`), chat (`/api/chat/`) |

---

## Network Endpoints (All BLOCKED in Reimplementation)

### Discovered endpoints
- `client.copykey.hyctec.cn` — **Primary API**: authentication, user management, cloud sync, analytics, telemetry **— PERMANENTLY BLOCKED**
- `copykey.hyctec.cn` — Firmware/library distribution

### Python network policy (whitelist + blacklist)

```python
ALLOWED_HOSTS = {"copykey.hyctec.cn"}
ALLOWED_PATHS = {"/firmware/", "/libraries/", "/version.json"}
DENIED_HOSTS = {"client.copykey.hyctec.cn"}
DENIED_PATHS = {
    "/api/auth/", "/api/user/", "/api/cloud/",
    "/api/analytics/", "/api/chat/", "/api/sync/", "/api/telemetry/",
    "/login", "/register", "/user/", "/cloud/",
}
```

Validation is multi-layer: host whitelist → path whitelist → path blacklist → purpose check. A static audit function scans code for unauthorized `requests`/`urllib`/`httpx`/`aiohttp` calls.

---

## Cryptography

### Key Management
- MIFARE keys are 6-byte values (12 hex chars). Factory defaults (`FF*6`, `00*6`, `A0A1A2A3A4A5`, etc.) are tried first during decode.
- Keys are persisted in an AES-256-GCM encrypted vault: `PBKDF2(password, salt, 100k iterations) → 32-byte key → AES-GCM encrypt(JSON key list)`.
- File format: `salt(16) + iv(12) + tag(16) + ciphertext(N)`.
- Metadata (salt, version) is stored separately in a `.meta` sidecar file.

### Card Encryption
- Sector trailer block (block 3 of 4) contains: `key_a(6) + access_bits(4) + key_b(6)`.
- Encryption = replace trailer bytes with new keys + optional access bit changes.
- Default transport configuration: `access_bits = ff 07 80 69`.
- Read-only config: `access_bits = 78 77 88 00` (key A/B not readable).

### Crypto-1 (MIFARE Classic stream cipher)
- 48-bit LFSR with proprietary feedback polynomial and non-linear filter function.
- Authentication: tag challenges with 32-bit nonce, 4-byte keystream for `{nr}`, 4-byte for `{nr} XOR {ar}`.
- The Python `Crypto1` class in `crypto1_cipher.py` wraps `Crypto1State` from `crypto1_attack.py` — a port of `crapto1.c` using the correct split 24-bit LFSR (odd/even halves). `crack_key()` delegates to `recover_key()` which implements the darkside attack via nonce distance reduction. Available via the `icopyzed crack` subcommand.

---

## X100 Dump Format

```
Offset  Size  Field
0       4     magic        "X100"
4       1     version_major
5       1     version_minor
6       2     header_len   (big-endian uint16)
8       4     payload_len  (big-endian uint32)
12      N     metadata     (header_len - 12 bytes, ignored)
12+N    M     payload      (MIFARE card dump, N = payload_len)
```

The Python `X100FormatStrategy` parses this header, validates lengths, extracts the payload, pads to 16-byte blocks in non-strict mode, then delegates key extraction to `RawFormatStrategy._extract_keys()`.

---

## Python Implementation Status

### `x100_decrypt/` (dump normalizer — COMPLETE)

| Module | Status | Lines |
|--------|--------|-------|
| `engine.py` | Complete | 351 |
| `crypto.py` | Complete | 470 |
| `keymanager.py` | Complete | 491 |
| `strategies/` subpackage | Complete | 233 |
| `kopized.py` | Complete | 548 |
| `kopized_cli.py` | Complete | 322 |
| `cli.py` | Complete | 114 |
| `external_tools.py` | Complete | 99 |
| `config.py` | Complete | 81 |
| `tests/` | Basic | 87 |

**Entry points**: `x100-decrypt` (batch converter), `kopized` (real-time decryption service)

### `src/icopykey/cli/` (copykey CLI — COMPLETE)

| Module | Status | Lines | Purpose |
|--------|--------|-------|---------|
| `copykey_cli.py` | Complete | ~420 | Main entry point, subcommand dispatch |
| `commands.py` | Complete | ~880 | All command handlers (read, decode, crack, encrypt, write, probe, ...) |
| `operations.py` | Complete | ~45 | Thin backward-compat re-export wrapper |
| `constants.py` | Complete | ~100 | USB VID/PID, default keys, HID report sizes |
| `vault.py` | Complete | ~200 | AESVault (PBKDF2 + AES-256-GCM) |
| `mifare_data.py` | Complete | ~80 | MifareSector, MifareCard dataclasses |
| `device.py` | Complete | ~590 | CopyKeyDevice (HID) + CopyKeyRemoteDevice (TCP relay) |
| `card_ops.py` | Complete | ~400 | CardOperations (decode, encrypt, write) |
| `library.py` | Complete | ~320 | LocalLibrary (encrypted key/card storage) |
| `crypto1_cipher.py` | Complete | ~220 | Crypto1 (MIFARE Classic stream cipher via crypto1_attack.py) |
| `crypto1_attack.py` | Complete | 736 | Port of crapto1.c — darkside/nested key recovery |
| `_relay_protocol.py` | Complete | ~100 | Shared HID relay constants + recv_frame/send_frame |
| `_protocol.py` | Complete | ~290 | Real HID protocol (64B frame, 12 commands, SessionKey, XOR templates from 3 USBPcap captures) |
| `analyze_capture.py` | Complete | ~470 | pcapng parser, OUT/IN pairing, XOR analysis, multi-card detection, F8/C9 stats, --json, --compare |
| `hidrelay.py` | Complete | ~445 | TCP HID relay server |
| `menus.py` | Complete | ~406 | Interactive menu loop |
| `config_manager.py` | Complete | ~196 | JSON config persistence |
| `display.py` | Complete | ~237 | Terminal formatting (rich + fallback) |
| `errors.py` | Complete | ~199 | Typed exception hierarchy |
| `progress.py` | Complete | ~168 | Progress bars/spinners |
| `validators.py` | Complete | ~333 | Input validation |
| `logger_setup.py` | Complete | ~85 | Logging config |
| `tests/` | Established | 6 files | 186 passing tests (2 xfailed) |

**CLI features**: card info read, one-click decode (key brute-force), Crypto-1 key cracking (`icopyzed crack`), sector encryption, card write, HID TCP relay, local key/card library management (encrypted vault), device probe/descriptor.

---

## HID Protocol (Reverse-Engineered from USBPcap Capture)

### Frame Format
```
Offset  Size   Field
0       1      prefix         0x95
1       21     payload_seg0   primary command/data (XOR-obfuscated)
22      21     payload_seg1   rotL 1 byte of seg0 (OUT only, redundancy)
43      21     payload_seg2   rotL 2 bytes of seg0 (OUT only, redundancy)
```

Total: 64 bytes (1 + 3×21). IN frames lack rotational redundancy.

### 21-Byte Payload
```
Byte 0:   Command byte (0x0d, 0xc9, 0xd9, 0xd8, 0x28, 0xed, 0x8d, etc.)
Bytes 1-20: Parameters (XOR-obfuscated per command type)
```

### Command Map
| Cmd  | Name         | Direction | Purpose                                  |
|------|-------------|-----------|------------------------------------------|
| 0x0d | Probe       | OUT↔IN    | Card detect, UID/SAK/ATQA, sector info   |
| 0xc9 | Sector Op   | OUT↔IN    | Sector read/write (primary operation)     |
| 0xd9 | Idle        | OUT↔IN    | Heartbeat (every ~100ms)                 |
| 0xd8 | Data Resp   | IN        | Multi-sector decoded data                |
| 0x28 | Write       | OUT       | Write sector command                     |
| 0xed | Write Ack   | IN        | Write confirmation                       |
| 0x8d | Dev Info    | OUT↔IN    | Device info request/response             |
| 0x8c | Dev Info R  | IN        | Device info response variant             |
| 0x9c | Version     | IN        | Firmware version                         |
| 0x5d | Echo        | OUT       | Device self-test (echo)                  |

### XOR Obfuscation
All 21 bytes are XOR'd against a per-session keystream derived from the device's Crypto1 state. The XOR key is NOT a fixed value per byte — it varies per message type and within payloads. Template-based replay works for known operations but dynamic parameter construction requires the XOR key.

### Probe (0x0d) Structure
- OUT header: `0d 44 52 5b 0c` (fixed across all probes). Byte 5 = XOR'd sector_id.
- IN header:  `0d 14 42 41 16` (fixed ack). Response data at bytes 4-20.

### Sector Op (0xc9)
- OUT: sends key + sector parameters. Template: `c9 f0 e6 7e c5` ...
- IN type A (ACK): header `56 40 49 4e 4b 6b 31 64`, payload d9d9... filler
- IN type B (data): cmd byte 0xc9, data at bytes 1-20

---

## Security Policy

1. **Offline-first**: All card/key/crypto operations work without internet.
2. **Whitelist enforcement**: Only `copykey.hyctec.cn` is reachable, and only on `/firmware/`, `/libraries/`, `/version.json` paths.
3. **`client.copykey.hyctec.cn` explicitly denied**: The original app's primary API server is hard-blocked.
4. **AES-GCM vault**: Keys and card data are optionally encrypted at rest with PBKDF2-derived AES-256 key.
5. **Static audit**: `audit_network_calls()` scans code for unauthorized network libraries/endpoints.

---

## Remaining Work

- **GUI layer** — PyQt6 frontend planned but not started
- **Crypto-1 attack completeness** — current darkside attack works for known nonces; nested attack (recovering unknown nonces) is a stub
- **HID XOR obfuscation** — Frame format and command set fully verified (3 USBPcap captures). XOR key derivation from device Crypto1 state unknown but session key can be extracted via idle pair. F8 bulk data protocol and 0xDF session init discovered and integrated.
- **Sector data location** — actual card data not present in primary 21B payload; likely embedded in 64B frame redundancy segments (bytes 22-63). Need capture with known-key card to decode the data format.
- **Full key recovery pipeline** — `crypto1_attack.py` DarksideAttack not wired to hardware; dictionary-only crack subcommand
- **NTAG/Ultralight/DESFire support** — only MIFARE Classic 1K/4K handled; 4K large sectors (32-39) are broken
- **Library import formats** — only JSON supported; .mfd/.bin require separate convert step
