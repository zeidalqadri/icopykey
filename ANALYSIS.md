# CopyKEY Manager V2.0.2.1 — Reverse Engineering Analysis

## Overview

CopyKEY Manager is a Windows desktop application (3.76 MB, MSVC-compiled 32-bit x86, ATL/WTL framework) for NFC/RFID card cloning, specifically MIFARE Classic 1K/4K. The app manages card reading, decoding, encryption, cloning to blank cards (CUID, FUID, UFUID, Gen3), and cloud-synced key/card libraries.

The Python reimplementation (`copykey_python/`) is **offline-first** — all cloud/auth/analytics endpoints are permanently blocked; only firmware and library definition updates are permitted against `copykey.hyctec.cn`.

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
- The Python `Crypto1` class implements the LFSR clock, filter function, keystream generation, and authentication protocol skeleton. The actual `crack_key()` (darkside/nested attack) is a stub pending reference implementation from `libnfc`/`mfoc`/`crapto1`.

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

### `copykey_python/` (reimplementation — PARTIAL)

| Module | Status | Lines |
|--------|--------|-------|
| `config/network_policy.py` | Complete | 261 |
| `core/device_interface.py` | Complete | 358 |
| `core/card_library.py` | Complete | 326 |
| `core/mifare_crypto.py` | Complete | 220 |
| `core/card_encryption.py` | Complete | 96 |
| `core/key_vault.py` | Complete | 192 |
| `cli/copykey_cli.py` | Complete | 1406 |
| `updater/firmware_updater.py` | Complete | 233 |
| `updater/library_updater.py` | Complete | 308 |
| `gui/` | Stub | — |
| `tests/` | Stub | — |

**CLI features**: card info read, one-click decode (key brute-force), sector encryption, card write, local key/card library management (encrypted vault), device reconnect.

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
- **Crypto-1 attack implementation** — `crack_key()` stub needs real darkside/nested attack code from `libnfc`/`crapto1`
- **HID protocol reverse engineering** — the exact USB command/response format is speculative; needs USBPcap/Wireshark capture from real device
- **Test suite** — only `x100_decrypt` has basic tests; `copykey_python` has none
- **Packaging** — `x100_decrypt` is packaged via `pyproject.toml`; `copykey_python` uses bare `requirements.txt`
