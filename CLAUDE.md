# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`icopyzed` (PyPI name) / `icopykey` (Python module) — offline-first NFC/RFID card management for CopyKEY / X100 Smart Card Replicator devices. Reverse-engineered Python reimplementation of the Windows `CopyKEY Manager` app, with all cloud/auth/analytics endpoints hard-blocked.

## Commands

```bash
# Install (editable, with dev deps)
pip install -e ".[dev]"

# Run tests (the two test trees live under src/, not /tests)
pytest src/icopykey/cli/tests/ src/icopykey/x100/tests/ -v

# Run a single test
pytest src/icopykey/cli/tests/test_protocol.py::TestName::test_case -v

# Lint/format
black src/

# Entry points
icopyzed                              # interactive menu (calls cli.copykey_cli:main)
icopyzed --read | --decode | ...      # batch mode
icopyzed decrypt                      # subcommand → x100.kopized_cli
icopyzed convert                      # subcommand → x100.cli
icopyzed relay-server                 # subcommand → cli.hidrelay
icopyzed probe | crack | descriptor   # subcommands handled inline in copykey_cli.py

python -m icopykey.gui                # PyQt5 GUI

# macOS .app bundle (PyInstaller)
pyinstaller --clean --noconfirm packaging/icopykey.spec
bash packaging/build_mac.sh --dmg     # also: --notarize
```

## Architecture

### Subcommand dispatch quirk

`icopyzed` is a single entry point but uses **manual `sys.argv` mutation** in `cli/copykey_cli.py:main()` rather than argparse subparsers: it inspects `sys.argv[1]`, pops it, then delegates to the matching subpackage's `main()`. When adding subcommands, follow this pattern — do NOT switch to argparse subparsers without updating every dispatch site.

### Three packages, one CLI

| Package | Role |
|---------|------|
| `icopykey.cli` | Interactive menu + batch mode + device I/O + key library |
| `icopykey.x100` | X100 dump format parsing (`convert`) and real-time decryption service (`decrypt`/`kopized`) |
| `icopykey.gui` | PyQt5 frontend (`python -m icopykey.gui`) |

The CLI dispatcher pulls subpackage `main()` functions lazily inside `main()` to avoid importing PyQt5/numpy unless needed.

### Device abstraction (`cli/device.py`)

- `CopyKeyDevice` — local USB HID via `hidapi`. Default `VID=0x6300, PID=0x1991` (see `constants.py`). README examples use `0x0483/0x5740` — the actual hardware default is in `constants.py`.
- `CopyKeyRemoteDevice` — TCP relay client; selected when `--relay HOST:PORT` is passed.
- Both share the same interface so command handlers in `commands.py` are device-agnostic.
- `cli/hidrelay.py` is the relay server (run on the box with the actual hardware).

### HID protocol (`cli/_protocol.py`, `cli/_relay_protocol.py`)

Reverse-engineered from 3 USBPcap captures. **Do not treat the wire format as stable documentation** — `ANALYSIS.md` is the source of truth. Key facts:

- 64-byte frame: `0x95` prefix + 3×21-byte payload segments (`seg1`/`seg2` are `ROTL` redundancy of `seg0` on OUT frames only).
- 12 commands (0x0d probe, 0xc9 sector op, 0xd9 idle, 0xd8 data, 0x28 write, 0xed ack, 0x8d/0x8c dev info, 0x9c version, 0x5d echo, plus 0xf8 bulk and 0xdf session init).
- All 21 payload bytes are XOR-obfuscated against a per-session keystream derived from device Crypto1 state. Template replay works for known ops; dynamic params need the XOR key.
- `cmd_device_probe` exercises all paths; use it after protocol changes.

### Crypto-1 (`cli/crypto1_cipher.py` → `cli/crypto1_attack.py`)

`Crypto1` (cipher) is a thin wrapper around `Crypto1State` (LFSR + attacks) — a port of `crapto1.c` with **split 24-bit odd/even LFSR halves**. The 2^20-entry numpy filter table accelerates `_filter` lookups by ~100×; `_extend_table_simple` was converted from O(n²) insert/pop to O(n) list-comprehension append. Touch carefully — there is one xfailed test (`test_lfsr_rollback_word`) documenting a 23-bit limitation.

`crack_key` → `recover_key` implements the darkside attack. `NestedAttack` (same file) has two paths:
- **Path A** — 3+ encrypted nonces from one sector → PRNG keystream recovery (mfcuk-style, no known key needed).
- **Path B** — known key + plaintext `nt_A` + at least one `{nt_B}` from a nested auth → PRNG-distance window. Optional `at_enc`/`nr` enable candidate validation via `_verify_at`.

Two entry points:
- `icopyzed crack` — wires `cmd_crack_key` to the device (and `--reader` for external nonce capture).
- `icopyzed crack --from-trace FILE` — pure software, no device. Loads `NestedAttack.from_trace_file` JSON; schema documented on the classmethod docstring.

Hardware nonce capture lives in `cli/nfc_reader.py` behind the `NonceSource` ABC: `LibNfcCLINonceSource` shells out to `mfcuk`, `NfcpyNonceSource` delegates to an optional `nfc._icopykey_capture_nonces` helper. `auto_nonce_source()` picks whichever is installed; stock PC/SC APDUs cannot supply raw nonces, so one of these backends is required for `--reader` mode.

### Card data flow

`card_ops.py:CardOperations` (decode/encrypt/write) → `device.py` (transport) → `_protocol.py` (frame build/parse). Card model lives in `mifare_data.py` (`MifareSector`, `MifareCard` dataclasses).

**Known limitation**: C9 sector reads return only 13 bytes (payload[8:21]), not a full sector. F8 bulk channel carries the rest but isn't fully wired. See `WORKLOG.md` "Sector Data Findings".

### X100 dump format (`x100/strategies/`)

Strategy pattern: `base.py` defines the interface, `x100_format.py` parses the X100 header then delegates payload key-extraction to `raw_format.py`. Add new formats by subclassing `BaseStrategy` and registering in `__init__.py`.

X100 header layout, big-endian:
```
0   4   magic "X100"
4   1   version_major
5   1   version_minor
6   2   header_len   (uint16)
8   4   payload_len  (uint32)
12  N   metadata (ignored)
12+N M  MIFARE payload
```

### Vault & library (`cli/vault.py`, `cli/library.py`)

`AESVault`: `PBKDF2(password, salt, 100k iters) → AES-256-GCM`. File layout: `salt(16) + iv(12) + tag(16) + ciphertext`. Metadata in a `.meta` sidecar.

`LocalLibrary` wraps the vault for both keys and cards. Pass `vault_password=None` for plaintext mode (also via `--no-encrypt`).

### Network policy (enforced in code)

Strict whitelist enforced in the X100/CLI HTTP paths:
- **Allowed**: `copykey.hyctec.cn` on `/firmware/`, `/libraries/`, `/version.json` only.
- **Denied**: `client.copykey.hyctec.cn` and every `/api/*`, `/login`, `/register`, `/user/`, `/cloud/` path.
- Static audit scans for unauthorized `requests`/`urllib`/`httpx`/`aiohttp` use.

When adding any network call, route it through the existing audited helper — do not introduce a new HTTP client.

## Conventions specific to this repo

- The two test trees are **`src/icopykey/cli/tests/`** and **`src/icopykey/x100/tests/`**. The top-level `/tests` directory holds fixture data only.
- `cli/operations.py` is a backward-compat re-export shim; new code should import from `card_ops.py` and `commands.py`.
- `_protocol.py` and `_relay_protocol.py` are underscore-prefixed (internal); the public surface is `CopyKeyDevice`.
- `ANALYSIS.md` documents reverse-engineering findings — update it when the protocol understanding changes. `WORKLOG.md` is the running task ledger.
- `--confirm-ownership` is required for the `convert` subcommand; do not bypass it.
