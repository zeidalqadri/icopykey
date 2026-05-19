# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## In-progress work

Two active threads. If you're a fresh session, read the relevant doc
first before touching anything else.

- **`docs/next_session_probe_record.md`** — local capture session with
  the connected CopyKEY device. Use the new `--record FILE.pcapng`
  flag on `icopyzed probe` to characterise the protocol surface from
  the host side. Pure data-gathering, no code anticipated. Decide on
  whether to add an `icopyzed listen` subcommand based on findings.
- **`docs/next_session_simulate_nfc.md`** — confirm or refute whether
  the device's `SimulateNFC` menu exposes MIFARE card emulation.
  Requires Windows + USBPcap. If you're on a Windows machine with the
  device attached, this is the doc to read.

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
icopyzed sniff [--out FILE.pcapng]    # built-in USB capture (wraps USBPcap/usbmon)
icopyzed --record FILE.pcapng <cmd>   # self-record icopyzed's own device I/O
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

### Crypto-1 (`cli/crypto1_canonical.py` + `cli/crypto1_attack.py` + `cli/crypto1_cipher.py`)

**Two coexisting implementations.** The original `crypto1_attack.py` is a partial, structurally-incomplete port of `crapto1.c` — the in-house `crypto1_bit` is missing the odd/even role swap at the end of each clock, `lfsr_rollback_word` loses the top bit of odd on each cycle (xfail'd `test_lfsr_rollback_word`), and `lfsr_recovery64`'s ks2/ks3 layout is wrong. Its `recover_key_from_keystream`, `DarksideAttack`, and `NestedAttack` Paths A/B all return candidates but **never recover the correct key** (xfail'd `test_recover_key_from_keystream_round_trip`). The module-level docstring is a prominent warning.

**`crypto1_canonical.py` is the working implementation.** Line-by-line port of `crapto1.c` from libnfc/mfcuk and proxmark3/mfkey.c, verified by self-consistent round-trips: `mfkey64(uid, nt, nr, ar_enc, at_enc)` recovers the target key across 15 random and hand-picked cases (`test_crypto1_canonical.py`). The canonical version differs from the in-house port in three ways: (1) `crypto1_bit` swaps odd/even at end of each clock; (2) `lfsr_rollback_bit` swaps at start; (3) `lfsr_recovery64` concatenates ks2/ks3 instead of interleaving. Values are kept in a full 32-bit window, not masked to 24 bits.

`NestedAttack.recover_key` tries paths in this order:
1. **mfkey64 path** (works) — uses canonical `crypto1_canonical.mfkey64` if any `mfkey64_traces` are present.
2. **Path A** (broken, kept for surface compat) — 3+ encrypted nonces, no known key.
3. **Path B** (broken, kept for surface compat) — known key + nested trace.

Two entry points:
- `icopyzed crack` — `cmd_crack_key` against the CopyKEY device. Dictionary attack via `DEFAULT_KEYS`. `--reader` flag adds darkside recovery via `mfcuk -R` for sectors that survive the dictionary (see `_crack_with_external_reader` in `commands.py` and `LibNfcCLIKeyRecovery` in `nfc_reader.py`).
- `icopyzed crack --from-trace FILE` — pure software, no device. The recommended path: use `mfkey64_traces` in the JSON (full `nt/nr/ar_enc/at_enc` per auth) and recovery is via the canonical port. Schema documented on `NestedAttack.from_trace_file` docstring and at `tests/data/nested_traces/README.md`. Ground-truth fixture at `tests/data/nested_traces/sample.json` (recovers `A0A1A2A3A4A5`).

External NFC reader integration lives in `cli/nfc_reader.py` behind two ABCs:
- `KeyRecoverySource` — runs the full attack and returns a key. `LibNfcCLIKeyRecovery` shells out to `mfcuk -R <block>:<A|B>` and parses the canonical `INFO: block N recovered KEY: <hex>` line. This is what `--reader` uses today.
- `NonceSource` — captures raw nonces only. `LibNfcCLINonceSource` (mfcuk -C) and `NfcpyNonceSource` exist for the older nonce-then-recover flow, but their recovery path feeds the broken in-house code. Useful only for diagnostic capture today; not the recommended end-to-end path.

### USB capture (`cli/sniff.py`, `cli/pcap_writer.py`)

Two complementary capture surfaces that both produce pcapng files
readable by `cli/analyze_capture.py` (USBPcap v1 framing,
REPORT_PREFIX=0x95 filter, 91-byte captured-data per frame):

- **`icopyzed sniff`** — wraps the OS-native sniffer (`USBPcapCMD.exe`
  on Windows, `tcpdump -i usbmonN` on Linux) via subprocess. Captures
  any host app's traffic with the device. Auto-detects the CopyKEY's
  bus by parsing `--devices` output (Windows) or
  `/sys/kernel/debug/usb/devices` (Linux). Capture is per-USB-bus, not
  per-device; analysis-time filtering keeps the output focused.
  macOS prints a clean unsupported message (no usbmon equivalent).
- **`icopyzed --record FILE.pcapng`** — self-records icopyzed's own
  device exchanges. Hooks `CopyKeyDevice.write_read()` (the single
  chokepoint for both local HID and TCP-relay paths), mirroring every
  OUT/IN pair into the pcapng via `PcapNgWriter`. Useful for protocol
  regression across firmware revisions; does NOT see other apps'
  traffic (`sniff` is the tool for that).

`PcapNgWriter` in `cli/pcap_writer.py` is intentionally minimal —
no third-party pcap libs. Layout is byte-exact to what
`analyze_capture.parse_pcapng` already reads.

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
