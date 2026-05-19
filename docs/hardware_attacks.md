# Hardware-assisted key recovery

Runbook for cracking unknown-key MIFARE Classic sectors using an
external libnfc-compatible reader. The CopyKEY HID device cannot supply
raw encrypted nonces; this is the path for cards where the dictionary
attack ([`manual_testing.md`](./manual_testing.md)) failed.

## What you need

Pick one reader. The toolchain is the same; only the install/setup
step differs.

| Reader      | USB-only | macOS support             | Cost (USD) | Notes                                       |
|-------------|----------|---------------------------|------------|---------------------------------------------|
| ACR122U     | ✓        | `brew install libnfc`     | ~$25       | Most common; what mfcuk/mfoc target by default |
| PN532 board | UART/USB | needs `libnfc.conf` tweak | ~$10       | Bare module; flexible but needs config       |
| Proxmark3   | ✓        | `brew install --HEAD proxmark3` | ~$100  | Different toolchain (`pm3`); see "Proxmark3 path" |

The `icopyzed crack --reader` and `--from-trace` flows are designed
around mfcuk / mfoc output, so the ACR122U/PN532 path is the recommended
default.

## ACR122U / PN532 path

### 1. Install libnfc + mfcuk

**macOS** (Homebrew):

```bash
brew install libnfc
```

The Homebrew `libnfc` formula bundles `mfcuk` and `mfoc` as part of its
binary distribution. Verify:

```bash
which mfcuk mfoc nfc-list
```

If `mfcuk` isn't on PATH, install it from the nfc-tools source:

```bash
git clone https://github.com/nfc-tools/mfcuk.git
cd mfcuk
autoreconf -is && ./configure && make && sudo make install
```

**Linux** (Debian/Ubuntu):

```bash
sudo apt install libnfc-bin mfoc mfcuk
```

### 2. Confirm reader detected

Plug the reader in, place a MIFARE Classic card on it, and run:

```bash
nfc-list
```

Expected output: device name (`ACR122U PICC Interface 00 00`), card
UID, ATQA, SAK. If `nfc-list` reports no readers, check the libnfc
config at `~/.config/libnfc/libnfc.conf` (PN532) or USB permissions
(linux: udev rule from libnfc docs).

### 3. Capture nonces

Two integration points are wired into `icopyzed`:

**Option A — direct `--reader` flag** (auto-detects mfcuk):

```bash
icopyzed crack --reader
```

This calls `LibNfcCLINonceSource` (`src/icopykey/cli/nfc_reader.py`)
which shells out to `mfcuk -C -R <block>:<keytype>` and parses the
`Nt = 0x...` lines from stdout. No intermediate files.

**Option B — offline trace + `--from-trace`** (for debugging or batch):

Capture once, save the auth, then run recovery as many times as you want:

```bash
mfcuk -C -R 4:A -v 2 -k FFFFFFFFFFFF 2>&1 | tee mfcuk.log
```

`-C` collects nonces. `-R 4:A` targets sector 4 KeyA. `-k FFFFFFFFFFFF`
adds the factory key as a known starting point — drop it if no sectors
are recoverable from defaults.

Then convert the mfcuk log into our JSON trace format (see
[Schema](#json-trace-schema) below) and run:

```bash
icopyzed crack --from-trace mfcuk_trace.json
```

This calls `cmd_crack_from_trace` (`src/icopykey/cli/commands.py`)
which feeds `NestedAttack.from_trace_file` and runs `mfkey64` against
each `mfkey64_traces` entry.

## Proxmark3 path

Different toolchain. The pm3 client has its own `hf mf` subcommands
for darkside (`hf mf darkside`) and nested (`hf mf nested 1 0 A
FFFFFFFFFFFF d`) attacks. It recovers keys natively — you do not need
to involve `icopyzed crack`.

If you want to feed pm3 captures into our pipeline (e.g., to use the
local key library/vault rather than pm3's), capture the auth with:

```bash
pm3 -c "hf mf sniff" > sniff.log
```

then manually convert the (uid, nt, nr, ar_enc, at_enc) tuple to our
JSON trace format. A converter script would belong at
`tools/proxmark_to_icopyzed.py` — not implemented yet because the
proxmark trace format is verbose and most users will just use pm3's
native recovery.

## JSON trace schema

The full schema lives in the docstring of
`NestedAttack.from_trace_file` (in `src/icopykey/cli/crypto1_attack.py`)
and on [`tests/data/nested_traces/README.md`](../tests/data/nested_traces/README.md).
Minimal example using `mfkey64_traces` (the preferred shape that
actually recovers keys today):

```json
{
  "uid": "11223344",
  "target_sector": 4,
  "mfkey64_traces": [
    {
      "nt": "deadbeef",
      "nr": "cafebabe",
      "ar_enc": "6fa25024",
      "at_enc": "ac33280b"
    }
  ]
}
```

Each `mfkey64_traces` entry is one complete MIFARE Classic auth (plain
nt + nr; encrypted ar + at). `NestedAttack.recover_key` runs `mfkey64`
on each entry until a key recovers.

A ground-truth example fixture lives at
[`tests/data/nested_traces/sample.json`](../tests/data/nested_traces/sample.json)
— it's generated from a known target key
(`A0A1A2A3A4A5`) and is exercised by the test
`test_cmd_crack_from_trace_runs_against_sample_fixture`.

## Verification checklist

When acquiring a new reader, walk through this list before relying on
the recovery flow:

- [ ] `nfc-list` detects the reader and a card.
- [ ] `which mfcuk` returns a path.
- [ ] `icopyzed crack --from-trace tests/data/nested_traces/sample.json`
      reports `Recovered key for sector 4: A0A1A2A3A4A5`. This is
      hardware-independent and proves the in-house algorithm is wired.
- [ ] `mfcuk -C -R 0:A -v 2` (with a real card on the reader) prints
      `Nt = 0x...` lines and eventually a recovered key.
- [ ] `icopyzed crack --reader` against the same card recovers the same
      key as step 4.

If step 3 fails: file an issue — the algorithm or wiring broke.
If steps 4/5 fail: the reader-specific path needs debugging; check
mfcuk stdout, libnfc config, and reader power.

## What we cannot do

- The CopyKEY HID device by itself cannot supply raw nonces. It must be
  paired with an external libnfc reader for any non-dictionary recovery.
- Cards using true random nonces (some MIFARE Classic EV1 variants and
  successor cards) defeat both darkside and nested attacks. `mfcuk`
  will spin forever; pm3's hardnested may help but is out of scope.
- DESFire EV1/EV2, NTAG-AES, and Ultralight-C use different ciphers
  entirely. None of the recovery paths here apply.
