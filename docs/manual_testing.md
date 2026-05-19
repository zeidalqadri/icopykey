# Manual testing — CopyKEY dictionary attack

This walks through verifying `icopyzed crack` end-to-end against a real
MIFARE Classic card using only the CopyKEY HID device. It exercises:

- HID discovery + connection
- Card read (UID, SAK, sector count)
- Per-sector brute-force against the bundled default keys + your library
- Key persistence into the encrypted vault

It does **not** exercise darkside/nested attacks (those need a libnfc
reader the CopyKEY can't be — see [`hardware_attacks.md`](./hardware_attacks.md)).

## Prerequisites

- CopyKEY / X100 device connected over USB (VID `0x6300`, PID `0x1991`).
- A MIFARE Classic 1K (S50) or 4K (S70) card, ideally factory-default
  (KeyA = KeyB = `FFFFFFFFFFFF`). Most blank UID-writable cards ship
  this way; if unsure, try this procedure and check how many sectors
  recover.
- `icopyzed` installed and on PATH (`pip install -e ".[cli]"` from the
  repo root works).

## Step 1 — confirm the device is detected

```bash
icopyzed --device-info
```

Expected: device VID/PID, firmware version, USB path. If nothing comes
back, check the connection and run `icopyzed --vid 0x6300 --pid 0x1991
--device-info` explicitly, or use `icopyzed probe` to enumerate HID
endpoints.

## Step 2 — place the card

Set the MIFARE card on the CopyKEY antenna. The device usually shows a
status LED when a card is detected.

## Step 3 — run the dictionary attack

```bash
icopyzed crack
```

`cmd_crack_key` (`src/icopykey/cli/commands.py:816`) iterates every
sector (0..15 for 1K, 0..39 for 4K) and tries each key from
`DEFAULT_KEYS` (`constants.py:13-24`) plus anything previously saved in
the vault, against KeyA then KeyB.

### Default keys tried (per sector, in order)

| # | Key            | Origin                          |
|---|----------------|---------------------------------|
| 1 | `FFFFFFFFFFFF` | NXP factory transport key       |
| 2 | `000000000000` | All zero — common test value    |
| 3 | `A0A1A2A3A4A5` | Common MAD sector A key         |
| 4 | `B0B1B2B3B4B5` | Common MAD sector B key         |
| 5 | `4D3A99C351DD` | Common transit key              |
| 6 | `1A982C7E459A` | Common transit key              |
| 7 | `D3F7D3F7D3F7` | Common vending key              |
| 8 | `AABBCCDDEEFF` | Demo / examples                 |
| 9 | `112233445566` | Demo / examples                 |
| 10| `654321FEDCBA` | Demo / examples                 |

Custom keys from `~/.copykey_cli/keys.json[.enc]` are tried after these.

## Step 4 — expected output

For a factory-default card:

```
Card: UID=11223344  Type=MIFARE Classic 1K  Sectors=16
────────────────────────────────────────────────────────────────────────────────
✓ Sector  0  KeyA: FFFFFFFFFFFF
✓ Sector  1  KeyA: FFFFFFFFFFFF
…
✓ Sector 15  KeyA: FFFFFFFFFFFF
────────────────────────────────────────────────────────────────────────────────
✓ Cracked 16/16 sectors
```

Per-sector timing budget: ~50 ms × 10 keys × 2 key-types = ~1 s. Full
1K card: ≤30 s wall-clock. A 4K card (40 sectors) takes ~75 s.

## Step 5 — verify side effects

Cracked keys are saved to the vault under `cracked_sector_<n>` (see
`cmd_crack_key` line 891). Confirm with:

```bash
icopyzed --list-keys
```

You should see one entry per recovered sector.

## What to do if it fails

| Symptom                              | Likely cause / fix                                                                                                                                              |
|--------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Device not found                     | `lsusb` (Linux) / `system_profiler SPUSBDataType` (macOS) — confirm VID/PID matches `constants.py`. Use `icopyzed probe` to enumerate HID interfaces.            |
| Card not detected                    | Reposition the card on the antenna; some readers are sensitive to placement. Confirm card is MIFARE Classic (not DESFire / NTAG — those need different paths).  |
| Some sectors locked                  | Card is not factory-default and the unknown key is not in your library. Add candidates via `icopyzed --list-keys` workflow, or capture nonces via a libnfc reader and use `icopyzed crack --from-trace` (see [`hardware_attacks.md`](./hardware_attacks.md)). |
| HID write timeout                    | Some hidapi builds on macOS need the device replugged after a hung session. Disconnect / reconnect and retry.                                                   |
| `icopyzed crack` hangs > 5 minutes   | Likely an HID read deadlock — Ctrl-C, replug, retry. File an issue with `icopyzed -v crack` output.                                                             |

## What "crack" cannot do (with only the CopyKEY)

- **Recover keys not in the dictionary.** The CopyKEY's HID protocol
  only reports auth-success/failure. It does not expose the raw
  encrypted nonces, NACKs, or parity bits that darkside/nested attacks
  need. To attack truly unknown-key cards, use a libnfc reader (ACR122U,
  PN532) and follow [`hardware_attacks.md`](./hardware_attacks.md).
- **Read cards with non-default Crypto-1 key diversification.** Most
  transit/access-control cards in the wild use diversified keys derived
  from the UID. The dictionary attack won't find those.

The dictionary attack is the right tool for blank UID-writable cards and
for "I know the key is one of the common defaults" workflows. For
unknown-key cards on the CopyKEY, your options are: (1) acquire a
libnfc reader, or (2) accept that the card cannot be cloned with this
hardware.
