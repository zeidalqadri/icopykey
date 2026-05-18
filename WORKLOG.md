# Active Work
Project: /home/the_bomb/icopykey
Task: All phases complete
Status: completed
Updated: 2026-05-18

## Completed Items
- [x] Crypto-1 LFSR: numpy-accelerated lfsr_recovery32 (10s → 1.1s)
- [x] Batch _extend_table_simple: O(n²) insert/pop → O(n) append (5s → 0.5s)
- [x] Sector data analysis: C9 returns 13B per read (not full 64). F8 channel for bulk.
- [x] PyQt6 GUI: app.py with card read/decode, library browser, key management, console
- [x] All 3 remaining items from ANALYSIS.md completed

## Changes
### crypto1_attack.py
- numpy filter table (2^20 entries) for O(1) _filter lookups (~100x perf for filter search)
- Batch `_extend_table_simple`: list comprehension replaces O(n²) insert/pop

### gui/ (new package)
- `app.py`: MainWindow with device connect, card read/decode, sector table, library, keys
- `__main__.py`: `python -m icopykey.gui` launcher
- Requires PyQt6: `pip install PyQt6`

## Sector Data Findings
- C9 sector reads return only 13 bytes (payload[8:21]) — NOT a full 64-byte sector
- IN frames have rotational redundancy (seg1=ROTL(seg0,1), seg2=ROTL(seg0,2)) but NO extra data
- F8 channel (3339 frames in capture) carries bulk data across 256 possible byte-5 values
- Full sector reads require F8 bulk integration or multiple C9 commands
- Current `read_sector()` returns partial data — documented limitation

## Test results
213 passed, 1 xfailed (test_lfsr_rollback_word — 23-bit limitation)
Test suite runs in ~16s (was 62s, 4x faster) thanks to numpy optimization

## Completed Archive
- [x] Crypto-1 LFSR rollback fixes
- [x] TCP HID relay (hidrelay.py, CopyKeyRemoteDevice)
- [x] Protocol tests / refactoring
- [x] USB capture reverse engineering (12 commands)
- [x] .mfd/.bin import, 4K sector fix, NTAG/DESFire decode
- [x] Key recovery pipeline: DarksideAttack, NestedAttack, nfc_reader
- [x] Crypto-1 speed: numpy + batch extension
- [x] Sector data analysis
- [x] PyQt6 GUI frontend
