# Active Work
Project: /home/the_bomb/icopykey
Task: USB protocol reverse engineering — DATA FLOW CONFIRMED
Status: completed
Updated: 2026-04-29

## Progress
- [x] 3-capture analysis: 14,931 HID frames across sessions
- [x] Protocol data flow confirmed: C9(auth) → D8(metadata) → F8(sector data)
- [x] 12 protocol commands discovered and modeled
- [x] SEGMENT_XOR_DELTA discovered (19B invariant across all IN frames)
- [x] Full 64B frame parsing (seg0/seg1/seg2 + redundancy validation)
- [x] F8 singleton data extraction (XOR-with-dominant reveals repeating patterns)
- [x] Session key derivation from idle pairs
- [x] 197 passed, 2 xfailed, 0 failures

## PROTOCOL MODEL (COMPLETE)

### Frame format
[0x95] + [21B seg0] + [21B seg1] + [21B seg2] = 64 bytes
- OUT: rotational redundancy (seg1=rotL1, seg2=rotL2)
- IN: seg1 XOR seg2 = SEGMENT_XOR_DELTA (16090705205a5520080916090705205a552008)

### Command map (12 discovered)
| Cmd | Name | Function |
|-----|------|----------|
| 0x0D | PROBE | Card probe + sector authentication request |
| 0xC9 | SECTOR_OP | Auth result (ACK=rejected, sector_data=accepted) |
| 0xD8 | DATA_RESPONSE | Card metadata (UID, sector status) |
| 0xD9 | IDLE | Heartbeat + session key carrier |
| 0xF8 | BULK_DATA | Sector data transfer (dominant=ACK, singletons=data) |
| 0xDF | BULK_SESSION | Session init for F8 bulk mode (switches XOR key) |
| 0x28 | WRITE | Sector write |
| 0xED | WRITE_ACK | Write confirmation |
| 0x8D | DEVICE_INFO | Device query |
| 0x8C | DEVICE_INFO_RESP | Device info response |
| 0x9C | DEVICE_VERSION | Version info |
| 0x5D | DEVICE_ECHO | Device echo / self-test |

### Data flow
1. C9 OUT(auth key try) → C9 IN(ACK=no, sector_data=yes)
2. D8 IN(card UID + sector access status)
3. 0xDF ↔ IN(session init, switches XOR key for F8 channel)
4. F8 OUT(sector/page address) → F8 IN(dominant=ACK, singleton=data)

### XOR scheme
- Per-session 21-byte XOR key (differs per power-cycle)
- Key derived via idle pair: key[i] = OUT[i] XOR IDLE_PLAINTEXT[i]
- F8 session gets its own key (0xDF init switches)
- XOR(OUT, IN) cancels key, reveals plaintext difference

## Test results
197 passed, 2 xfailed, 0 failures

## Completed
- [x] Built TCP HID relay (hidrelay.py, CopyKeyRemoteDevice, protocol)
- [x] Structural refactoring: broke up operations.py, rewired crypto1, added crack
- [x] USB capture reverse engineering: 12 commands, data flow, XOR scheme
- [x] Protocol tests: 58 tests for frames, templates, classification, redundancy
- [x] ANALYSIS.md updated with full protocol documentation
