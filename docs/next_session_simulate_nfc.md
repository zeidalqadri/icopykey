# Next session — investigate SimulateNFC firmware capability (Windows)

**Status:** in-progress. The previous session pushed the working
`mfkey64` recovery + `--reader` rewire and then discovered the device
has a `SimulateNFC` menu we hadn't analyzed. Further investigation
requires Windows + USBPcap, which is what this session is for.

If you're a fresh Claude session (or a human) picking this up on a
Windows machine with the CopyKEY device attached, this file is your
brief.

---

## Where we left off

- All the cryptographic work is **done and shipped** — see the commit
  history. `icopyzed crack --from-trace tests/data/nested_traces/sample.json`
  recovers `A0A1A2A3A4A5` end-to-end via the canonical `mfkey64` port.
- `icopyzed crack --reader` now shells out to `mfcuk -R` and recovers
  keys directly (was previously silently broken).
- We don't fully understand the **SimulateNFC** menu on the device. The
  user observed:
  > Press the "SIMULATE" button to write encrypted data on the phone
- Best guess: it's a host-to-phone NFC channel, not MIFARE card
  emulation. But the device clearly has NFC TX capability, so true
  card emulation is **possible in firmware** — just not exposed in the
  UI we've seen.
- macOS lacks `usbmon`-equivalent for USB capture, and our brute-force
  HID command scan (0x00..0xFF with proper 0x95-framing) returned zero
  responses — the XOR obfuscation + state-gated firmware means
  command-byte enumeration alone can't reveal hidden capability. We
  need to observe what the **real Windows app** does during
  SimulateNFC, which requires Windows + USBPcap.

## Goal

Either:
1. Confirm `SimulateNFC` is only the phone-pairing TX (not useful for
   key recovery), and update `ANALYSIS.md` accordingly. Close out.
2. OR discover undocumented HID commands / payload templates that look
   like MIFARE card emulation. If so: port them into our `_protocol.py`
   and offer a card-emulation API in `device.py`.

## Prerequisites (do these once)

On the Windows machine with the CopyKEY device attached:

1. Clone the repo: `git clone https://github.com/zeidalqadri/icopykey.git`
2. Install Python 3.12+ and the project deps:
   `pip install -e ".[dev]"`
3. Install [USBPcap](https://desowin.org/usbpcap/) — it's a Windows
   kernel driver that exposes USB buses to user-mode capture.
   `icopyzed sniff` will auto-locate `USBPcapCMD.exe` afterwards; you
   do **not** need Wireshark or a separate GUI for this workflow.
4. Install the official `CopyKEY Manager` Windows app
   (`CopyKEY Manager V2.0.2.1.2604132.exe` is in the repo root — copy
   it across).
5. Have a MIFARE Classic test card on hand.

Verify the toolchain by running `icopyzed sniff --list` — it should
print every USBPcap filter with `← CopyKEY here` against whichever
filter holds your device. If that line is missing, the device isn't
plugged in or USBPcap can't see it; fix that before the captures.

VPS / remote-desktop variant: if the device is plugged into a different
Windows host and you're remoting in via a VPS, USB-over-IP works (USB
Network Gate, VirtualHere) but USBPcap must run on the side that sees
the device as locally-attached. Capture on that side, copy the
`.pcapng` to the side running this repo.

## The three captures to take

Save each into `tests/data/captures/`, named exactly as below.

### 1. Baseline idle (`tests/data/captures/baseline_idle.pcapng`)

```cmd
icopyzed sniff --out tests/data/captures/baseline_idle.pcapng --duration 30
```

- Open CopyKEY Manager. Connect to the device.
- Let it sit idle for the full 30 seconds with nothing happening.
- `--duration 30` stops the capture automatically; otherwise Ctrl-C
  also works.

This gives us the heartbeat / idle traffic envelope to subtract from
later captures.

### 2. SimulateNFC activation (`tests/data/captures/simulate_nfc.pcapng`)

```cmd
icopyzed sniff --out tests/data/captures/simulate_nfc.pcapng
```

- On the device's physical menu, navigate to **CARD PARAM**.
- Press the **SIMULATE** button to start the phone-transfer mode.
- Pair / open the CopyKEY phone app if applicable. Let any data
  transfer complete.
- Ctrl-C to stop.

If no phone is available, capture the device's HID activity from when
you press SIMULATE until it returns to idle — even an empty
"waiting-for-phone" state is informative.

### 3. Reference card read (`tests/data/captures/reference_read.pcapng`)

```cmd
icopyzed sniff --out tests/data/captures/reference_read.pcapng
```

- In the Windows app, place a MIFARE card on the device and trigger a
  read.
- Wait for decode to complete.
- Ctrl-C to stop.

This is a baseline of what known commands look like in this exact
firmware version (some commands may have changed across firmware
revisions; current `_protocol.py` was derived from older captures).

### Bonus: self-recorded baseline

```cmd
icopyzed --record tests/data/captures/self_dev_info.pcapng --device-info
icopyzed --record tests/data/captures/self_probe.pcapng probe
```

This records only what `icopyzed` itself sends/receives (no other
apps), which is useful for diffing against the captures above: any
commands or payload templates present in the official-app captures
but absent here are firmware features we haven't implemented yet.

## How to decode each capture

```bash
# Repo root
python -m icopykey.cli.analyze_capture tests/data/captures/baseline_idle.pcapng > baseline_decoded.txt
python -m icopykey.cli.analyze_capture tests/data/captures/simulate_nfc.pcapng > simulate_decoded.txt
python -m icopykey.cli.analyze_capture tests/data/captures/reference_read.pcapng > reference_decoded.txt
```

`analyze_capture.py` already does: OUT/IN frame pairing, XOR analysis,
command-byte stats, F8/C9 multi-frame detection. It will print a per-
opcode summary table.

For diffing:

```bash
# What command bytes appear in simulate that AREN'T in baseline?
python -m icopykey.cli.analyze_capture tests/data/captures/simulate_nfc.pcapng --compare tests/data/captures/baseline_idle.pcapng
```

`--compare` is a documented flag of `analyze_capture` per the existing
ANALYSIS.md.

## What to look for

In the **simulate_nfc** decode, scan for:

1. **New command bytes** that don't appear in `_protocol.py`'s
   documented set (0x0d, 0xc9, 0xd9, 0xd8, 0x28, 0xed, 0x8d, 0x8c,
   0x9c, 0x5d, 0xf8, 0xdf). New opcodes are the most direct evidence
   of additional firmware capability.

2. **New payload templates** — `analyze_capture` prints common
   per-position byte distributions. A new opcode with a structured
   payload (e.g., `<cmd> <uid:4> <key:6> <atqa:2>`) would suggest card
   emulation configuration.

3. **Long sequences of F8 bulk** — if SimulateNFC pushes the whole
   card content to the device's NFC TX in one go, F8 bulk count will
   spike compared to baseline.

4. **Repetitive ATQA/SAK responses** — if the device is emulating a
   MIFARE tag, the host-side traffic might mirror what a reader would
   see (UID send, ATQA, SAK).

## If you find something

1. Capture the relevant frames into `_protocol.py` as new
   `build_<verb>_frame()` helpers + register the opcode in the
   `CommandID` enum.
2. Add a high-level method to `CopyKeyDevice` (e.g.,
   `start_emulation(uid, atqa, sak, keys)`) that builds the frame and
   reads the response.
3. Write tests under `src/icopykey/cli/tests/test_protocol.py`
   covering the new frame shapes (mock the device with the captured
   IN frames).
4. Update `ANALYSIS.md` "Command Map" table with the new opcodes.
5. Update `CLAUDE.md` Crypto-1 section if emulation enables a new key-
   recovery path (e.g., the CopyKEY could now stand in for a libnfc
   reader by emulating a tag against itself).

If you find nothing — i.e., SimulateNFC really is just phone-pairing
TX — update `ANALYSIS.md` "Network policy" with a note that there's an
unmonitored NFC-to-phone exfiltration channel (since cloud upload goes
phone → cloud while we only enforce the host-side network whitelist).
Then close out task #14.

## Known pitfalls picked up this session

- `~/.copykey_cli/config.json` (or its Windows-side equivalent) may
  contain a **stale** `vid`/`pid` of `0x0483/0x5740` left over from
  early development. The `probe` subcommand reads from this file
  rather than `constants.DEVICE_VID`/`DEVICE_PID`, so it will fail
  with "Device not found" on machines with that config. Two fixes:
  - Quick: delete `~/.copykey_cli/config.json` or update it to
    `"vid": "0x6300", "pid": "0x1991"`.
  - Proper: change `_parse_vid_pid_args` in `copykey_cli.py` to prefer
    constants over stale-looking config values, OR validate against
    available HID devices before trusting config.

- `python -m black --check src/` reports many pre-existing style
  diffs. They are not from this work; do not "fix" them as a side
  effect.

- Stop and re-read `CLAUDE.md` before starting — the Crypto-1
  architecture is non-obvious (two coexisting implementations:
  `crypto1_attack.py` documented-broken, `crypto1_canonical.py` is
  the working path).
