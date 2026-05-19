# Next session — probe + --record experimental capture session

**Status:** ready to run. Plan was written and approved on 2026-05-19;
deferred to a future session.

If you're a fresh Claude session (or a human) picking this up with the
CopyKEY device attached, this file is your brief.

---

## Goal

Use the now-shipped capture tooling against the connected CopyKEY
device to **characterise the protocol surface**: which HID commands
respond, what payload templates the IN frames carry, which opcodes
time out, and whether anything new shows up outside the documented 12
opcodes. Output is **findings**, not code.

## Prerequisite check

```bash
# Device present?
python -c "import hid; print([d for d in hid.enumerate(0x6300, 0x1991)])"
```

Should print one entry for `CopyKEY Smart Card Copy Machine`. If empty,
plug the device in (any USB port). The stale-config rescue (commit
c99abe8) handles old `~/.copykey_cli/config.json` automatically; no
manual VID/PID needed.

Have one MIFARE Classic card ready (factory-default `FFFFFFFFFFFF` is
fine; the probe doesn't require unlocking it — just card presence).

## Steps

### 1. Run probe with self-recording

```bash
icopyzed --record /tmp/probe_session.pcapng probe
```

`probe` is interactive. It will prompt for card placement / removal
at certain sections — comply. The buttons on the device (READ, WRITE,
EDIT, DETECT, SIMULATE) **do not need to be pressed** for probe to
work; probe is host-driven HID-only.

`--record` hooks `CopyKeyDevice.write_read()`, so every host-initiated
OUT and its matching IN response lands in the pcapng. Spontaneous
device-initiated IN frames (which the device might emit when buttons
are pressed) will **not** be captured by this mechanism — that's the
gap the listener subcommand would close, but we don't add it
preemptively.

### 2. Decode the capture

```bash
python -m icopykey.cli.analyze_capture /tmp/probe_session.pcapng
```

`analyze_capture` (`src/icopykey/cli/analyze_capture.py`) prints:
- Total HID reports + OUT/IN split
- Per-opcode command distribution
- F8 / C9 stats (bulk reads vs. sector ops)
- XOR analysis across paired OUT/IN frames

The file format is the same pcapng layout `PcapNgWriter` produces;
round-trip is verified by `test_pcap_writer.py`.

### 3. Compile findings

For each section probe runs (see `cmd_device_probe` in
`src/icopykey/cli/commands.py:435`), record:

- Which command bytes produced IN responses, which timed out.
- IN frame structure: does it match the templates documented in
  `_protocol.py`? Any unexpected bytes?
- Any opcodes outside the documented 12 (`0x0d 0xc9 0xd9 0xd8 0x28
  0xed 0x8d 0x8c 0x9c 0x5d 0xf8 0xdf`)?
- XOR-obfuscated session-init patterns (cmd 0xdf)?

Cross-reference any findings against `ANALYSIS.md` "Command Map" and
`_protocol.py:CommandID` (if it exists).

### 4. Decide on follow-up

Branch based on what step 3 produced:

| Finding | Recommended follow-up |
|---|---|
| Mostly OUT-only, very few IN responses, no new opcodes | Device is passive on the HID channel. `listen` subcommand unlikely to add value. The SimulateNFC investigation remains a Windows USBPcap job (see [next_session_simulate_nfc.md](next_session_simulate_nfc.md)). Close this thread. |
| Rich IN traffic with unexpected opcodes / payloads | Worth adding `icopyzed listen` (passive `read_input_report` polling that logs IN frames without a matching OUT). ~50 lines new + tests. Then re-run a session pressing each device button during capture. |
| A recognisable XOR-obfuscated session key in 0xdf | Consider extending `_protocol.py:derive_session_key` to actually unmask subsequent frames; would let us speak the real protocol rather than replay templates. |
| Anything else surprising | Quote the captured frames (file:line into the pcapng's EPB indices) and we'll figure it out together. |

## Reference

- Existing built-in capture tooling: commits `440b457` (writer),
  `a8d1df5` (--record), `8aff503` (sniff subcommand), `be0cbc3`
  (probe-dispatch --record honour).
- Related handoff: [next_session_simulate_nfc.md](next_session_simulate_nfc.md)
  for the Windows USBPcap investigation that this probe session may
  inform.
- Stale-config rescue: commit `c99abe8` — `_parse_vid_pid_args` falls
  back to constants when the config-supplied IDs don't enumerate.

## Known caveat

probe is interactive — it `input()`s for card placement. If running
unattended (CI, batch script), it will hang on the first prompt. Not
a concern for a hands-on session with the device.
