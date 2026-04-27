"""
Command handlers for CopyKEY CLI.

Each command wraps a business-logic operation from :mod:`.operations`
with user-facing display, validation, and progress feedback.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

from .operations import (
    CopyKeyDevice,
    CardOperations,
    LocalLibrary,
    MifareCard,
    MifareSector,
)
from .display import (
    print_success,
    print_error,
    print_warning,
    print_info,
    print_card_info,
    print_divider,
    print_table,
)
from .progress import create_progress, spinning
from .validators import (
    validate_key,
    validate_uid,
    validate_access_bits,
    validate_card_type,
    validate_vid_pid,
    validate_path,
    validate_filename,
)

logger = logging.getLogger("copykey_cli.commands")


# ── Command Result ───────────────────────────────────────────────


class CommandResult:
    """Standardised return type for all command handlers."""

    def __init__(
        self,
        success: bool,
        message: str = "",
        data: Any = None,
        error: str | None = None,
    ) -> None:
        self.success = success
        self.message = message
        self.data = data
        self.error = error


# ── Commands ─────────────────────────────────────────────────────


def cmd_read_card(ops: CardOperations) -> CommandResult:
    """Read card info from device."""
    info = ops.read_card_info()
    if not info:
        print_error("Failed to read card info. Ensure a card is on the reader.")
        return CommandResult(False, error="No card detected")

    uid = info["uid"].hex().upper()
    sak = info["sak"]
    atqa = info["atqa"].hex().upper()
    card_type = info["card_type"]

    print_card_info(uid, sak, atqa, card_type)
    return CommandResult(True, f"Card {uid} detected", data=info)


def cmd_decode_card(ops: CardOperations, library: LocalLibrary) -> CommandResult:
    """One-click decode all sectors."""
    custom_keys = library.get_keys() if library.keys else None
    print_info(f"Decoding card with {len(custom_keys) + 10 if custom_keys else 10} keys...")

    with spinning("Decoding sectors"):
        card = ops.decode_card(custom_keys=custom_keys)

    if not card:
        print_error("Decode failed. Some sectors may be locked with unknown keys.")
        return CommandResult(False, error="Decode failed")

    decoded = sum(
        1 for s in card.sectors if s.key_a != b"\xff" * 6 or s.key_b != b"\xff" * 6
    )
    print_success(f"Card decoded: {decoded}/{card.num_sectors} sectors readable")
    print_info(f"UID: {card.uid_hex} | Type: {card.card_type}")

    return CommandResult(True, f"Decoded {decoded}/{card.num_sectors} sectors", data=card)


def cmd_encrypt_card(
    ops: CardOperations,
    new_key_a: bytes | None = None,
    new_key_b: bytes | None = None,
    random_keys: bool = False,
    sectors: list[int] | None = None,
) -> CommandResult:
    """Encrypt card sector data with new keys."""
    if not ops.current_card:
        print_error("No card data. Decode or load a card first.")
        return CommandResult(False, error="No card loaded")

    with spinning("Encrypting sectors"):
        ok = ops.encrypt_card_data(
            new_key_a=new_key_a,
            new_key_b=new_key_b,
            random_keys=random_keys,
            sectors=sectors,
        )

    if ok:
        print_success("Card data encrypted with new keys")
        return CommandResult(True, "Encryption complete")
    print_error("Encryption failed")
    return CommandResult(False, error="Encryption failed")


def cmd_write_card(ops: CardOperations) -> CommandResult:
    """Write card data to blank clone card."""
    if not ops.current_card:
        print_error("No card data. Decode or load a card first.")
        return CommandResult(False, error="No card loaded")

    print_warning("This will OVERWRITE the card on the reader!")
    confirm = input("  Type 'yes' to confirm: ").strip().lower()
    if confirm != "yes":
        print_info("Write cancelled.")
        return CommandResult(False, error="Cancelled by user")

    with spinning("Writing card"):
        ok = ops.write_full_card()

    if ok:
        print_success("Card written successfully")
        return CommandResult(True, "Write complete")
    print_error("Card write failed or was partial")
    return CommandResult(False, error="Write failed")


def cmd_list_keys(library: LocalLibrary) -> CommandResult:
    """Display all keys in the library."""
    if not library.keys:
        print_info("No keys stored. Use 'add <name> <key>' to add one.")
        return CommandResult(True, "Key library is empty", data=[])

    rows = [[name, key.hex().upper()] for name, key in library.keys.items()]
    print_table(["Name", "Key (hex)"], rows, "Key Library")
    return CommandResult(True, f"{len(library.keys)} keys", data=library.keys)


def cmd_add_key(library: LocalLibrary, name: str, key_hex: str) -> CommandResult:
    """Add a key to the library."""
    try:
        key = validate_key(key_hex)
        library.add_key(name, key)
        print_success(f"Key '{name}' added: {key.hex().upper()}")
        return CommandResult(True, f"Key '{name}' added")
    except Exception as e:
        print_error(str(e))
        return CommandResult(False, error=str(e))


def cmd_del_key(library: LocalLibrary, name: str) -> CommandResult:
    """Delete a key from the library."""
    if library.remove_key(name):
        print_success(f"Key '{name}' deleted")
        return CommandResult(True, f"Key '{name}' deleted")
    print_warning(f"Key '{name}' not found")
    return CommandResult(False, error=f"Key '{name}' not found")


def cmd_list_cards(library: LocalLibrary) -> CommandResult:
    """Display all cards in the library."""
    cards = library.list_cards()
    if not cards:
        print_info("No cards stored. Use 'load' to add one after decoding.")
        return CommandResult(True, "Card library is empty", data=[])

    rows = [
        [str(i), c["name"], c["uid"], c["card_type"], c["created"][:10] if c["created"] else ""]
        for i, c in enumerate(cards)
    ]
    print_table(["#", "Name", "UID", "Type", "Date"], rows, "Card Library")
    return CommandResult(True, f"{len(cards)} cards", data=cards)


def cmd_load_card(library: LocalLibrary, ops: CardOperations, index: int) -> CommandResult:
    """Load a card from library into memory."""
    cards = library.list_cards()
    if index < 0 or index >= len(cards):
        print_error(f"Invalid index: {index}")
        return CommandResult(False, error=f"Invalid index {index}")

    card_meta = cards[index]
    full_card = library.get_card(card_meta["id"])
    if not full_card:
        print_error("Card not found in library")
        return CommandResult(False, error="Card not found")

    card = MifareCard.from_dict(full_card)
    ops.current_card = card
    print_success(f"Loaded card: {card_meta['name']} (UID: {card.uid_hex})")
    return CommandResult(True, f"Loaded {card_meta['name']}", data=card)


def cmd_save_card(library: LocalLibrary, ops: CardOperations, name: str) -> CommandResult:
    """Save the current card to the library."""
    if not ops.current_card:
        print_error("No card data in memory")
        return CommandResult(False, error="No card loaded")

    card_id = library.add_card(ops.current_card, name)
    print_success(f"Card '{name}' saved to library (ID: {card_id})")
    return CommandResult(True, f"Card '{name}' saved", data=card_id)


def cmd_delete_card(library: LocalLibrary, index: int) -> CommandResult:
    """Delete a card from the library."""
    cards = library.list_cards()
    if index < 0 or index >= len(cards):
        print_error(f"Invalid index: {index}")
        return CommandResult(False, error=f"Invalid index {index}")

    card_meta = cards[index]
    if library.remove_card(card_meta["id"]):
        print_success(f"Card '{card_meta['name']}' deleted")
        return CommandResult(True, f"Card '{card_meta['name']}' deleted")
    print_error("Failed to delete card")
    return CommandResult(False, error="Delete failed")


def cmd_export_card(library: LocalLibrary, index: int, output_dir: str = ".") -> CommandResult:
    """Export a card from the library to a JSON file."""
    cards = library.list_cards()
    if index < 0 or index >= len(cards):
        print_error(f"Invalid index: {index}")
        return CommandResult(False, error=f"Invalid index {index}")

    card_meta = cards[index]
    data = library.export_card(card_meta["id"])
    if not data:
        print_error("Failed to export card")
        return CommandResult(False, error="Export failed")

    filename = validate_filename(f"{card_meta['name']}.json")
    out_path = Path(output_dir) / filename
    out_path.write_bytes(data)
    print_success(f"Exported to {out_path}")
    return CommandResult(True, f"Exported to {out_path}")


def cmd_import_card(
    library: LocalLibrary, ops: CardOperations, filepath: str, fmt: str = "json"
) -> CommandResult:
    """Import a card from a file into the library."""
    try:
        path = validate_path(filepath)
    except Exception as e:
        print_error(str(e))
        return CommandResult(False, error=str(e))

    try:
        data = path.read_bytes()
        card_id = library.import_card(data, fmt)
        if card_id:
            print_success(f"Card imported (ID: {card_id})")
            return CommandResult(True, f"Imported {card_id}")
        print_error("Import failed - invalid file format")
        return CommandResult(False, error="Invalid format")
    except Exception as e:
        print_error(f"Import error: {e}")
        return CommandResult(False, error=str(e))


def cmd_device_info(device: CopyKeyDevice) -> CommandResult:
    """Display device information."""
    if not device.is_connected():
        print_error("No device connected")
        return CommandResult(False, error="No device connected")

    info = device.get_device_info()
    if not info:
        print_error("Could not retrieve device info")
        return CommandResult(False, error="No device info")

    rows = [
        ["Manufacturer", info.get("manufacturer", "")],
        ["Product", info.get("product", "")],
        ["Serial", info.get("serial", "")],
        ["Path", info.get("path", "")],
    ]
    print_table(["Property", "Value"], rows, "Device Information")
    return CommandResult(True, "Device info displayed", data=info)


def cmd_device_change(device: CopyKeyDevice, vid: str, pid: str) -> CommandResult:
    """Change device VID/PID and reconnect."""
    try:
        new_vid = validate_vid_pid(vid, "VID")
        new_pid = validate_vid_pid(pid, "PID")
    except Exception as e:
        print_error(str(e))
        return CommandResult(False, error=str(e))

    device.disconnect()
    device.vid = new_vid
    device.pid = new_pid

    if device.connect():
        print_success(f"Connected with VID=0x{new_vid:04X} PID=0x{new_pid:04X}")
        return CommandResult(True, "Device reconfigured")
    print_warning("Device not found with new VID/PID. Using configure values.")
    return CommandResult(False, error="Device not found")


def cmd_device_reconnect(device: CopyKeyDevice) -> CommandResult:
    """Reconnect to the device."""
    print_info("Reconnecting...")
    device.disconnect()
    if device.connect():
        print_success("Reconnected")
        info = device.get_device_info()
        if info:
            print_info(f"  {info.get('product', '')} ({info.get('manufacturer', '')})")
        return CommandResult(True, "Reconnected")
    print_error("Failed to reconnect. Check USB connection.")
    return CommandResult(False, error="Reconnect failed")


def cmd_device_descriptor(device: CopyKeyDevice) -> CommandResult:
    """Dump the HID report descriptor from the device."""
    if not device.is_connected():
        print_error("No device connected")
        return CommandResult(False, error="No device connected")

    print_divider("HID Report Descriptor")

    desc = device.dump_report_descriptor()
    if desc and desc.get("items"):
        report_ids = desc.get("report_ids", [])
        print_success(f"Descriptor: {len(desc['raw']) // 2} bytes, {len(desc['items'])} items")
        print_info(f"Report IDs: {report_ids}")

        # Build summary per report_id
        current_id = None
        current_size = 0
        current_count = 0
        current_direction = "?"
        for item in desc["items"]:
            if item["tag"] == "REPORT_ID":
                if current_id is not None:
                    bits = current_size * current_count
                    print_info(f"  Report 0x{current_id:02X}: {current_direction}  "
                               f"{current_size}bit x {current_count} = {bits}bit ({bits // 8} bytes)")
                current_id = item["value"]
                current_size = 0
                current_count = 0
                current_direction = "?"
            elif item["tag"] == "REPORT_SIZE":
                current_size = item["value"]
            elif item["tag"] == "REPORT_COUNT":
                current_count = item["value"]
            elif item["tag"] == "INPUT":
                current_direction = "INPUT"
            elif item["tag"] == "OUTPUT":
                current_direction = "OUTPUT"
            elif item["tag"] == "FEATURE":
                current_direction = "FEATURE"
        if current_id is not None:
            bits = current_size * current_count
            print_info(f"  Report 0x{current_id:02X}: {current_direction}  "
                       f"{current_size}bit x {current_count} = {bits}bit ({bits // 8} bytes)")

        # Interfaces
        print_divider("-")
        interfaces = device.list_interfaces()
        if interfaces:
            print_info("Device interfaces:")
            for iface in interfaces:
                print_info(f"  usage=0x{iface['usage']:04X} page=0x{iface['usage_page']:04X} "
                           f"intf={iface['interface_number']} '{iface['product_string']}'")

        print_divider("-")
        print_info("Raw descriptor:")
        raw_hex = desc["raw"]
        for i in range(0, len(raw_hex), 64):
            print_info(f"  {raw_hex[i:i+64]}")

        return CommandResult(True, f"Descriptor with {len(report_ids)} report IDs", data=desc)
    else:
        print_error("No report descriptor available (device may block it)")
        return CommandResult(False, error="No descriptor")


def cmd_device_probe(device: CopyKeyDevice) -> CommandResult:
    """Aggressive HID protocol probe: test every command path systematically.

    Tries multiple transport layers, framing formats, and opcodes against
    the X100 device.  Prompts the user to place/remove a card between tests
    to discover which commands require card presence.
    """
    if not device.is_connected():
        print_error("Device not connected")
        return CommandResult(False, error="No device connected")

    print_divider("HID Protocol Probe — Aggressive Discovery")
    print_info(f"Device: {device.product} (VID=0x{device.vid:04X} PID=0x{device.pid:04X})")
    print_info(f"Serial: {device.serial}")
    print_divider()

    results: list[dict] = []

    # ── Section 0: HID Report Descriptor ───────────────────────

    print_info("── Section 0: HID Report Descriptor ──")
    desc = device.dump_report_descriptor()
    if desc and desc.get("items"):
        report_ids = desc.get("report_ids", [])
        print_success(f"  Descriptor: {len(desc['raw']) // 2} bytes, {len(desc['items'])} items")
        print_info(f"  Report IDs found: {report_ids}")

        # Build a summary table: for each report_id, show direction, size, count
        current_id = None
        current_size = 0
        current_count = 0
        current_direction = "?"
        for item in desc["items"]:
            if item["tag"] == "REPORT_ID":
                # Flush previous
                if current_id is not None:
                    bits = current_size * current_count
                    byte_size = bits // 8
                    print_info(f"    Report 0x{current_id:02X}: {current_direction}  size={current_size}bit  count={current_count}  total={bits}bit ({byte_size} bytes)")
                current_id = item["value"]
                current_size = 0
                current_count = 0
                current_direction = "?"
            elif item["tag"] == "REPORT_SIZE":
                current_size = item["value"]
            elif item["tag"] == "REPORT_COUNT":
                current_count = item["value"]
            elif item["tag"] == "INPUT":
                current_direction = "INPUT"
            elif item["tag"] == "OUTPUT":
                current_direction = "OUTPUT"
            elif item["tag"] == "FEATURE":
                current_direction = "FEATURE"
        # Flush last
        if current_id is not None:
            bits = current_size * current_count
            byte_size = bits // 8
            print_info(f"    Report 0x{current_id:02X}: {current_direction}  size={current_size}bit  count={current_count}  total={bits}bit ({byte_size} bytes)")

        # Show raw hex
        print_divider("-")
        print_info("  Raw descriptor bytes:")
        raw_hex = desc["raw"]
        for i in range(0, len(raw_hex), 64):
            print_info(f"    {raw_hex[i:i+64]}")
        print_divider("-")
    else:
        print_warning("  No report descriptor available (device may block it)")

    # ── Section 0b: Interface listing ──────────────────────────

    print_info("── Section 0b: Interface Discovery ──")
    interfaces = device.list_interfaces()
    if interfaces:
        print_info(f"  {len(interfaces)} interface(s):")
        for iface in interfaces:
            print_info(f"    usage=0x{iface['usage']:04X} page=0x{iface['usage_page']:04X} "
                       f"intf={iface['interface_number']} "
                       f"'{iface['product_string']}'")
    else:
        print_warning("  No interface info available")

    print_divider()

    def _test(path: str, cmd: bytes, timeout_ms: int = 500) -> tuple[bool, str, bytes | None]:
        """Test one command. Returns (success, detail, raw_response_bytes)."""
        resp = device.send_command(cmd, timeout_ms=timeout_ms)
        if resp:
            txt = ""
            try:
                txt = resp.decode("ascii", errors="replace").rstrip("\x00").strip()
            except Exception:
                pass
            detail = f"GOT {len(resp)} bytes"
            if txt:
                detail += f'  TXT="{txt[:80]}"'
            return True, detail, resp
        return False, "NO RESPONSE (timeout)", None

    # ── Section 1: Real transport probe (output/input reports) ──

    print_info("\n── Section 1: Output/Input Report Transport ──")
    print_info("  Transport: device.write(64 bytes) → device.read(64 bytes)")
    print_info("  No report ID, no feature reports (matches HID descriptor)")
    print_info("")

    def _build_packet(fmt: str, cmd_id: int, sub: int = 0) -> bytes:
        """Build a 64-byte packet with the given format and command ID."""
        if fmt == "raw":
            return bytes([cmd_id])
        elif fmt == "len8":
            return bytes([cmd_id, 0x00])
        elif fmt == "csum":
            # [cmd_id] [0x00] [data...] [checksum xor of first 62] [0x00]
            buf = bytearray(64)
            buf[0] = cmd_id
            buf[1] = sub
            buf[62] = cmd_id ^ sub ^ 0x5A
            return bytes(buf)
        elif fmt == "xor_csum":
            # [cmd_id] [length] [data...] [xor_check] [checksum]
            buf = bytearray(64)
            buf[0] = cmd_id
            buf[1] = sub
            buf[2] = 0x00  # payload length (0 = just header)
            xor = buf[0] ^ buf[1] ^ buf[2]
            for i in range(3, 62):
                xor ^= buf[i]
            buf[62] = xor
            csum = 0
            for i in range(63):
                csum += buf[i]
            buf[63] = csum & 0xFF
            return bytes(buf)
        elif fmt == "cmd_sub_4byte":
            # [cmd_id] [0x00] [0x00] [0x00] [0x00] - 5-byte header
            return bytes([cmd_id, sub, 0x00, 0x00, 0x00])
        elif fmt == "cmd_sub_8byte":
            return bytes([cmd_id, sub, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        elif fmt == "cmd_sub_16byte":
            return bytes([cmd_id, sub]) + b"\x00" * 14
        elif fmt == "cmd_full64":
            buf = bytearray([cmd_id, sub])
            buf.extend(b"\x00" * 62)
            return bytes(buf)
        return bytes([cmd_id])

    def _probe_formats(cmd_ids: list[int], label: str, card_needed: bool = False) -> None:
        """Test multiple packet formats against command IDs."""
        print_divider(f"── {label} ──")

        formats = ["raw", "len8", "csum", "xor_csum", "cmd_full64"]

        # Header
        header = f"{'ID':>4}"
        for fmt in formats:
            header += f"  {fmt:>6}"
        print_info(header)

        for cmd_id in cmd_ids:
            row = f"0x{cmd_id:02X}"
            any_ok = False
            for fmt in formats:
                packet = _build_packet(fmt, cmd_id)
                resp = device.write_read(packet, timeout_ms=500)
                if resp and len(resp) > 0 and resp != b"\x00" * len(resp):
                    # Check if response has non-zero content
                    has_data = any(b != 0 for b in resp)
                    if has_data:
                        row += f"  {len(resp):>3}B ✓"
                        any_ok = True
                        results.append({
                            "layer": f"output/{fmt}", "opcode": cmd_id,
                            "name": label, "ok": True,
                            "detail": f"{len(resp)}B: {resp[:16].hex()}"
                        })
                    else:
                        row += f"  {'--':>6}"
                        results.append({"layer": f"output/{fmt}", "opcode": cmd_id,
                                      "name": label, "ok": False, "detail": "zero-filled"})
                else:
                    row += f"  {'--':>6}"
                    results.append({"layer": f"output/{fmt}", "opcode": cmd_id,
                                  "name": label, "ok": False, "detail": "no response"})
            if any_ok:
                print_success(row)
            else:
                print_info(row)

    # ── Test 1: Core command IDs (0x01-0x10) without card ──────
    _probe_formats(list(range(0x01, 0x11)), "Core Commands (no card)")

    # ── Test with card ────────────────────────────────────────
    print_divider()
    print_warning("PLACE A MIFARE CARD ON THE READER")
    input("  Press Enter when card is in place... ")
    print_info("")
    _probe_formats(list(range(0x01, 0x11)), "Core Commands (CARD PRESENT)")

    # ── Test 2: Extended command IDs (0x11-0x2F) ──────────────
    _probe_formats(list(range(0x11, 0x30)), "Extended Commands (CARD PRESENT)")

    # ── Section 2: MIFARE ISO 14443-3 Protocol Probe ────────

    print_divider("── MIFARE ISO 14443-3 Protocol Probe ──")
    print_info("  Sending standard MIFARE Classic commands (card must be present).")
    print_info("  These are raw ISO 14443-3 frames, not our custom opcodes.")
    print_info("")

    def _test_mifare(label: str, cmd: bytes, timeout_ms: int = 2000) -> tuple[bool, str, bytes | None]:
        resp = device.write_read(cmd, timeout_ms=timeout_ms)
        if resp is None:
            return False, "NO RESPONSE", None
        data = bytes(resp)
        if all(b == 0 for b in data) or len(data) == 0:
            return False, "ZERO-FILLED", data
        return True, f"{len(data)}B: {data[:16].hex()}", data

    mifare_results: list[dict] = []

    # MIFARE Classic ISO 14443-3 commands (1-4 byte short frames)
    mifare_commands = [
        ("REQA",        bytes([0x26])),                # wake-up, 7-bit
        ("WUPA",        bytes([0x52])),                # wake-up type A
        ("ANTICOLL L1",  bytes([0x93, 0x20])),         # cascade level 1
        ("SELECT L1",   bytes([0x93, 0x70])),          # select (needs UID appended)
        ("HLTA",        bytes([0x50, 0x00])),          # halt
        ("AUTH KEY A 0",bytes([0x60, 0x00])),          # auth key A block 0 (needs key)
        ("AUTH KEY B 0",bytes([0x61, 0x00])),          # auth key B block 0 (needs key)
        ("READ BLOCK 0", bytes([0x30, 0x00])),         # read block 0
    ]

    print_divider("── MIFARE Commands (card present) ──")
    for name, cmd_bytes in mifare_commands:
        ok, detail, raw = _test_mifare(name, cmd_bytes, timeout_ms=3000)
        mifare_results.append({"name": name, "cmd": cmd_bytes.hex(), "ok": ok, "detail": detail, "raw": raw})
        if ok:
            print_success(f"  {name:<18} {cmd_bytes.hex():<12} -> {detail}")
        else:
            print_info(f"  {name:<18} {cmd_bytes.hex():<12} -> {detail}")

    # ── Section 3: Passive Listen (no command sent) ──────

    print_divider("── Passive Listen (output-only device test) ──")
    print_info("  Reading from device WITHOUT sending any command.")
    print_info("  If the device streams output text (like its LCD), we'll see it.")
    print_info("  Tries 10 reads at 500ms intervals. Press Ctrl-C to stop early.")
    print_info("")
    print_warning("  PLACE A MIFARE CARD ON THE READER")
    input("  Press Enter when card is in place... ")
    print_info("")

    passive_hits = 0
    for i in range(10):
        try:
            resp = device.read_only(timeout_ms=500)
        except AttributeError:
            resp = None
        if resp is None:
            resp = device.read_input_report(timeout_ms=500)
        if resp and len(resp) > 0 and any(b != 0 for b in resp):
            passive_hits += 1
            txt = ""
            try:
                txt = resp.decode("ascii", errors="replace").rstrip("\x00").strip()
            except Exception:
                pass
            if txt:
                print_success(f"    Read {i+1:>2}: {txt[:120]}")
            else:
                print_success(f"    Read {i+1:>2}: {resp[:32].hex()}")
        else:
            print_info(f"    Read {i+1:>2}: (no data)")

    if passive_hits == 0:
        print_error("  No passive data received. Device is truly silent.")
        print_warning("  The device may only output to its LCD, not to USB.")
    else:
        print_success(f"  Received data on {passive_hits}/10 passive reads!")

    # ── Section 4: USB Control Transfer Probe ──────────

    print_divider("── USB Control Transfer Probe ──")
    print_info("  Trying GET_REPORT (HidD_GetInputReport / control transfer).")
    print_info("  This is a different USB pipe than interrupt reads — the device")
    print_info("  may only respond to explicit report requests.")
    print_info("")

    print_warning("  PLACE A MIFARE CARD ON THE READER")
    input("  Press Enter when card is in place... ")
    print_info("")

    ctrl_results: list[dict] = []

    # GET_INPUT_REPORT (no write — just request input report via control pipe)
    print_info("  ── GET_INPUT_REPORT (control transfer) ──")
    for attempt in range(5):
        try:
            resp = device.get_input_report()
        except AttributeError:
            resp = None
        if resp and len(resp) > 0 and any(b != 0 for b in resp):
            txt = ""
            try:
                txt = resp.decode("ascii", errors="replace").rstrip("\x00").strip()
            except Exception:
                pass
            ctrl_results.append({"type": "GET_INPUT_REPORT", "attempt": attempt, "ok": True, "data": resp, "text": txt})
            if txt:
                print_success(f"    GET_INPUT_REPORT {attempt+1}: {txt[:120]}")
            else:
                print_success(f"    GET_INPUT_REPORT {attempt+1}: {resp[:32].hex()}")
        else:
            ctrl_results.append({"type": "GET_INPUT_REPORT", "attempt": attempt, "ok": False, "data": None, "text": ""})
            print_info(f"    GET_INPUT_REPORT {attempt+1}: (no data)")

    # SET_FEATURE_REPORT — try waking device with known init patterns
    print_info("")
    print_info("  ── SET_FEATURE_REPORT (wake-up attempts) ──")
    wake_patterns = [
        ("Init (0x01)", bytes([0x01])),
        ("Enable (0x55)", bytes([0x55])),
        ("Wake (0xA5)", bytes([0xA5])),
        ("ASCII 'START'", b"START"),
        ("Full 64B w/ 0x01", b"\x01" + b"\x00" * 63),
    ]
    for name, pattern in wake_patterns:
        try:
            ok = device.send_feature_report(pattern)
        except AttributeError:
            ok = False
        status = "sent" if ok else "FAILED"
        ctrl_results.append({"type": "SET_FEATURE", "name": name, "ok": ok})
        if ok:
            print_success(f"    {name:<24} -> {status}")
            # After wake, try GET_INPUT_REPORT
            get_resp = device.get_input_report() if hasattr(device, 'get_input_report') else None
            if get_resp and any(b != 0 for b in get_resp):
                print_success(f"      -> post-wake GET: {get_resp[:32].hex()}")
        else:
            print_info(f"    {name:<24} -> {status}")

    ctrl_ok = sum(1 for r in ctrl_results if r.get("ok"))

    # ── Summary ────────────────────────────────────────────────

    print_divider()
    ok_count = sum(1 for r in results if r["ok"])
    mifare_ok = sum(1 for r in mifare_results if r["ok"])
    ctrl_ok_count = ctrl_ok
    total = len(results) + len(mifare_results) + len(ctrl_results)
    ok_total = ok_count + mifare_ok + ctrl_ok_count
    print_info(f"\n  Results: {ok_total}/{total} tests returned data")
    print_info(f"  Generic: {ok_count}/{len(results)}   MIFARE: {mifare_ok}/{len(mifare_results)}   Control: {ctrl_ok_count}/{len(ctrl_results)}")
    if ok_count:
        print_success(f"  Responding generic command IDs:")
        for r in results:
            if r["ok"]:
                print_success(f"    {r['layer']} cmd=0x{r['opcode']:02X}: {r['detail']}")
    if mifare_ok:
        print_success(f"  Responding MIFARE commands:")
        for r in mifare_results:
            if r["ok"]:
                print_success(f"    {r['name']}: {r['detail']}")
    if ctrl_ok_count:
        print_success(f"  Responding control transfers:")
        for r in ctrl_results:
            if r.get("ok"):
                label = r.get("type", "") + ":" + r.get("name", str(r.get("attempt", "")))
                txt = r.get("text", "") or ""
                print_success(f"    {label}: {txt[:100]}" if txt else f"    {label}: data")
    else:
        if ok_count == 0 and mifare_ok == 0:
            print_error("  No responses from any transport or protocol.")
            print_warning("  Device may be output-only (text to LCD), not command-driven.")

    return CommandResult(True, f"Probed {total} paths ({ok_total} responses)")
