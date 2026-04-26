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


def cmd_device_probe(device: CopyKeyDevice) -> CommandResult:
    """Passive HID listener: read raw input reports from device.

    Opens the device and reads HID input reports in a loop with a
    short timeout.  When the X100 scans a card (button press), it may
    send data as input reports.  Raw hex is printed for protocol
    discovery. Press Ctrl+C to stop.
    """
    if not device.is_connected():
        print_error("Device not connected")
        return CommandResult(False, error="No device connected")

    if not device.device:
        print_error("No HID device handle")
        return CommandResult(False, error="No device handle")

    print_divider("HID Probe — Passive Listener")
    print_info(f"Device: {device.product} ({device.serial})")
    print_info("Listening for HID input reports...")
    print_info("PRESS THE SCAN BUTTON ON THE X100 DEVICE")
    print_info("Press Ctrl+C to stop.")
    print_divider()

    report_count: int = 0

    try:
        while True:
            try:
                data = device.device.read(64, timeout_ms=100)
                if data:
                    report_count += 1
                    raw = bytes(data)
                    ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
                    print_info(f"\n[#{report_count}] {len(raw)} bytes")
                    print_info(f"  HEX: {raw.hex(' ').upper()}")
                    print_info(f"  RAW: {raw.hex().upper()}")
                    # Try to decode as text
                    try:
                        text = raw.decode("ascii", errors="replace").rstrip("\x00").strip()
                        if text:
                            print_info(f"  TXT: {text}")
                    except Exception:
                        pass
                    sys.stdout.flush()
            except Exception as e:
                # Timeout is normal — just means no data yet
                if "timeout" not in str(e).lower():
                    logger.debug("Probe read error: %s", e)
    except KeyboardInterrupt:
        print_info(f"\n\nProbe stopped. Received {report_count} report(s).")

    return CommandResult(True, f"Captured {report_count} report(s)")
