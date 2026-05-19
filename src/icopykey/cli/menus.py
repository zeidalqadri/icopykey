"""
Interactive menu system for CopyKEY CLI.

Provides the main menu loop, sub-menus (key library, card library,
settings), and input dispatch.  All presentation is handled by
:mod:`.display` and business logic by :mod:`.commands`.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from .device import CopyKeyDevice
from .card_ops import CardOperations
from .library import LocalLibrary
from .commands import (
    CommandResult,
    cmd_read_card,
    cmd_decode_card,
    cmd_encrypt_card,
    cmd_write_card,
    cmd_list_keys,
    cmd_add_key,
    cmd_del_key,
    cmd_list_cards,
    cmd_load_card,
    cmd_save_card,
    cmd_delete_card,
    cmd_export_card,
    cmd_import_card,
    cmd_device_info,
    cmd_device_change,
    cmd_device_reconnect,
    cmd_device_probe,
)
from .display import (
    print_success,
    print_error,
    print_warning,
    print_info,
    print_header,
    print_divider,
    print_status_line,
)
from .validators import validate_key, validate_index, validate_filename

logger = logging.getLogger("copykey_cli.menus")


# ── Helpers ──────────────────────────────────────────────────────


def _get_device_status(device: CopyKeyDevice) -> str:
    if device.is_connected():
        try:
            info = device.get_device_info()
            if info:
                return f"{info.get('product', 'Unknown')} [{info.get('serial', 'N/A')}]"
        except Exception:
            pass
        return "Connected"
    return "No device"


def _get_library_status(library: LocalLibrary) -> str:
    return f"{len(library.keys)} keys, {len(library.cards)} cards"


def _confirm(prompt: str) -> bool:
    """Ask user for yes/no confirmation."""
    answer = input(f"  {prompt} [y/N]: ").strip().lower()
    return answer in ("y", "yes")


# ── Main Menu ────────────────────────────────────────────────────


def run_main_menu(
    device: CopyKeyDevice,
    ops: CardOperations,
    library: LocalLibrary,
) -> None:
    """Run the main interactive menu loop."""
    while True:
        _render_main_menu(device, library)
        choice = input("\n  Select [1-9/h/q]: ").strip().lower()

        if choice == "1":
            # ── Read Card ──────────────────────────────────
            print_divider("Read Card")
            cmd_read_card(ops)

        elif choice == "2":
            # ── One-Click Decode ───────────────────────────
            print_divider("One-Click Decode")
            result = cmd_decode_card(ops, library)
            if result.success and library:
                name = input("\n  Save to library? Enter name (or Enter to skip): ").strip()
                if name:
                    cmd_save_card(library, ops, name)

        elif choice == "3":
            # ── Encrypt Card Data ──────────────────────────
            print_divider("Encrypt Card Data")
            if not ops.current_card:
                print_error("No card loaded. Decode or load a card first.")
                continue

            print_info("1. Use same keys for all sectors")
            print_info("2. Random keys for each sector")
            opt = input("  Choose [1-2] (default 1): ").strip() or "1"

            if opt == "2":
                if _confirm("Apply random keys to all modifiable sectors?"):
                    cmd_encrypt_card(ops, random_keys=True)
            else:
                ka = input("  New Key A (12 hex digits, or Enter to keep): ").strip()
                kb = input("  New Key B (12 hex digits, or Enter to keep): ").strip()
                try:
                    new_a = bytes.fromhex(ka) if ka else None
                    new_b = bytes.fromhex(kb) if kb else None
                    if new_a and len(new_a) != 6:
                        print_error("Key A must be 6 bytes (12 hex digits)")
                        continue
                    if new_b and len(new_b) != 6:
                        print_error("Key B must be 6 bytes (12 hex digits)")
                        continue
                    cmd_encrypt_card(ops, new_key_a=new_a, new_key_b=new_b)
                except ValueError:
                    print_error("Invalid hex format for key")

        elif choice == "4":
            # ── Write Card ─────────────────────────────────
            print_divider("Write Card")
            cmd_write_card(ops)

        elif choice == "5":
            # ── Key Library ────────────────────────────────
            _run_key_menu(library)

        elif choice == "6":
            # ── Card Library ───────────────────────────────
            _run_card_menu(library, ops)

        elif choice == "7":
            # ── Import Card ────────────────────────────────
            print_divider("Import Card")
            filepath = input("  File path (.json/.mfd/.bin): ").strip()
            if filepath:
                cmd_import_card(library, ops, filepath)

        elif choice == "8":
            # ── Export Card ────────────────────────────────
            print_divider("Export Card")
            cards = library.list_cards()
            if not cards:
                print_info("No cards to export")
                continue
            for i, c in enumerate(cards):
                print_info(f"  {i}. {c['name']} (UID: {c['uid']})")
            try:
                idx = int(input("\n  Card index: ").strip())
                output_dir = input("  Output directory (Enter for current): ").strip() or "."
                cmd_export_card(library, idx, output_dir)
            except ValueError:
                print_error("Invalid index")

        elif choice == "9":
            # ── Device Settings ────────────────────────────
            _run_device_menu(device)

        elif choice == "h":
            # ── Help ───────────────────────────────────────
            _show_help()

        elif choice == "q":
            # ── Quit ───────────────────────────────────────
            print_divider()
            print_info("Goodbye!")
            device.disconnect()
            sys.exit(0)

        else:
            print_warning("Invalid option. Enter 1-9, h for help, or q to quit.")


def _render_main_menu(device: CopyKeyDevice, library: LocalLibrary) -> None:
    """Draw the main menu screen."""
    print_header("icopyzed v2.1", "NFC/RFID Card Management Tool")
    print_status_line(_get_device_status(device), _get_library_status(library))
    print_divider()
    print_info(" 1. Read Card          Read MIFARE/ID/NTAG from device")
    print_info(" 2. One-Click Decode   Auto-decrypt all sectors")
    print_info(" 3. Encrypt Data       Modify sector keys & access bits")
    print_info(" 4. Write Card         Write data to blank/clone card")
    print_info(" 5. Key Library        Manage authentication keys")
    print_info(" 6. Card Library       Browse saved cards")
    print_info(" 7. Import Card        Load .json/.mfd/.bin file")
    print_info(" 8. Export Card        Export card to file")
    print_info(" 9. Device Settings    VID/PID, info, reconnect")
    print_info(" h. Help               Show usage guide")
    print_info(" q. Quit               Exit application")


# ── Key Library Sub-Menu ─────────────────────────────────────────


def _run_key_menu(library: LocalLibrary) -> None:
    """Key library management sub-menu."""
    while True:
        print_divider("Key Library")

        if library.keys:
            for name, key in library.keys.items():
                print_info(f"  {name}: {key.hex().upper()}")
        else:
            print_info("  (No keys stored)")

        print_info("\n  Commands: add <name> <key> | del <name> | back")
        cmd = input("\n  key> ").strip()

        if not cmd:
            continue
        if cmd == "back":
            break

        parts = cmd.split()
        if parts[0] == "add" and len(parts) >= 3:
            name = parts[1]
            key_hex = parts[2]
            cmd_add_key(library, name, key_hex)
        elif parts[0] == "del" and len(parts) >= 2:
            name = parts[1]
            cmd_del_key(library, name)
        else:
            print_warning("Usage: add <name> <key_hex> | del <name> | back")


# ── Card Library Sub-Menu ────────────────────────────────────────


def _run_card_menu(library: LocalLibrary, ops: CardOperations) -> None:
    """Card library management sub-menu."""
    while True:
        print_divider("Card Library")
        cards = library.list_cards()

        if cards:
            for idx, card in enumerate(cards):
                print_info(f"  {idx}. {card['name']}")
                print_info(f"     UID: {card['uid']} | Type: {card['card_type']}")
        else:
            print_info("  (No cards stored)")

        print_info("\n  Commands: load <idx> | del <idx> | export <idx> | back")
        cmd = input("\n  card> ").strip()

        if not cmd:
            continue
        if cmd == "back":
            break

        parts = cmd.split()
        if parts[0] == "load" and len(parts) >= 2:
            try:
                idx = int(parts[1])
                cmd_load_card(library, ops, idx)
            except ValueError:
                print_error("Invalid index")
        elif parts[0] == "del" and len(parts) >= 2:
            try:
                idx = int(parts[1])
                cmd_delete_card(library, idx)
            except ValueError:
                print_error("Invalid index")
        elif parts[0] == "export" and len(parts) >= 2:
            try:
                idx = int(parts[1])
                out_dir = input("  Output directory (Enter for current): ").strip() or "."
                cmd_export_card(library, idx, out_dir)
            except ValueError:
                print_error("Invalid index")
        else:
            print_warning("Usage: load <idx> | del <idx> | export <idx> | back")


# ── Device Settings Sub-Menu ────────────────────────────────────


def _run_device_menu(device: CopyKeyDevice) -> None:
    """Device settings sub-menu."""
    while True:
        print_divider("Device Settings")

        status = "Connected" if device.is_connected() else "Disconnected"
        print_info(f"  Status: {status}")
        print_info(f"  VID: 0x{device.vid:04X}  PID: 0x{device.pid:04X}")
        if device.is_connected():
            info = device.get_device_info()
            if info:
                print_info(f"  Product: {info.get('product', 'N/A')}")
                print_info(f"  Serial:  {info.get('serial', 'N/A')}")

        print_info("\n  Commands:")
        print_info("  info       - Show device details")
        print_info("  change     - Change VID/PID and reconnect")
        print_info("  reconnect  - Reconnect with current settings")
        print_info("  enumerate  - List all HID devices")
        print_info("  descriptor - Dump HID report descriptor")
        print_info("  probe      - Test all HID commands against device")
        print_info("  back       - Return to main menu")

        cmd = input("\n  device> ").strip().lower()

        if not cmd:
            continue
        if cmd == "back":
            break
        elif cmd == "info":
            cmd_device_info(device)
        elif cmd == "change":
            vid = input("  New VID (hex, e.g. 0x6300): ").strip()
            pid = input("  New PID (hex, e.g. 0x1991): ").strip()
            if vid and pid:
                cmd_device_change(device, vid.replace("0x", ""), pid.replace("0x", ""))
        elif cmd == "reconnect":
            cmd_device_reconnect(device)
        elif cmd == "enumerate":
            all_devices = device.enumerate_devices()
            if not all_devices:
                # Fallback: try hidapi directly for full bus scan
                try:
                    import hid as _hid
                    all_devices = _hid.enumerate()
                except Exception:
                    pass
            if all_devices:
                print_info(f"  All HID devices ({len(all_devices)}):")
                for i, d in enumerate(all_devices):
                    vend = d.get('vendor_id', 0)
                    prod = d.get('product_id', 0)
                    name = d.get('product_string', '') or d.get('manufacturer_string', '')
                    marker = " <<<" if (vend == device.vid and prod == device.pid) else ""
                    print_info(f"  {i}. {vend:04X}:{prod:04X} {name}{marker}")
            else:
                print_warning("  No HID devices found. Is the device connected?")
        elif cmd == "descriptor":
            from .commands import cmd_device_descriptor
            cmd_device_descriptor(device)
        elif cmd == "probe":
            cmd_device_probe(device)
        else:
            print_warning("Unknown command. Try: info | change | reconnect | enumerate | descriptor | probe | back")


# ── Help Screen ──────────────────────────────────────────────────


def _show_help() -> None:
    """Display comprehensive help."""
    print_divider("Help")
    print_info("""
ICOPYZED CLI — NFC/RFID Card Management Tool
================================================

Quick Start:
  1. Connect the X100/CopyKEY device via USB
  2. Select '1' to read a card placed on the reader
  3. Select '2' to decode all sectors automatically
  4. Select '3' to encrypt with new keys
  5. Select '4' to write to a blank clone card

Subcommands:
  icopyzed                  Interactive menu (default)
  icopyzed decrypt          Launch kopized decryption service
  icopyzed convert FILE     Normalize card dumps to JSON

Card Types Supported:
  - MIFARE Classic 1K (S50):  16 sectors, 64 blocks
  - MIFARE Classic 4K (S70):  40 sectors, 256 blocks
  - ID/PID/NSC cards:         Read/write via device
  - NTAG/Ultralight EV1:      Read/write via device

Key Management:
  Keys are stored encrypted in ~/.copykey_cli/keys.json.enc
  Use the Key Library menu (5) to add, delete, or view keys.
  Default factory keys are tried automatically during decode.

Card Library:
  Decoded cards are saved in ~/.copykey_cli/cards.json.enc
  Import/export cards as .json files.
  Search by name or UID.

Device Settings:
  The default VID=0x6300, PID=0x1991 may need adjustment.
  Use the Device Settings menu (9) to enumerate and change.

Keyboard Shortcuts:
  Ctrl+C - Cancel current operation / return to menu
  q      - Quit application (from any menu)

Logging:
  Session logs are stored in ~/.copykey_cli/logs/
  Use --verbose flag for detailed debug output.
""")
