#!/usr/bin/env python3
"""
CopyKEY Manager CLI — Interactive NFC/RFID Card Management Tool

This is the main entry point for the CopyKEY command-line interface.
It provides both an interactive menu mode and a batch/scriptable mode
via command-line arguments.

Usage:
    copykey-cli                          # Interactive menu
    copykey-cli --read                   # Read card and print info
    copykey-cli --decode                 # Decode card (requires device)
    copykey-cli --import card.json       # Import card from file
    copykey-cli --export 0 --output dir/ # Export card by index
    copykey-cli --list-cards             # List stored cards
    copykey-cli --list-keys              # List stored keys
    copykey-cli --device-info            # Show device info
    copykey-cli --vid 0x0483 --pid 0x5740  # Specify device VID/PID
    copykey-cli --verbose                # Enable debug logging
    copykey-cli --no-color               # Disable colored output
    copykey-cli --help                   # Show help
"""

from __future__ import annotations

import argparse
import getpass
import logging
import sys
from pathlib import Path

from .logger_setup import setup_logging
from .config_manager import ConfigManager, AppConfig
from .display import print_success, print_error, print_warning, print_info
from .operations import (
    HID_AVAILABLE,
    CopyKeyDevice,
    CardOperations,
    LocalLibrary,
)
from .menus import run_main_menu

logger = logging.getLogger("copykey_cli")


# ── Argument Parser ──────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="copykey-cli",
        description="CopyKEY NFC/RFID Card Management Tool (CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  copykey-cli                        Launch interactive menu
  copykey-cli --read                 Read card from device
  copykey-cli --decode               One-click decode
  copykey-cli --list-cards           Show card library
  copykey-cli --import card.json     Import card file
  copykey-cli --export 0 -o ./exports Export card by index
  copykey-cli --device-info          Show connected device details
  copykey-cli --vid 0x0483 --pid 0x5740  Use custom VID/PID
  copykey-cli --verbose              Enable debug output
        """,
    )

    # ── Operations ────────────────────────────────────────
    op_group = parser.add_argument_group("Operations")
    op_group.add_argument("--read", action="store_true", help="Read card info from device")
    op_group.add_argument("--decode", action="store_true", help="One-click decode all sectors")
    op_group.add_argument("--list-cards", action="store_true", help="List stored cards")
    op_group.add_argument("--list-keys", action="store_true", help="List stored keys")
    op_group.add_argument("--device-info", action="store_true", help="Show device information")
    op_group.add_argument("--import", dest="import_file", metavar="FILE", help="Import card from file")
    op_group.add_argument("--export", dest="export_index", type=int, metavar="INDEX", help="Export card by index")
    op_group.add_argument("--delete", dest="delete_index", type=int, metavar="INDEX", help="Delete card by index")

    # ── Options ───────────────────────────────────────────
    opt_group = parser.add_argument_group("Options")
    opt_group.add_argument("--vid", metavar="HEX", help="Device Vendor ID (default: 0x0483)")
    opt_group.add_argument("--pid", metavar="HEX", help="Device Product ID (default: 0x5740)")
    opt_group.add_argument("-o", "--output", metavar="DIR", default=".", help="Output directory for exports")
    opt_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    opt_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    opt_group.add_argument("--no-encrypt", action="store_true", help="Skip vault encryption (plaintext storage)")
    opt_group.add_argument("--vault-password", metavar="PASS", help="Vault password (prefer interactive prompt)")
    opt_group.add_argument("--data-dir", metavar="DIR", help="Override data directory (default: ~/.copykey_cli)")
    opt_group.add_argument("--version", action="version", version="copykey-cli 2.1.0")

    return parser


# ── Batch Mode ───────────────────────────────────────────────────


def run_batch_mode(args: argparse.Namespace) -> int:
    """Execute a single operation and exit (non-interactive mode)."""
    config = ConfigManager()
    cfg = config.config

    vid = int(args.vid, 16) if args.vid else config.get_vid()
    pid = int(args.pid, 16) if args.pid else config.get_pid()
    data_dir = Path(args.data_dir) if args.data_dir else Path(cfg.paths.vault_dir)

    if not HID_AVAILABLE and any([args.read, args.decode, args.device_info]):
        print_error("hidapi library not available. Install with: pip install hidapi")
        return 1

    device = CopyKeyDevice(vid=vid, pid=pid)

    # Connect for device operations
    if any([args.read, args.decode, args.device_info]):
        if not device.connect():
            print_warning("Device not found. Some operations may fail.")

    # Vault password
    vault_pw: str | None = None
    if not args.no_encrypt:
        if args.vault_password:
            vault_pw = args.vault_password
        else:
            try:
                vault_pw = getpass.getpass("Vault password (Enter for plaintext): ")
            except (EOFError, KeyboardInterrupt):
                vault_pw = ""
        if not vault_pw:
            vault_pw = None

    library = LocalLibrary(data_dir, vault_pw)
    ops = CardOperations(device)

    # ── Execute requested operation ───────────────────────

    if args.list_keys:
        from .commands import cmd_list_keys
        cmd_list_keys(library)

    elif args.list_cards:
        from .commands import cmd_list_cards
        cmd_list_cards(library)

    elif args.import_file:
        from .commands import cmd_import_card
        cmd_import_card(library, ops, args.import_file)

    elif args.export_index is not None:
        from .commands import cmd_export_card
        cmd_export_card(library, args.export_index, args.output)

    elif args.delete_index is not None:
        from .commands import cmd_delete_card
        cmd_delete_card(library, args.delete_index)

    elif args.device_info:
        from .commands import cmd_device_info
        cmd_device_info(device)

    elif args.read:
        from .commands import cmd_read_card
        cmd_read_card(ops)

    elif args.decode:
        from .commands import cmd_decode_card
        cmd_decode_card(ops, library)

    else:
        print_warning("No operation specified. Use --help to see options.")
        return 1

    device.disconnect()
    return 0


# ── Main ─────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """Entry point for the CopyKEY CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Setup logging
    setup_logging(verbose=args.verbose)

    # Load config
    config = ConfigManager()
    cfg = config.config

    if args.no_color:
        cfg.display.colors = False

    logger.info("CopyKEY CLI v2.1 starting")
    logger.debug("Config: %s", cfg.to_dict())

    # ── Determine mode ────────────────────────────────────

    has_batch_op = any([
        args.read, args.decode, args.list_cards, args.list_keys,
        args.device_info, args.import_file, args.export_index is not None,
        args.delete_index is not None,
    ])

    if has_batch_op:
        return run_batch_mode(args)

    # ── Interactive mode ──────────────────────────────────

    vid = int(args.vid, 16) if args.vid else config.get_vid()
    pid = int(args.pid, 16) if args.pid else config.get_pid()
    data_dir = Path(args.data_dir) if args.data_dir else Path(cfg.paths.vault_dir)

    if not HID_AVAILABLE:
        print_warning("hidapi not installed. Device operations unavailable.")
        print_info("Install with: pip install hidapi")
        print_info("(macOS: brew install hidapi && pip install hidapi)")

    device = CopyKeyDevice(vid=vid, pid=pid)

    # Connect
    if HID_AVAILABLE:
        if not device.connect():
            print_warning("Device not found. Running in offline mode.")
            print_info("You can still manage key/card libraries and import/export.")
    else:
        print_info("Running in offline mode (no HID support).")

    # Vault password
    vault_pw: str | None = None
    if not args.no_encrypt:
        if args.vault_password:
            vault_pw = args.vault_password
        else:
            print("\n  Local Library Encryption")
            print("  Enter a password to encrypt your key/card libraries,")
            print("  or press Enter for plaintext storage.")
            try:
                vault_pw = getpass.getpass("\n  Vault password: ")
            except (EOFError, KeyboardInterrupt):
                print()
                vault_pw = ""
        if not vault_pw:
            vault_pw = None
            print_info("Using plaintext storage (no encryption).")

    library = LocalLibrary(data_dir, vault_pw)
    ops = CardOperations(device)

    # ── Run interactive menu ──────────────────────────────

    try:
        run_main_menu(device, ops, library)
    except KeyboardInterrupt:
        print("\n")
        print_warning("Interrupted by user")
        device.disconnect()
        return 0
    except Exception:
        logger.exception("Fatal error in main loop")
        print_error("An unexpected error occurred. Check the log for details.")
        device.disconnect()
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
