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
    copykey-cli --vid 0x6300 --pid 0x1991  # Specify device VID/PID
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
from .constants import DEVICE_VID, DEVICE_PID
from .library import LocalLibrary
from .device import CopyKeyDevice, CopyKeyRemoteDevice, HID_AVAILABLE
from .card_ops import CardOperations
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
  icopyzed                          Launch interactive menu
  icopyzed --read                   Read card from device
  icopyzed --decode                 One-click decode
  icopyzed --list-cards             Show card library
  icopyzed --import card.json       Import card file
  icopyzed --export 0 -o ./exports  Export card by index
  icopyzed --device-info            Show connected device details
  icopyzed --vid 0x6300 --pid 0x1991  Custom VID/PID
  icopyzed --verbose                Enable debug output
  icopyzed decrypt                  Launch kopized decryption service
  icopyzed convert input.dump       Normalize card dump to JSON
  icopyzed descriptor               Dump HID report descriptor from device
  icopyzed probe                    Test all HID command paths against device
  icopyzed relay-server             Start TCP HID relay (run on machine with hardware)
  icopyzed probe --relay :9999      Probe device through a relay tunnel
        """,
    )

    # ── Operations ────────────────────────────────────────
    op_group = parser.add_argument_group("Operations")
    op_group.add_argument("--read", action="store_true", help="Read card info from device")
    op_group.add_argument("--decode", action="store_true", help="One-click decode all sectors")
    op_group.add_argument("--crack", metavar="SECTOR", type=int, nargs="?", const=-1, help="Crack sector keys (all if no sector given)")
    op_group.add_argument("--list-cards", action="store_true", help="List stored cards")
    op_group.add_argument("--list-keys", action="store_true", help="List stored keys")
    op_group.add_argument("--device-info", action="store_true", help="Show device information")
    op_group.add_argument("--import", dest="import_file", metavar="FILE", help="Import card from file")
    op_group.add_argument("--export", dest="export_index", type=int, metavar="INDEX", help="Export card by index")
    op_group.add_argument("--delete", dest="delete_index", type=int, metavar="INDEX", help="Delete card by index")

    # ── Options ───────────────────────────────────────────
    opt_group = parser.add_argument_group("Options")
    opt_group.add_argument("--vid", metavar="HEX", help="Device Vendor ID (default: 0x6300)")
    opt_group.add_argument("--pid", metavar="HEX", help="Device Product ID (default: 0x1991)")
    opt_group.add_argument("-o", "--output", metavar="DIR", default=".", help="Output directory for exports")
    opt_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    opt_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    opt_group.add_argument("--no-encrypt", action="store_true", help="Skip vault encryption (plaintext storage)")
    opt_group.add_argument("--vault-password", metavar="PASS", help="Vault password (prefer interactive prompt)")
    opt_group.add_argument("--data-dir", metavar="DIR", help="Override data directory (default: ~/.copykey_cli)")
    opt_group.add_argument("--relay", metavar="HOST:PORT", help="Connect via TCP relay (e.g. localhost:9999)")
    opt_group.add_argument("--reader", action="store_true", help="Use external NFC reader for darkside/nested attack")
    opt_group.add_argument("--from-trace", dest="from_trace", metavar="FILE", help="Run `crack` against a captured nonce JSON trace (no hardware needed)")
    opt_group.add_argument("--record", dest="record", metavar="FILE", help="Self-record every device write/read into a pcapng (compatible with analyze_capture)")
    opt_group.add_argument("--version", action="version", version="copykey-cli 2.1.0")

    return parser


# ── Device Factory ───────────────────────────────────────────────


def _create_device(args: argparse.Namespace) -> CopyKeyDevice:
    """Return local or remote device based on --relay flag.

    If ``--record FILE`` is set, instantiate a :class:`PcapNgWriter`
    and attach it to the device so every ``write_read`` is mirrored
    into the pcapng for later analysis.
    """
    recorder = None
    record_path = getattr(args, "record", None)
    if record_path:
        from .pcap_writer import PcapNgWriter

        recorder = PcapNgWriter(record_path)
        print_info(f"Recording device I/O to {record_path}")

    if args.relay:
        host = "localhost"
        port = 9999
        parts = args.relay.rsplit(":", 1)
        if parts[0]:
            host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 9999
        return CopyKeyRemoteDevice(host=host, port=port, recorder=recorder)

    vid = int(args.vid, 16) if args.vid else DEVICE_VID
    pid = int(args.pid, 16) if args.pid else DEVICE_PID
    return CopyKeyDevice(vid=vid, pid=pid, recorder=recorder)


# ── Batch Mode ───────────────────────────────────────────────────


def run_batch_mode(args: argparse.Namespace) -> int:
    """Execute a single operation and exit (non-interactive mode)."""
    config = ConfigManager()
    cfg = config.config
    data_dir = Path(args.data_dir) if args.data_dir else Path(cfg.paths.vault_dir)

    if not args.relay and not HID_AVAILABLE and any([args.read, args.decode, args.device_info]):
        print_error("hidapi library not available. Install with: pip install hidapi")
        return 1

    device = _create_device(args)

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


def _parse_vid_pid_args(argv: list[str], cfg: Any) -> tuple[int, int]:
    """Parse --vid / --pid from argv, falling back to config, then to
    the authoritative constants (:data:`constants.DEVICE_VID` /
    :data:`DEVICE_PID`).

    When neither CLI args nor config name a device that is actually
    present on the USB bus, fall through to the constants — this saves
    users whose ``~/.copykey_cli/config.json`` still contains the
    pre-2026-05-19 placeholder ``0x0483/0x5740`` from a silent
    "Device not found".  Also accepts positional args:
    ``icopyzed descriptor 0x6300 0x1991``.
    """
    vid: int = 0
    pid: int = 0
    explicit = False  # set when --vid or positional argv was used
    i = 2
    while i < len(argv):
        if argv[i] == "--vid" and i + 1 < len(argv):
            vid = int(argv[i + 1], 16)
            explicit = True
            i += 2
        elif argv[i] == "--pid" and i + 1 < len(argv):
            pid = int(argv[i + 1], 16)
            explicit = True
            i += 2
        else:
            break
    # If no --vid, try positional args (legacy 4-arg descriptor invocation)
    if vid == 0 and len(argv) > 2 and not argv[2].startswith("--"):
        vid = int(argv[2], 16)
        explicit = True
    if pid == 0 and len(argv) > 3 and not argv[3].startswith("--"):
        pid = int(argv[3], 16)
        explicit = True
    if vid == 0:
        vid = int(cfg.device.vid, 16) if isinstance(cfg.device.vid, str) else cfg.device.vid
    if pid == 0:
        pid = int(cfg.device.pid, 16) if isinstance(cfg.device.pid, str) else cfg.device.pid

    # If the user did NOT explicitly pass VID/PID, sanity-check the
    # config-derived values against what's actually plugged in. If the
    # config-supplied IDs don't enumerate but the constants do, fall
    # through to the constants with a warning. This rescues users with
    # stale config.json files.
    if not explicit and (vid, pid) != (DEVICE_VID, DEVICE_PID):
        try:
            import hid  # type: ignore
            if not hid.enumerate(vid, pid) and hid.enumerate(DEVICE_VID, DEVICE_PID):
                print_warning(
                    f"Stale config VID=0x{vid:04X}/PID=0x{pid:04X} not present; "
                    f"falling back to defaults 0x{DEVICE_VID:04X}/0x{DEVICE_PID:04X}. "
                    "Consider editing ~/.copykey_cli/config.json or running "
                    "`icopyzed --vid 0x6300 --pid 0x1991 ...` once to update it."
                )
                vid, pid = DEVICE_VID, DEVICE_PID
        except ImportError:
            pass

    return vid, pid


def main(argv: list[str] | None = None) -> int:
    """Entry point for the CopyKEY CLI."""

    # ── Subcommand dispatch ────────────────────────────────

    if len(sys.argv) > 1 and sys.argv[1] == "decrypt":
        sys.argv.pop(1)
        from icopykey.x100.kopized_cli import main as decrypt_main
        return decrypt_main()

    if len(sys.argv) > 1 and sys.argv[1] == "convert":
        sys.argv.pop(1)
        from icopykey.x100.cli import main as convert_main
        return convert_main()

    if len(sys.argv) > 1 and sys.argv[1] == "relay-server":
        sys.argv.pop(1)
        from .hidrelay import main as relay_main
        return relay_main()

    if len(sys.argv) > 1 and sys.argv[1] == "sniff":
        sys.argv.pop(1)
        from .sniff import main as sniff_main
        return sniff_main()

    if len(sys.argv) > 1 and sys.argv[1] == "probe":
        import sys as _sys
        if "--relay" in _sys.argv:
            _sys.argv.pop(_sys.argv.index("probe"))
            from .commands import cmd_device_probe
            parser = build_parser()
            args = parser.parse_args(_sys.argv[1:])
            d = _create_device(args)
            if not d.connect():
                print("Device not found.", file=_sys.stderr)
                return 1
            cmd_device_probe(d)
            d.disconnect()
            return 0

        from .commands import cmd_device_probe
        from .config_manager import ConfigManager as _CM
        cfg = _CM().config
        vid_str, pid_str = _parse_vid_pid_args(_sys.argv, cfg)
        # Honour --record FILE.pcapng even on the no-relay probe path.
        record_path: str | None = None
        if "--record" in _sys.argv:
            idx = _sys.argv.index("--record")
            if idx + 1 < len(_sys.argv):
                record_path = _sys.argv[idx + 1]
        recorder = None
        if record_path:
            from .pcap_writer import PcapNgWriter

            recorder = PcapNgWriter(record_path)
            print_info(f"Recording device I/O to {record_path}")
        d = CopyKeyDevice(vid=vid_str, pid=pid_str, recorder=recorder)
        if not d.connect():
            print("Device not found.", file=_sys.stderr)
            return 1
        cmd_device_probe(d)
        d.disconnect()
        return 0

    if len(sys.argv) > 1 and sys.argv[1] == "crack":
        import sys as _sys
        _sys.argv.pop(1)
        from .commands import cmd_crack_key, cmd_crack_from_trace
        from .config_manager import ConfigManager as _CM
        parser = build_parser()
        args = parser.parse_args(_sys.argv[1:])

        # Trace-file path: pure-software attack, no device needed.
        if args.from_trace:
            return cmd_crack_from_trace(args.from_trace)

        cfg = _CM().config
        data_dir = Path(args.data_dir) if args.data_dir else Path(cfg.paths.vault_dir)
        vault_pw = args.vault_password
        library = LocalLibrary(data_dir, vault_password=vault_pw)

        d = _create_device(args)
        if not d.connect():
            print("Device not found.", file=_sys.stderr)
            return 1
        sector = args.crack if args.crack != -1 else None
        use_reader = getattr(args, "reader", False)
        cmd_crack_key(d, library, sector=sector, use_external_reader=use_reader)
        d.disconnect()
        return 0

    if len(sys.argv) > 1 and sys.argv[1] == "descriptor":
        import sys as _sys
        if "--relay" in _sys.argv:
            _sys.argv.pop(_sys.argv.index("descriptor"))
            from .commands import cmd_device_descriptor
            parser = build_parser()
            args = parser.parse_args(_sys.argv[1:])
            d = _create_device(args)
            if not d.connect():
                print("Device not found.", file=_sys.stderr)
                return 1
            cmd_device_descriptor(d)
            d.disconnect()
            return 0

        from .commands import cmd_device_descriptor
        from .config_manager import ConfigManager as _CM
        cfg = _CM().config
        vid_str, pid_str = _parse_vid_pid_args(_sys.argv, cfg)
        d = CopyKeyDevice(vid=vid_str, pid=pid_str)
        if not d.connect():
            print("Device not found.", file=_sys.stderr)
            return 1
        cmd_device_descriptor(d)
        d.disconnect()
        return 0

    # ── Argparse ───────────────────────────────────────────

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
        args.read, args.decode, args.crack is not None, args.list_cards, args.list_keys,
        args.device_info, args.import_file, args.export_index is not None,
        args.delete_index is not None,
    ])

    if has_batch_op:
        return run_batch_mode(args)

    # ── Interactive mode ──────────────────────────────────

    data_dir = Path(args.data_dir) if args.data_dir else Path(cfg.paths.vault_dir)
    using_relay = bool(args.relay)

    if not using_relay and not HID_AVAILABLE:
        print_warning("hidapi not installed. Device operations unavailable.")
        print_info("Install with: pip install hidapi")
        print_info("(macOS: brew install hidapi && pip install hidapi)")

    device = _create_device(args)

    # Connect
    if using_relay or HID_AVAILABLE:
        if not device.connect():
            if using_relay:
                print_error("Could not connect to relay. Is relay-server running on the remote machine?")
            else:
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
