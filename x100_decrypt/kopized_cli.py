"""
Kopized CLI - Command-line interface for real-time X100 device decryption

This module provides the 'kopized' command that listens for decryption requests
from the X100 Smart Card Replicator and responds with decrypted sector keys.

Usage:
    kopized                          # Start with default settings
    kopized --keys keys.txt          # Load additional keys from file
    kopized --key FFFFFFFFFFFF       # Add a specific key
    kopized --verbose                # Enable verbose output
    kopized --listen-usb             # Listen for USB device connections
    kopized --demo                   # Run in demo mode without hardware
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional

from .kopized import (
    KopizedService,
    DecryptionRequest,
    create_kopized_service,
)

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    logging.basicConfig(
        level=level,
        format=format_str,
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="kopized",
        description="Real-time decryption service for X100 Smart Card Replicator",
        epilog="""
Examples:
  kopized                           Start with default factory keys
  kopized --keys mykeys.txt         Load additional keys from file
  kopized --key A0A1A2A3A4A5        Add a specific key
  kopized --verbose                 Show detailed debug information
  kopized --demo                    Run in demo/test mode
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "-k", "--key",
        action="append",
        dest="keys",
        metavar="HEX",
        help="Add a hex-encoded key (can be specified multiple times)",
    )
    
    parser.add_argument(
        "-f", "--keys-file",
        dest="keys_file",
        metavar="FILE",
        help="Load keys from a text file (one key per line)",
    )
    
    parser.add_argument(
        "--no-defaults",
        action="store_true",
        help="Don't use default factory keys, only use provided keys",
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run in demo mode without hardware interaction",
    )
    
    parser.add_argument(
        "--listen-usb",
        action="store_true",
        help="Listen for USB device connections (requires libusb)",
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Timeout for device communication (default: 300s)",
    )
    
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Save decryption results to a JSON file",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="kopized 0.1.0",
    )
    
    return parser.parse_args(argv or sys.argv[1:])


def run_demo_mode(service: KopizedService, verbose: bool = False) -> int:
    """Run kopized in demo mode to test functionality without hardware.
    
    This simulates a decryption request from the X100 device using
    sample card data.
    """
    print("Running in DEMO mode...")
    print("-" * 60)
    
    # Simulate device output
    sample_output = """
CN: 16198219
Model: IC/MI-S50+
UID: 4B 2A F7 53
ATQA: 04 00       SAK: 08

TIPS
There are encrypted sectors. Please connect to the computer 
and use decryption software to decrypt
"""
    
    print("Simulated device output:")
    print(sample_output)
    print("-" * 60)
    
    # Parse the simulated output
    request = DecryptionRequest.from_device_output(sample_output)
    print(f"Parsed request ID: {request.request_id}")
    print(f"Card UID: {request.card_info.uid}")
    print(f"Card Type: {request.card_info.card_type}")
    print(f"Sectors to decrypt: {len(request.sector_numbers)}")
    print()
    
    # Process the request
    print("Attempting decryption...")
    response = service.decrypt_request(request)
    
    # Display results
    print("\n" + "=" * 60)
    print("DECRYPTION RESULTS")
    print("=" * 60)
    print(f"Success: {response.success}")
    print(f"Keys recovered: {response.keys_recovered}")
    print(f"Time taken: {response.time_taken_ms:.2f}ms")
    
    if response.decrypted_sectors:
        print(f"\nDecrypted sectors ({len(response.decrypted_sectors)}):")
        for sector in response.decrypted_sectors[:5]:  # Show first 5
            print(f"  Sector {sector.sector_number}: "
                  f"Key A={sector.key_a}, Key B={sector.key_b}")
        if len(response.decrypted_sectors) > 5:
            print(f"  ... and {len(response.decrypted_sectors) - 5} more")
    
    if response.error_message:
        print(f"\nWarning: {response.error_message}")
    
    # Generate device commands
    print("\n" + "-" * 60)
    print("Commands to send to device:")
    print("-" * 60)
    commands = service.generate_device_command(response)
    print(commands)
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)
    
    return 0 if response.success else 1


def run_usb_listener(service: KopizedService, timeout: int = 300) -> int:
    """Listen for USB device connections and process decryption requests.
    
    This function would integrate with libusb or similar to detect when
    the X100 device is connected and ready for communication.
    
    Note: Full USB implementation requires platform-specific libraries
    and device protocol documentation.
    """
    print("USB listener mode not yet fully implemented.")
    print("This would require:")
    print("  - libusb or pyusb installation")
    print("  - X100 device USB protocol specification")
    print("  - Platform-specific USB drivers")
    print()
    print("For now, please use demo mode or manual input mode.")
    return 1


def run_interactive_mode(service: KopizedService, output_file: Optional[str] = None) -> int:
    """Run kopized in interactive mode, accepting device output via stdin.
    
    The user can paste the device output directly into the terminal,
    and kopized will process it and return the decryption results.
    """
    print("Kopized Interactive Mode")
    print("=" * 60)
    print("Paste the X100 device output below (or Ctrl+D to exit):")
    print("Example device output:")
    print("  CN: 16198219")
    print("  Model: IC/MI-S50+")
    print("  UID: 4B 2A F7 53")
    print("  ATQA: 04 00       SAK: 08")
    print()
    print("Waiting for input...")
    print("-" * 60)
    
    try:
        while True:
            print("\nEnter device output (empty line to process):")
            lines = []
            while True:
                try:
                    line = input()
                    if not line.strip():
                        break
                    lines.append(line)
                except EOFError:
                    break
            
            if not lines:
                print("No input provided. Use Ctrl+C to exit.")
                continue
            
            # Parse and process the input
            device_output = "\n".join(lines)
            request = DecryptionRequest.from_device_output(device_output)
            
            print(f"\nProcessing request for card {request.card_info.uid}...")
            response = service.decrypt_request(request)
            
            # Display results
            print("\n" + "=" * 60)
            print("DECRYPTION RESULTS")
            print("=" * 60)
            print(f"Success: {response.success}")
            print(f"Keys recovered: {response.keys_recovered}")
            print(f"Time taken: {response.time_taken_ms:.2f}ms")
            
            if response.decrypted_sectors:
                print(f"\nDecrypted sectors:")
                for sector in response.decrypted_sectors:
                    print(f"  Sector {sector.sector_number}: "
                          f"Key A={sector.key_a}, Key B={sector.key_b}")
            
            # Generate and display device commands
            print("\n" + "-" * 60)
            print("Send these commands to the device:")
            print("-" * 60)
            commands = service.generate_device_command(response)
            print(commands)
            
            # Save to file if requested
            if output_file:
                import json
                with open(output_file, 'w') as f:
                    json.dump(response.to_dict(), f, indent=2)
                print(f"\nResults saved to: {output_file}")
            
            print("\n" + "=" * 60)
    
    except KeyboardInterrupt:
        print("\n\nExiting...")
        return 0
    
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the kopized CLI."""
    args = parse_args(argv)
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Create service with configured keys
    logger.info("Initializing Kopized service...")
    service = create_kopized_service(
        key_file=args.keys_file,
        custom_keys=args.keys,
        use_defaults=not args.no_defaults,
        verbose=args.verbose,
    )
    
    logger.info(f"Loaded {len(service.available_keys)} keys")
    
    # Determine which mode to run
    if args.demo:
        return run_demo_mode(service, args.verbose)
    elif args.listen_usb:
        return run_usb_listener(service, args.timeout)
    else:
        # Default to interactive mode
        return run_interactive_mode(service, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
