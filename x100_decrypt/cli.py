"""
Command line interface for x100_decrypt.

The CLI provides a simple interface for converting one or more card
dumps into another format.  It supports batch processing, optional
external key recovery and configurable strictness.  To prevent
unintended misuse the user must explicitly acknowledge ownership of
the card dumps via the ``--confirm-ownership`` flag.

Usage example::

    python -m x100_decrypt.cli dumps_dir -o out_dir --format json --workers 4 --confirm-ownership

This will recursively process all files in ``dumps_dir`` with up to
four worker threads, outputting JSON files into ``out_dir``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from .engine import DumpEngine


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalise MIFARE Classic dumps")
    parser.add_argument(
        "inputs",
        nargs="+",
        help="One or more files or directories to process",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Directory in which converted dumps will be written",
    )
    parser.add_argument(
        "--format",
        choices=["mfd", "bin", "json"],
        default="bin",
        help="Output format (default: bin)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker threads to use for concurrent processing",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on malformed dumps instead of attempting to salvage",
    )
    parser.add_argument(
        "--recover-keys",
        action="store_true",
        help="Attempt to recover missing keys using external tools (mfoc)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to a YAML configuration file overriding defaults",
    )
    parser.add_argument(
        "--confirm-ownership",
        action="store_true",
        help="Confirm that you own the card dumps you are processing.  This flag is required."
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.confirm_ownership:
        sys.stderr.write(
            "Error: you must specify --confirm-ownership to acknowledge that you are authorised to process these dumps.\n"
        )
        return 2
    # Load optional YAML configuration
    cfg = None
    if args.config:
        try:
            from .config import Config

            cfg = Config.from_yaml(args.config)
        except Exception as exc:
            sys.stderr.write(f"Failed to load config {args.config}: {exc}\n")
            return 1
    # Determine whether to use external key recovery.  CLI flag takes precedence.
    use_external = args.recover_keys
    if not args.recover_keys and cfg is not None:
        use_external = cfg.use_external_recovery
    engine = DumpEngine(use_external_recovery=use_external)
    try:
        engine.run(
            inputs=args.inputs,
            output=args.output,
            fmt=args.format,
            workers=args.workers,
            strict=args.strict,
        )
    except Exception as exc:  # pylint: disable=broad-except
        sys.stderr.write(f"Fatal error: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())